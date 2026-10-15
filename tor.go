package torscraper

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// DefaultTorSOCKSAddr is the standard Tor SOCKS5 proxy port.
const DefaultTorSOCKSAddr = "127.0.0.1:9050"

// DefaultTorControlAddr is the standard Tor control port.
const DefaultTorControlAddr = "127.0.0.1:9051"

// TorConfig holds configuration options for Tor integration.
type TorConfig struct {
	// Enabled indicates whether requests should be routed through Tor.
	Enabled bool

	// ProxyAddr is the SOCKS5 address of the Tor daemon (default: 127.0.0.1:9050).
	ProxyAddr string

	// StreamIsolation causes each request or session to authenticate to SOCKS5
	// with a unique virtual username/password. Tor's IsolateSOCKSAuth feature
	// will route each distinct credential over an independent Tor circuit,
	// allowing concurrent requests to use different exit nodes simultaneously.
	StreamIsolation bool

	// ControlAddr is the optional address of the Tor control port (default: 127.0.0.1:9051).
	ControlAddr string

	// ControlPassword is the optional authentication password for the Tor control port.
	ControlPassword string
}

// Clone creates a shallow copy of TorConfig.
func (c *TorConfig) Clone() *TorConfig {
	if c == nil {
		return nil
	}
	cpy := *c
	return &cpy
}

// EnsureDefaults populates sensible defaults for TorConfig.
func (c *TorConfig) EnsureDefaults() {
	if c.ProxyAddr == "" {
		c.ProxyAddr = DefaultTorSOCKSAddr
	}
	if c.ControlAddr == "" {
		c.ControlAddr = DefaultTorControlAddr
	}
}

// generateIsolationAuth creates a random SOCKS5 auth credential for Tor Stream Isolation.
func generateIsolationAuth() *proxy.Auth {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	return &proxy.Auth{
		User:     "iso_" + id,
		Password: "iso",
	}
}

// newSOCKS5Dialer creates a proxy.ContextDialer connecting to Tor SOCKS5.
func newSOCKS5Dialer(ctx context.Context, proxyAddr string, auth *proxy.Auth) (proxy.ContextDialer, error) {
	forward := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, forward)
	if err != nil {
		return nil, fmt.Errorf("failed to create tor socks5 dialer: %w", err)
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks5 dialer does not implement proxy.ContextDialer")
	}

	return contextDialer, nil
}

// TorController manages explicit Tor control commands (e.g. SIGNAL NEWNYM for IP rotation).
type TorController struct {
	addr     string
	password string
	mu       sync.Mutex
	lastNew  time.Time
}

// NewTorController creates a new TorController instance.
func NewTorController(addr, password string) *TorController {
	if addr == "" {
		addr = DefaultTorControlAddr
	}
	return &TorController{
		addr:     addr,
		password: password,
	}
}

// NewIdentity requests Tor to switch to a new circuit (SIGNAL NEWNYM).
// Tor enforces a 10-second minimum cooldown between NEWNYM signals.
// If called within the cooldown period, this method waits until the 10s cooldown expires.
func (tc *TorController) NewIdentity(ctx context.Context) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Handle Tor's 10-second rate-limit on NEWNYM
	cooldown := 10 * time.Second
	elapsed := time.Since(tc.lastNew)
	if elapsed < cooldown {
		wait := cooldown - elapsed
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", tc.addr)
	if err != nil {
		return fmt.Errorf("failed to connect to tor control port %s: %w", tc.addr, err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Send AUTHENTICATE
	authCmd := "AUTHENTICATE\r\n"
	if tc.password != "" {
		authCmd = fmt.Sprintf("AUTHENTICATE \"%s\"\r\n", tc.password)
	}
	if _, err := conn.Write([]byte(authCmd)); err != nil {
		return fmt.Errorf("failed to send authenticate command: %w", err)
	}

	authResp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read authenticate response: %w", err)
	}
	if !strings.HasPrefix(authResp, "250") {
		return fmt.Errorf("tor control authentication failed: %s", strings.TrimSpace(authResp))
	}

	// Send SIGNAL NEWNYM
	if _, err := conn.Write([]byte("SIGNAL NEWNYM\r\n")); err != nil {
		return fmt.Errorf("failed to send signal newnym: %w", err)
	}

	signalResp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read signal newnym response: %w", err)
	}
	if !strings.HasPrefix(signalResp, "250") {
		return fmt.Errorf("tor signal newnym failed: %s", strings.TrimSpace(signalResp))
	}

	tc.lastNew = time.Now()
	return nil
}
