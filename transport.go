package torscraper

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

type ctxKeyProfile struct{}

func withRequestProfile(ctx context.Context, p BrowserProfile) context.Context {
	return context.WithValue(ctx, ctxKeyProfile{}, p)
}

// CustomTransport implements http.RoundTripper with support for:
// 1. Direct or Tor SOCKS5 routing (with optional Stream Isolation)
// 2. Browser TLS fingerprinting via uTLS (Chrome, Firefox, Safari, Edge)
// 3. HTTP/2 and HTTP/1.1 ALPN multiplexing and connection pooling
type CustomTransport struct {
	torConfig          *TorConfig
	proxyPool          *ProxyPool
	profile            BrowserProfile
	insecureSkipVerify bool
	timeout            time.Duration

	proxyMu       sync.Mutex
	lastProxy     string
	onProxyRotate func(oldProxy, newProxy string)

	// HTTP/1.1 fallback / standard transport
	stdTransport *http.Transport

	// HTTP/2 transport for multiplexed h2 connections
	h2Transport *http2.Transport

	// Connection cache for HTTP/2 client connections
	h2Mu    sync.RWMutex
	h2Conns map[string]*http2.ClientConn
}

// NewCustomTransport constructs a configured CustomTransport.
func NewCustomTransport(torCfg *TorConfig, profile BrowserProfile, insecure bool, timeout time.Duration) *CustomTransport {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	var torCopy *TorConfig
	if torCfg != nil && torCfg.Enabled {
		torCopy = torCfg.Clone()
		torCopy.EnsureDefaults()
	}

	t := &CustomTransport{
		torConfig:          torCopy,
		profile:            profile,
		insecureSkipVerify: insecure,
		timeout:            timeout,
		h2Conns:            make(map[string]*http2.ClientConn),
		h2Transport: &http2.Transport{
			AllowHTTP: false,
		},
	}

	disableKeepAlives := torCopy != nil && torCopy.StreamIsolation

	// Setup standard transport for plain HTTP and ProfileNone requests
	t.stdTransport = &http.Transport{
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   disableKeepAlives,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer, err := t.getDialer(ctx)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	return t
}

// SetProxyPool assigns a proxy pool to the transport.
func (t *CustomTransport) SetProxyPool(pool *ProxyPool) {
	t.proxyPool = pool
	if pool != nil && t.stdTransport != nil {
		t.stdTransport.DisableKeepAlives = true
	}
}

// SetOnProxyRotate registers a callback invoked when the active proxy changes.
func (t *CustomTransport) SetOnProxyRotate(fn func(oldProxy, newProxy string)) {
	t.proxyMu.Lock()
	t.onProxyRotate = fn
	t.proxyMu.Unlock()
}

// SetProfile updates the active browser profile.
func (t *CustomTransport) SetProfile(p BrowserProfile) {
	t.profile = p
}

// getDialer returns the appropriate dialer (ProxyPool, Tor SOCKS5, or direct net.Dialer).
func (t *CustomTransport) getDialer(ctx context.Context) (proxy.ContextDialer, error) {
	if t.proxyPool != nil {
		node, err := t.proxyPool.Next()
		if err != nil {
			return nil, err
		}
		t.proxyMu.Lock()
		oldProxy := t.lastProxy
		newProxy := node.RawURL
		t.lastProxy = newProxy
		rotateFn := t.onProxyRotate
		t.proxyMu.Unlock()

		if oldProxy != "" && oldProxy != newProxy && rotateFn != nil {
			rotateFn(oldProxy, newProxy)
		}
		return t.proxyPool.DialerForNode(ctx, node, t.timeout)
	}

	if t.torConfig != nil && t.torConfig.Enabled {
		var auth *proxy.Auth
		if t.torConfig.StreamIsolation {
			auth = generateIsolationAuth()
		}
		return newSOCKS5Dialer(ctx, t.torConfig.ProxyAddr, auth)
	}

	return &net.Dialer{
		Timeout:   t.timeout,
		KeepAlive: 30 * time.Second,
	}, nil
}

// RoundTrip executes a single HTTP request.
func (t *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	activeProfile := t.profile
	if p, ok := req.Context().Value(ctxKeyProfile{}).(BrowserProfile); ok {
		activeProfile = p
	}

	// If plain HTTP or ProfileNone, use the standard transport
	if req.URL.Scheme == "http" || activeProfile == ProfileNone {
		return t.stdTransport.RoundTrip(req)
	}

	// For HTTPS with a browser profile, use our uTLS engine
	return t.roundTripBrowserHTTPS(req, activeProfile)
}

// roundTripBrowserHTTPS handles HTTPS with uTLS and ALPN negotiation (h2 or http/1.1).
func (t *CustomTransport) roundTripBrowserHTTPS(req *http.Request, activeProfile BrowserProfile) (*http.Response, error) {
	ctx := req.Context()
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	targetAddr := net.JoinHostPort(host, port)

	canPoolH2 := t.proxyPool == nil &&
		(t.torConfig == nil || !t.torConfig.Enabled || !t.torConfig.StreamIsolation) &&
		ctx.Value(ctxKeyProfile{}) == nil

	if canPoolH2 {
		// Check if we have an existing healthy HTTP/2 connection
		t.h2Mu.RLock()
		cc, exists := t.h2Conns[targetAddr]
		t.h2Mu.RUnlock()

		if exists && cc.CanTakeNewRequest() {
			resp, err := cc.RoundTrip(req)
			if err == nil {
				return resp, nil
			}
			// If error occurred on pooled conn, remove from cache and proceed to redial
			t.h2Mu.Lock()
			delete(t.h2Conns, targetAddr)
			t.h2Mu.Unlock()
		}
	}

	// Dial TCP / Tor SOCKS5
	dialer, err := t.getDialer(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dialer: %w", err)
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", targetAddr, err)
	}

	// Prepare uTLS config & handshake
	profConfig := GetProfileConfig(activeProfile)
	uConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: t.insecureSkipVerify,
	}

	uConn := utls.UClient(rawConn, uConfig, profConfig.ClientHelloID)
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake failed for %s: %w", targetAddr, err)
	}

	negotiatedALPN := uConn.ConnectionState().NegotiatedProtocol

	// If HTTP/2 was negotiated
	if negotiatedALPN == "h2" {
		clientConn, err := t.h2Transport.NewClientConn(uConn)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("failed to initialize h2 connection: %w", err)
		}

		if canPoolH2 {
			t.h2Mu.Lock()
			t.h2Conns[targetAddr] = clientConn
			t.h2Mu.Unlock()
		}

		return clientConn.RoundTrip(req)
	}

	// HTTP/1.1 fallback
	return t.doHTTP1(uConn, req)
}

// doHTTP1 writes an HTTP/1.1 request over a direct connection and parses the response.
func (t *CustomTransport) doHTTP1(conn net.Conn, req *http.Request) (*http.Response, error) {
	// Write the request to the wire
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write http/1.1 request: %w", err)
	}

	// Read and parse response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read http/1.1 response: %w", err)
	}

	// Wrap body to close underlying connection when done
	resp.Body = &connCloser{
		ReadCloser: resp.Body,
		conn:       conn,
	}

	return resp, nil
}

// CloseIdleConnections closes any cached or idle connections.
func (t *CustomTransport) CloseIdleConnections() {
	t.h2Mu.Lock()
	for k, cc := range t.h2Conns {
		cc.Close()
		delete(t.h2Conns, k)
	}
	t.h2Mu.Unlock()

	t.stdTransport.CloseIdleConnections()
}

// connCloser ensures the net.Conn is closed when the response body is closed.
type connCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (cc *connCloser) Close() error {
	bodyErr := cc.ReadCloser.Close()
	connErr := cc.conn.Close()
	if bodyErr != nil {
		return bodyErr
	}
	return connErr
}
