package torscraper

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyStrategy defines how proxies are selected from the pool.
type ProxyStrategy int

const (
	// StrategyRoundRobin cycles through proxies sequentially.
	StrategyRoundRobin ProxyStrategy = iota

	// StrategyRandom selects a random healthy proxy.
	StrategyRandom

	// StrategyFailover uses the first healthy proxy until it fails, then falls back.
	StrategyFailover
)

// ProxyNode represents a single proxy endpoint in the pool.
type ProxyNode struct {
	RawURL          string
	ParsedURL       *url.URL
	IsTor           bool
	StreamIsolation bool

	mu            sync.RWMutex
	failures      int
	disabledUntil time.Time
}

// IsHealthy returns true if the proxy is not in cooldown.
func (p *ProxyNode) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return time.Now().After(p.disabledUntil)
}

// RecordSuccess resets the failure counter for this proxy.
func (p *ProxyNode) RecordSuccess() {
	p.mu.Lock()
	p.failures = 0
	p.disabledUntil = time.Time{}
	p.mu.Unlock()
}

// RecordFailure increments failure count and triggers cooldown if threshold is met.
func (p *ProxyNode) RecordFailure(cooldown time.Duration, maxFailures int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures++
	if p.failures >= maxFailures {
		p.disabledUntil = time.Now().Add(cooldown)
	}
}

// ProxyPool manages a collection of Tor, SOCKS5, and HTTP proxies.
type ProxyPool struct {
	strategy     ProxyStrategy
	nodes        []*ProxyNode
	cooldown     time.Duration
	maxFailures  int
	rrCounter    uint64
	mu           sync.RWMutex
}

// NewProxyPool creates a ProxyPool from a list of proxy URLs.
// URLs can be "socks5://127.0.0.1:9050", "http://user:pass@host:port", etc.
func NewProxyPool(strategy ProxyStrategy, proxyURLs ...string) (*ProxyPool, error) {
	if len(proxyURLs) == 0 {
		return nil, errors.New("cannot create empty proxy pool")
	}

	nodes := make([]*ProxyNode, 0, len(proxyURLs))
	for _, raw := range proxyURLs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// If scheme is missing, default to socks5://
		toParse := raw
		if !strings.Contains(toParse, "://") {
			toParse = "socks5://" + toParse
		}

		u, err := url.Parse(toParse)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", raw, err)
		}

		isTor := strings.Contains(u.Host, "9050") || strings.Contains(u.Host, "9052") ||
			strings.Contains(u.Host, "9150") || strings.Contains(strings.ToLower(u.Host), "tor")

		nodes = append(nodes, &ProxyNode{
			RawURL:          raw,
			ParsedURL:       u,
			IsTor:           isTor,
			StreamIsolation: isTor, // Enable stream isolation by default for Tor proxies
		})
	}

	if len(nodes) == 0 {
		return nil, errors.New("no valid proxy URLs provided")
	}

	return &ProxyPool{
		strategy:    strategy,
		nodes:       nodes,
		cooldown:    30 * time.Second,
		maxFailures: 3,
	}, nil
}

// SetCooldown configures the cooldown duration when a proxy exceeds max failures.
func (pp *ProxyPool) SetCooldown(d time.Duration) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	pp.cooldown = d
}

// SetMaxFailures sets consecutive failure threshold before disabling a proxy.
func (pp *ProxyPool) SetMaxFailures(n int) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	pp.maxFailures = n
}

// Next selects the next healthy proxy based on the configured strategy.
func (pp *ProxyPool) Next() (*ProxyNode, error) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	healthy := make([]*ProxyNode, 0, len(pp.nodes))
	for _, n := range pp.nodes {
		if n.IsHealthy() {
			healthy = append(healthy, n)
		}
	}

	// If all proxies are currently in cooldown, fallback to using all proxies
	candidates := healthy
	if len(candidates) == 0 {
		candidates = pp.nodes
	}

	switch pp.strategy {
	case StrategyRandom:
		idx := rand.Intn(len(candidates))
		return candidates[idx], nil

	case StrategyFailover:
		return candidates[0], nil

	case StrategyRoundRobin:
		fallthrough
	default:
		idx := atomic.AddUint64(&pp.rrCounter, 1) - 1
		return candidates[idx%uint64(len(candidates))], nil
	}
}

// DialerForNode constructs a proxy.ContextDialer for a specific ProxyNode.
func (pp *ProxyPool) DialerForNode(ctx context.Context, node *ProxyNode, timeout time.Duration) (proxy.ContextDialer, error) {
	forward := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	scheme := strings.ToLower(node.ParsedURL.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if node.ParsedURL.User != nil {
			pwd, _ := node.ParsedURL.User.Password()
			auth = &proxy.Auth{
				User:     node.ParsedURL.User.Username(),
				Password: pwd,
			}
		} else if node.IsTor && node.StreamIsolation {
			auth = generateIsolationAuth()
		}

		dialer, err := proxy.SOCKS5("tcp", node.ParsedURL.Host, auth, forward)
		if err != nil {
			return nil, fmt.Errorf("failed to create socks5 dialer for %s: %w", node.RawURL, err)
		}
		cDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("socks5 dialer does not implement proxy.ContextDialer")
		}
		return cDialer, nil

	case "http", "https":
		// HTTP CONNECT tunnel dialer
		return &httpConnectDialer{
			proxyURL: node.ParsedURL,
			forward:  forward,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", scheme)
	}
}

// httpConnectDialer implements proxy.ContextDialer for HTTP CONNECT tunneling.
type httpConnectDialer struct {
	proxyURL *url.URL
	forward  *net.Dialer
}

func (h *httpConnectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Connect to proxy server
	conn, err := h.forward.DialContext(ctx, "tcp", h.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to http proxy %s: %w", h.proxyURL.Host, err)
	}

	// Issue HTTP CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if h.proxyURL.User != nil {
		auth := h.proxyURL.User.String()
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", basicAuth(auth))
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT to proxy: %w", err)
	}

	// Read CONNECT response header
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}

	respStr := string(buf[:n])
	if !strings.Contains(respStr, "200") {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected CONNECT request: %s", strings.TrimSpace(respStr))
	}

	return conn, nil
}

func basicAuth(userPass string) string {
	return base64.StdEncoding.EncodeToString([]byte(userPass))
}
