package torscraper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"
)

// Client represents an aiohttp-style scraping session.
// It is thread-safe and manages cookies, connection pools, Tor routing, and browser emulation.
type Client struct {
	cfg       *clientConfig
	transport *CustomTransport
	httpCli   *http.Client
}

// NewClient creates a new Client configured with the provided options.
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := defaultClientConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Initialize cookie jar if not explicitly set
	if cfg.cookieJar == nil {
		jar, err := cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cookie jar: %w", err)
		}
		cfg.cookieJar = jar
	}

	transport := NewCustomTransport(cfg.torConfig, cfg.profile, cfg.insecureSkipVerify, cfg.timeout)

	cli := &http.Client{
		Transport:     transport,
		Jar:           cfg.cookieJar,
		Timeout:       cfg.timeout,
		CheckRedirect: buildCheckRedirect(cfg.followRedirects, cfg.maxRedirects, cfg.checkRedirect),
	}

	return &Client{
		cfg:       cfg,
		transport: transport,
		httpCli:   cli,
	}, nil
}

// buildCheckRedirect constructs a CheckRedirect function based on configuration.
func buildCheckRedirect(follow bool, max int, customFn func(req *http.Request, via []*http.Request) error) func(req *http.Request, via []*http.Request) error {
	if !follow {
		return func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	if customFn != nil {
		return customFn
	}
	if max > 0 {
		return func(req *http.Request, via []*http.Request) error {
			if len(via) >= max {
				return fmt.Errorf("stopped after %d redirects", max)
			}
			return nil
		}
	}
	return nil
}

// Get sends an HTTP GET request and returns an aiohttp-style Response.
func (c *Client) Get(ctx context.Context, rawURL string, opts ...RequestOption) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}
	return c.Do(req, opts...)
}

// Post sends an HTTP POST request with an arbitrary body.
func (c *Client) Post(ctx context.Context, rawURL string, body io.Reader, opts ...RequestOption) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	return c.Do(req, opts...)
}

// PostJSON serializes payload as JSON and sends an HTTP POST request.
func (c *Client) PostJSON(ctx context.Context, rawURL string, payload any, opts ...RequestOption) (*Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return c.Do(req, opts...)
}

// Do executes an HTTP request with headers, browser emulation, and optional Tor routing.
func (c *Client) Do(req *http.Request, opts ...RequestOption) (*Response, error) {
	ro := &requestOptions{}
	for _, opt := range opts {
		opt(ro)
	}

	// Apply browser profile headers if missing
	if c.cfg.profile != ProfileNone {
		prof := GetProfileConfig(c.cfg.profile)
		for k, v := range prof.DefaultHeaders {
			if req.Header.Get(k) == "" {
				req.Header.Set(k, v)
			}
		}
	}

	// Apply client default headers
	for k, v := range c.cfg.defaultHeaders {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	// Apply per-request header overrides
	for k, v := range ro.headers {
		req.Header.Set(k, v)
	}

	// Determine which client/transport to execute with
	caller := c.httpCli
	if ro.torConfig != nil || ro.followRedirects != nil {
		trans := c.transport
		if ro.torConfig != nil {
			trans = NewCustomTransport(ro.torConfig, c.cfg.profile, c.cfg.insecureSkipVerify, c.cfg.timeout)
		}
		follow := c.cfg.followRedirects
		if ro.followRedirects != nil {
			follow = *ro.followRedirects
		}
		caller = &http.Client{
			Transport:     trans,
			Jar:           c.cfg.cookieJar,
			Timeout:       c.cfg.timeout,
			CheckRedirect: buildCheckRedirect(follow, c.cfg.maxRedirects, c.cfg.checkRedirect),
		}
	}

	// Apply per-request timeout context if specified
	if ro.timeout > 0 {
		ctx, cancel := context.WithTimeout(req.Context(), ro.timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	rawResp, err := caller.Do(req)
	if err != nil {
		return nil, err
	}

	return newResponse(rawResp)
}

// Clone creates a new Client sharing the base settings, optionally modified with new options.
// Useful for creating worker clients with unique Tor circuits or separate cookie jars.
func (c *Client) Clone(opts ...ClientOption) (*Client, error) {
	cpyCfg := *c.cfg
	// Copy default headers
	cpyHeaders := make(map[string]string, len(c.cfg.defaultHeaders))
	for k, v := range c.cfg.defaultHeaders {
		cpyHeaders[k] = v
	}
	cpyCfg.defaultHeaders = cpyHeaders

	for _, opt := range opts {
		opt(&cpyCfg)
	}

	return NewClient(
		WithTor(cpyCfg.torConfig),
		WithBrowserProfile(cpyCfg.profile),
		WithTimeout(cpyCfg.timeout),
		WithCookieJar(cpyCfg.cookieJar),
		WithDefaultHeaders(cpyCfg.defaultHeaders),
		WithInsecureSkipVerify(cpyCfg.insecureSkipVerify),
		WithFollowRedirects(cpyCfg.followRedirects),
		WithMaxRedirects(cpyCfg.maxRedirects),
		WithCheckRedirect(cpyCfg.checkRedirect),
	)
}

// Close closes any open/idle connections in the client transport.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}
