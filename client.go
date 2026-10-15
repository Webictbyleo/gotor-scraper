package torscraper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Client represents an aiohttp-style scraping session.
// It is thread-safe and manages cookies, connection pools, Tor routing, browser emulation,
// and a reusable headless Chrome CDP instance for dynamic JavaScript rendering.
type Client struct {
	cfg           *clientConfig
	transport     *CustomTransport
	httpCli       *http.Client
	browserMu     sync.Mutex
	browserCtx    context.Context
	browserCancel context.CancelFunc
	allocCancel   context.CancelFunc
}

// NewClient creates a new Client configured with the provided options.
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := defaultClientConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Initialize cookie jar: check sessionFile or sessionDir first
	if cfg.cookieJar == nil {
		if cfg.sessionFile != "" {
			jar, err := NewPersistentCookieJar(cfg.sessionFile, cfg.autoSaveSession)
			if err != nil {
				return nil, err
			}
			cfg.cookieJar = jar
		} else if cfg.sessionDir != "" {
			jar, err := NewSessionDirJar(cfg.sessionDir, cfg.sessionName, cfg.autoSaveSession)
			if err != nil {
				return nil, err
			}
			cfg.cookieJar = jar
		} else {
			jar, err := cookiejar.New(&cookiejar.Options{
				PublicSuffixList: publicsuffix.List,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to initialize cookie jar: %w", err)
			}
			cfg.cookieJar = jar
		}
	}

	transport := NewCustomTransport(cfg.torConfig, cfg.profile, cfg.insecureSkipVerify, cfg.timeout)
	if cfg.proxyPool != nil {
		transport.SetProxyPool(cfg.proxyPool)
	}

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

	// Apply browser profile headers (with optional per-request rotation)
	activeProfile := c.cfg.profile
	if c.cfg.profileRotation == RotatePerRequest {
		prof := GetRandomProfileConfig()
		for k, v := range prof.DefaultHeaders {
			req.Header.Set(k, v)
		}
	} else if activeProfile != ProfileNone {
		prof := GetProfileConfig(activeProfile)
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

	// Preserve body for potential retries
	if req.Body != nil && req.GetBody == nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	// Apply per-request timeout context if specified
	if ro.timeout > 0 {
		ctx, cancel := context.WithTimeout(req.Context(), ro.timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	maxRetries := c.cfg.maxRetries
	if ro.maxRetries != nil {
		maxRetries = *ro.maxRetries
	}
	backoff := c.cfg.retryBackoff
	if backoff <= 0 {
		backoff = 500 * time.Millisecond
	}

	var lastResp *Response
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Rewind request body for retry
			if req.GetBody != nil {
				newBody, bErr := req.GetBody()
				if bErr == nil {
					req.Body = newBody
				}
			}

			// If Tor rotation on retry is enabled and Tor is active, force a new circuit
			if c.cfg.rotateTorOnRetry && ((c.cfg.torConfig != nil && c.cfg.torConfig.Enabled) || (ro.torConfig != nil && ro.torConfig.Enabled)) {
				torBase := c.cfg.torConfig
				if ro.torConfig != nil {
					torBase = ro.torConfig
				}
				ro.torConfig = &TorConfig{
					Enabled:         true,
					ProxyAddr:       torBase.ProxyAddr,
					StreamIsolation: true, // Forces new circuit
				}
			}
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

		// Trigger OnRequest hook
		if c.cfg.hooks != nil && c.cfg.hooks.OnRequest != nil {
			c.cfg.hooks.OnRequest(req)
		}

		start := time.Now()
		rawResp, err := caller.Do(req)
		duration := time.Since(start)

		if err != nil {
			lastErr = err
			lastResp = nil
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, err, attempt)
			}
		} else {
			respCfg := &responseConfig{
				maxContentLength:    c.cfg.maxContentLength,
				allowedContentTypes: c.cfg.allowedContentTypes,
				blockedContentTypes: c.cfg.blockedContentTypes,
				contentFilter:       c.cfg.contentFilter,
				urlPath:             req.URL.Path,
			}
			if ro.maxContentLength != nil {
				respCfg.maxContentLength = *ro.maxContentLength
			}
			if len(ro.allowedContentTypes) > 0 {
				respCfg.allowedContentTypes = append(respCfg.allowedContentTypes, ro.allowedContentTypes...)
			}
			if len(ro.blockedContentTypes) > 0 {
				respCfg.blockedContentTypes = append(respCfg.blockedContentTypes, ro.blockedContentTypes...)
			}
			if ro.contentFilter != nil {
				respCfg.contentFilter = ro.contentFilter
			}

			lastResp, lastErr = newResponse(rawResp, respCfg)
			if lastErr != nil {
				if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
					c.cfg.hooks.OnError(req, lastErr, attempt)
				}
			} else {
				if c.cfg.hooks != nil && c.cfg.hooks.OnResponse != nil {
					c.cfg.hooks.OnResponse(lastResp, duration)
				}
			}
		}

		// Check if we should retry
		shouldRetry := false
		if attempt < maxRetries {
			if c.cfg.retryCondition != nil {
				shouldRetry = c.cfg.retryCondition(lastResp, lastErr)
			} else {
				if lastErr != nil && !errors.Is(lastErr, ErrContentLengthExceeded) && !errors.Is(lastErr, ErrContentTypeBlocked) && !errors.Is(lastErr, ErrContentTypeNotAllowed) {
					shouldRetry = true
				} else if lastResp != nil && (lastResp.StatusCode == http.StatusTooManyRequests || lastResp.StatusCode >= 500) {
					shouldRetry = true
				}
			}
		}

		if shouldRetry {
			if c.cfg.hooks != nil && c.cfg.hooks.OnRetry != nil {
				c.cfg.hooks.OnRetry(req, lastErr, attempt, backoff)
			}
			select {
			case <-req.Context().Done():
				if lastErr != nil {
					return nil, lastErr
				}
				return lastResp, req.Context().Err()
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
				continue
			}
		}

		break
	}

	return lastResp, lastErr
}

// SaveSession flushes cookies to disk if a persistent session file or directory is configured.
func (c *Client) SaveSession() error {
	if pj, ok := c.cfg.cookieJar.(*PersistentCookieJar); ok {
		return pj.Save()
	}
	return nil
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

	optsList := []ClientOption{
		WithTor(cpyCfg.torConfig),
		WithBrowserProfile(cpyCfg.profile),
		WithTimeout(cpyCfg.timeout),
		WithCookieJar(cpyCfg.cookieJar),
		WithDefaultHeaders(cpyCfg.defaultHeaders),
		WithInsecureSkipVerify(cpyCfg.insecureSkipVerify),
		WithFollowRedirects(cpyCfg.followRedirects),
		WithMaxRedirects(cpyCfg.maxRedirects),
		WithCheckRedirect(cpyCfg.checkRedirect),
		WithRetries(cpyCfg.maxRetries, cpyCfg.retryBackoff),
		WithRotateTorOnRetry(cpyCfg.rotateTorOnRetry),
		WithRetryCondition(cpyCfg.retryCondition),
		WithMaxContentLength(cpyCfg.maxContentLength),
		WithAllowedContentTypes(cpyCfg.allowedContentTypes...),
		WithBlockedContentTypes(cpyCfg.blockedContentTypes...),
		WithContentFilter(cpyCfg.contentFilter),
		WithProxyPool(cpyCfg.proxyPool),
		WithProfileRotation(cpyCfg.profileRotation),
		WithSessionFile(cpyCfg.sessionFile),
		WithSessionDir(cpyCfg.sessionDir, cpyCfg.sessionName),
		WithAutoSaveSession(cpyCfg.autoSaveSession),
	}
	if cpyCfg.hooks != nil {
		optsList = append(optsList, WithHooks(*cpyCfg.hooks))
	}

	return NewClient(optsList...)
}

// Close closes any open/idle connections in the client transport and cleanly
// terminates any background headless Chrome browser process started by GetRendered.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
	c.browserMu.Lock()
	defer c.browserMu.Unlock()
	if c.browserCancel != nil {
		c.browserCancel()
		c.browserCancel = nil
	}
	if c.allocCancel != nil {
		c.allocCancel()
		c.allocCancel = nil
	}
	c.browserCtx = nil
}
