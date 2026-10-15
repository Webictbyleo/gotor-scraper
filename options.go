package torscraper

import (
	"net/http"
	"time"
)

type clientConfig struct {
	torConfig          *TorConfig
	profile            BrowserProfile
	timeout            time.Duration
	cookieJar          http.CookieJar
	defaultHeaders     map[string]string
	insecureSkipVerify bool
	followRedirects    bool
	maxRedirects       int
	checkRedirect      func(req *http.Request, via []*http.Request) error
	maxRetries         int
	retryBackoff       time.Duration
	rotateTorOnRetry   bool
	retryCondition     func(resp *Response, err error) bool
}

func defaultClientConfig() *clientConfig {
	return &clientConfig{
		torConfig:          nil,
		profile:            ProfileChrome, // Default to Chrome for modern web compatibility
		timeout:            30 * time.Second,
		defaultHeaders:     make(map[string]string),
		insecureSkipVerify: false,
		followRedirects:    true,
		maxRedirects:       10,
		maxRetries:         0,
		retryBackoff:       500 * time.Millisecond,
		rotateTorOnRetry:   true,
	}
}

// ClientOption configures a Client.
type ClientOption func(*clientConfig)

// WithTor enables and configures Tor routing for the client.
func WithTor(cfg *TorConfig) ClientOption {
	return func(c *clientConfig) {
		if cfg != nil {
			c.torConfig = cfg.Clone()
			c.torConfig.Enabled = true
		}
	}
}

// WithTorProxy enables Tor with a specific SOCKS5 address (e.g. "127.0.0.1:9050").
func WithTorProxy(proxyAddr string) ClientOption {
	return func(c *clientConfig) {
		if c.torConfig == nil {
			c.torConfig = &TorConfig{
				Enabled:         true,
				ProxyAddr:       proxyAddr,
				StreamIsolation: true,
			}
		} else {
			c.torConfig.Enabled = true
			c.torConfig.ProxyAddr = proxyAddr
		}
	}
}

// WithStreamIsolation toggles Tor Stream Isolation.
// When enabled, every new connection sends unique virtual SOCKS5 credentials,
// compelling Tor to assign separate circuits concurrently.
func WithStreamIsolation(enabled bool) ClientOption {
	return func(c *clientConfig) {
		if c.torConfig == nil {
			c.torConfig = &TorConfig{
				Enabled:         true,
				StreamIsolation: enabled,
			}
		} else {
			c.torConfig.StreamIsolation = enabled
		}
	}
}

// WithBrowserProfile sets the browser TLS and header emulation profile (Chrome, Firefox, Safari, Edge, None).
func WithBrowserProfile(profile BrowserProfile) ClientOption {
	return func(c *clientConfig) {
		c.profile = profile
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

// WithCookieJar assigns a custom cookie jar to the client session.
func WithCookieJar(jar http.CookieJar) ClientOption {
	return func(c *clientConfig) {
		c.cookieJar = jar
	}
}

// WithDefaultHeader adds a default header to all requests.
func WithDefaultHeader(key, value string) ClientOption {
	return func(c *clientConfig) {
		c.defaultHeaders[key] = value
	}
}

// WithDefaultHeaders adds multiple default headers.
func WithDefaultHeaders(headers map[string]string) ClientOption {
	return func(c *clientConfig) {
		for k, v := range headers {
			c.defaultHeaders[k] = v
		}
	}
}

// WithInsecureSkipVerify controls whether to skip TLS certificate verification.
func WithInsecureSkipVerify(skip bool) ClientOption {
	return func(c *clientConfig) {
		c.insecureSkipVerify = skip
	}
}

// WithFollowRedirects controls whether redirects should be followed automatically.
func WithFollowRedirects(follow bool) ClientOption {
	return func(c *clientConfig) {
		c.followRedirects = follow
	}
}

// WithMaxRedirects sets the maximum number of consecutive redirects to follow (default: 10).
func WithMaxRedirects(max int) ClientOption {
	return func(c *clientConfig) {
		c.maxRedirects = max
	}
}

// WithCheckRedirect allows providing a custom redirect policy function.
func WithCheckRedirect(fn func(req *http.Request, via []*http.Request) error) ClientOption {
	return func(c *clientConfig) {
		c.checkRedirect = fn
	}
}

// WithRetries sets the maximum retry attempts and initial backoff duration for failed requests.
func WithRetries(maxRetries int, backoff time.Duration) ClientOption {
	return func(c *clientConfig) {
		c.maxRetries = maxRetries
		if backoff > 0 {
			c.retryBackoff = backoff
		}
	}
}

// WithRotateTorOnRetry toggles whether a new isolated Tor circuit is used when retrying.
func WithRotateTorOnRetry(rotate bool) ClientOption {
	return func(c *clientConfig) {
		c.rotateTorOnRetry = rotate
	}
}

// WithRetryCondition sets a custom predicate to decide if a request should be retried.
func WithRetryCondition(fn func(resp *Response, err error) bool) ClientOption {
	return func(c *clientConfig) {
		c.retryCondition = fn
	}
}

// requestOptions holds per-request overrides.
type requestOptions struct {
	torConfig       *TorConfig
	headers         map[string]string
	timeout         time.Duration
	followRedirects *bool
	maxRetries      *int
}

// RequestOption allows customizing an individual request.
type RequestOption func(*requestOptions)

// ReqWithRetries overrides the maximum retry attempts for an individual request.
func ReqWithRetries(maxRetries int) RequestOption {
	return func(ro *requestOptions) {
		ro.maxRetries = &maxRetries
	}
}

// ReqWithFollowRedirects overrides the redirect behavior for an individual request.
func ReqWithFollowRedirects(follow bool) RequestOption {
	return func(ro *requestOptions) {
		ro.followRedirects = &follow
	}
}

// ReqWithTor overrides or toggles Tor specifically for this request.
func ReqWithTor(cfg *TorConfig) RequestOption {
	return func(ro *requestOptions) {
		ro.torConfig = cfg
	}
}

// ReqWithHeader adds or overrides a header on the request.
func ReqWithHeader(key, value string) RequestOption {
	return func(ro *requestOptions) {
		if ro.headers == nil {
			ro.headers = make(map[string]string)
		}
		ro.headers[key] = value
	}
}

// ReqWithHeaders adds or overrides multiple headers on the request.
func ReqWithHeaders(headers map[string]string) RequestOption {
	return func(ro *requestOptions) {
		if ro.headers == nil {
			ro.headers = make(map[string]string)
		}
		for k, v := range headers {
			ro.headers[k] = v
		}
	}
}

// ReqWithTimeout overrides the timeout for this specific request.
func ReqWithTimeout(d time.Duration) RequestOption {
	return func(ro *requestOptions) {
		ro.timeout = d
	}
}
