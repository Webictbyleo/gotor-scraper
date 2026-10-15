package torscraper

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// DefaultBlockedAssetPatterns are media, font, and tracker patterns blocked to maximize speed over Tor.
var DefaultBlockedAssetPatterns = []string{
	"*://*:*/*.png", "*://*:*/*.jpg", "*://*:*/*.jpeg", "*://*:*/*.gif", "*://*:*/*.webp", "*://*:*/*.ico",
	"*://*:*/*.woff", "*://*:*/*.woff2", "*://*:*/*.ttf", "*://*:*/*.eot", "*://*:*/*.otf",
	"*://*:*/*.mp4", "*://*:*/*.webm", "*://*:*/*.mp3", "*://*:*/*.wav", "*://*:*/*.avi",
	"*://*.google-analytics.com/*", "*://*.doubleclick.net/*", "*://*.googletagmanager.com/*",
}

// RenderConfig holds options for headless Chrome rendering.
type RenderConfig struct {
	WaitForSelector string
	WaitDuration    time.Duration
	Timeout         time.Duration
	BlockAssets     bool
	BlockedPatterns []string
	ProxyURL        string
	ExecPath        string
	IsolatedBrowser bool
	WindowWidth     int
	WindowHeight    int
}

// RenderOption configures the JavaScript rendering process.
type RenderOption func(*RenderConfig)

// RenderExecPath specifies the path to the Chrome/Chromium/Edge executable binary.
func RenderExecPath(path string) RenderOption {
	return func(rc *RenderConfig) {
		rc.ExecPath = path
	}
}

// RenderIsolatedBrowser forces the creation of a standalone one-off Chrome process for this scrape,
// bypassing the Client's shared browser instance pool. By default (false), the Client shares a single
// persistent Chrome instance and opens lightweight tabs for each scrape to maximize throughput and minimize RAM.
func RenderIsolatedBrowser(isolated bool) RenderOption {
	return func(rc *RenderConfig) {
		rc.IsolatedBrowser = isolated
	}
}

// WaitForSelector instructs the renderer to wait until the CSS selector is visible in the DOM.
func WaitForSelector(selector string) RenderOption {
	return func(rc *RenderConfig) {
		rc.WaitForSelector = selector
	}
}

// WaitForDuration waits a fixed duration after navigation for dynamic scripts to finish.
func WaitForDuration(d time.Duration) RenderOption {
	return func(rc *RenderConfig) {
		rc.WaitDuration = d
	}
}

// RenderTimeout sets the maximum deadline for rendering the page.
func RenderTimeout(d time.Duration) RenderOption {
	return func(rc *RenderConfig) {
		rc.Timeout = d
	}
}

// BlockAssets controls whether images, fonts, and media are dropped to maximize speed over Tor.
func BlockAssets(block bool) RenderOption {
	return func(rc *RenderConfig) {
		rc.BlockAssets = block
	}
}

// RenderProxy specifies an explicit proxy for the headless browser instance (e.g. "socks5://127.0.0.1:9050").
func RenderProxy(proxyURL string) RenderOption {
	return func(rc *RenderConfig) {
		rc.ProxyURL = proxyURL
	}
}

// buildAllocOpts constructs the command-line flags and profile emulation options for Chrome.
func (c *Client) buildAllocOpts(rc *RenderConfig) []chromedp.ExecAllocatorOption {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		// Anti-Bot Camouflage: strips navigator.webdriver so fingerprinting scripts
		// and anti-bot systems (Cloudflare, Datadome) do not detect automated browser control
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.WindowSize(rc.WindowWidth, rc.WindowHeight),
	)

	// Synchronize browser User-Agent with the client's active emulation profile
	if c.cfg.profile != ProfileNone {
		prof := GetProfileConfig(c.cfg.profile)
		if prof.UserAgent != "" {
			allocOpts = append(allocOpts, chromedp.UserAgent(prof.UserAgent))
		}
	}

	// Route browser traffic through proxy if specified (Tor or custom proxy pool)
	if rc.ProxyURL != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(rc.ProxyURL))
	}

	// Set browser binary path or auto-discover installed Chromium/Edge on Windows
	if rc.ExecPath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(rc.ExecPath))
	} else if runtime.GOOS == "windows" {
		candidates := []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		}
		for _, cPath := range candidates {
			if _, err := os.Stat(cPath); err == nil {
				allocOpts = append(allocOpts, chromedp.ExecPath(cPath))
				break
			}
		}
	}

	return allocOpts
}

// getOrCreateBrowser retrieves the existing persistent headless Chrome browser context,
// or launches a new background browser process if one hasn't been started yet or if it died.
// Reusing a single browser process across multiple URLs avoids the 1-2s process startup latency
// and heavy memory footprint of spawning a new Chrome process for every URL.
func (c *Client) getOrCreateBrowser(ctx context.Context, rc *RenderConfig) (context.Context, error) {
	c.browserMu.Lock()
	defer c.browserMu.Unlock()

	// If browser context is already active and healthy, reuse it
	if c.browserCtx != nil && c.browserCtx.Err() == nil {
		return c.browserCtx, nil
	}

	// Clean up any stale or dead context
	if c.browserCancel != nil {
		c.browserCancel()
	}
	if c.allocCancel != nil {
		c.allocCancel()
	}

	allocOpts := c.buildAllocOpts(rc)

	// Use context.Background() as root allocator so individual request deadlines
	// do NOT terminate the persistent Chrome browser process.
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	// Warm up browser so process starts once
	if _, err := chromedp.Run(browserCtx, chromedp.Sleep(0)); err != nil {
		browserCancel()
		allocCancel()
		return nil, fmt.Errorf("failed to start shared headless browser: %w", err)
	}

	c.allocCancel = allocCancel
	c.browserCtx = browserCtx
	c.browserCancel = browserCancel

	return c.browserCtx, nil
}

// GetRendered executes a full headless Chrome navigation, executes all client-side JavaScript,
// and returns the modified, fully-rendered DOM wrapped in a standard Response.
//
// By default, it reuses the Client's shared browser instance and opens a lightweight browser tab
// per URL, closing the tab when done while keeping the underlying Chrome process alive for maximum speed.
func (c *Client) GetRendered(ctx context.Context, targetURL string, opts ...RenderOption) (*Response, error) {
	rc := &RenderConfig{
		Timeout:         25 * time.Second,
		BlockAssets:     true,
		BlockedPatterns: DefaultBlockedAssetPatterns,
		WindowWidth:     1920,
		WindowHeight:    1080,
	}

	// Apply default proxy from client config if set
	if c.cfg.torConfig != nil && c.cfg.torConfig.Enabled {
		rc.ProxyURL = "socks5://" + c.cfg.torConfig.ProxyAddr
	} else if c.cfg.proxyPool != nil {
		node, err := c.cfg.proxyPool.Next()
		if err == nil && node != nil {
			rc.ProxyURL = node.RawURL
		}
	}

	for _, opt := range opts {
		opt(rc)
	}

	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)

	// Fire OnRequest lifecycle hook
	if c.cfg.hooks != nil && c.cfg.hooks.OnRequest != nil {
		c.cfg.hooks.OnRequest(req)
	}

	var taskCtx context.Context
	var cleanupTab func()

	if rc.IsolatedBrowser {
		// Standalone mode: spawn a dedicated one-off browser process for this request only
		allocOpts := c.buildAllocOpts(rc)
		allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
		bCtx, cancelBrowser := chromedp.NewContext(allocCtx)
		tabCtx, cTab := chromedp.NewContext(bCtx)
		tCtx, cTimeout := context.WithTimeout(tabCtx, rc.Timeout)
		taskCtx = tCtx
		cleanupTab = func() {
			cTimeout()
			cTab()
			cancelBrowser()
			cancelAlloc()
		}
	} else {
		// High-performance shared mode: reuse existing Chrome process, allocate only a new tab
		browserCtx, err := c.getOrCreateBrowser(ctx, rc)
		if err != nil {
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, err, 1)
			}
			return nil, err
		}

		// chromedp.NewContext(browserCtx) opens an isolated target tab inside the running Chrome process
		tabCtx, cTab := chromedp.NewContext(browserCtx)
		tCtx, cTimeout := context.WithTimeout(tabCtx, rc.Timeout)
		taskCtx = tCtx
		cleanupTab = func() {
			cTimeout()
			cTab() // Closes only this tab target; leaves the browser running for subsequent URLs
		}
	}
	defer cleanupTab()

	var tasks []chromedp.Action[chromedp.Void]

	// Enable Network domain for asset blocking & cookies
	tasks = append(tasks, chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
		_, err := cdp.Call(ctx, t, network.Enable, network.EnableParams{})
		return err
	}))

	// Block images, fonts, and media if enabled (saves 90% Tor bandwidth and speeds up load 5x)
	if rc.BlockAssets && len(rc.BlockedPatterns) > 0 {
		patterns := make([]*network.BlockPattern, 0, len(rc.BlockedPatterns))
		for _, p := range rc.BlockedPatterns {
			patterns = append(patterns, &network.BlockPattern{
				URLPattern: p,
				Block:      true,
			})
		}
		tasks = append(tasks, chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
			_, err := cdp.Call(ctx, t, network.SetBlockedURLs, network.SetBlockedURLsParams{
				URLPatterns: patterns,
			})
			return err
		}))
	}

	// Synchronize existing cookies from Go CookieJar into Chrome
	parsedURL, _ := url.Parse(targetURL)
	if parsedURL != nil && c.cfg.cookieJar != nil {
		existingCookies := c.cfg.cookieJar.Cookies(parsedURL)
		for _, ck := range existingCookies {
			cookie := ck
			tasks = append(tasks, chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
				_, err := cdp.Call(ctx, t, network.SetCookie, network.SetCookieParams{
					Name:     cookie.Name,
					Value:    cookie.Value,
					Domain:   parsedURL.Hostname(),
					Path:     cookie.Path,
					HTTPOnly: &cookie.HttpOnly,
					Secure:   &cookie.Secure,
				})
				return err
			}))
		}
	}

	// Navigate to target URL
	tasks = append(tasks, chromedp.Navigate(targetURL))

	// Apply DOM wait conditions
	if rc.WaitForSelector != "" {
		tasks = append(tasks, chromedp.WaitVisible(chromedp.CSS(rc.WaitForSelector)))
	} else if rc.WaitDuration > 0 {
		tasks = append(tasks, chromedp.Sleep(rc.WaitDuration))
	} else {
		// Default: wait for document body ready
		tasks = append(tasks, chromedp.WaitReady(chromedp.CSS("body")))
	}

	// Execute setup, navigation, and wait actions inside browser tab
	if err := chromedp.Do(taskCtx, tasks...); err != nil {
		renderErr := fmt.Errorf("chromedp rendering failed for %s: %w", targetURL, err)
		if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
			c.cfg.hooks.OnError(req, renderErr, 1)
		}
		return nil, renderErr
	}

	// Extract the live, hydrated, modified DOM HTML
	renderedHTML, err := chromedp.Run(taskCtx, chromedp.OuterHTML(chromedp.CSS("html")))
	if err != nil {
		renderErr := fmt.Errorf("chromedp failed to retrieve outer HTML for %s: %w", targetURL, err)
		if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
			c.cfg.hooks.OnError(req, renderErr, 1)
		}
		return nil, renderErr
	}

	// Wrap in standard Response structure
	rawHeader := make(http.Header)
	rawHeader.Set("Content-Type", "text/html; charset=utf-8")

	resp := &Response{
		StatusCode:  http.StatusOK,
		Status:      "200 OK",
		Headers:     rawHeader,
		RawResponse: &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     rawHeader,
			Request: &http.Request{
				URL: parsedURL,
			},
		},
		rawBody: []byte(renderedHTML),
	}

	resp.ContentInfo = &ContentInfo{
		DeclaredType:  "text/html; charset=utf-8",
		MediaType:     "text/html",
		SniffedType:   "text/html",
		ContentLength: int64(len(renderedHTML)),
		IsHTML:        true,
	}

	// Fire OnResponse lifecycle hook
	if c.cfg.hooks != nil && c.cfg.hooks.OnResponse != nil {
		c.cfg.hooks.OnResponse(resp, time.Since(start))
	}

	return resp, nil
}
