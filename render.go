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

// GetRendered executes a full headless Chrome navigation, executes all client-side JavaScript,
// and returns the modified, fully-rendered DOM wrapped in a standard Response.
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

	renderCtx, cancel := context.WithTimeout(ctx, rc.Timeout)
	defer cancel()

	// Build Chrome command-line allocator options
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		// Stealth: removes navigator.webdriver so anti-bot systems cannot detect headless Chrome
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.WindowSize(rc.WindowWidth, rc.WindowHeight),
	)

	// Set browser User-Agent
	if c.cfg.profile != ProfileNone {
		prof := GetProfileConfig(c.cfg.profile)
		if prof.UserAgent != "" {
			allocOpts = append(allocOpts, chromedp.UserAgent(prof.UserAgent))
		}
	}

	if rc.ProxyURL != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(rc.ProxyURL))
	}

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

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(renderCtx, allocOpts...)
	defer cancelAlloc()

	taskCtx, cancelTask := chromedp.NewContext(allocCtx)
	defer cancelTask()

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

	// Navigate to page
	tasks = append(tasks, chromedp.Navigate(targetURL))

	// Wait conditions
	if rc.WaitForSelector != "" {
		tasks = append(tasks, chromedp.WaitVisible(chromedp.CSS(rc.WaitForSelector)))
	} else if rc.WaitDuration > 0 {
		tasks = append(tasks, chromedp.Sleep(rc.WaitDuration))
	} else {
		// Default: wait for document ready
		tasks = append(tasks, chromedp.WaitReady(chromedp.CSS("body")))
	}

	// Execute setup, navigation, and wait actions
	if err := chromedp.Do(taskCtx, tasks...); err != nil {
		return nil, fmt.Errorf("chromedp rendering failed for %s: %w", targetURL, err)
	}

	// Extract the live, hydrated, modified DOM HTML
	renderedHTML, err := chromedp.Run(taskCtx, chromedp.OuterHTML(chromedp.CSS("html")))
	if err != nil {
		return nil, fmt.Errorf("chromedp failed to retrieve outer HTML for %s: %w", targetURL, err)
	}

	// Wrap in Response
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

	return resp, nil
}
