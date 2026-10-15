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
	Actions         []chromedp.Action[chromedp.Void]
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

// Click queues a click action on the element matching the CSS selector.
func Click(selector string) RenderOption {
	return func(rc *RenderConfig) {
		rc.Actions = append(rc.Actions,
			chromedp.WaitVisible(selector),
			chromedp.Click(selector),
		)
	}
}

// TypeText types the specified text into the input element matching the CSS selector.
func TypeText(selector, text string) RenderOption {
	return func(rc *RenderConfig) {
		rc.Actions = append(rc.Actions,
			chromedp.WaitVisible(selector),
			chromedp.SendKeys(selector, text),
		)
	}
}

// ScrollToBottom scrolls down the page in step increments with delays to trigger lazy-loaded images and infinite scrolling.
func ScrollToBottom(stepPx int, stepDelay time.Duration) RenderOption {
	if stepPx <= 0 {
		stepPx = 600
	}
	if stepDelay <= 0 {
		stepDelay = 200 * time.Millisecond
	}
	return func(rc *RenderConfig) {
		rc.Actions = append(rc.Actions, chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
			script := fmt.Sprintf(`
				new Promise((resolve) => {
					let totalHeight = 0;
					let distance = %d;
					let timer = setInterval(() => {
						let scrollHeight = document.body.scrollHeight;
						window.scrollBy(0, distance);
						totalHeight += distance;
						if (totalHeight >= scrollHeight) {
							clearInterval(timer);
							resolve();
						}
					}, %d);
				})
			`, stepPx, stepDelay.Milliseconds())
			_, err := chromedp.Evaluate[any](script, chromedp.EvalAwaitPromise)(ctx, t)
			return err
		}))
	}
}

// EvaluateScript executes custom JavaScript in the browser context before capturing the rendered DOM.
func EvaluateScript(js string) RenderOption {
	return func(rc *RenderConfig) {
		rc.Actions = append(rc.Actions, chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
			_, err := chromedp.Evaluate[any](js)(ctx, t)
			return err
		}))
	}
}

// Screenshot captures a full page screenshot and writes it to the specified file path.
func Screenshot(outputPath string) RenderOption {
	return func(rc *RenderConfig) {
		rc.Actions = append(rc.Actions, chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
			buf, err := chromedp.FullScreenshot(90)(ctx, t)
			if err != nil {
				return fmt.Errorf("failed to take screenshot: %w", err)
			}
			return os.WriteFile(outputPath, buf, 0644)
		}))
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

	// Execute initial network and cookie setup
	if err := chromedp.Do(taskCtx, tasks...); err != nil {
		renderErr := fmt.Errorf("chromedp network setup failed for %s: %w", targetURL, err)
		if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
			c.cfg.hooks.OnError(req, renderErr, 1)
		}
		return nil, renderErr
	}

	// Navigate to target URL and capture actual HTTP response metadata from Chrome
	navResp, err := chromedp.Run(taskCtx, chromedp.NavigateResponse(targetURL))
	if err != nil {
		// Fallback to standard Navigate if NavigateResponse encounters non-standard scheme
		if navErr := chromedp.Do(taskCtx, chromedp.Navigate(targetURL)); navErr != nil {
			renderErr := fmt.Errorf("chromedp navigation failed for %s: %w", targetURL, err)
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, renderErr, 1)
			}
			return nil, renderErr
		}
	}

	// -------------------------------------------------------------------------
	// Stage 1 Content Check: Zero-Byte MIME Preflight Check
	// -------------------------------------------------------------------------
	if navResp != nil && navResp.MimeType != "" {
		for _, pattern := range c.cfg.blockedContentTypes {
			if MatchesContentType(navResp.MimeType, pattern) {
				if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
					c.cfg.hooks.OnError(req, ErrContentTypeBlocked, 1)
				}
				return nil, ErrContentTypeBlocked
			}
		}
		if len(c.cfg.allowedContentTypes) > 0 {
			matched := false
			for _, pattern := range c.cfg.allowedContentTypes {
				if MatchesContentType(navResp.MimeType, pattern) {
					matched = true
					break
				}
			}
			if !matched {
				if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
					c.cfg.hooks.OnError(req, ErrContentTypeNotAllowed, 1)
				}
				return nil, ErrContentTypeNotAllowed
			}
		}
	}

	// Apply DOM wait conditions
	var waitTasks []chromedp.Action[chromedp.Void]
	if rc.WaitForSelector != "" {
		waitTasks = append(waitTasks, chromedp.WaitVisible(rc.WaitForSelector))
	} else if rc.WaitDuration > 0 {
		waitTasks = append(waitTasks, chromedp.Sleep(rc.WaitDuration))
	} else {
		// Default: wait for document body ready
		waitTasks = append(waitTasks, chromedp.WaitReady("body"))
	}

	if err := chromedp.Do(taskCtx, waitTasks...); err != nil {
		renderErr := fmt.Errorf("chromedp wait condition failed for %s: %w", targetURL, err)
		if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
			c.cfg.hooks.OnError(req, renderErr, 1)
		}
		return nil, renderErr
	}

	// Execute interactive user action chains (clicks, typing, scroll, custom scripts, screenshots)
	if len(rc.Actions) > 0 {
		if err := chromedp.Do(taskCtx, rc.Actions...); err != nil {
			renderErr := fmt.Errorf("chromedp action chain failed for %s: %w", targetURL, err)
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, renderErr, 1)
			}
			return nil, renderErr
		}
	}

	// Extract the live, hydrated, modified DOM HTML
	renderedHTML, err := chromedp.Run(taskCtx, chromedp.OuterHTML("html"))
	if err != nil {
		renderErr := fmt.Errorf("chromedp failed to retrieve outer HTML for %s: %w", targetURL, err)
		if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
			c.cfg.hooks.OnError(req, renderErr, 1)
		}
		return nil, renderErr
	}

	bodyBytes := []byte(renderedHTML)

	// -------------------------------------------------------------------------
	// Stage 2 Content Check: Safety Size Limits & Magic-Byte Verification
	// -------------------------------------------------------------------------
	maxLimit := c.cfg.maxContentLength
	if maxLimit <= 0 {
		maxLimit = DefaultMaxContentLength
	}
	if maxLimit > 0 && int64(len(bodyBytes)) > maxLimit {
		if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
			c.cfg.hooks.OnError(req, ErrContentLengthExceeded, 1)
		}
		return nil, ErrContentLengthExceeded
	}

	// Reconstruct response headers and status from Chrome CDP response
	rawHeader := make(http.Header)
	statusCode := http.StatusOK
	statusText := "200 OK"
	finalURL := parsedURL

	if navResp != nil {
		if navResp.Status > 0 {
			statusCode = int(navResp.Status)
			statusText = fmt.Sprintf("%d %s", navResp.Status, navResp.StatusText)
		}
		if navResp.URL != "" {
			if u, uErr := url.Parse(navResp.URL); uErr == nil {
				finalURL = u
			}
		}
		for k, v := range navResp.Headers {
			if strVal, ok := v.(string); ok {
				rawHeader.Set(k, strVal)
			}
		}
	}
	if rawHeader.Get("Content-Type") == "" {
		rawHeader.Set("Content-Type", "text/html; charset=utf-8")
	}

	rawResp := &http.Response{
		StatusCode: statusCode,
		Status:     statusText,
		Header:     rawHeader,
		Request: &http.Request{
			URL: finalURL,
		},
	}

	// Run full magic-byte sniffing & semantic content classification on rendered HTML
	urlPath := ""
	if finalURL != nil {
		urlPath = finalURL.Path
	}
	contentInfo := DetectContent(rawResp, bodyBytes, urlPath)
	if contentInfo.ContentLength <= 0 {
		contentInfo.ContentLength = int64(len(bodyBytes))
	}

	// Check blocked content types on post-rendered content
	for _, pattern := range c.cfg.blockedContentTypes {
		if MatchesContentType(contentInfo.MediaType, pattern) || (contentInfo.SniffedType != "" && MatchesContentType(contentInfo.SniffedType, pattern)) {
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, ErrContentTypeBlocked, 1)
			}
			return nil, ErrContentTypeBlocked
		}
	}

	// Check allowed content types on post-rendered content
	if len(c.cfg.allowedContentTypes) > 0 {
		matched := false
		for _, pattern := range c.cfg.allowedContentTypes {
			if MatchesContentType(contentInfo.MediaType, pattern) || (contentInfo.SniffedType != "" && MatchesContentType(contentInfo.SniffedType, pattern)) {
				matched = true
				break
			}
		}
		if !matched {
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, ErrContentTypeNotAllowed, 1)
			}
			return nil, ErrContentTypeNotAllowed
		}
	}

	// Run custom ContentFilter middleware hook if defined
	if c.cfg.contentFilter != nil {
		if err := c.cfg.contentFilter(contentInfo, rawResp); err != nil {
			filterErr := fmt.Errorf("%w: %v", ErrContentRejected, err)
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, filterErr, 1)
			}
			return nil, filterErr
		}
	}

	resp := &Response{
		StatusCode:  statusCode,
		Status:      statusText,
		Headers:     rawHeader,
		RawResponse: rawResp,
		ContentInfo: contentInfo,
		rawBody:     bodyBytes,
	}

	// Inspect rendered content for anti-bot challenge or WAF mitigation
	abDetection := resp.AntiBot()
	if abDetection != nil && abDetection.Detected {
		if c.cfg.hooks != nil && c.cfg.hooks.OnAntiBot != nil {
			c.cfg.hooks.OnAntiBot(req, resp, abDetection)
		}

		if c.cfg.abortOnAntiBot && resp.IsBlocked() {
			blockedErr := &BlockedError{Detection: abDetection}
			if c.cfg.hooks != nil && c.cfg.hooks.OnError != nil {
				c.cfg.hooks.OnError(req, blockedErr, 1)
			}
			return resp, blockedErr
		}
	}

	// Fire OnResponse lifecycle hook
	if c.cfg.hooks != nil && c.cfg.hooks.OnResponse != nil {
		c.cfg.hooks.OnResponse(resp, time.Since(start))
	}

	return resp, nil
}
