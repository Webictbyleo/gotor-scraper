# Go Tor & Anti-Bot Scraper (`gotor-scraper`)

A modular, high-concurrency Go scraping module designed with an **`aiohttp`**-style developer experience, custom **`uTLS` browser fingerprinting** (pure Go, zero third-party wrappers like `bogdanfinn/tls-client`), and **optional Tor routing with Stream Isolation**.

---

## Features

- **`aiohttp`-Style Session API**:
  - Thread-safe client session with automatic cookie jar management (`net/http/cookiejar`).
  - Fluent response helpers: `resp.Text()`, `resp.JSON(&v)`, `resp.Bytes()`, `resp.IsSuccess()`.
  - Automatic multi-format decompression (`gzip`, `deflate`, `br` via Brotli).
  - Rich redirect handling (automatic follow, disable per-request/session, max redirect limits, and `resp.FinalURL()`).
- **Custom `uTLS` Engine (Pure Go, No Heavy Wrappers)**:
  - Direct integration with `github.com/refraction-networking/utls`.
  - Bypasses Cloudflare / Akamai / Datadome JA3 & JA4 fingerprint filters.
  - Native HTTP/2 multiplexing via ALPN negotiation and pooled client connections.
  - Selectable browser profiles: `ProfileChrome`, `ProfileFirefox`, `ProfileSafari`, `ProfileEdge`, or `ProfileNone` (standard Go TLS).
- **Optional & Flexible Tor Integration**:
  - **Toggleable per Client or per Scrape**: Switch Tor on or off depending on the target.
  - **Tor Stream Isolation (`IsolateSOCKSAuth`)**: Automatically passes dynamic virtual SOCKS5 credentials per connection, allowing Tor to allocate separate circuits/exit nodes concurrently without blocking.
  - **Tor Control Port Manager**: Built-in `TorController` to issue `SIGNAL NEWNYM` with cooldown handling.
- **High-Concurrency Worker Pool**:
  - Multi-worker dispatcher (analogous to Python's `asyncio.gather` + `asyncio.Semaphore`).
  - Token bucket rate limiter (`golang.org/x/time/rate`).
  - Exponential backoff retries with optional circuit rotation on failure.
- **Universal Video Handling & Downloader Engine**:
  - Full support for **YouTube**, **Loom**, **Vimeo**, and **Wistia**.
  - URL identification, parsing, timestamp normalization, and embed/canonical/thumbnail generation.
  - Page-level video harvesting (`doc.Videos()`) across `<iframe>`, `<embed>`, `<video>`, `<source>`, `<a>`, and Wistia async DOM containers.
  - Media stream extraction (`client.ExtractVideoStreams`) and streaming downloader (`client.DownloadVideo`) with live progress callbacks (`OnProgress`).

---

## Installation & Setup

### 1. Configure Go for Private GitHub Repositories
Since this repository is private under `Webictbyleo`, tell Go to bypass the public proxy:

```bash
go env -w GOPRIVATE="github.com/Webictbyleo/*"
```

Configure Git to use your GitHub credentials or SSH:
```bash
git config --global url."https://github.com/".insteadOf "git@github.com:"
# or if using personal access tokens:
# git config --global url."https://<token>@github.com/".insteadOf "https://github.com/"
```

### 2. Add to Your Project
```bash
go get github.com/Webictbyleo/gotor-scraper
```

---

## Usage Guide

### 1. Direct Scrape with Chrome Fingerprint (No Tor)

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/Webictbyleo/gotor-scraper"
)

func main() {
    ctx := context.Background()

    // Initialize client with Chrome TLS profile
    client, err := torscraper.NewClient(
        torscraper.WithBrowserProfile(torscraper.ProfileChrome),
        torscraper.WithTimeout(15 * time.Second),
    )
    if err != nil {
        panic(err)
    }
    defer client.Close()

    // Send GET request
    resp, err := client.Get(ctx, "https://httpbin.org/get")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Status: %d\n", resp.StatusCode)
    fmt.Printf("Body: %s\n", resp.Text())
}
```

---

### 2. Enabling Tor with Stream Isolation

```go
torClient, err := torscraper.NewClient(
    torscraper.WithTor(&torscraper.TorConfig{
        Enabled:         true,
        ProxyAddr:       "127.0.0.1:9050",
        StreamIsolation: true, // Allocates distinct circuits across concurrent requests
    }),
    torscraper.WithBrowserProfile(torscraper.ProfileChrome),
    torscraper.WithTimeout(30 * time.Second),
)
if err != nil {
    panic(err)
}
defer torClient.Close()

resp, err := torClient.Get(ctx, "https://api.ipify.org?format=json")
if err != nil {
    panic(err)
}

var ipInfo struct {
    IP string `json:"ip"`
}
if err := resp.JSON(&ipInfo); err != nil {
    panic(err)
}
fmt.Println("Tor Exit IP:", ipInfo.IP)
```

---

### 3. Toggling Tor Per-Request / Per-Scrape

You can keep a single direct client and dynamically route individual requests through Tor:

```go
// Direct request
resp1, _ := client.Get(ctx, "https://example.com/unprotected")

// Route this specific scrape through Tor:
resp2, _ := client.Get(ctx, "https://example.com/protected",
    torscraper.ReqWithTor(&torscraper.TorConfig{
        Enabled:   true,
        ProxyAddr: "127.0.0.1:9050",
    }),
)
```

---

### 4. Handling Redirects

By default, the client automatically follows redirects (up to 10 redirects) and preserves cookies in the cookie jar across redirects (identical to `aiohttp`).

#### Disabling Redirects (Global or Per-Request)
```go
// Option A: Disable globally on the client session (like aiohttp allow_redirects=False)
client, _ := torscraper.NewClient(
    torscraper.WithFollowRedirects(false),
)

// Option B: Disable per-request on a client that normally follows them
resp, _ := client.Get(ctx, "https://example.com/login",
    torscraper.ReqWithFollowRedirects(false),
)

if resp.IsRedirect() {
    fmt.Println("Redirect status:", resp.StatusCode)         // 301, 302, 307, etc.
    fmt.Println("Redirect target:", resp.RedirectURL())       // Location header
}
```

#### Custom Redirect Limit & Inspecting Final URL
```go
client, _ := torscraper.NewClient(
    torscraper.WithMaxRedirects(5), // Stop after 5 consecutive redirects
)

resp, _ := client.Get(ctx, "https://example.com/shortlink")
fmt.Println("Final destination URL:", resp.FinalURL()) // e.g. https://target.com/final
```

---

### 5. Automatic Retries & Tor Circuit Rotation

The library provides exponential backoff retries for transient failures, network timeouts, HTTP 429 (Too Many Requests), and 5xx server errors. When Tor is active, it can automatically rotate to a fresh Tor circuit on every retry.

#### Client Session Retries
```go
client, _ := torscraper.NewClient(
    torscraper.WithRetries(3, 1 * time.Second), // Retry up to 3 times with 1s initial backoff (1s, 2s, 4s)
    torscraper.WithRotateTorOnRetry(true),      // Forces a new Tor circuit on each retry!
)

// Automatically retries if the server returns 429/503 or drops the connection:
resp, err := client.Get(ctx, "https://target-site.com/api")
```

#### Per-Request Retry Override
```go
// Override retry count on an individual request:
resp, err := client.Get(ctx, "https://target-site.com/flaky",
    torscraper.ReqWithRetries(5),
)
```

---

### 6. Content Detection Middleware & Safety Limits

The library includes a **Two-Stage Content Detection Middleware** that intercepts responses **before** downloading the body. This prevents downloading huge files or unwanted media types over Tor and RAM:

* **Stage 1 (Header Preflight)**: Aborts instantly if declared `Content-Length` exceeds limits or `Content-Type` is blocked. Zero body bytes are downloaded.
* **Stage 2 (Magic-Byte Sniffing)**: Peeks the first 512 uncompressed bytes on-demand. Disambiguates WebP vs WAV vs AVI, AVIF vs MP4, JSON vs HTML, and detects Cloudflare CAPTCHAs disguised as APIs.

#### Setting Max Body Size & Content Type Guards
```go
client, _ := torscraper.NewClient(
    // Safety guard: max 5MB (default is 10MB; 0 for unlimited)
    torscraper.WithMaxContentLength(5 * 1024 * 1024),

    // Only allow HTML and JSON — drops PDFs, images, archives immediately
    torscraper.WithAllowedContentTypes("text/html", "application/json"),

    // Or explicitly block media/binary files
    torscraper.WithBlockedContentTypes("image/*", "video/*", "application/zip", "application/pdf"),
)

resp, err := client.Get(ctx, "https://example.com/target")
if errors.Is(err, torscraper.ErrContentLengthExceeded) {
    fmt.Println("File was too large; aborted before downloading!")
} else if errors.Is(err, torscraper.ErrContentTypeBlocked) {
    fmt.Println("Content-Type was blocked; aborted before downloading!")
}
```

#### Inspecting Verified Content Metadata
Every response includes a rich `ContentInfo` struct:
```go
resp, _ := client.Get(ctx, "https://api.example.com/data")

fmt.Println("Media Type:", resp.ContentInfo.MediaType)       // e.g. "application/json"
fmt.Println("Sniffed Type:", resp.ContentInfo.SniffedType)   // Verified from magic bytes
fmt.Println("Is JSON?:", resp.ContentInfo.IsJSON)           // true
fmt.Println("Is HTML?:", resp.ContentInfo.IsHTML)           // false
fmt.Println("Is Binary?:", resp.ContentInfo.IsBinary)       // false

// Detect if server claimed JSON but actually returned a Cloudflare block page:
if resp.ContentInfo.MismatchDetected {
    fmt.Println("Warning: Server lied!", resp.ContentInfo.MismatchReason)
}
```

#### Custom Pre-Download Middleware Hook
```go
client, _ := torscraper.NewClient(
    torscraper.WithContentFilter(func(info *torscraper.ContentInfo, raw *http.Response) error {
        if info.IsBinary {
            return errors.New("binary files not allowed")
        }
        return nil // nil = proceed to download
    }),
)
```

---

### 7. High-Concurrency Batch Scraping (Worker Pool)

For scraping thousands of URLs in parallel with rate limits and retry resilience:

```go
pool := torscraper.NewWorkerPool(torClient, torscraper.PoolConfig{
    Workers:          10,                     // 10 concurrent goroutines
    RateLimit:        5.0,                    // 5 requests per second
    MaxRetries:       3,                      // Retry failed requests up to 3 times
    RetryBackoff:     500 * time.Millisecond, // Exponential backoff (500ms, 1s, 2s)
    RotateTorOnRetry: true,                   // Rotate Tor circuit on retry
})

urls := []string{
    "https://httpbin.org/get?id=1",
    "https://httpbin.org/get?id=2",
    "https://httpbin.org/get?id=3",
}

results := pool.ScrapeBatch(ctx, urls)
for _, res := range results {
    if res.Error != nil {
        fmt.Printf("Failed: %s -> %v\n", res.Job.URL, res.Error)
    } else {
        fmt.Printf("Success [%d]: %s (took %v)\n", res.Response.StatusCode, res.Job.URL, res.Duration)
    }
}
```

---

---

### 8. Multi-Tor & Multi-Proxy Pool

Manage a resilient pool of proxies (Tor SOCKS5, standard SOCKS5, and HTTP/HTTPS proxies) with automated health tracking and failover:

```go
pool, err := torscraper.NewProxyPool(torscraper.StrategyRoundRobin,
    "socks5://127.0.0.1:9050",               // Tor instance 1
    "socks5://127.0.0.1:9052",               // Tor instance 2
    "http://user:password@proxy.net:8080",   // Datacenter HTTP proxy
)
if err != nil {
    panic(err)
}

// Customize resilience thresholds
pool.SetMaxFailures(3)              // Disable proxy after 3 consecutive failures
pool.SetCooldown(2 * time.Minute)   // Re-probe after 2 minutes

client, _ := torscraper.NewClient(
    torscraper.WithProxyPool(pool),
)
```

---

### 9. Headless Chrome JS Rendering (Chrome DevTools Protocol)

For dynamic Single-Page Applications (SPAs, React, Angular, Vue) or JavaScript challenge walls, execute headless Chrome through Chrome DevTools Protocol (CDP) to obtain the live, fully-hydrated DOM:

* **Persistent Browser Reuse (Tab Pooling)**: Does **NOT** spawn a new Chrome process for every URL. The `Client` initializes a single shared headless Chrome instance and opens lightweight, isolated browser tabs per URL, closing only the tab when completed. This eliminates the 1-2s process startup penalty and saves massive CPU/RAM.
* **Full Hooks Integration**: All lifecycle event hooks (`OnRequest`, `OnResponse`, `OnError`, `OnRetry`) execute seamlessly during headless Chrome rendering, giving unified logging and metrics across both HTTP requests and browser renders.
* **Asset Blocking over Tor**: Automatically drops images, videos, fonts, and tracking scripts to save ~90% Tor bandwidth and accelerate page load up to 5x.
* **Cookie Synchronization**: Automatically loads active cookies from the client's cookie jar into the headless Chrome session.
* **Batch Headless Rendering**: Worker pool supports `pool.ScrapeBatchRender(ctx, urls, ...)` to scrape dozens or hundreds of JavaScript-rendered pages concurrently across browser tabs with rate limiting and retries.
* **Clean Termination**: Calling `client.Close()` automatically closes all open connections and cleanly terminates the background Chrome process.

```go
// Render dynamic JavaScript page and extract modified DOM
renderedResp, err := client.GetRendered(ctx, "https://example.com/app",
    torscraper.WaitForSelector("#main-feed"), // Wait until #main-feed appears in DOM
    torscraper.BlockAssets(true),             // Block images/fonts to maximize Tor speed
    torscraper.RenderTimeout(25 * time.Second),
)
if err != nil {
    panic(err)
}

// Query the modified DOM
doc, _ := renderedResp.HTML()
feed := doc.FindByID("main-feed")
fmt.Println("Rendered Feed Content:", feed.Text())

// Batch render multiple URLs concurrently using the shared browser instance:
pool := torscraper.NewWorkerPool(client, torscraper.PoolConfig{Workers: 5})
results := pool.ScrapeBatchRender(ctx, []string{
    "https://example.com/item/1",
    "https://example.com/item/2",
    "https://example.com/item/3",
}, torscraper.WaitForSelector(".loaded"), torscraper.BlockAssets(true))
```

---

### 10. Built-in HTML Query Engine & Semantic Extraction

Extract data directly without importing external parser packages:

```go
resp, _ := client.Get(ctx, "https://news.ycombinator.com")
doc, err := resp.HTML()
if err != nil {
    panic(err)
}

// Page title
fmt.Println("Title:", doc.Title())

// Semantic lookups
banner := doc.FindByID("banner")
articles := doc.FindByClass("athing")
allLinks := doc.Links()   // Automatically resolved to absolute URLs!
allImages := doc.Images() // Automatically resolved to absolute URLs!

// Helper for relative URL resolution
absURL := resp.AbsoluteURL("/item?id=12345")
```

---

### 11. Persistent Cookie Jar & Session Storage

Persist logins, session cookies, and tokens across script restarts:

```go
// Option A: Single JSON session file
client, _ := torscraper.NewClient(
    torscraper.WithSessionFile("./sessions/user_session.json"),
    torscraper.WithAutoSaveSession(true), // Automatically writes changes to disk
)

// Option B: Session directory
client, _ := torscraper.NewClient(
    torscraper.WithSessionDir("./sessions", "account_admin"),
    torscraper.WithAutoSaveSession(true),
)
```

---

### 12. Profile Rotation & Lifecycle Event Hooks

Camouflage requests by rotating both TLS fingerprints and HTTP headers, and attach audit/logging hooks:

```go
client, _ := torscraper.NewClient(
    // Rotates TLS ClientHello + Sec-Ch-Ua + User-Agent on every single request
    torscraper.WithProfileRotation(torscraper.RotatePerRequest),

    // Pluggable event hooks
    torscraper.WithHooks(torscraper.Hooks{
        OnRequest: func(req *http.Request) {
            fmt.Println("[HOOK] Sending request:", req.Method, req.URL.String())
        },
        OnResponse: func(resp *torscraper.Response, duration time.Duration) {
            fmt.Printf("[HOOK] Received %d in %v\n", resp.StatusCode, duration)
        },
        OnRetry: func(attempt int, err error, delay time.Duration) {
            fmt.Printf("[HOOK] Retry #%d after error: %v (sleeping %v)\n", attempt, err, delay)
        },
    }),
)
```

---

### 13. Comprehensive Anti-Bot & WAF Challenge Detection (`antibot.go`)

Accurately detect whether a scrape was intercepted by bot defenses, challenge walls, or WAF IP bans—even when servers stealthily return **HTTP 200 OK** (e.g. Cloudflare Turnstile, Imperva Incapsula) or non-standard status codes (**AWS WAF 405/202**):

* **Multi-Factor Correlation**: Prevents false positives by distinguishing genuine security gates from normal tech articles mentioning "Cloudflare" or "reCAPTCHA".
* **Vendor Signatures Covered**:
  - **Cloudflare**: `cf-mitigated: challenge`, Turnstile DOM (`challenges.cloudflare.com/turnstile`), Error 1020, Error 1015, and RayID extraction.
  - **DataDome**: `x-datadome` headers, `datadome` cookie, `captcha-delivery.com`, and API 403 JSON payloads.
  - **Akamai Bot Manager**: `AkamaiGHost`, `akamai-bot-decision`, and `Reference #18...` parsing.
  - **PerimeterX / HUMAN Security**: `<div id="px-captcha">`, `window._pxAppId`, and Advanced Blocking Response (ABR) JSON.
  - **Imperva / Incapsula**: Incident block iframes (`/_Incapsula_Resource`), `X-Iinfo`, and incident ID parsing (even on HTTP 200).
  - **Kasada**: `x-kpsdk-*` headers and `/ips.js` bytecode VM Proof-of-Work telemetry.
  - **AWS WAF**: `x-amzn-waf-action: captcha` (HTTP 405) and `challenge` (HTTP 202).
  - **F5 BIG-IP ASM / Shape**: URL rejection notices and 19-digit Support ID extraction.
  - **Standalone Captchas**: Google reCAPTCHA, hCaptcha, GeeTest, Arkose Labs (FunCaptcha).
  - **Volumetric Rate Limits**: HTTP 429 with `Retry-After` header extraction.

```go
resp, err := client.Get(ctx, "https://target-site.com")
if err != nil {
    panic(err)
}

// 1. Quick boolean check
if resp.IsBlocked() {
    // 2. Detailed anti-bot telemetry
    detection := resp.AntiBot()
    fmt.Println("Blocked By Provider:", detection.Provider)         // e.g. "cloudflare", "datadome"
    fmt.Println("Challenge Type:", detection.ChallengeType)        // e.g. "js_challenge", "interactive", "access_denied"
    fmt.Println("Incident / Ray ID:", detection.IncidentID)        // e.g. "89abcdef01234567"
    fmt.Println("Action Hint:", detection.ActionHint)              // e.g. "rotate_proxy", "use_headless", "sleep_backoff"
    fmt.Println("Reason:", detection.Reason)
}
```

---

### 14. Tor Control Port (Explicit IP Rotation)

If you have Tor's control port enabled (default `127.0.0.1:9051`) and want to explicitly trigger a circuit reset:

```go
torCtrl := torscraper.NewTorController("127.0.0.1:9051", "optional_password")

// Requests a new Tor circuit (respects Tor's 10-second cooldown internally)
if err := torCtrl.NewIdentity(ctx); err != nil {
    log.Printf("Failed to rotate Tor identity: %v", err)
}
```

---

### 15. Video URL Parsing, HTML Extraction & Stream Downloader (YouTube, Loom, Vimeo, Wistia)

`gotor-scraper` provides built-in utilities to identify, normalize, extract, and download video assets from **YouTube**, **Loom**, **Vimeo**, and **Wistia**.

#### 1. Universal URL Parsing

```go
video, err := torscraper.ParseVideoURL("https://youtu.be/dQw4w9WgXcQ?t=1m30s")
if err != nil {
    panic(err)
}

fmt.Println("Platform:", video.Platform)       // "youtube"
fmt.Println("Video ID:", video.ID)             // "dQw4w9WgXcQ"
fmt.Println("Canonical URL:", video.CanonicalURL) // "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
fmt.Println("Embed URL:", video.EmbedURL)         // "https://www.youtube.com/embed/dQw4w9WgXcQ?start=90"
fmt.Println("Start Offset:", video.Timestamp)     // 90s
fmt.Println("Thumbnail URL:", video.ThumbnailURL) // "https://img.youtube.com/vi/dQw4w9WgXcQ/hqdefault.jpg"
```

#### 2. HTML Video Extraction

Effortlessly extract all embedded videos and links from any scraped page:

```go
resp, err := client.Get(ctx, "https://example.com/blog/video-guide")
doc, err := resp.HTML()

// Automatically detects iframes, embeds, links, and Wistia async containers
videos := doc.Videos()
for _, v := range videos {
    fmt.Printf("[%s] ID=%s Embed=%s\n", v.Platform, v.ID, v.EmbedURL)
}
```

#### 3. Extracting Streams & Downloading Videos

Query available direct streams and stream-download the highest quality MP4 directly to disk with live progress:

```go
// 1. Extract direct downloadable streams
streams, err := client.ExtractVideoStreams(ctx, "https://fast.wistia.net/embed/iframe/g5pnf59ala")
for _, s := range streams {
    fmt.Printf("Quality: %s (%dx%d), Container: %s, Bitrate: %d\n",
        s.Quality, s.Width, s.Height, s.Container, s.Bitrate)
}

// 2. Download the best quality stream with real-time progress tracking
result, err := client.DownloadVideo(ctx, "https://fast.wistia.net/embed/iframe/g5pnf59ala", torscraper.DownloadOptions{
    Quality:    "best",
    OutputPath: "./downloads/video.mp4",
    OnProgress: func(downloaded, total int64, pct float64) {
        fmt.Printf("\rDownloading: %.1f%% (%d / %d bytes)", pct, downloaded, total)
    },
})
if err != nil {
    log.Fatalf("Download failed: %v", err)
}

fmt.Printf("\nSaved %d bytes in %v to %s\n", result.BytesWritten, result.Duration, result.OutputPath)
```

---

## Running the Example

Run the included demonstration in `examples/main.go`:

```bash
go run examples/main.go
```

## Running Tests

```bash
go test -v ./...
```
