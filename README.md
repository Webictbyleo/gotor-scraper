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

### 5. High-Concurrency Batch Scraping (Worker Pool)

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

### 6. Tor Control Port (Explicit IP Rotation)

If you have Tor's control port enabled (default `127.0.0.1:9051`) and want to explicitly trigger a circuit reset:

```go
torCtrl := torscraper.NewTorController("127.0.0.1:9051", "optional_password")

// Requests a new Tor circuit (respects Tor's 10-second cooldown internally)
if err := torCtrl.NewIdentity(ctx); err != nil {
    log.Printf("Failed to rotate Tor identity: %v", err)
}
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
