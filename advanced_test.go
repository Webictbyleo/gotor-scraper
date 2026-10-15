package torscraper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyPool(t *testing.T) {
	pool, err := NewProxyPool(StrategyRoundRobin,
		"socks5://127.0.0.1:9050",
		"socks5://127.0.0.1:9052",
		"http://user:pass@127.0.0.1:8080",
	)
	if err != nil {
		t.Fatalf("Failed to create proxy pool: %v", err)
	}

	// 1. Test Round Robin cycling
	node1, err := pool.Next()
	if err != nil || node1.RawURL != "socks5://127.0.0.1:9050" {
		t.Errorf("Unexpected node 1: %v", node1)
	}

	node2, err := pool.Next()
	if err != nil || node2.RawURL != "socks5://127.0.0.1:9052" {
		t.Errorf("Unexpected node 2: %v", node2)
	}

	node3, err := pool.Next()
	if err != nil || node3.RawURL != "http://user:pass@127.0.0.1:8080" {
		t.Errorf("Unexpected node 3: %v", node3)
	}

	// Cycles back to 9050
	node4, err := pool.Next()
	if err != nil || node4.RawURL != "socks5://127.0.0.1:9050" {
		t.Errorf("Unexpected node 4: %v", node4)
	}

	// 2. Test Cooldown on failure
	pool.SetMaxFailures(2)
	pool.SetCooldown(100 * time.Millisecond)

	node1.RecordFailure(100*time.Millisecond, 2)
	if !node1.IsHealthy() {
		t.Error("Node should still be healthy after 1 failure (max is 2)")
	}

	node1.RecordFailure(100*time.Millisecond, 2)
	if node1.IsHealthy() {
		t.Error("Node should be disabled after 2 failures")
	}

	// Wait for cooldown to expire
	time.Sleep(120 * time.Millisecond)
	if !node1.IsHealthy() {
		t.Error("Node should recover after cooldown expires")
	}
}

func TestProfileRotation(t *testing.T) {
	var userAgents []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgents = append(userAgents, r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client, err := NewClient(
		WithProfileRotation(RotatePerRequest),
		WithTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, err := client.Get(ctx, server.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
	}

	if len(userAgents) != 5 {
		t.Fatalf("Expected 5 user-agents, got %d", len(userAgents))
	}
	// Verify that user-agents are populated
	for _, ua := range userAgents {
		if ua == "" {
			t.Error("Expected non-empty User-Agent on rotated request")
		}
	}
}

func TestPersistentSession(t *testing.T) {
	tempDir := t.TempDir()
	sessionFile := filepath.Join(tempDir, "test_session.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{
				Name:     "auth_token",
				Value:    "secret_token_12345",
				Path:     "/",
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
			})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("logged in"))
		case "/dashboard":
			cookie, err := r.Cookie("auth_token")
			if err != nil || cookie.Value != "secret_token_12345" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("welcome to dashboard"))
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// 1. First Client: Login and receive cookie
	client1, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithSessionFile(sessionFile),
		WithAutoSaveSession(true),
	)
	if err != nil {
		t.Fatalf("Failed to create client1: %v", err)
	}

	resp, err := client1.Get(ctx, server.URL+"/login")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("Login returned status: %d", resp.StatusCode)
	}
	client1.Close()

	// Verify session file exists on disk
	if _, err := os.Stat(sessionFile); err != nil {
		t.Fatalf("Expected session file to exist at %s: %v", sessionFile, err)
	}

	// 2. Second Client: Start fresh, should automatically load cookie and access /dashboard
	client2, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithSessionFile(sessionFile),
	)
	if err != nil {
		t.Fatalf("Failed to create client2: %v", err)
	}
	defer client2.Close()

	dashResp, err := client2.Get(ctx, server.URL+"/dashboard")
	if err != nil {
		t.Fatalf("Dashboard request failed: %v", err)
	}
	if dashResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK from restored session, got %d", dashResp.StatusCode)
	}
	if dashResp.Text() != "welcome to dashboard" {
		t.Errorf("Unexpected body: %s", dashResp.Text())
	}
}

func TestHooks(t *testing.T) {
	var reqCount int64
	var respCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hook test"))
	}))
	defer server.Close()

	client, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithHooks(Hooks{
			OnRequest: func(req *http.Request) {
				atomic.AddInt64(&reqCount, 1)
			},
			OnResponse: func(resp *Response, duration time.Duration) {
				atomic.AddInt64(&respCount, 1)
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if atomic.LoadInt64(&reqCount) != 1 {
		t.Errorf("Expected OnRequest to be called 1 time, got %d", reqCount)
	}
	if atomic.LoadInt64(&respCount) != 1 {
		t.Errorf("Expected OnResponse to be called 1 time, got %d", respCount)
	}
}

func TestHTMLQuerying(t *testing.T) {
	htmlContent := `<!DOCTYPE html>
<html>
<head>
    <title>E-Commerce Store</title>
</head>
<body>
    <div id="main-content">
        <h1 class="store-title">Welcome</h1>
        <div class="product-card featured">
            <a href="/products/laptop">MacBook Pro</a>
            <img src="/images/laptop.jpg" />
        </div>
        <div class="product-card">
            <a href="https://other.com/item/phone">iPhone 15</a>
            <img src="https://other.com/img/phone.png" />
        </div>
    </div>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlContent))
	}))
	defer server.Close()

	client, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(context.Background(), server.URL+"/shop")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	doc, err := resp.HTML()
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	// 1. Test Title
	if doc.Title() != "E-Commerce Store" {
		t.Errorf("Expected title 'E-Commerce Store', got: %s", doc.Title())
	}

	// 2. Test FindByID
	mainDiv := doc.FindByID("main-content")
	if mainDiv == nil {
		t.Fatal("Expected to find element by ID 'main-content'")
	}

	// 3. Test FindByClass
	products := doc.FindByClass("product-card")
	if len(products) != 2 {
		t.Errorf("Expected 2 products with class 'product-card', got %d", len(products))
	}

	// 4. Test Links (resolved to absolute URLs)
	links := doc.Links()
	if len(links) != 2 {
		t.Fatalf("Expected 2 links, got %d", len(links))
	}
	if !strings.HasPrefix(links[0], "http") || !strings.HasSuffix(links[0], "/products/laptop") {
		t.Errorf("Expected resolved absolute link for /products/laptop, got: %s", links[0])
	}
	if links[1] != "https://other.com/item/phone" {
		t.Errorf("Expected unchanged absolute URL, got: %s", links[1])
	}

	// 5. Test Images (resolved to absolute URLs)
	images := doc.Images()
	if len(images) != 2 {
		t.Fatalf("Expected 2 images, got %d", len(images))
	}
	if !strings.HasSuffix(images[0], "/images/laptop.jpg") {
		t.Errorf("Expected resolved image URL, got: %s", images[0])
	}

	// 6. Test AbsoluteURL helper on Response
	resolved := resp.AbsoluteURL("/api/v1/checkout")
	u, _ := url.Parse(server.URL)
	expectedResolved := server.URL + "/api/v1/checkout"
	if u.Port() != "" {
		expectedResolved = server.URL + "/api/v1/checkout"
	}
	if resolved != expectedResolved {
		t.Errorf("AbsoluteURL() = %s, want %s", resolved, expectedResolved)
	}
}

func TestRenderJS(t *testing.T) {
	htmlPage := `<!DOCTYPE html>
<html>
<head><title>JS Test</title></head>
<body>
    <div id="content">Original Server Content</div>
    <script>
        document.getElementById("content").textContent = "Hydrated Client Content";
    </script>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlPage))
	}))
	defer server.Close()

	client, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := client.GetRendered(ctx, server.URL,
		WaitForSelector("#content"),
		BlockAssets(true),
	)
	if err != nil {
		t.Logf("GetRendered skipped or failed (browser might not be installed): %v", err)
		return
	}

	doc, err := resp.HTML()
	if err != nil {
		t.Fatalf("Failed to parse rendered HTML: %v", err)
	}

	contentDiv := doc.FindByID("content")
	if contentDiv == nil {
		t.Fatal("Could not find #content in rendered DOM")
	}

	if contentDiv.Text() != "Hydrated Client Content" {
		t.Errorf("Expected 'Hydrated Client Content', got: %s", contentDiv.Text())
	}
}

func TestRenderHooksAndBrowserReuse(t *testing.T) {
	var reqCount int64
	var respCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><div id="status">OK</div></body></html>`))
	}))
	defer server.Close()

	client, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithHooks(Hooks{
			OnRequest: func(req *http.Request) {
				atomic.AddInt64(&reqCount, 1)
			},
			OnResponse: func(resp *Response, duration time.Duration) {
				atomic.AddInt64(&respCount, 1)
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// 1. First render (initializes shared browser process)
	resp1, err := client.GetRendered(ctx, server.URL, WaitForSelector("#status"), BlockAssets(true))
	if err != nil {
		t.Logf("GetRendered skipped (no browser binary): %v", err)
		return
	}
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp1.StatusCode)
	}

	// 2. Second render (reuses existing shared browser process via lightweight tab)
	resp2, err := client.GetRendered(ctx, server.URL, WaitForSelector("#status"), BlockAssets(true))
	if err != nil {
		t.Fatalf("Second render failed: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp2.StatusCode)
	}

	// Verify that hooks fired for both headless Chrome renders
	if atomic.LoadInt64(&reqCount) != 2 {
		t.Errorf("Expected 2 OnRequest hook invocations, got %d", reqCount)
	}
	if atomic.LoadInt64(&respCount) != 2 {
		t.Errorf("Expected 2 OnResponse hook invocations, got %d", respCount)
	}
}

func TestWorkerPoolRenderBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1 id="item">Page ` + r.URL.Query().Get("id") + `</h1></body></html>`))
	}))
	defer server.Close()

	client, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	pool := NewWorkerPool(client, PoolConfig{
		Workers: 3,
	})

	urls := []string{
		server.URL + "?id=1",
		server.URL + "?id=2",
		server.URL + "?id=3",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	results := pool.ScrapeBatchRender(ctx, urls, WaitForSelector("#item"), BlockAssets(true))
	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	for _, res := range results {
		if res.Error != nil {
			t.Logf("ScrapeBatchRender item error (browser may be missing): %v", res.Error)
			return
		}
		if res.Response.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK for %s, got %d", res.Job.URL, res.Response.StatusCode)
		}
	}
}

func TestRenderContentDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><p id="msg">Hello World</p></body></html>`))
		case "/large":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			largeBody := "<!DOCTYPE html><html><body>" + strings.Repeat("A", 200*1024) + "</body></html>"
			_, _ = w.Write([]byte(largeBody))
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// 1. Verify ContentInfo is properly populated by DetectContent on rendered page
	client, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.GetRendered(ctx, server.URL+"/html", WaitForSelector("#msg"), BlockAssets(true))
	if err != nil {
		t.Logf("GetRendered skipped (no browser binary): %v", err)
		return
	}

	if resp.ContentInfo == nil {
		t.Fatal("Expected ContentInfo to be populated on rendered response")
	}
	if !resp.ContentInfo.IsHTML {
		t.Error("Expected ContentInfo.IsHTML to be true")
	}
	if resp.ContentInfo.MediaType != "text/html" {
		t.Errorf("Expected media type text/html, got %s", resp.ContentInfo.MediaType)
	}

	// 2. Verify MaxContentLength safety limit enforces on GetRendered
	strictClient, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithMaxContentLength(50*1024), // 50KB limit (server serves >200KB)
	)
	if err != nil {
		t.Fatalf("Failed to create strict client: %v", err)
	}
	defer strictClient.Close()

	_, err = strictClient.GetRendered(ctx, server.URL+"/large", WaitForSelector("body"), BlockAssets(true))
	if !errors.Is(err, ErrContentLengthExceeded) {
		t.Errorf("Expected ErrContentLengthExceeded, got: %v", err)
	}

	// 3. Verify Blocked Content Types enforces on GetRendered
	blockedClient, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithBlockedContentTypes("text/html"),
	)
	if err != nil {
		t.Fatalf("Failed to create blocked client: %v", err)
	}
	defer blockedClient.Close()

	_, err = blockedClient.GetRendered(ctx, server.URL+"/html", WaitForSelector("#msg"), BlockAssets(true))
	if !errors.Is(err, ErrContentTypeBlocked) {
		t.Errorf("Expected ErrContentTypeBlocked, got: %v", err)
	}
}



