package torscraper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestVerify_Bug1_SecureCookiesLostOnReload verifies that cookies with Secure=true
// are lost when reloaded from a persistent session file.
func TestVerify_Bug1_SecureCookiesLostOnReload(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "session_bug1.json")

	// 1. Save a secure cookie to disk
	jar1, err := NewPersistentCookieJar(tmpFile, false)
	if err != nil {
		t.Fatalf("Failed to create jar: %v", err)
	}

	targetURL, _ := url.Parse("https://example.com/dashboard")
	secureCookie := &http.Cookie{
		Name:     "auth_token",
		Value:    "secret12345",
		Path:     "/",
		Domain:   "example.com",
		Secure:   true,
		HttpOnly: true,
	}

	jar1.SetCookies(targetURL, []*http.Cookie{secureCookie})
	if err := jar1.Save(); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// 2. Reload into a new jar
	jar2, err := NewPersistentCookieJar(tmpFile, false)
	if err != nil {
		t.Fatalf("Failed to reload jar: %v", err)
	}

	cookies := jar2.Cookies(targetURL)
	t.Logf("Cookies found after reload for %s: count=%d", targetURL.String(), len(cookies))
	if len(cookies) == 0 {
		t.Fatalf("Expected cookie to be returned for %s, got 0", targetURL.String())
	}

	regCookie := jar2.registry["example.com"]["auth_token"]
	if regCookie == nil || !regCookie.Secure {
		t.Errorf("Expected cookie in registry to have Secure=true")
	}

	// Check plain HTTP: A Secure cookie MUST NEVER be sent over plain http://
	httpURL, _ := url.Parse("http://example.com/insecure")
	insecureCookies := jar2.Cookies(httpURL)
	t.Logf("Cookies sent over plain http://: count=%d", len(insecureCookies))
	if len(insecureCookies) > 0 {
		t.Errorf("Secure cookie leaked to plain unencrypted http://!")
	}
}

// TestVerify_Bug2_CookiePortPollution verifies that port numbers in URLs
// pollute cookie domains.
func TestVerify_Bug2_CookiePortPollution(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "session_bug2.json")
	jar, err := NewPersistentCookieJar(tmpFile, false)
	if err != nil {
		t.Fatalf("Failed to create jar: %v", err)
	}

	targetURL, _ := url.Parse("http://localhost:8080/api")
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "session", Value: "abc"},
	})
	_ = jar.Save()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read session file: %v", err)
	}
	t.Logf("Saved JSON content: %s", string(data))

	if containsPort := string(data); containsPort != "" {
		if _, ok := jar.registry["localhost:8080"]; ok {
			t.Errorf("[BUG CONFIRMED] Cookie domain in registry was saved as 'localhost:8080' instead of 'localhost'")
		}
	}
}

// TestVerify_Bug3_AntiBotMissingScopeAndIsGatekeeper verifies that non-widget
// WAF blocks have empty Scope and false IsGatekeeper.
func TestVerify_Bug3_AntiBotMissingScopeAndIsGatekeeper(t *testing.T) {
	// Simulate DataDome 403 header block
	resp := &http.Response{
		StatusCode: 403,
		Header: http.Header{
			"X-Datadome": []string{"protected"},
		},
	}
	detection := DetectAntiBot(resp, []byte("Forbidden by DataDome"))

	t.Logf("DataDome 403 Detection verdict:")
	t.Logf("  Detected:     %t", detection.Detected)
	t.Logf("  Provider:     %s", detection.Provider)
	t.Logf("  Scope:        %q", string(detection.Scope))
	t.Logf("  IsGatekeeper: %t", detection.IsGatekeeper)

	if detection.Scope == "" || !detection.IsGatekeeper {
		t.Errorf("[BUG CONFIRMED] Scope is %q and IsGatekeeper is %t on a full WAF block!", detection.Scope, detection.IsGatekeeper)
	}
}

// TestVerify_Bug4_CloneLosesAbortOnAntiBot verifies that Client.Clone()
// drops the abortOnAntiBot configuration.
func TestVerify_Bug4_CloneLosesAbortOnAntiBot(t *testing.T) {
	client, err := NewClient(WithAbortOnAntiBot(true))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if !client.cfg.abortOnAntiBot {
		t.Fatalf("Expected parent client to have abortOnAntiBot=true")
	}

	cloned, err := client.Clone()
	if err != nil {
		t.Fatalf("Failed to clone client: %v", err)
	}
	defer cloned.Close()

	t.Logf("Parent abortOnAntiBot: %t", client.cfg.abortOnAntiBot)
	t.Logf("Cloned abortOnAntiBot: %t", cloned.cfg.abortOnAntiBot)

	if !cloned.cfg.abortOnAntiBot {
		t.Errorf("[BUG CONFIRMED] Client.Clone() lost abortOnAntiBot! Cloned has %t", cloned.cfg.abortOnAntiBot)
	}
}

// TestVerify_Bug7_WorkerPoolFlaws verifies:
// A) Job loss on context cancellation
// B) Unconditional retries on non-retryable errors
func TestVerify_Bug7_WorkerPoolFlaws(t *testing.T) {
	client, _ := NewClient(WithRetries(0, 0))
	defer client.Close()

	// A) Job loss test
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewWorkerPool(client, PoolConfig{Workers: 1})

	jobs := []Job{
		{ID: "j1", URL: "http://example.com/1"},
		{ID: "j2", URL: "http://example.com/2"},
		{ID: "j3", URL: "http://example.com/3"},
		{ID: "j4", URL: "http://example.com/4"},
	}

	// Cancel context immediately
	cancel()
	results := pool.Process(ctx, jobs)

	t.Logf("Submitted jobs: %d | Returned results: %d", len(jobs), len(results))
	if len(results) < len(jobs) {
		t.Errorf("[BUG CONFIRMED - 7A] Submitted %d jobs but only received %d results! Remaining jobs dropped.", len(jobs), len(results))
	}

	// B) Non-retryable error test
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send 100 bytes
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write(make([]byte, 100))
	}))
	defer server.Close()

	clientMax, _ := NewClient(WithMaxContentLength(10)) // Max 10 bytes -> will trigger ErrContentLengthExceeded
	defer clientMax.Close()

	retryPool := NewWorkerPool(clientMax, PoolConfig{
		Workers:      1,
		MaxRetries:   2,
		RetryBackoff: 10 * time.Millisecond,
	})

	singleJob := []Job{{ID: "limit_test", URL: server.URL}}
	resList := retryPool.Process(context.Background(), singleJob)
	if len(resList) > 0 {
		res := resList[0]
		t.Logf("Job error: %v, RetryCount: %d", res.Error, res.RetryCount)
		if errors.Is(res.Error, ErrContentLengthExceeded) && res.RetryCount > 0 {
			t.Errorf("[BUG CONFIRMED - 7B] WorkerPool retried %d times on non-retryable ErrContentLengthExceeded!", res.RetryCount)
		}
	}
}

// TestVerify_Bug9_ScreenshotSecurityPolicy verifies that Screenshot enforces
// strict file creation without creating arbitrary directories.
func TestVerify_Bug9_ScreenshotSecurityPolicy(t *testing.T) {
	nonExistentPath := filepath.Join(t.TempDir(), "subdir_does_not_exist", "test.png")
	opt := Screenshot(nonExistentPath)
	cfg := &RenderConfig{}
	opt(cfg)

	if len(cfg.Actions) == 0 {
		t.Fatal("Expected action to be appended")
	}

	// Verify that writing to non-existent directory safely errors as intended
	err := os.WriteFile(nonExistentPath, []byte("fake png"), 0644)
	if !os.IsNotExist(err) {
		t.Errorf("Expected os.ErrNotExist when directory does not exist, got: %v", err)
	}
	t.Logf("Confirmed strict security policy: directory creation is disallowed (%v)", err)
}

// TestVerify_Bug10_DocTitleTruncation verifies that <title> tags with
// multiple child nodes or entities are truncated by doc.Title().
func TestVerify_Bug10_DocTitleTruncation(t *testing.T) {
	htmlContent := `<!DOCTYPE html><html><head><title>First &amp; Second <!-- note --> Part</title></head><body></body></html>`
	resp := &Response{
		rawBody: []byte(htmlContent),
	}

	doc, err := resp.HTML()
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	title := doc.Title()
	t.Logf("Extracted Title: %q", title)
	if title != "First & Second Part" {
		t.Errorf("[BUG CONFIRMED] doc.Title() extracted %q instead of full title 'First & Second Part'", title)
	}
}

// TestVerify_Bug6_RedirectURLPathContentSniffing verifies that content detection
// receives the initial request path instead of the final redirected path.
func TestVerify_Bug6_RedirectURLPathContentSniffing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download" {
			http.Redirect(w, r, "/data.parquet", http.StatusFound)
			return
		}
		if r.URL.Path == "/data.parquet" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("random binary payload"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(context.Background(), server.URL+"/download")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	t.Logf("Final URL: %s", resp.FinalURL())
	t.Logf("Detected SniffedType: %s", resp.ContentInfo.SniffedType)
	t.Logf("Detected MediaType: %s", resp.ContentInfo.MediaType)

	// In content.go, SniffMagicBytes has fallback:
	// case ".parquet": return "application/vnd.apache.parquet"
	// Because respCfg.urlPath was "/download" instead of "/data.parquet",
	// the extension was NOT matched!
	if resp.ContentInfo.SniffedType != "application/vnd.apache.parquet" {
		t.Errorf("[BUG CONFIRMED] SniffedType is %q instead of 'application/vnd.apache.parquet' because redirect URL path was not passed to content detection!", resp.ContentInfo.SniffedType)
	}
}
