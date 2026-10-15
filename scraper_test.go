package torscraper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientDirectHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/get":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message": "hello scraper", "status": 200}`))
		case "/post":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test GET
	resp, err := client.Get(ctx, server.URL+"/get")
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	if !resp.IsSuccess() {
		t.Errorf("Expected success status, got %d", resp.StatusCode)
	}

	var getResult struct {
		Message string `json:"message"`
		Status  int    `json:"status"`
	}
	if err := resp.JSON(&getResult); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if getResult.Message != "hello scraper" {
		t.Errorf("Expected 'hello scraper', got '%s'", getResult.Message)
	}

	// Test PostJSON
	postData := map[string]string{"query": "golang tor scraper"}
	postResp, err := client.PostJSON(ctx, server.URL+"/post", postData)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	if postResp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201 Created, got %d", postResp.StatusCode)
	}

	var postResult map[string]string
	if err := postResp.JSON(&postResult); err != nil {
		t.Fatalf("Failed to parse POST JSON: %v", err)
	}
	if postResult["query"] != "golang tor scraper" {
		t.Errorf("Unexpected query value: %v", postResult["query"])
	}
}

func TestBrowserProfileHeaders(t *testing.T) {
	var receivedUA string
	var receivedSecChUa string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		receivedSecChUa = r.Header.Get("Sec-Ch-Ua")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client, err := NewClient(
		WithBrowserProfile(ProfileChrome),
		WithTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if !strings.Contains(receivedUA, "Chrome") {
		t.Errorf("Expected Chrome User-Agent, got: %s", receivedUA)
	}
	if !strings.Contains(receivedSecChUa, "Chromium") {
		t.Errorf("Expected Chromium in sec-ch-ua, got: %s", receivedSecChUa)
	}
}

func TestTorStreamIsolationAuth(t *testing.T) {
	auth1 := generateIsolationAuth()
	auth2 := generateIsolationAuth()

	if auth1.User == "" || !strings.HasPrefix(auth1.User, "iso_") {
		t.Errorf("Invalid isolation user: %s", auth1.User)
	}
	if auth1.User == auth2.User {
		t.Errorf("Expected unique isolation credentials, but got matching users: %s == %s", auth1.User, auth2.User)
	}
}

func TestWorkerPool(t *testing.T) {
	var attempts sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val, _ := attempts.LoadOrStore(r.URL.Path, new(int64))
		cnt := atomic.AddInt64(val.(*int64), 1)
		// First attempt fails with 500 to test retries
		if cnt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("retry me"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("response %d", cnt)))
	}))
	defer server.Close()

	client, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	pool := NewWorkerPool(client, PoolConfig{
		Workers:      3,
		MaxRetries:   2,
		RetryBackoff: 10 * time.Millisecond,
	})

	urls := []string{
		server.URL + "/1",
		server.URL + "/2",
		server.URL + "/3",
		server.URL + "/4",
	}

	results := pool.ScrapeBatch(context.Background(), urls)
	if len(results) != len(urls) {
		t.Fatalf("Expected %d results, got %d", len(urls), len(results))
	}

	for _, res := range results {
		if res.Error != nil {
			t.Errorf("Job %s failed: %v", res.Job.URL, res.Error)
		}
		if res.Response == nil || !res.Response.IsSuccess() {
			t.Errorf("Job %s did not succeed: %v", res.Job.URL, res.Response)
		}
	}
}

func TestRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/origin":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("reached target"))
		case "/loop1":
			http.Redirect(w, r, "/loop2", http.StatusFound)
		case "/loop2":
			http.Redirect(w, r, "/loop1", http.StatusFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// 1. Default: follow redirects
	client, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, server.URL+"/origin")
	if err != nil {
		t.Fatalf("Failed to follow redirect: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK after redirect, got: %d", resp.StatusCode)
	}
	if resp.Text() != "reached target" {
		t.Errorf("Expected 'reached target', got: %s", resp.Text())
	}
	if !strings.HasSuffix(resp.FinalURL(), "/target") {
		t.Errorf("Expected final URL to end in /target, got: %s", resp.FinalURL())
	}

	// 2. Disabled redirects globally
	noRedirectClient, err := NewClient(WithBrowserProfile(ProfileNone), WithFollowRedirects(false))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer noRedirectClient.Close()

	noRedirResp, err := noRedirectClient.Get(ctx, server.URL+"/origin")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !noRedirResp.IsRedirect() {
		t.Errorf("Expected redirect response, got: %d", noRedirResp.StatusCode)
	}
	if noRedirResp.RedirectURL() != "/target" {
		t.Errorf("Expected Location '/target', got: %s", noRedirResp.RedirectURL())
	}

	// 3. Per-request override: disable redirects on a client that has them enabled
	perReqResp, err := client.Get(ctx, server.URL+"/origin", ReqWithFollowRedirects(false))
	if err != nil {
		t.Fatalf("Per-request override failed: %v", err)
	}
	if !perReqResp.IsRedirect() {
		t.Errorf("Expected per-request redirect not followed, got: %d", perReqResp.StatusCode)
	}

	// 4. Max redirects limit
	maxClient, err := NewClient(WithBrowserProfile(ProfileNone), WithMaxRedirects(3))
	if err != nil {
		t.Fatalf("Failed to create max client: %v", err)
	}
	defer maxClient.Close()

	_, err = maxClient.Get(ctx, server.URL+"/loop1")
	if err == nil {
		t.Error("Expected error due to max redirects exceeded, but got nil")
	} else if !strings.Contains(err.Error(), "stopped after 3 redirects") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestClientRetries(t *testing.T) {
	var attempts int64
	var postAttempts int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/retry-get":
			cnt := atomic.AddInt64(&attempts, 1)
			if cnt <= 2 {
				http.Error(w, "server busy", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success on attempt 3"))
		case "/retry-post":
			cnt := atomic.AddInt64(&postAttempts, 1)
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if cnt == 1 {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("posted: " + payload["data"]))
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// 1. Client with retries enabled
	client, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithRetries(3, 10*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, server.URL+"/retry-get")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK after retries, got: %d", resp.StatusCode)
	}
	if resp.Text() != "success on attempt 3" {
		t.Errorf("Unexpected body: %s", resp.Text())
	}

	// 2. Test POST payload rewinding across retry
	postResp, err := client.PostJSON(ctx, server.URL+"/retry-post", map[string]string{"data": "test payload"})
	if err != nil {
		t.Fatalf("Post request failed: %v", err)
	}
	if postResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK after retry, got: %d", postResp.StatusCode)
	}
	if postResp.Text() != "posted: test payload" {
		t.Errorf("Unexpected post body: %s", postResp.Text())
	}

	// 3. Test per-request retry override
	noRetryClient, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create no-retry client: %v", err)
	}
	defer noRetryClient.Close()

	// Without override, should return 503
	atomic.StoreInt64(&attempts, 0)
	failResp, err := noRetryClient.Get(ctx, server.URL+"/retry-get")
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}
	if failResp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 without retries, got: %d", failResp.StatusCode)
	}

	// With per-request override, should retry and succeed
	atomic.StoreInt64(&attempts, 0)
	overrideResp, err := noRetryClient.Get(ctx, server.URL+"/retry-get", ReqWithRetries(3))
	if err != nil {
		t.Fatalf("Override request failed: %v", err)
	}
	if overrideResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 with per-request retries, got: %d", overrideResp.StatusCode)
	}
}
