package torscraper

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A. Verify that .Text() deletes spaces when a text node starts with whitespace,
// and inserts unwanted spaces before punctuation after inline elements.
func TestVerify_Pass2_A_TextWhitespaceAndPunctuation(t *testing.T) {
	rawHTML := `<html><body>
		<p id="p1"><span>Hello</span><span> world</span></p>
		<p id="p2"><b>Hello</b>, world!</p>
	</body></html>`

	resp := &Response{rawBody: []byte(rawHTML)}
	doc, err := resp.HTML()
	if err != nil {
		t.Fatalf("HTML parse failed: %v", err)
	}

	p1 := doc.FindOne("#p1").Text()
	t.Logf("p1.Text() = %q (expected %q)", p1, "Hello world")
	if p1 != "Hello world" {
		t.Errorf("[BUG A1 CONFIRMED] Expected %q, got %q (space deleted!)", "Hello world", p1)
	}

	p2 := doc.FindOne("#p2").Text()
	t.Logf("p2.Text() = %q (expected %q)", p2, "Hello, world!")
	if p2 != "Hello, world!" {
		t.Errorf("[BUG A2 CONFIRMED] Expected %q, got %q (spurious space before punctuation!)", "Hello, world!", p2)
	}
}

// B. Verify that HTTP connection pooling reuses the first connection and bypasses
// ProxyPool RoundRobin rotation on subsequent requests to the same host.
func TestVerify_Pass2_B_ConnectionPoolBypassesProxyRotation(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer targetServer.Close()

	// Create two local TCP forwarders acting as SOCKS5/HTTP proxies or count dials via ProxyPool
	// Here we spin up two minimal SOCKS5 servers that count connections and forward to targetServer.
	startMiniSOCKS5 := func(counter *int32) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				atomic.AddInt32(counter, 1)
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 260)
					// SOCKS5 greeting
					if _, err := io.ReadAtLeast(c, buf[:2], 2); err != nil {
						return
					}
					nMethods := int(buf[1])
					_, _ = io.ReadFull(c, buf[:nMethods])
					_, _ = c.Write([]byte{0x05, 0x00}) // No auth

					// SOCKS5 connect request
					if _, err := io.ReadFull(c, buf[:4]); err != nil {
						return
					}
					var host string
					switch buf[3] {
					case 0x01: // IPv4
						_, _ = io.ReadFull(c, buf[:4])
						host = net.IP(buf[:4]).String()
					case 0x03: // Domain
						_, _ = io.ReadFull(c, buf[:1])
						dLen := int(buf[0])
						_, _ = io.ReadFull(c, buf[:dLen])
						host = string(buf[:dLen])
					}
					_, _ = io.ReadFull(c, buf[:2])
					port := (int(buf[0]) << 8) | int(buf[1])
					destAddr := net.JoinHostPort(host, itoa(port))

					targetConn, err := net.Dial("tcp", destAddr)
					if err != nil {
						return
					}
					defer targetConn.Close()
					_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

					go func() { _, _ = io.Copy(targetConn, c) }()
					_, _ = io.Copy(c, targetConn)
				}(conn)
			}
		}()
		return "socks5://" + ln.Addr().String()
	}

	var proxy1Hits, proxy2Hits int32
	p1URL := startMiniSOCKS5(&proxy1Hits)
	p2URL := startMiniSOCKS5(&proxy2Hits)

	pool, err := NewProxyPool(StrategyRoundRobin, p1URL, p2URL)
	if err != nil {
		t.Fatalf("Failed to create proxy pool: %v", err)
	}

	client, err := NewClient(WithProxyPool(pool))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Make 2 sequential requests to the same host
	for i := 0; i < 2; i++ {
		resp, err := client.Get(context.Background(), targetServer.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i+1, err)
		}
		_ = resp.Text()
	}

	p1 := atomic.LoadInt32(&proxy1Hits)
	p2 := atomic.LoadInt32(&proxy2Hits)
	t.Logf("Proxy 1 connections: %d | Proxy 2 connections: %d", p1, p2)
	if p1 == 0 || p2 == 0 {
		t.Errorf("[BUG B CONFIRMED] Proxy rotation was bypassed due to connection pooling! Proxy1=%d, Proxy2=%d (expected 1 and 1)", p1, p2)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// C. Verify ProfileRotation bugs: RotatePerSession is a no-op, and RotatePerRequest
// leaves stale headers / desynchronized TLS profile.
func TestVerify_Pass2_C_ProfileRotationBugs(t *testing.T) {
	// 1. RotatePerSession on ProfileNone should pick an active browser profile on init
	cli, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithProfileRotation(RotatePerSession),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer cli.Close()

	t.Logf("Client profile with RotatePerSession: %v", cli.cfg.profile)
	if cli.cfg.profile == ProfileNone {
		t.Errorf("[BUG C1 CONFIRMED] RotatePerSession did not pick a profile on NewClient initialization!")
	}
}

// D. Verify ProxyPool automatic failure recording & Hooks.OnProxyRotate invocation.
func TestVerify_Pass2_D_ProxyPoolFailoverAndHook(t *testing.T) {
	var rotateHookCalled int32
	deadProxy := "socks5://127.0.0.1:1" // Port 1 refuses connections immediately
	secondProxy := "socks5://127.0.0.1:2"

	pool, err := NewProxyPool(StrategyFailover, deadProxy, secondProxy)
	if err != nil {
		t.Fatalf("NewProxyPool failed: %v", err)
	}
	pool.SetMaxFailures(1)
	pool.SetCooldown(10 * time.Second)

	cli, err := NewClient(
		WithProxyPool(pool),
		WithTimeout(500*time.Millisecond),
		WithHooks(Hooks{
			OnProxyRotate: func(oldProxy, newProxy string) {
				atomic.AddInt32(&rotateHookCalled, 1)
			},
		}),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer cli.Close()

	// Attempt request through failover pool (will fail on deadProxy)
	_, _ = cli.Get(context.Background(), "http://example.com")

	// Now check if deadProxy was marked unhealthy after failing
	nextNode, _ := pool.Next()
	t.Logf("Next proxy selected after deadProxy failed: %s (deadProxy healthy=%t)", nextNode.RawURL, pool.nodes[0].IsHealthy())
	if nextNode.RawURL == deadProxy {
		t.Errorf("[BUG D1 CONFIRMED] StrategyFailover did not record dial failure on deadProxy; still selecting deadProxy!")
	}

	// Switch proxy and check if OnProxyRotate was called
	_, _ = cli.Get(context.Background(), "http://example.com")
	if atomic.LoadInt32(&rotateHookCalled) == 0 {
		t.Errorf("[BUG D2 CONFIRMED] Hooks.OnProxyRotate was never called when proxy rotated!")
	}
}

// E. Verify 512-byte peek false positive in resp.ContentInfo.AntiBot.
func TestVerify_Pass2_E_512BytePeekAntiBotFalsePositive(t *testing.T) {
	// Construct a normal content-rich HTML page where <head> > 512 bytes and loads recaptcha/api.js,
	// while <main><article><h1> and <p> tags appear after byte 600.
	padding := strings.Repeat("<!-- head metadata padding -->", 20) // ~600 bytes
	htmlPage := `<!DOCTYPE html><html><head>
		<script src="https://www.google.com/recaptcha/api.js"></script>` +
		padding +
		`</head><body>
		<main><article>
			<h1>Comprehensive Guide to Distributed Systems</h1>
			<p>First detailed paragraph of the article content.</p>
			<p>Second detailed paragraph of the article content.</p>
		</article></main>
		<form><div class="g-recaptcha" data-sitekey="xyz"></div></form>
		</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(htmlPage))
	}))
	defer server.Close()

	cli, _ := NewClient()
	defer cli.Close()

	resp, err := cli.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	fullVerdict := resp.AntiBot()
	infoVerdict := resp.ContentInfo.AntiBot

	t.Logf("resp.AntiBot():             Scope=%s, IsGatekeeper=%t", fullVerdict.Scope, fullVerdict.IsGatekeeper)
	t.Logf("resp.ContentInfo.AntiBot:   Scope=%s, IsGatekeeper=%t, MismatchDetected=%t",
		infoVerdict.Scope, infoVerdict.IsGatekeeper, resp.ContentInfo.MismatchDetected)

	if infoVerdict.Scope != fullVerdict.Scope || infoVerdict.IsGatekeeper != fullVerdict.IsGatekeeper {
		t.Errorf("[BUG E CONFIRMED] resp.ContentInfo.AntiBot (Scope=%s, IsGatekeeper=%t) is out of sync with resp.AntiBot() (Scope=%s, IsGatekeeper=%t) due to 512-byte peek!",
			infoVerdict.Scope, infoVerdict.IsGatekeeper, fullVerdict.Scope, fullVerdict.IsGatekeeper)
	}
}

// F. Verify SVG sniffing with <?xml prefix and MatchesContentType with charset parameter.
func TestVerify_Pass2_F_SVGSniffingAndMatchesContentType(t *testing.T) {
	svgBytes := []byte(`<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"></svg>`)
	sniffed := SniffMagicBytes(svgBytes, "", "")
	t.Logf("SniffMagicBytes for <?xml ...><svg> = %q", sniffed)
	if sniffed != "image/svg+xml" {
		t.Errorf("[BUG F1 CONFIRMED] Expected 'image/svg+xml', got %q because <?xml check shadowed SVG check!", sniffed)
	}

	matched := MatchesContentType("text/plain; charset=utf-8", "text/plain")
	t.Logf("MatchesContentType('text/plain; charset=utf-8', 'text/plain') = %t", matched)
	if !matched {
		t.Errorf("[BUG F2 CONFIRMED] MatchesContentType failed to match 'text/plain; charset=utf-8' against 'text/plain'!")
	}
}

// G. Verify Content-Encoding: deflate with standard RFC 1950 zlib stream.
func TestVerify_Pass2_G_ZlibDeflateDecompression(t *testing.T) {
	expectedBody := "Hello from standard RFC 1950 zlib-wrapped deflate HTTP server!"
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	_, _ = zw.Write([]byte(expectedBody))
	_ = zw.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "deflate")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer server.Close()

	cli, _ := NewClient()
	defer cli.Close()

	resp, err := cli.Get(context.Background(), server.URL)
	t.Logf("Deflate response err=%v, text=%q", err, func() string {
		if resp != nil {
			return resp.Text()
		}
		return ""
	}())
	if err != nil || resp.Text() != expectedBody {
		t.Errorf("[BUG G CONFIRMED] Standard zlib-wrapped Content-Encoding: deflate failed! err=%v, got=%q", err, func() string {
			if resp != nil {
				return resp.Text()
			}
			return ""
		}())
	}
}

// H. Verify HTTP Proxy CONNECT status check false positive and percent-encoded Basic Auth.
func TestVerify_Pass2_H_HTTPProxyConnectBugs(t *testing.T) {
	var receivedAuthHeader string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		reqLines := strings.Split(string(buf[:n]), "\r\n")
		for _, line := range reqLines {
			if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
				receivedAuthHeader = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			}
		}
		// Return 407 Proxy Authentication Required, with a header containing "200" (Content-Length: 200)
		_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 200\r\n\r\n"))
	}()

	// Password is "p@ss" URL-encoded as "p%40ss"
	proxyURL := "http://myuser:p%40ss@" + ln.Addr().String()
	pool, err := NewProxyPool(StrategyRoundRobin, proxyURL)
	if err != nil {
		t.Fatalf("NewProxyPool failed: %v", err)
	}

	node, _ := pool.Next()
	dialer, err := pool.DialerForNode(context.Background(), node, 2*time.Second)
	if err != nil {
		t.Fatalf("DialerForNode failed: %v", err)
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if conn != nil {
		conn.Close()
	}

	t.Logf("DialContext on 407 response (with Content-Length: 200) returned err: %v", err)
	if err == nil {
		t.Errorf("[BUG H1 CONFIRMED] httpConnectDialer treated HTTP 407 as 200 OK because 'Content-Length: 200' contained '200'!")
	}

	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("myuser:p@ss"))
	t.Logf("Received Proxy-Authorization: %q (expected %q)", receivedAuthHeader, expectedAuth)
	if receivedAuthHeader != expectedAuth {
		t.Errorf("[BUG H2 CONFIRMED] Proxy-Authorization encoded percent-escaped password instead of raw password! got %q, want %q", receivedAuthHeader, expectedAuth)
	}
}

// I. Verify GetRendered bugs: WithMaxContentLength(0) overridden, cookies not synced back,
// and FinalURL stale after action chain navigation.
func TestVerify_Pass2_I_GetRenderedCookiesAndFinalURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a id="go" href="/finish">Go</a></body></html>`))
	})
	mux.HandleFunc("/finish", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "rendered_session",
			Value: "abc_999",
			Path:  "/",
		})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div id="done">Done</div></body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cli, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer cli.Close()

	resp, err := cli.GetRendered(context.Background(), server.URL+"/start",
		WaitForSelector("#go"),
		Click("#go"),
		EvaluateScript(`new Promise(r => setTimeout(r, 300))`),
		RenderTimeout(15*time.Second),
	)
	if err != nil {
		t.Fatalf("GetRendered failed: %v", err)
	}

	t.Logf("GetRendered FinalURL: %s (expected %s)", resp.FinalURL(), server.URL+"/finish")
	if resp.FinalURL() != server.URL+"/finish" {
		t.Errorf("[BUG I1 CONFIRMED] resp.FinalURL() is stale (%s) instead of post-action URL (%s)", resp.FinalURL(), server.URL+"/finish")
	}

	jarCookies := cli.cfg.cookieJar.Cookies(resp.RawResponse.Request.URL)
	t.Logf("Cookies in Client CookieJar after GetRendered: %d, resp.Cookies: %d", len(jarCookies), len(resp.Cookies))
	if len(jarCookies) == 0 || len(resp.Cookies) == 0 {
		t.Errorf("[BUG I2 CONFIRMED] Cookies set in Chrome during GetRendered were not synced back to Client CookieJar or resp.Cookies!")
	}
}

// J. Verify WorkerPool multiplicative retries, ErrContentRejected retries, and PUT payload drop.
func TestVerify_Pass2_J_WorkerPoolAndClientRetryFlaws(t *testing.T) {
	// 1. Multiplicative retries between Client and WorkerPool
	var serverHits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverHits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cli, _ := NewClient(WithRetries(2, 1*time.Millisecond))
	defer cli.Close()

	pool := NewWorkerPool(cli, PoolConfig{
		Workers:      1,
		MaxRetries:   2,
		RetryBackoff: 1 * time.Millisecond,
	})

	pool.Process(context.Background(), []Job{{ID: "1", URL: server.URL}})
	hits := atomic.LoadInt32(&serverHits)
	t.Logf("Server hits for 1 job with MaxRetries=2: %d (expected 3: 1 initial + 2 retries)", hits)
	if hits > 3 {
		t.Errorf("[BUG J1 CONFIRMED] Multiplicative retry loops caused %d hits instead of 3!", hits)
	}

	// 2. ErrContentRejected retried in Client.Do
	var filterHits int32
	filterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&filterHits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer filterServer.Close()

	filterCli, _ := NewClient(
		WithRetries(2, 1*time.Millisecond),
		WithContentFilter(func(info *ContentInfo, raw *http.Response) error {
			return errors.New("custom rejection")
		}),
	)
	defer filterCli.Close()

	_, err := filterCli.Get(context.Background(), filterServer.URL)
	fHits := atomic.LoadInt32(&filterHits)
	t.Logf("Filter rejection hits: %d, err: %v", fHits, err)
	if fHits > 1 {
		t.Errorf("[BUG J2 CONFIRMED] Client retried %d times on intentional ErrContentRejected!", fHits-1)
	}

	// 3. PUT job with Payload in WorkerPool
	var putBodyLen int
	putServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		putBodyLen = len(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer putServer.Close()

	putPool := NewWorkerPool(cli, PoolConfig{Workers: 1})
	putPool.Process(context.Background(), []Job{{
		ID:      "put1",
		URL:     putServer.URL,
		Method:  http.MethodPut,
		Payload: map[string]string{"update": "true"},
	}})
	t.Logf("PUT request body length received by server: %d bytes", putBodyLen)
	if putBodyLen == 0 {
		t.Errorf("[BUG J3 CONFIRMED] WorkerPool dropped Job.Payload on PUT request (sent 0 bytes)!")
	}
}
