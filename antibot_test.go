package torscraper

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAntiBotDetection(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		headers       map[string]string
		body          string
		wantDetected  bool
		wantProvider  BotProvider
		wantType      ChallengeType
		wantHint      ActionHint
		checkIncident string
	}{
		{
			name:       "Cloudflare cf-mitigated header",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"cf-mitigated": "challenge",
				"cf-ray":       "89abcdef01234567-LHR",
				"Server":       "cloudflare",
			},
			body:          "<html><body>Cloudflare Challenge</body></html>",
			wantDetected:  true,
			wantProvider:  BotProviderCloudflare,
			wantType:      ChallengeJSChallenge,
			wantHint:      ActionHintUseHeadless,
			checkIncident: "89abcdef01234567",
		},
		{
			name:       "Cloudflare Turnstile HTTP 200 Interstitial",
			statusCode: http.StatusOK,
			headers: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
				"Server":       "cloudflare",
			},
			body:         "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div class=\"cf-turnstile\" data-sitekey=\"0x4AAAAAA\"></div></body></html>",
			wantDetected: true,
			wantProvider: BotProviderCloudflare,
			wantType:     ChallengeInteractive,
			wantHint:     ActionHintSolveCaptcha,
		},
		{
			name:       "Cloudflare Error 1020 Ray ID Access Denied",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"cf-ray": "7711223344556677-AMS",
				"Server": "cloudflare",
			},
			body:          "<!DOCTYPE html><html><body><h1>Error 1020</h1><p>Access denied. Ray ID: 7711223344556677</p></body></html>",
			wantDetected:  true,
			wantProvider:  BotProviderCloudflare,
			wantType:      ChallengeAccessDenied,
			wantHint:      ActionHintRotateProxy,
			checkIncident: "7711223344556677",
		},
		{
			name:       "DataDome Header and Cookie block",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"X-DataDome": "protected",
				"Set-Cookie": "datadome=abc123xyz; Path=/; Domain=.example.com; Secure",
			},
			body:         "<html><body>Forbidden</body></html>",
			wantDetected: true,
			wantProvider: BotProviderDataDome,
			wantType:     ChallengeInteractive,
			wantHint:     ActionHintRotateProfile,
		},
		{
			name:       "DataDome API 403 JSON Response",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:         `{"url": "https://geo.captcha-delivery.com/captcha/?initialCid=AHrlqAAAAAMA..."}`,
			wantDetected: true,
			wantProvider: BotProviderDataDome,
			wantType:     ChallengeInteractive,
			wantHint:     ActionHintRotateProxy,
		},
		{
			name:       "Akamai Ghost WAF Reference # Access Denied",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"Server": "AkamaiGHost",
			},
			body:          "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>You don't have permission to access on this server.<p>Reference #18.82390a5c.1680000000.123456</p></body></html>",
			wantDetected:  true,
			wantProvider:  BotProviderAkamai,
			wantType:      ChallengeAccessDenied,
			wantHint:      ActionHintRotateProxy,
			checkIncident: "18.82390a5c.1680000000.123456",
		},
		{
			name:       "PerimeterX / HUMAN Security DOM Challenge",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"Content-Type": "text/html",
			},
			body:         "<html><head><script>window._pxAppId='PX123456';window._pxJsClientSrc='//client.perimeterx.net/PX123456/main.min.js';</script></head><body><div id=\"px-captcha\"></div></body></html>",
			wantDetected: true,
			wantProvider: BotProviderPerimeterX,
			wantType:     ChallengeInteractive,
			wantHint:     ActionHintSolveCaptcha,
		},
		{
			name:       "PerimeterX Advanced Blocking Response (ABR) JSON",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:          `{"appId":"PXabcdef","blockScript":"//client.perimeterx.net/PXabcdef/main.min.js","uuid":"11223344-5566-7788-99aa-bbccddeeff00"}`,
			wantDetected:  true,
			wantProvider:  BotProviderPerimeterX,
			wantType:      ChallengeInteractive,
			wantHint:      ActionHintRotateProxy,
			checkIncident: "11223344-5566-7788-99aa-bbccddeeff00",
		},
		{
			name:       "Imperva / Incapsula Incident HTTP 200 Block",
			statusCode: http.StatusOK, // Classic Imperva edge case: returns 200 OK!
			headers: map[string]string{
				"X-Iinfo": "12-345678-0",
				"X-CDN":   "Incapsula",
			},
			body:          "<iframe id=\"main-iframe\" src=\"/_Incapsula_Resource?incident_id=12345-67890\">Request unsuccessful. Incapsula incident ID: 12345-67890</iframe>",
			wantDetected:  true,
			wantProvider:  BotProviderImperva,
			wantType:      ChallengeAccessDenied,
			wantHint:      ActionHintRotateProxy,
			checkIncident: "12345-67890",
		},
		{
			name:       "Kasada Bytecode VM PoW Challenge",
			statusCode: http.StatusTooManyRequests,
			headers: map[string]string{
				"X-Kpsdk-Ct": "token_abc123",
				"X-Kpsdk-R":  "block",
			},
			body:         "<html><head><script src=\"/149e9513-01/ips.js\"></script></head><body></body></html>",
			wantDetected: true,
			wantProvider: BotProviderKasada,
			wantType:     ChallengeJSChallenge,
			wantHint:     ActionHintUseHeadless,
		},
		{
			name:       "AWS WAF Captcha HTTP 405 Method Not Allowed",
			statusCode: http.StatusMethodNotAllowed, // AWS WAF RFC signature: 405 for captcha
			headers: map[string]string{
				"X-Amzn-Waf-Action": "captcha",
			},
			body:         "<html><body><script src=\"aws-waf-captcha.js\"></script></body></html>",
			wantDetected: true,
			wantProvider: BotProviderAWSWAF,
			wantType:     ChallengeInteractive,
			wantHint:     ActionHintSolveCaptcha,
		},
		{
			name:       "AWS WAF Background Challenge HTTP 202 Accepted",
			statusCode: http.StatusAccepted, // AWS WAF RFC signature: 202 for challenge
			headers: map[string]string{
				"X-Amzn-Waf-Action": "challenge",
			},
			body:         "<html><body>Running browser challenge</body></html>",
			wantDetected: true,
			wantProvider: BotProviderAWSWAF,
			wantType:     ChallengeJSChallenge,
			wantHint:     ActionHintUseHeadless,
		},
		{
			name:       "F5 BIG-IP ASM URL Rejected with Support ID",
			statusCode: http.StatusOK,
			headers: map[string]string{
				"Set-Cookie": "TS01abcdef=123456",
			},
			body:          "<html><body>The requested URL was rejected. Please consult with your administrator.<p>Your support ID is: 1234567890123456789</p></body></html>",
			wantDetected:  true,
			wantProvider:  BotProviderF5Shape,
			wantType:      ChallengeAccessDenied,
			wantHint:      ActionHintRotateProxy,
			checkIncident: "1234567890123456789",
		},
		{
			name:       "Google reCAPTCHA Challenge Wall",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"Content-Type": "text/html",
			},
			body:         "<html><head><title>Security Check</title></head><body><div class=\"g-recaptcha\" data-sitekey=\"xyz\"></div></body></html>",
			wantDetected: true,
			wantProvider: BotProviderReCaptcha,
			wantType:     ChallengeInteractive,
			wantHint:     ActionHintSolveCaptcha,
		},
		{
			name:       "hCaptcha Challenge Wall",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				"Content-Type": "text/html",
			},
			body:         "<html><head><title>Verify you are human</title></head><body><div class=\"h-captcha\" data-sitekey=\"abc\"></div></body></html>",
			wantDetected: true,
			wantProvider: BotProviderHCaptcha,
			wantType:     ChallengeInteractive,
			wantHint:     ActionHintSolveCaptcha,
		},
		{
			name:       "HTTP 429 Volumetric Rate Limit with Retry-After",
			statusCode: http.StatusTooManyRequests,
			headers: map[string]string{
				"Retry-After": "120",
			},
			body:         "Too Many Requests",
			wantDetected: true,
			wantProvider: BotProviderGeneric,
			wantType:     ChallengeRateLimit,
			wantHint:     ActionHintSleepBackoff,
		},
		// =====================================================================
		// ANTI-FALSE-POSITIVE TEST CASE:
		// A blog article discussing Cloudflare and reCAPTCHA must NOT be flagged!
		// =====================================================================
		{
			name:       "False-Positive Guard: Tech blog post discussing Cloudflare & Captchas",
			statusCode: http.StatusOK,
			headers: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
				"Server":       "nginx",
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Tutorial: Understanding Cloudflare Turnstile and Google reCAPTCHA</title></head>
<body>
    <article>
        <h1>How Bot Defenses Work</h1>
        <p>In this post we explain how Cloudflare, DataDome, and reCAPTCHA detect bot traffic on modern web servers.</p>
        <p>You can learn more about captcha verification on our engineering blog.</p>
    </article>
</body>
</html>`,
			wantDetected: false,
			wantProvider: BotProviderNone,
			wantType:     ChallengeNone,
			wantHint:     ActionHintNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawHeader := make(http.Header)
			for k, v := range tt.headers {
				rawHeader.Set(k, v)
			}

			rawResp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     rawHeader,
			}

			result := DetectAntiBot(rawResp, []byte(tt.body))

			if result.Detected != tt.wantDetected {
				t.Errorf("Detected = %v, want %v (Reason: %s)", result.Detected, tt.wantDetected, result.Reason)
			}
			if result.Provider != tt.wantProvider {
				t.Errorf("Provider = %v, want %v", result.Provider, tt.wantProvider)
			}
			if result.ChallengeType != tt.wantType {
				t.Errorf("ChallengeType = %v, want %v", result.ChallengeType, tt.wantType)
			}
			if result.ActionHint != tt.wantHint {
				t.Errorf("ActionHint = %v, want %v", result.ActionHint, tt.wantHint)
			}
			if tt.checkIncident != "" && result.IncidentID != tt.checkIncident {
				t.Errorf("IncidentID = %q, want %q", result.IncidentID, tt.checkIncident)
			}
		})
	}
}

func TestAbortOnAntiBot(t *testing.T) {
	// Create mock server returning Cloudflare 1020 block
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "1234567890abcdef-LHR")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><head><title>Access Denied</title></head><body>error 1020 access denied</body></html>"))
	}))
	defer ts.Close()

	// 1. Test client with WithAbortOnAntiBot(true)
	var antiBotHookCalled bool
	var detectedProvider BotProvider

	client, err := NewClient(
		WithAbortOnAntiBot(true),
		WithHooks(Hooks{
			OnAntiBot: func(req *http.Request, resp *Response, detection *AntiBotDetection) {
				antiBotHookCalled = true
				detectedProvider = detection.Provider
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx := t.Context()
	resp, reqErr := client.Get(ctx, ts.URL)

	if reqErr == nil {
		t.Fatal("Expected error when WithAbortOnAntiBot is true, got nil")
	}

	if !errors.Is(reqErr, ErrAntiBotBlocked) {
		t.Fatalf("Expected errors.Is(reqErr, ErrAntiBotBlocked), got: %v", reqErr)
	}

	var blockedErr *BlockedError
	if !errors.As(reqErr, &blockedErr) {
		t.Fatalf("Expected errors.As(reqErr, &blockedErr), got: %T", reqErr)
	}

	if blockedErr.Detection.Provider != BotProviderCloudflare {
		t.Errorf("Expected blocked error provider cloudflare, got: %v", blockedErr.Detection.Provider)
	}

	if !antiBotHookCalled {
		t.Error("Expected OnAntiBot hook to be called")
	}

	if detectedProvider != BotProviderCloudflare {
		t.Errorf("Expected OnAntiBot hook provider cloudflare, got: %v", detectedProvider)
	}

	if resp == nil {
		t.Fatal("Expected response object to be returned alongside error for caller inspection")
	}

	// 2. Test request-level override: ReqWithAbortOnAntiBot(false) allows normal return
	resp2, err2 := client.Get(ctx, ts.URL, ReqWithAbortOnAntiBot(false))
	if err2 != nil {
		t.Fatalf("Expected nil error when ReqWithAbortOnAntiBot(false) overrides client, got: %v", err2)
	}
	if !resp2.IsBlocked() {
		t.Errorf("Expected resp2.IsBlocked() to be true")
	}
}

func TestEmbeddableWidgetEdgeCases(t *testing.T) {
	// =========================================================================
	// Edge Case A: Embedded Widget on Normal Content Page
	// (Article content with an inline Turnstile / reCAPTCHA widget protecting a comment form)
	// => ScopeInlineWidget, IsGatekeeper=false, IsBlocked()=false.
	// WithAbortOnAntiBot MUST NOT abort so product/article content is read successfully!
	// =========================================================================
	pageWithInlineWidget := `<!DOCTYPE html>
<html>
<head>
    <title>10 Best Practices for Go Scrapers - Webict Blog</title>
</head>
<body>
    <article>
        <h1>10 Best Practices for Building High Performance Scrapers</h1>
        <p>Web scraping requires careful consideration of rate limits, fingerprinting, and content detection.</p>
        <p>In this comprehensive guide, we cover connection reuse, uTLS Camouflage, and headless browser rendering.</p>
        <section>
            <h2>Leave a Comment</h2>
            <form action="/submit-comment" method="POST">
                <textarea name="comment" placeholder="Write your thoughts..."></textarea>
                <!-- Embedded Turnstile widget protecting comment submission -->
                <div class="cf-turnstile" data-sitekey="0x4AAAAAA"></div>
                <button type="submit">Submit Comment</button>
            </form>
        </section>
    </article>
</body>
</html>`

	tsInline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(pageWithInlineWidget))
	}))
	defer tsInline.Close()

	// =========================================================================
	// Edge Case B: Standalone Widget-Only Page
	// (HTTP 200 OK, but the widget is the SOLE thing on the page; acting as an interstitial)
	// => ScopeFullPageWall, IsGatekeeper=true, IsBlocked()=true.
	// WithAbortOnAntiBot MUST abort to prevent empty junk from polluting crawler pipeline!
	// =========================================================================
	standaloneWidgetPage := `<!DOCTYPE html>
<html>
<head>
    <title>Just a moment...</title>
</head>
<body>
    <div class="cf-turnstile" data-sitekey="0x4AAAAAA"></div>
</body>
</html>`

	tsStandalone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(standaloneWidgetPage))
	}))
	defer tsStandalone.Close()

	client, err := NewClient(
		WithAbortOnAntiBot(true),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx := t.Context()

	// 1. Verify Edge Case A: Inline Widget does NOT abort, content is fully accessible
	respInline, errInline := client.Get(ctx, tsInline.URL)
	if errInline != nil {
		t.Fatalf("[Edge Case A FAILED] Scraper aborted on inline form widget: %v", errInline)
	}
	if respInline.IsBlocked() {
		t.Errorf("[Edge Case A FAILED] resp.IsBlocked() should be false for inline widget, got true")
	}
	abInline := respInline.AntiBot()
	if abInline.Scope != ScopeInlineWidget {
		t.Errorf("Expected ScopeInlineWidget, got: %v", abInline.Scope)
	}
	if abInline.IsGatekeeper {
		t.Errorf("Expected IsGatekeeper=false for inline widget on content page")
	}
	doc, err := respInline.HTML()
	if err != nil || doc.Title() != "10 Best Practices for Go Scrapers - Webict Blog" {
		t.Errorf("Failed to read article content on page with inline widget: title=%q", doc.Title())
	}

	// 2. Verify Edge Case B: Standalone Widget-Only Page aborts cleanly with ErrAntiBotBlocked
	respStandalone, errStandalone := client.Get(ctx, tsStandalone.URL)
	if errStandalone == nil {
		t.Fatalf("[Edge Case B FAILED] Expected error for standalone widget gatekeeper, got nil")
	}
	if !errors.Is(errStandalone, ErrAntiBotBlocked) {
		t.Fatalf("Expected ErrAntiBotBlocked, got: %v", errStandalone)
	}
	if !respStandalone.IsBlocked() {
		t.Errorf("[Edge Case B FAILED] resp.IsBlocked() should be true for standalone gatekeeper widget")
	}
	abStandalone := respStandalone.AntiBot()
	if abStandalone.Scope != ScopeFullPageWall {
		t.Errorf("Expected ScopeFullPageWall, got: %v", abStandalone.Scope)
	}
	if !abStandalone.IsGatekeeper {
		t.Errorf("Expected IsGatekeeper=true for standalone widget gatekeeper")
	}
}
