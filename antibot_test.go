package torscraper

import (
	"net/http"
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
