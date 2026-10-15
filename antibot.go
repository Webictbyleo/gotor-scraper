package torscraper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ErrAntiBotBlocked is returned when an anti-bot or WAF challenge/block is detected
// and fail-fast abort is enabled (WithBlockOnAntiBot / WithAbortOnAntiBot).
var ErrAntiBotBlocked = errors.New("request blocked by anti-bot defense system")

// BlockedError is a detailed typed error that wraps ErrAntiBotBlocked with full detection telemetry.
type BlockedError struct {
	Detection *AntiBotDetection
}

func (e *BlockedError) Error() string {
	if e == nil || e.Detection == nil {
		return ErrAntiBotBlocked.Error()
	}
	ref := ""
	if e.Detection.IncidentID != "" {
		ref = fmt.Sprintf(" [Incident/Ref: %s]", e.Detection.IncidentID)
	}
	return fmt.Sprintf("%s: provider=%s, type=%s, hint=%s%s (%s)",
		ErrAntiBotBlocked.Error(),
		e.Detection.Provider,
		e.Detection.ChallengeType,
		e.Detection.ActionHint,
		ref,
		e.Detection.Reason,
	)
}

func (e *BlockedError) Unwrap() error {
	return ErrAntiBotBlocked
}

// BotProvider identifies the Web Application Firewall (WAF) or anti-bot defense vendor.
type BotProvider string

const (
	// BotProviderNone indicates no anti-bot protection was detected.
	BotProviderNone BotProvider = "none"

	// BotProviderCloudflare indicates Cloudflare WAF, Turnstile, or Under Attack Mode.
	BotProviderCloudflare BotProvider = "cloudflare"

	// BotProviderDataDome indicates DataDome device and behavioral protection.
	BotProviderDataDome BotProvider = "datadome"

	// BotProviderAkamai indicates Akamai Bot Manager, EdgeProtect, or Ghost WAF.
	BotProviderAkamai BotProvider = "akamai"

	// BotProviderPerimeterX indicates HUMAN Security (formerly PerimeterX).
	BotProviderPerimeterX BotProvider = "perimeterx"

	// BotProviderImperva indicates Imperva / Incapsula WAF.
	BotProviderImperva BotProvider = "imperva"

	// BotProviderKasada indicates Kasada PoW and virtual machine telemetry defenses.
	BotProviderKasada BotProvider = "kasada"

	// BotProviderAWSWAF indicates AWS WAF Bot Control and Captcha.
	BotProviderAWSWAF BotProvider = "aws_waf"

	// BotProviderF5Shape indicates F5 BIG-IP Application Security Manager or Shape Security.
	BotProviderF5Shape BotProvider = "f5_shape"

	// BotProviderFastlySigSci indicates Fastly or Signal Sciences WAF.
	BotProviderFastlySigSci BotProvider = "fastly_sigsci"

	// BotProviderReCaptcha indicates standalone Google reCAPTCHA v2/v3/Enterprise.
	BotProviderReCaptcha BotProvider = "recaptcha"

	// BotProviderHCaptcha indicates standalone hCaptcha.
	BotProviderHCaptcha BotProvider = "hcaptcha"

	// BotProviderGeetest indicates GeeTest interactive slider or puzzle.
	BotProviderGeetest BotProvider = "geetest"

	// BotProviderArkoseLabs indicates Arkose Labs (FunCaptcha).
	BotProviderArkoseLabs BotProvider = "arkose_labs"

	// BotProviderGeneric indicates generic rate limits (HTTP 429) or unknown anti-bot challenge walls.
	BotProviderGeneric BotProvider = "generic"
)

// ChallengeType categorizes the nature of the challenge or restriction.
type ChallengeType string

const (
	// ChallengeNone indicates normal unhindered content.
	ChallengeNone ChallengeType = "none"

	// ChallengeJSChallenge indicates a client-side JavaScript challenge (e.g. Cloudflare 5s shield, Kasada PoW).
	// A headless browser with JavaScript execution may solve this automatically.
	ChallengeJSChallenge ChallengeType = "js_challenge"

	// ChallengeInteractive indicates an interactive user puzzle, CAPTCHA, or slider.
	// Cannot be passed without solving or token injection.
	ChallengeInteractive ChallengeType = "interactive"

	// ChallengeAccessDenied indicates a hard IP or firewall block (e.g. Cloudflare 1020, Akamai Access Denied).
	// Traffic is dropped regardless of JavaScript or headers.
	ChallengeAccessDenied ChallengeType = "access_denied"

	// ChallengeRateLimit indicates volumetric rate-limiting (e.g. HTTP 429, Cloudflare 1015).
	ChallengeRateLimit ChallengeType = "rate_limit"

	// ChallengeDeviceCheck indicates deep device or browser telemetry profiling.
	ChallengeDeviceCheck ChallengeType = "device_check"
)

// ActionHint provides automated guidance on the most effective resolution strategy.
type ActionHint string

const (
	// ActionHintNone indicates no corrective action is necessary.
	ActionHintNone ActionHint = "none"

	// ActionHintRotateProxy advises immediately switching proxy node or Tor circuit (IP is burned).
	ActionHintRotateProxy ActionHint = "rotate_proxy"

	// ActionHintRotateProfile advises changing TLS ClientHello and browser headers (fingerprint flagged).
	ActionHintRotateProfile ActionHint = "rotate_profile"

	// ActionHintSleepBackoff advises pausing execution and retrying with exponential backoff.
	ActionHintSleepBackoff ActionHint = "sleep_backoff"

	// ActionHintUseHeadless advises using headless Chrome CDP (GetRendered) to evaluate dynamic challenge scripts.
	ActionHintUseHeadless ActionHint = "use_headless"

	// ActionHintSolveCaptcha advises interactive solving or routing through an external captcha solver.
	ActionHintSolveCaptcha ActionHint = "solve_captcha"
)

// ProtectionScope distinguishes between a full-page access barrier and an inline embeddable widget.
type ProtectionScope string

const (
	// ScopeNone indicates no anti-bot or widget was detected.
	ScopeNone ProtectionScope = "none"

	// ScopeFullPageWall indicates the anti-bot challenge is an unavoidable barrier blocking
	// access to the target page content (e.g. 403 Access Denied, 503 Challenge, or an HTTP 200
	// page where the widget is the sole element on the screen).
	ScopeFullPageWall ProtectionScope = "full_page_wall"

	// ScopeInlineWidget indicates an embeddable widget (e.g. Turnstile, reCAPTCHA, hCaptcha,
	// AWS WAF widget) protecting a specific form/button on an otherwise healthy, fully-rendered page.
	// Normal content (articles, products) is accessible and was NOT blocked.
	ScopeInlineWidget ProtectionScope = "inline_widget"
)

// AntiBotDetection contains the parsed verdict and telemetry of an anti-bot inspection.
type AntiBotDetection struct {
	// Detected is true if any anti-bot or WAF challenge/block was confirmed.
	Detected bool `json:"detected"`

	// Provider identifies the defense system (Cloudflare, DataDome, Akamai, etc.).
	Provider BotProvider `json:"provider"`

	// ChallengeType indicates whether the block is a JS challenge, interactive captcha, or IP ban.
	ChallengeType ChallengeType `json:"challenge_type"`

	// Scope indicates whether this is a full-page gatekeeper or an inline form widget.
	Scope ProtectionScope `json:"scope"`

	// IsGatekeeper is true if the defense actively blocks access to the page content.
	// When false (e.g. ScopeInlineWidget on a normal article page), page content is readable.
	IsGatekeeper bool `json:"is_gatekeeper"`

	// Confidence is a score between 0.0 (uncertain) and 1.0 (authoritative header/signature match).
	Confidence float64 `json:"confidence"`

	// Reason is a human-readable explanation of why this verdict was issued.
	Reason string `json:"reason"`

	// IncidentID is the unique reference ID provided by the firewall (RayID, Reference #, Incident ID).
	IncidentID string `json:"incident_id,omitempty"`

	// ActionHint advises the caller on the recommended recovery action.
	ActionHint ActionHint `json:"action_hint"`

	// MatchedSignatures lists the specific headers, tokens, or DOM elements that triggered detection.
	MatchedSignatures []string `json:"matched_signatures"`
}

// Regex patterns for extracting incident reference IDs
var (
	reCloudflareRayID   = regexp.MustCompile(`(?i)Ray ID:\s*([a-f0-9]+)`)
	reAkamaiReference   = regexp.MustCompile(`(?i)Reference(?:\s*|&#32;)(?:#|&#35;)([0-9a-zA-Z.&#;]+)`)
	reIncapsulaIncident = regexp.MustCompile(`(?i)Incapsula incident ID:\s*([0-9a-zA-Z\-_]+)`)
	reF5SupportID       = regexp.MustCompile(`(?i)support ID is:\s*([0-9]+)`)
)

// DetectAntiBot evaluates an HTTP response (headers, status code, and body) to identify
// active bot defenses, WAF blocks, and interactive CAPTCHAs with multi-factor correlation.
func DetectAntiBot(raw *http.Response, body []byte) *AntiBotDetection {
	res := detectAntiBotInner(raw, body)
	if res != nil && res.Detected {
		if res.Scope == "" {
			res.Scope = ScopeFullPageWall
			res.IsGatekeeper = true
		}
	}
	return res
}

func detectAntiBotInner(raw *http.Response, body []byte) *AntiBotDetection {
	if raw == nil {
		return &AntiBotDetection{
			Detected:      false,
			Provider:      BotProviderNone,
			ChallengeType: ChallengeNone,
			ActionHint:    ActionHintNone,
		}
	}

	headers := raw.Header
	statusCode := raw.StatusCode
	bodyLower := bytes.ToLower(body)
	server := strings.ToLower(headers.Get("Server"))

	// =========================================================================
	// 1. CLOUDFLARE
	// =========================================================================
	// 1a. Proprietary Challenge Header: cf-mitigated: challenge (Authoritative 100% confidence)
	if strings.EqualFold(headers.Get("cf-mitigated"), "challenge") {
		incidentID := extractRayID(headers, body)
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderCloudflare,
			ChallengeType:     ChallengeJSChallenge,
			Confidence:        1.0,
			Reason:            "Cloudflare cf-mitigated: challenge header present",
			IncidentID:        incidentID,
			ActionHint:        ActionHintUseHeadless,
			MatchedSignatures: []string{"header:cf-mitigated=challenge"},
		}
	}

	// 1b. Cloudflare Title & Turnstile in HTML Body
	if bytes.Contains(bodyLower, []byte("<title>just a moment...</title>")) ||
		bytes.Contains(bodyLower, []byte("challenges.cloudflare.com/turnstile")) ||
		bytes.Contains(bodyLower, []byte("class=\"cf-turnstile\"")) ||
		bytes.Contains(bodyLower, []byte("id=\"cf-challenge-running\"")) ||
		bytes.Contains(bodyLower, []byte("window._cf_chl_opt")) {

		chType := ChallengeJSChallenge
		hint := ActionHintUseHeadless
		if bytes.Contains(bodyLower, []byte("cf-turnstile")) || bytes.Contains(bodyLower, []byte("turnstile")) {
			chType = ChallengeInteractive
			hint = ActionHintSolveCaptcha
		}

		scope, isGatekeeper := classifyWidgetScope(statusCode, body)
		reason := "Cloudflare Turnstile or JavaScript verification challenge DOM detected"
		if scope == ScopeInlineWidget {
			reason = "Cloudflare Turnstile embedded form widget detected on content page (page content accessible)"
		}

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderCloudflare,
			ChallengeType:     chType,
			Scope:             scope,
			IsGatekeeper:      isGatekeeper,
			Confidence:        0.99,
			Reason:            reason,
			IncidentID:        extractRayID(headers, body),
			ActionHint:        hint,
			MatchedSignatures: []string{"dom:cloudflare_challenge_marker"},
		}
	}

	// 1c. Cloudflare Error 1020 / 1015 / WAF Block
	if (statusCode == http.StatusForbidden || statusCode == http.StatusServiceUnavailable || statusCode == http.StatusTooManyRequests) &&
		(strings.Contains(server, "cloudflare") || headers.Get("CF-RAY") != "") {

		if bytes.Contains(bodyLower, []byte("error 1020")) || bytes.Contains(bodyLower, []byte("error code: 1010")) ||
			bytes.Contains(bodyLower, []byte("error 1010")) || bytes.Contains(bodyLower, []byte("error 1006")) ||
			bytes.Contains(bodyLower, []byte("error 1007")) || bytes.Contains(bodyLower, []byte("error 1008")) ||
			bytes.Contains(bodyLower, []byte("access denied")) {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderCloudflare,
				ChallengeType:     ChallengeAccessDenied,
				Confidence:        0.98,
				Reason:            "Cloudflare WAF Access Denied: Firewall security rule or IP reputation block",
				IncidentID:        extractRayID(headers, body),
				ActionHint:        ActionHintRotateProxy,
				MatchedSignatures: []string{"body:cloudflare_waf_block", "header:cf-ray"},
			}
		}
		if bytes.Contains(bodyLower, []byte("error 1015")) || statusCode == http.StatusTooManyRequests {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderCloudflare,
				ChallengeType:     ChallengeRateLimit,
				Confidence:        0.95,
				Reason:            "Cloudflare Error 1015: Rate limit exceeded",
				IncidentID:        extractRayID(headers, body),
				ActionHint:        ActionHintSleepBackoff,
				MatchedSignatures: []string{"body:error_1015_rate_limit", "header:cf-ray"},
			}
		}
		// General Cloudflare 403 block with CF-RAY
		if statusCode == http.StatusForbidden {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderCloudflare,
				ChallengeType:     ChallengeAccessDenied,
				Confidence:        0.95,
				Reason:            "Cloudflare WAF 403 Forbidden edge block",
				IncidentID:        extractRayID(headers, body),
				ActionHint:        ActionHintRotateProxy,
				MatchedSignatures: []string{"status:403", "header:cf-ray"},
			}
		}
	}

	// =========================================================================
	// 2. DATADOME
	// =========================================================================
	// 2a. DataDome Headers & Cookies
	hasDDHeader := headers.Get("X-DataDome") != "" || headers.Get("X-DataDome-Response") != "" || headers.Get("X-DataDome-Request-Id") != ""
	hasDDCookie := false
	for _, cookieStr := range headers.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(cookieStr), "datadome=") {
			hasDDCookie = true
			break
		}
	}

	if hasDDHeader || (hasDDCookie && statusCode == http.StatusForbidden) {
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderDataDome,
			ChallengeType:     ChallengeInteractive,
			Confidence:        1.0,
			Reason:            "DataDome security protection header or cookie detected on blocked response",
			ActionHint:        ActionHintRotateProfile,
			MatchedSignatures: []string{"header:x-datadome", "cookie:datadome"},
		}
	}

	// 2b. DataDome Body & JSON API Blocks
	if bytes.Contains(bodyLower, []byte("geo.captcha-delivery.com/captcha/")) ||
		bytes.Contains(bodyLower, []byte("ct.captcha-delivery.com")) ||
		bytes.Contains(bodyLower, []byte("please enable js and disable any ad blocker")) {

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderDataDome,
			ChallengeType:     ChallengeInteractive,
			Confidence:        0.98,
			Reason:            "DataDome captcha-delivery interstitial or device check detected",
			ActionHint:        ActionHintRotateProxy,
			MatchedSignatures: []string{"body:captcha-delivery.com"},
		}
	}

	// 2c. DataDome JSON Payload: {"url": "https://geo.captcha-delivery.com/..."}
	if statusCode == http.StatusForbidden && bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		var ddPayload struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(body, &ddPayload); err == nil && strings.Contains(ddPayload.URL, "captcha-delivery.com") {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderDataDome,
				ChallengeType:     ChallengeInteractive,
				Confidence:        1.0,
				Reason:            "DataDome API 403 JSON challenge URL detected",
				ActionHint:        ActionHintRotateProxy,
				MatchedSignatures: []string{"json:captcha-delivery.com"},
			}
		}
	}

	// =========================================================================
	// 3. AKAMAI BOT MANAGER & GHOST WAF
	// =========================================================================
	// 3a. Akamai Headers
	if headers.Get("X-Akamai-Transformed") != "" || headers.Get("Akamai-Bot-Decision") != "" {
		if statusCode == http.StatusForbidden {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderAkamai,
				ChallengeType:     ChallengeAccessDenied,
				Confidence:        0.95,
				Reason:            "Akamai Bot Manager edge block decision",
				ActionHint:        ActionHintRotateProxy,
				MatchedSignatures: []string{"header:akamai-bot-decision"},
			}
		}
	}

	// 3b. Akamai Reference # Access Denied Page
	if statusCode == http.StatusForbidden &&
		(bytes.Contains(bodyLower, []byte("access denied")) || strings.Contains(server, "akamaighost") || headers.Get("Akamai-GRN") != "") {

		refID := ""
		if matches := reAkamaiReference.FindSubmatch(body); len(matches) > 1 {
			refID = string(matches[1])
			refID = strings.ReplaceAll(refID, "&#46;", ".")
			refID = strings.ReplaceAll(refID, "&#35;", "")
			refID = strings.ReplaceAll(refID, "&#32;", " ")
		} else if grn := headers.Get("Akamai-GRN"); grn != "" {
			refID = grn
		}

		matchedSigs := []string{"status:403"}
		if strings.Contains(server, "akamaighost") {
			matchedSigs = append(matchedSigs, "header:server=akamaighost")
		}
		if refID != "" {
			matchedSigs = append(matchedSigs, "body:akamai_reference_denied")
		}

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderAkamai,
			ChallengeType:     ChallengeAccessDenied,
			Confidence:        0.98,
			Reason:            "Akamai Ghost WAF Access Denied with Reference ID",
			IncidentID:        refID,
			ActionHint:        ActionHintRotateProxy,
			MatchedSignatures: matchedSigs,
		}
	}

	// =========================================================================
	// 4. PERIMETERX / HUMAN SECURITY
	// =========================================================================
	// 4a. PerimeterX Headers & Cookies
	hasPXHeader := false
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-px-") {
			hasPXHeader = true
			break
		}
	}
	if hasPXHeader && statusCode == http.StatusForbidden {
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderPerimeterX,
			ChallengeType:     ChallengeInteractive,
			Confidence:        0.98,
			Reason:            "PerimeterX / HUMAN Security WAF response header",
			ActionHint:        ActionHintRotateProfile,
			MatchedSignatures: []string{"header:x-px"},
		}
	}

	// 4b. PerimeterX Advanced Blocking Response (ABR) JSON (inspected first for structured API 403s)
	if statusCode == http.StatusForbidden && bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		var pxJSON struct {
			AppID       string `json:"appId"`
			BlockScript string `json:"blockScript"`
			UUID        string `json:"uuid"`
		}
		if err := json.Unmarshal(body, &pxJSON); err == nil && pxJSON.AppID != "" && pxJSON.BlockScript != "" {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderPerimeterX,
				ChallengeType:     ChallengeInteractive,
				Confidence:        1.0,
				Reason:            "PerimeterX Advanced Blocking Response (ABR) JSON payload",
				IncidentID:        pxJSON.UUID,
				ActionHint:        ActionHintRotateProxy,
				MatchedSignatures: []string{"json:perimeterx_abr"},
			}
		}
	}

	// 4c. PerimeterX DOM Elements & Configuration
	if bytes.Contains(bodyLower, []byte("id=\"px-captcha\"")) ||
		bytes.Contains(bodyLower, []byte("window._pxappid")) ||
		bytes.Contains(bodyLower, []byte("client.perimeterx.net")) ||
		bytes.Contains(bodyLower, []byte("px-cdn.net")) ||
		bytes.Contains(bodyLower, []byte("press and hold")) && bytes.Contains(bodyLower, []byte("perimeterx")) {

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderPerimeterX,
			ChallengeType:     ChallengeInteractive,
			Confidence:        0.99,
			Reason:            "PerimeterX / HUMAN Security Human Challenge DOM mounted",
			ActionHint:        ActionHintSolveCaptcha,
			MatchedSignatures: []string{"dom:px-captcha"},
		}
	}

	// =========================================================================
	// 5. IMPERVA / INCAPSULA
	// =========================================================================
	// 5a. Imperva Headers
	if headers.Get("X-Iinfo") != "" || strings.EqualFold(headers.Get("X-CDN"), "Incapsula") {
		// Note: Imperva often returns HTTP 200 with an incident iframe!
		if statusCode == http.StatusForbidden || bytes.Contains(bodyLower, []byte("incapsula incident id")) || bytes.Contains(bodyLower, []byte("/_incapsula_resource")) {
			incidentID := ""
			if m := reIncapsulaIncident.FindSubmatch(body); len(m) > 1 {
				incidentID = string(m[1])
			}
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderImperva,
				ChallengeType:     ChallengeAccessDenied,
				Confidence:        0.99,
				Reason:            "Imperva / Incapsula WAF block or challenge resource",
				IncidentID:        incidentID,
				ActionHint:        ActionHintRotateProxy,
				MatchedSignatures: []string{"header:x-iinfo", "body:incapsula_incident"},
			}
		}
	}

	// 5b. Imperva Resource Body Signature (even on HTTP 200)
	if bytes.Contains(bodyLower, []byte("request unsuccessful. incapsula incident id:")) ||
		bytes.Contains(bodyLower, []byte("/_incapsula_resource?")) {

		incidentID := ""
		if m := reIncapsulaIncident.FindSubmatch(body); len(m) > 1 {
			incidentID = string(m[1])
		}
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderImperva,
			ChallengeType:     ChallengeAccessDenied,
			Confidence:        1.0,
			Reason:            "Imperva Incapsula Incident block page",
			IncidentID:        incidentID,
			ActionHint:        ActionHintRotateProxy,
			MatchedSignatures: []string{"body:incapsula_incident"},
		}
	}

	// =========================================================================
	// 6. KASADA
	// =========================================================================
	// 6a. Kasada Response Headers
	if headers.Get("X-Kpsdk-Ct") != "" || headers.Get("X-Kpsdk-Cd") != "" || headers.Get("X-Kpsdk-R") != "" {
		if statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderKasada,
				ChallengeType:     ChallengeJSChallenge,
				Confidence:        1.0,
				Reason:            "Kasada Proof-of-Work challenge header",
				ActionHint:        ActionHintUseHeadless,
				MatchedSignatures: []string{"header:x-kpsdk"},
			}
		}
	}

	// 6b. Kasada Bytecode VM Script (ips.js)
	if (statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests) &&
		(bytes.Contains(bodyLower, []byte("/ips.js")) || bytes.Contains(bodyLower, []byte("k-script"))) {

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderKasada,
			ChallengeType:     ChallengeJSChallenge,
			Confidence:        0.96,
			Reason:            "Kasada client-side bytecode VM challenge script detected",
			ActionHint:        ActionHintUseHeadless,
			MatchedSignatures: []string{"dom:kasada_ips_js"},
		}
	}

	// =========================================================================
	// 7. AWS WAF
	// =========================================================================
	// 7a. AWS WAF Action Header: x-amzn-waf-action: captcha (status 405) or challenge (status 202)
	wafAction := strings.ToLower(headers.Get("X-Amzn-Waf-Action"))
	if wafAction == "captcha" || statusCode == http.StatusMethodNotAllowed && wafAction != "" {
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderAWSWAF,
			ChallengeType:     ChallengeInteractive,
			Confidence:        1.0,
			Reason:            "AWS WAF Bot Control x-amzn-waf-action: captcha required",
			ActionHint:        ActionHintSolveCaptcha,
			MatchedSignatures: []string{"header:x-amzn-waf-action=captcha"},
		}
	}
	if wafAction == "challenge" || statusCode == http.StatusAccepted && wafAction != "" {
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderAWSWAF,
			ChallengeType:     ChallengeJSChallenge,
			Confidence:        1.0,
			Reason:            "AWS WAF background browser challenge required",
			ActionHint:        ActionHintUseHeadless,
			MatchedSignatures: []string{"header:x-amzn-waf-action=challenge"},
		}
	}

	// 7b. AWS WAF Captcha Script in DOM
	if bytes.Contains(bodyLower, []byte("aws-waf-captcha.js")) || bytes.Contains(bodyLower, []byte("awswafcaptcha.rendercaptcha")) {
		scope, isGatekeeper := classifyWidgetScope(statusCode, body)
		reason := "AWS WAF Captcha component embedded in DOM"
		if scope == ScopeInlineWidget {
			reason = "AWS WAF Captcha embedded form widget detected on content page (page content accessible)"
		}

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderAWSWAF,
			ChallengeType:     ChallengeInteractive,
			Scope:             scope,
			IsGatekeeper:      isGatekeeper,
			Confidence:        0.98,
			Reason:            reason,
			ActionHint:        ActionHintSolveCaptcha,
			MatchedSignatures: []string{"dom:aws-waf-captcha"},
		}
	}

	// =========================================================================
	// 8. F5 BIG-IP ASM / SHAPE SECURITY
	// =========================================================================
	if bytes.Contains(bodyLower, []byte("the requested url was rejected. please consult with your administrator.")) {
		supportID := ""
		if m := reF5SupportID.FindSubmatch(body); len(m) > 1 {
			supportID = string(m[1])
		}
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderF5Shape,
			ChallengeType:     ChallengeAccessDenied,
			Confidence:        0.99,
			Reason:            "F5 BIG-IP Application Security Manager (ASM) policy violation",
			IncidentID:        supportID,
			ActionHint:        ActionHintRotateProxy,
			MatchedSignatures: []string{"body:f5_asm_rejected"},
		}
	}

	// =========================================================================
	// 9. STANDALONE THIRD-PARTY CAPTCHA PROVIDERS
	// =========================================================================
	// 9a. Google reCAPTCHA
	if bytes.Contains(bodyLower, []byte("google.com/recaptcha/api.js")) ||
		bytes.Contains(bodyLower, []byte("class=\"g-recaptcha\"")) ||
		bytes.Contains(bodyLower, []byte("g-recaptcha-response")) {

		scope, isGatekeeper := classifyWidgetScope(statusCode, body)
		reason := "Google reCAPTCHA verification wall detected"
		if scope == ScopeInlineWidget {
			reason = "Google reCAPTCHA embedded form widget detected on content page (page content accessible)"
		}

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderReCaptcha,
			ChallengeType:     ChallengeInteractive,
			Scope:             scope,
			IsGatekeeper:      isGatekeeper,
			Confidence:        0.92,
			Reason:            reason,
			ActionHint:        ActionHintSolveCaptcha,
			MatchedSignatures: []string{"dom:g-recaptcha"},
		}
	}

	// 9b. hCaptcha
	if bytes.Contains(bodyLower, []byte("hcaptcha.com/1/api.js")) ||
		bytes.Contains(bodyLower, []byte("class=\"h-captcha\"")) ||
		bytes.Contains(bodyLower, []byte("h-captcha-response")) {

		scope, isGatekeeper := classifyWidgetScope(statusCode, body)
		reason := "hCaptcha verification wall detected"
		if scope == ScopeInlineWidget {
			reason = "hCaptcha embedded form widget detected on content page (page content accessible)"
		}

		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderHCaptcha,
			ChallengeType:     ChallengeInteractive,
			Scope:             scope,
			IsGatekeeper:      isGatekeeper,
			Confidence:        0.92,
			Reason:            reason,
			ActionHint:        ActionHintSolveCaptcha,
			MatchedSignatures: []string{"dom:h-captcha"},
		}
	}

	// 9c. GeeTest
	if bytes.Contains(bodyLower, []byte("geetest.com")) || bytes.Contains(bodyLower, []byte("gt.js")) {
		if isChallengeContext(statusCode, bodyLower) {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderGeetest,
				ChallengeType:     ChallengeInteractive,
				Confidence:        0.90,
				Reason:            "GeeTest interactive slider challenge detected",
				ActionHint:        ActionHintSolveCaptcha,
				MatchedSignatures: []string{"dom:geetest"},
			}
		}
	}

	// 9d. Arkose Labs (FunCaptcha)
	if bytes.Contains(bodyLower, []byte("arkoselabs.com")) || bytes.Contains(bodyLower, []byte("funcaptcha")) {
		if isChallengeContext(statusCode, bodyLower) {
			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderArkoseLabs,
				ChallengeType:     ChallengeInteractive,
				Confidence:        0.90,
				Reason:            "Arkose Labs (FunCaptcha) puzzle challenge detected",
				ActionHint:        ActionHintSolveCaptcha,
				MatchedSignatures: []string{"dom:arkose_funcaptcha"},
			}
		}
	}

	// =========================================================================
	// 10. GENERIC RATE LIMITS & SECURITY CHECK WALLS
	// =========================================================================
	// 10a. HTTP 429 Too Many Requests
	if statusCode == http.StatusTooManyRequests {
		retryAfter := headers.Get("Retry-After")
		reason := "HTTP 429 Too Many Requests"
		if retryAfter != "" {
			reason += " (Retry-After: " + retryAfter + "s)"
		}
		return &AntiBotDetection{
			Detected:          true,
			Provider:          BotProviderGeneric,
			ChallengeType:     ChallengeRateLimit,
			Confidence:        1.0,
			Reason:            reason,
			ActionHint:        ActionHintSleepBackoff,
			MatchedSignatures: []string{"status:429"},
		}
	}

	// 10b. Generic Block Page Titles (Pardon Our Interruption, Access Denied, etc.)
	if statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized || statusCode == http.StatusServiceUnavailable {
		if bytes.Contains(bodyLower, []byte("<title>pardon our interruption")) ||
			bytes.Contains(bodyLower, []byte("automated access to this page was denied")) ||
			bytes.Contains(bodyLower, []byte("please verify you are a human")) ||
			bytes.Contains(bodyLower, []byte("<title>security check</title>")) {

			return &AntiBotDetection{
				Detected:          true,
				Provider:          BotProviderGeneric,
				ChallengeType:     ChallengeAccessDenied,
				Confidence:        0.85,
				Reason:            "Generic bot mitigation or interruption notice detected",
				ActionHint:        ActionHintRotateProxy,
				MatchedSignatures: []string{"body:generic_interruption_page"},
			}
		}
	}

	// Clean content, no bot defense detected
	return &AntiBotDetection{
		Detected:      false,
		Provider:      BotProviderNone,
		ChallengeType: ChallengeNone,
		Confidence:    0.0,
		Reason:        "No bot mitigation detected",
		ActionHint:    ActionHintNone,
	}
}

// classifyWidgetScope inspects an embeddable widget detection on a page and determines
// whether the widget is acting as a full-page access barrier (blocking page access)
// or merely protecting an individual element/form on a normal, fully readable page.
func classifyWidgetScope(statusCode int, body []byte) (ProtectionScope, bool) {
	// 1. If HTTP status code is a blocking/challenge status, it is always a full-page gatekeeper.
	if statusCode == http.StatusForbidden || statusCode == http.StatusMethodNotAllowed ||
		statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable {
		return ScopeFullPageWall, true
	}

	bodyLower := bytes.ToLower(body)

	// 2. Explicit challenge/verification page titles indicate the entire page is a gatekeeper.
	challengeTitleMarkers := [][]byte{
		[]byte("<title>security check"),
		[]byte("<title>verify you are human"),
		[]byte("<title>are you a robot"),
		[]byte("<title>bot detection"),
		[]byte("<title>captcha"),
		[]byte("<title>just a moment"),
		[]byte("<title>pardon our interruption"),
		[]byte("<title>attention required!"),
		[]byte("<title>access to this page has been denied"),
	}
	for _, tm := range challengeTitleMarkers {
		if bytes.Contains(bodyLower, tm) {
			return ScopeFullPageWall, true
		}
	}

	// 3. Cloudflare challenge-specific runtime script variables indicate a managed challenge page.
	if bytes.Contains(bodyLower, []byte("window._cf_chl_opt")) ||
		bytes.Contains(bodyLower, []byte("id=\"cf-challenge-running\"")) {
		return ScopeFullPageWall, true
	}

	// 4. Standalone Widget Page Detection (Edge Case: Widget is the ONLY content on the page).
	// If the page body is sparse (e.g. < 2.5KB) and lacks substantial editorial/product content
	// (no <article>, <main>, <h1>, <h2>, or substantial paragraphs outside the captcha),
	// it is a standalone gatekeeper challenge.
	if isStandaloneWidgetPage(bodyLower) {
		return ScopeFullPageWall, true
	}

	// 5. Otherwise, the page has rich content (articles, products, navigation) and the widget
	// is embedded inline protecting a specific form or button.
	return ScopeInlineWidget, false
}

// isStandaloneWidgetPage checks if the HTML body contains little to no readable text
// and exists solely to mount an anti-bot challenge widget.
func isStandaloneWidgetPage(bodyLower []byte) bool {
	// Check if the page contains rich content tags (article, main, headings, multiple paragraphs).
	hasSubstantialContent := bytes.Contains(bodyLower, []byte("<article")) ||
		bytes.Contains(bodyLower, []byte("<main")) ||
		bytes.Contains(bodyLower, []byte("<section")) ||
		bytes.Count(bodyLower, []byte("<p>")) >= 2 ||
		bytes.Count(bodyLower, []byte("<p ")) >= 2 ||
		bytes.Contains(bodyLower, []byte("<h1")) ||
		bytes.Contains(bodyLower, []byte("<h2"))

	if hasSubstantialContent {
		return false
	}

	// If it lacks substantial content and contains a widget, it is a standalone gatekeeper.
	return true
}

// isChallengeContext determines if an embedded captcha is acting as a wall/blocker
// rather than an innocuous form element on a normal page (preventing false positives).
func isChallengeContext(statusCode int, bodyLower []byte) bool {
	scope, isGatekeeper := classifyWidgetScope(statusCode, bodyLower)
	return scope == ScopeFullPageWall && isGatekeeper
}

// extractRayID searches headers and body text for Cloudflare Ray IDs.
func extractRayID(headers http.Header, body []byte) string {
	if ray := headers.Get("CF-RAY"); ray != "" {
		return strings.Split(ray, "-")[0]
	}
	if matches := reCloudflareRayID.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

// AntiBot inspects the response and returns the full AntiBotDetection verdict.
func (r *Response) AntiBot() *AntiBotDetection {
	if r == nil {
		return &AntiBotDetection{Detected: false, Provider: BotProviderNone}
	}
	return DetectAntiBot(r.RawResponse, r.rawBody)
}

// IsBlocked returns true if the response was flagged by an active WAF or anti-bot gatekeeper
// that prevented access to the requested page content.
//
// NOTE: If an embeddable widget (Turnstile, reCAPTCHA, etc.) is detected protecting only
// an individual form on an otherwise normal, content-rich page (ScopeInlineWidget),
// IsBlocked returns FALSE so scrapers can read article, product, or catalog text freely.
func (r *Response) IsBlocked() bool {
	if r == nil {
		return false
	}
	ab := r.AntiBot()
	if !ab.Detected {
		return false
	}
	// If scope was explicitly classified, respect IsGatekeeper
	if ab.Scope == ScopeInlineWidget {
		return false
	}
	return true
}
