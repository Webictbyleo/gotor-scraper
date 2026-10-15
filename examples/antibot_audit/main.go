package main

import (
	"context"
	"fmt"
	"os"
	"time"

	torscraper "github.com/Webictbyleo/gotor-scraper"
)

type Target struct {
	Name            string
	URL             string
	ExpectedVendors string
	Description     string
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("       gotor-scraper: Multi-Vendor Anti-Bot Detection Audit       ")
	fmt.Println("=================================================================")

	// Curated list of validated live targets actively serving anti-bot interstitials or challenges:
	targets := []Target{
		{
			Name:            "Cloudflare Testbed",
			URL:             "https://nowsecure.nl",
			ExpectedVendors: "Cloudflare (Turnstile / Challenge)",
			Description:     "Dedicated Cloudflare challenge benchmark testbed",
		},
		{
			Name:            "Antoine Vastel (Cloudflare 1010 Edge Block)",
			URL:             "https://antoinevastel.com/bots/datadome",
			ExpectedVendors: "Cloudflare (WAF Error 1010)",
			Description:     "Protected by Cloudflare Edge Firewall (Error 1010)",
		},
		{
			Name:            "DataDome Live Target",
			URL:             "https://www.leboncoin.fr",
			ExpectedVendors: "DataDome",
			Description:     "Live French portal protected by DataDome Shield",
		},
		{
			Name:            "Akamai Ghost WAF Site",
			URL:             "https://www.homedepot.com",
			ExpectedVendors: "Akamai",
			Description:     "Strict Akamai Ghost WAF Access Denied with Reference ID",
		},
		{
			Name:            "PerimeterX / HUMAN Security",
			URL:             "https://www.zillow.com",
			ExpectedVendors: "PerimeterX / HUMAN Security",
			Description:     "Live real estate portal protected by HUMAN Security (px-captcha)",
		},
		{
			Name:            "Google reCAPTCHA Standalone Demo Page",
			URL:             "https://www.google.com/recaptcha/api2/demo",
			ExpectedVendors: "reCAPTCHA (Scope: full_page_wall)",
			Description:     "Standalone Google verification demo page (widget is the only content on page)",
		},
		{
			Name:            "hCaptcha Standalone Demo Page",
			URL:             "https://accounts.hcaptcha.com/demo",
			ExpectedVendors: "hCaptcha (Scope: full_page_wall)",
			Description:     "Standalone hCaptcha verification demo page (widget is the only content on page)",
		},
		{
			Name:            "Incolumitas Bot Analyzer (Clean Reference)",
			URL:             "https://bot.incolumitas.com",
			ExpectedVendors: "None (Clean Page)",
			Description:     "Bot analyzer testbed serving clean content (false-positive test)",
		},
	}

	// Initialize scraper client with Chrome profile and realistic timeout
	client, err := torscraper.NewClient(
		torscraper.WithBrowserProfile(torscraper.ProfileChrome),
		torscraper.WithTimeout(20*time.Second),
	)
	if err != nil {
		fmt.Printf("[-] Failed to create client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	ctx := context.Background()

	// Execute live audit on each target
	for i, t := range targets {
		fmt.Printf("\n[%d/%d] Target: %s\n", i+1, len(targets), t.Name)
		fmt.Printf("      URL:             %s\n", t.URL)
		fmt.Printf("      Expected:        %s\n", t.ExpectedVendors)
		fmt.Printf("      Description:     %s\n", t.Description)

		start := time.Now()
		resp, err := client.Get(ctx, t.URL)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("      [!] Request Error: %v\n", err)
			continue
		}

		// Inspect Anti-Bot detection
		ab := resp.AntiBot()
		blocked := resp.IsBlocked()

		fmt.Printf("      HTTP Status:     %d (%s in %v)\n", resp.StatusCode, resp.Status, duration.Truncate(time.Millisecond))
		fmt.Printf("      Is Blocked:      %t\n", blocked)
		fmt.Printf("      Detected Vendor: %s\n", ab.Provider)
		fmt.Printf("      Challenge Type:  %s\n", ab.ChallengeType)
		fmt.Printf("      Scope:           %s\n", ab.Scope)
		fmt.Printf("      Is Gatekeeper:   %t\n", ab.IsGatekeeper)
		fmt.Printf("      Action Hint:     %s\n", ab.ActionHint)
		if ab.IncidentID != "" {
			fmt.Printf("      Incident/Ref ID: %s\n", ab.IncidentID)
		}
		if ab.Reason != "" {
			fmt.Printf("      Reason:          %s\n", ab.Reason)
		}
		if len(ab.MatchedSignatures) > 0 {
			fmt.Printf("      Signatures:      %v\n", ab.MatchedSignatures)
		}

		if ab.Provider != torscraper.BotProviderNone {
			fmt.Printf("      => [CONFIRMED] Anti-Bot Provider '%s' detected! (Confidence: %.0f%%)\n", ab.Provider, ab.Confidence*100)
		} else {
			fmt.Printf("      => [CLEAN] Clean page served without bot mitigation wall.\n")
		}

		// Throttle slightly between requests
		time.Sleep(1 * time.Second)
	}

	fmt.Println("\n=================================================================")
	fmt.Println("             Anti-Bot Live Verification Completed!               ")
	fmt.Println("=================================================================")
}
