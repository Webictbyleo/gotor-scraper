package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Webictbyleo/gotor-scraper"
)

type IPResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
}

func main() {
	ctx := context.Background()

	fmt.Println("=================================================================")
	fmt.Println("           Go Modular Tor + uTLS Anti-Bot Scraper                ")
	fmt.Println("=================================================================")

	// -------------------------------------------------------------------------
	// 1. Direct Scraper (No Tor, with Chrome TLS & HTTP/2 Camouflage)
	// -------------------------------------------------------------------------
	fmt.Println("\n[1] Running Direct Scrape (Tor Disabled, Chrome Fingerprint)...")

	directClient, err := torscraper.NewClient(
		torscraper.WithBrowserProfile(torscraper.ProfileChrome),
		torscraper.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to initialize direct client: %v", err)
	}
	defer directClient.Close()

	resp, err := directClient.Get(ctx, "https://api.ipify.org?format=json")
	if err != nil {
		fmt.Printf("Direct scrape request failed: %v\n", err)
	} else {
		var ipInfo IPResponse
		if err := resp.JSON(&ipInfo); err != nil {
			fmt.Printf("Response text: %s\n", resp.Text())
		} else {
			fmt.Printf("-> Direct Real IP: %s (Status: %d)\n", ipInfo.IP, resp.StatusCode)
		}
	}

	// -------------------------------------------------------------------------
	// 2. Tor Scraper with Stream Isolation (Optional per Client or Scrape)
	// -------------------------------------------------------------------------
	fmt.Println("\n[2] Setting up Tor Client (SOCKS5 127.0.0.1:9050)...")

	torClient, err := torscraper.NewClient(
		torscraper.WithTor(&torscraper.TorConfig{
			Enabled:         true,
			ProxyAddr:       torscraper.DefaultTorSOCKSAddr, // "127.0.0.1:9050"
			StreamIsolation: true,                        // Auto-assigns distinct circuits concurrently!
		}),
		torscraper.WithBrowserProfile(torscraper.ProfileChrome),
		torscraper.WithTimeout(25*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to initialize Tor client: %v", err)
	}
	defer torClient.Close()

	// Try testing through Tor (will succeed if local Tor daemon is running)
	torResp, err := torClient.Get(ctx, "https://api.ipify.org?format=json")
	if err != nil {
		fmt.Printf("-> Tor daemon not detected or unreachable on 127.0.0.1:9050 (%v).\n", err)
		fmt.Println("   (Note: To test Tor locally, run 'tor' or a Tor docker container).")
	} else {
		var torIP IPResponse
		_ = torResp.JSON(&torIP)
		fmt.Printf("-> Tor Exit Node IP: %s (Status: %d)\n", torIP.IP, torResp.StatusCode)
	}

	// -------------------------------------------------------------------------
	// 3. Per-Request Tor Toggle (Run Tor on a specific scrape only)
	// -------------------------------------------------------------------------
	fmt.Println("\n[3] Testing Per-Request Tor Toggle on Direct Client...")

	// We use the direct client, but pass ReqWithTor for a specific request:
	reqTorResp, err := directClient.Get(ctx, "https://api.ipify.org?format=json",
		torscraper.ReqWithTor(&torscraper.TorConfig{
			Enabled:   true,
			ProxyAddr: torscraper.DefaultTorSOCKSAddr,
		}),
	)
	if err != nil {
		fmt.Printf("-> Per-request Tor failed as expected if daemon is offline: %v\n", err)
	} else {
		fmt.Printf("-> Per-request Tor response status: %d\n", reqTorResp.StatusCode)
	}

	// -------------------------------------------------------------------------
	// 4. High-Concurrency Batch Worker Pool (like aiohttp asyncio.gather)
	// -------------------------------------------------------------------------
	fmt.Println("\n[4] Running High-Concurrency Worker Pool (5 workers, Rate-limited)...")

	pool := torscraper.NewWorkerPool(directClient, torscraper.PoolConfig{
		Workers:          5,
		RateLimit:        10.0, // 10 req/s max
		MaxRetries:       2,
		RetryBackoff:     500 * time.Millisecond,
		RotateTorOnRetry: true,
	})

	urlsToScrape := []string{
		"https://httpbin.org/get?item=1",
		"https://httpbin.org/get?item=2",
		"https://httpbin.org/get?item=3",
		"https://httpbin.org/get?item=4",
		"https://httpbin.org/get?item=5",
	}

	start := time.Now()
	results := pool.ScrapeBatch(ctx, urlsToScrape)
	elapsed := time.Since(start)

	fmt.Printf("-> Scraped %d targets in %v:\n", len(results), elapsed)
	for _, res := range results {
		if res.Error != nil {
			fmt.Printf("   [FAILED] %s (err: %v)\n", res.Job.URL, res.Error)
		} else {
			fmt.Printf("   [OK %d] %s (took %v, retries: %d)\n",
				res.Response.StatusCode, res.Job.URL, res.Duration, res.RetryCount)
		}
	}

	fmt.Println("\n=================================================================")
	fmt.Println("Scraper demonstration completed successfully.")
	fmt.Println("=================================================================")
}
