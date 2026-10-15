package torscraper

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestClientUTLSLive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live internet test in short mode")
	}

	client, err := NewClient(
		WithBrowserProfile(ProfileChrome),
		WithTimeout(15*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		t.Logf("Live request to tls.peet.ws failed (possibly network restricted): %v", err)
		return
	}

	if !resp.IsSuccess() {
		t.Errorf("Expected 200 OK, got: %d", resp.StatusCode)
	}

	text := resp.Text()
	if !strings.Contains(text, "tls") && !strings.Contains(text, "http") {
		t.Errorf("Unexpected response body: %s", text)
	}
}

func TestRealSitesSitebulbAndScreamingFrog(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live internet test in short mode")
	}

	targets := []string{
		"https://sitebulb.com",
		"https://www.screamingfrog.co.uk",
	}

	client, err := NewClient(
		WithBrowserProfile(ProfileChrome),
		WithTimeout(30*time.Second),
		WithMaxContentLength(15*1024*1024),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for _, target := range targets {
		t.Logf("----------------------------------------------------------------")
		t.Logf("Testing Target: %s", target)
		t.Logf("----------------------------------------------------------------")

		// 1. Direct uTLS HTTP/2 Request
		startDirect := time.Now()
		resp, err := client.Get(ctx, target)
		durDirect := time.Since(startDirect)

		if err != nil {
			t.Errorf("[DIRECT FAILED] %s: %v", target, err)
			continue
		}

		t.Logf("[DIRECT OK] Status: %d | Time: %v | Final URL: %s", resp.StatusCode, durDirect, resp.FinalURL())
		if resp.ContentInfo != nil {
			t.Logf("            Media Type: %s | IsHTML: %v | Size: %d bytes",
				resp.ContentInfo.MediaType, resp.ContentInfo.IsHTML, resp.ContentInfo.ContentLength)
		}

		doc, err := resp.HTML()
		if err != nil {
			t.Errorf("Failed to parse HTML: %v", err)
		} else {
			t.Logf("            Title: %s", doc.Title())
			t.Logf("            Extracted Links: %d | Images: %d", len(doc.Links()), len(doc.Images()))
		}

		// 2. Headless Chrome CDP JavaScript Rendering with Asset Blocking
		startRender := time.Now()
		renderResp, err := client.GetRendered(ctx, target,
			WaitForSelector("body"),
			BlockAssets(true),
			RenderTimeout(30*time.Second),
		)
		durRender := time.Since(startRender)

		if err != nil {
			t.Logf("[RENDER SKIPPED/FAILED] %s: %v", target, err)
			continue
		}

		t.Logf("[RENDER OK] Status: %d | Time: %v", renderResp.StatusCode, durRender)
		if renderResp.ContentInfo != nil {
			t.Logf("            Media Type: %s | IsHTML: %v | Rendered Size: %d bytes",
				renderResp.ContentInfo.MediaType, renderResp.ContentInfo.IsHTML, renderResp.ContentInfo.ContentLength)
		}

		renderDoc, err := renderResp.HTML()
		if err != nil {
			t.Errorf("Failed to parse rendered HTML: %v", err)
		} else {
			t.Logf("            Rendered Title: %s", renderDoc.Title())
			t.Logf("            Rendered Links: %d | Images: %d", len(renderDoc.Links()), len(renderDoc.Images()))
		}
	}
}

