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

func TestLiveCSSQueryingAndFormattedText(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live internet test in short mode")
	}

	client, err := NewClient(
		WithBrowserProfile(ProfileChrome),
		WithTimeout(30*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Test live CSS selectors and formatted text on quotes.toscrape.com
	t.Log("Testing live CSS selectors and formatted text on https://quotes.toscrape.com ...")
	resp, err := client.Get(ctx, "https://quotes.toscrape.com")
	if err != nil {
		t.Fatalf("Live request to quotes.toscrape.com failed: %v", err)
	}

	doc, err := resp.HTML()
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	quotes := doc.Find(".quote")
	if len(quotes) == 0 {
		t.Fatalf("Expected .quote elements on quotes.toscrape.com, found 0")
	}
	t.Logf("Found %d quote items on quotes.toscrape.com", len(quotes))

	firstQuote := quotes[0]
	textEl := firstQuote.FindOne("span.text")
	if textEl == nil {
		t.Fatal("Expected span.text in first quote")
	}
	quoteText := textEl.Text()
	t.Logf("First quote formatted text: %q", quoteText)
	if !strings.Contains(quoteText, "The world as we have created it") && len(quoteText) < 10 {
		t.Errorf("Unexpected quote text: %s", quoteText)
	}

	authorEl := firstQuote.FindOne("small.author")
	if authorEl == nil {
		t.Fatal("Expected small.author in first quote")
	}
	author := authorEl.Text()
	t.Logf("First quote author: %q", author)
	if author != "Albert Einstein" {
		t.Errorf("Expected author 'Albert Einstein', got %q", author)
	}

	// Test AbsoluteURL resolution
	aboutLinkEl := firstQuote.FindOne("a[href*='/author/']")
	if aboutLinkEl != nil {
		absURL := aboutLinkEl.AbsoluteURL("href")
		t.Logf("Absolute author URL: %s", absURL)
		if !strings.HasPrefix(absURL, "https://quotes.toscrape.com/author/") {
			t.Errorf("Expected absolute URL starting with domain, got %s", absURL)
		}
	}

	// 2. Test live CSS selectors on Hacker News
	t.Log("Testing live CSS selectors on https://news.ycombinator.com ...")
	hnResp, err := client.Get(ctx, "https://news.ycombinator.com")
	if err != nil {
		t.Logf("Live request to news.ycombinator.com failed: %v", err)
		return
	}

	hnDoc, err := hnResp.HTML()
	if err != nil {
		t.Fatalf("Failed to parse HN HTML: %v", err)
	}

	stories := hnDoc.Find("tr.athing")
	if len(stories) == 0 {
		t.Fatalf("Expected stories matching 'tr.athing' on Hacker News, found 0")
	}
	t.Logf("Found %d stories on Hacker News", len(stories))

	topStory := stories[0]
	titleEl := topStory.FindOne("span.titleline a")
	if titleEl == nil {
		t.Fatal("Expected title link in top story")
	}
	t.Logf("Top HN Story: %s (URL: %s)", titleEl.Text(), titleEl.AbsoluteURL("href"))
}

func TestLiveChromeActionChains(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live internet test in short mode")
	}

	client, err := NewClient(
		WithBrowserProfile(ProfileChrome),
		WithTimeout(60*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	t.Log("Testing real headless Chrome action chains on https://quotes.toscrape.com/login ...")
	// quotes.toscrape.com/login accepts any login credentials and redirects to logged-in dashboard
	renderResp, err := client.GetRendered(ctx, "https://quotes.toscrape.com/login",
		WaitForSelector("form"),
		TypeText("#username", "leo_automated_tester"),
		TypeText("#password", "supersecret123"),
		Click("input[type='submit']"),
		ScrollToBottom(200, 50*time.Millisecond),
		RenderTimeout(30*time.Second),
	)
	if err != nil {
		t.Fatalf("GetRendered with action chains failed on live URL: %v", err)
	}

	doc, err := renderResp.HTML()
	if err != nil {
		t.Fatalf("Failed to parse rendered HTML: %v", err)
	}

	// Verify logged in state
	logoutLink := doc.FindOne("a[href='/logout']")
	if logoutLink == nil {
		t.Fatalf("Expected logout link after form submission action chain, but it was not found in rendered DOM. Page text: %s", doc.Text())
	}

	outerHTML, _ := logoutLink.OuterHTML()
	t.Logf("[SUCCESS] Live Action Chain executed! Found element: %s with text %q",
		outerHTML, logoutLink.Text())
}

