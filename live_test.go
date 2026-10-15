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
