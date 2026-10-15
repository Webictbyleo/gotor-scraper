package torscraper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSniffMagicBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		urlPath  string
		expected string
	}{
		{
			name:     "JSON object with leading whitespace",
			input:    []byte(" \n\t  {\"status\": \"ok\", \"count\": 42}"),
			expected: "application/json",
		},
		{
			name:     "JSON array with numbers",
			input:    []byte("\t[10, 20, 30]"),
			expected: "application/json",
		},
		{
			name:     "JSON with UTF-8 BOM",
			input:    []byte("\xef\xbb\xbf{\"key\": \"value\"}"),
			expected: "application/json",
		},
		{
			name:     "HTML with DOCTYPE",
			input:    []byte("<!DOCTYPE html><html><body><h1>Hello</h1></body></html>"),
			expected: "text/html",
		},
		{
			name:     "HTML starting with comment",
			input:    []byte("<!-- Page comment -->\n<div id=\"root\">App</div>"),
			expected: "text/html",
		},
		{
			name:     "XML document",
			input:    []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?><rss version=\"2.0\"></rss>"),
			expected: "text/xml",
		},
		{
			name:     "WebP image (RIFF with WEBP)",
			input:    []byte("RIFF\x00\x00\x00\x00WEBPVP8 "),
			expected: "image/webp",
		},
		{
			name:     "WAV audio (RIFF with WAVE)",
			input:    []byte("RIFF\x00\x00\x00\x00WAVEfmt "),
			expected: "audio/wav",
		},
		{
			name:     "AVI video (RIFF with AVI )",
			input:    []byte("RIFF\x00\x00\x00\x00AVI LIST"),
			expected: "video/x-msvideo",
		},
		{
			name:     "AVIF image (ftyp with avif)",
			input:    []byte("\x00\x00\x00\x1cftypavif\x00\x00\x00\x00"),
			expected: "image/avif",
		},
		{
			name:     "MP4 video (ftyp with isom)",
			input:    []byte("\x00\x00\x00\x20ftypisom\x00\x00\x02\x00"),
			expected: "video/mp4",
		},
		{
			name:     "PNG image",
			input:    []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
			expected: "image/png",
		},
		{
			name:     "JPEG image",
			input:    []byte("\xff\xd8\xff\xe0\x00\x10JFIF"),
			expected: "image/jpeg",
		},
		{
			name:     "PDF document",
			input:    []byte("%PDF-1.7\n%abc"),
			expected: "application/pdf",
		},
		{
			name:     "GZIP archive",
			input:    []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00"),
			expected: "application/gzip",
		},
		{
			name:     "ZIP archive",
			input:    []byte("PK\x03\x04\x14\x00\x00\x00"),
			expected: "application/zip",
		},
		{
			name:     "DOCX Word Document (Zip with word/ directory)",
			input:    []byte("PK\x03\x04\x14\x00\x00\x00word/document.xml"),
			expected: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		},
		{
			name:     "Apache extension fallback for Parquet",
			input:    []byte("some-binary-data"),
			urlPath:  "/data/warehouse.parquet",
			expected: "application/vnd.apache.parquet",
		},
		{
			name:     "Apache extension fallback for CSV",
			input:    []byte("id,name,email\n1,alice,alice@example.com"),
			urlPath:  "/exports/users.csv",
			expected: "text/csv",
		},
		{
			name:     "Empty body (zero bytes)",
			input:    []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SniffMagicBytes(tt.input, "", tt.urlPath)
			if got != tt.expected {
				t.Errorf("SniffMagicBytes() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContentDetectionMiddleware(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large-declared":
			w.Header().Set("Content-Length", "20000000") // 20MB declared
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("too large"))
		case "/chunked-large":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			// Send 3KB chunked data
			bigData := strings.Repeat("A", 3000)
			_, _ = w.Write([]byte(bigData))
		case "/fake-json-cloudflare-block":
			w.Header().Set("Content-Type", "application/json") // Server claims JSON
			w.WriteHeader(http.StatusOK)
			// But server actually returns Cloudflare HTML challenge
			_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Cloudflare DDOS challenge</title></head><body>Please wait...</body></html>"))
		case "/image":
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
		case "/valid-json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items": [1, 2, 3], "total": 3}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// 1. Test MaxContentLength limit via Header (Stage 1 Instant Abort)
	limitClient, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithMaxContentLength(1024*1024), // 1MB limit
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer limitClient.Close()

	_, err = limitClient.Get(ctx, server.URL+"/large-declared")
	if !errors.Is(err, ErrContentLengthExceeded) {
		t.Errorf("Expected ErrContentLengthExceeded, got: %v", err)
	}

	// 2. Test Chunked stream size limit (Stage 3 limit enforcement)
	smallLimitClient, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithMaxContentLength(1000), // 1KB limit
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer smallLimitClient.Close()

	_, err = smallLimitClient.Get(ctx, server.URL+"/chunked-large")
	if !errors.Is(err, ErrContentLengthExceeded) {
		t.Errorf("Expected ErrContentLengthExceeded on chunked overflow, got: %v", err)
	}

	// 3. Test Blocked Content Types (e.g. Block Images)
	blockImagesClient, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithBlockedContentTypes("image/*"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer blockImagesClient.Close()

	_, err = blockImagesClient.Get(ctx, server.URL+"/image")
	if !errors.Is(err, ErrContentTypeBlocked) {
		t.Errorf("Expected ErrContentTypeBlocked, got: %v", err)
	}

	// 4. Test Allowed Content Types (e.g. Only Allow JSON)
	onlyJSONClient, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithAllowedContentTypes("application/json"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer onlyJSONClient.Close()

	// An image should be rejected
	_, err = onlyJSONClient.Get(ctx, server.URL+"/image")
	if !errors.Is(err, ErrContentTypeNotAllowed) {
		t.Errorf("Expected ErrContentTypeNotAllowed for image, got: %v", err)
	}

	// Valid JSON should succeed
	resp, err := onlyJSONClient.Get(ctx, server.URL+"/valid-json")
	if err != nil {
		t.Fatalf("Expected valid JSON to succeed, got: %v", err)
	}
	if !resp.ContentInfo.IsJSON {
		t.Error("Expected resp.ContentInfo.IsJSON to be true")
	}
	if resp.ContentInfo.Charset != "utf-8" {
		t.Errorf("Expected charset 'utf-8', got: %s", resp.ContentInfo.Charset)
	}

	// 5. Test Mismatch Detection (Server says JSON, but magic bytes are HTML)
	detectClient, err := NewClient(WithBrowserProfile(ProfileNone))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer detectClient.Close()

	mismatchResp, err := detectClient.Get(ctx, server.URL+"/fake-json-cloudflare-block")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !mismatchResp.ContentInfo.MismatchDetected {
		t.Error("Expected MismatchDetected to be true when server lied about JSON")
	}
	if mismatchResp.ContentInfo.SniffedType != "text/html" {
		t.Errorf("Expected SniffedType text/html, got: %s", mismatchResp.ContentInfo.SniffedType)
	}

	// 6. Test Custom ContentFilter middleware hook
	customFilterClient, err := NewClient(
		WithBrowserProfile(ProfileNone),
		WithContentFilter(func(info *ContentInfo, raw *http.Response) error {
			if info.MismatchDetected {
				return errors.New("aborted due to Cloudflare challenge page")
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer customFilterClient.Close()

	_, err = customFilterClient.Get(ctx, server.URL+"/fake-json-cloudflare-block")
	if err == nil || !strings.Contains(err.Error(), "Cloudflare challenge page") {
		t.Errorf("Expected custom filter error, got: %v", err)
	}
}
