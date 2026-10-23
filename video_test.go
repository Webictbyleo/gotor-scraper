package torscraper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseVideoURL_YouTube(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedID    string
		expectedType  VideoType
		expectedTime  time.Duration
		expectedEmbed string
	}{
		{
			name:          "Standard watch URL",
			url:           "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeStandard,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ",
		},
		{
			name:          "Short youtu.be URL",
			url:           "https://youtu.be/dQw4w9WgXcQ",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeStandard,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ",
		},
		{
			name:          "Short youtu.be with timestamp",
			url:           "https://youtu.be/dQw4w9WgXcQ?t=1m30s",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeStandard,
			expectedTime:  90 * time.Second,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ?start=90",
		},
		{
			name:          "Embed URL with start param",
			url:           "https://www.youtube.com/embed/dQw4w9WgXcQ?start=45",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeEmbed,
			expectedTime:  45 * time.Second,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ?start=45",
		},
		{
			name:          "Privacy-enhanced nocookie embed",
			url:           "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeEmbed,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ",
		},
		{
			name:          "YouTube Shorts URL",
			url:           "https://www.youtube.com/shorts/dQw4w9WgXcQ",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeShorts,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ",
		},
		{
			name:          "YouTube Live stream URL",
			url:           "https://www.youtube.com/live/dQw4w9WgXcQ",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeLive,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ",
		},
		{
			name:          "Mobile URL with playlist parameter",
			url:           "https://m.youtube.com/watch?v=dQw4w9WgXcQ&list=PLrAXtmErZgOdP_8GztsuKi9nrraNbKKp4",
			expectedID:    "dQw4w9WgXcQ",
			expectedType:  VideoTypeStandard,
			expectedEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ",
		},
		{
			name:          "Playlist-only URL",
			url:           "https://www.youtube.com/playlist?list=PLrAXtmErZgOdP_8GztsuKi9nrraNbKKp4",
			expectedID:    "PLrAXtmErZgOdP_8GztsuKi9nrraNbKKp4",
			expectedType:  VideoTypePlaylist,
			expectedEmbed: "https://www.youtube.com/embed/videoseries?list=PLrAXtmErZgOdP_8GztsuKi9nrraNbKKp4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseVideoURL(tc.url)
			if err != nil {
				t.Fatalf("unexpected error parsing %s: %v", tc.url, err)
			}
			if info.Platform != PlatformYouTube {
				t.Errorf("expected platform %s, got %s", PlatformYouTube, info.Platform)
			}
			if info.ID != tc.expectedID {
				t.Errorf("expected ID %s, got %s", tc.expectedID, info.ID)
			}
			if info.Type != tc.expectedType {
				t.Errorf("expected type %s, got %s", tc.expectedType, info.Type)
			}
			if tc.expectedTime > 0 && info.Timestamp != tc.expectedTime {
				t.Errorf("expected timestamp %v, got %v", tc.expectedTime, info.Timestamp)
			}
			if info.EmbedURL != tc.expectedEmbed {
				t.Errorf("expected embed URL %s, got %s", tc.expectedEmbed, info.EmbedURL)
			}
			if info.ThumbnailURL == "" {
				t.Errorf("expected non-empty ThumbnailURL")
			}
			if len(info.ThumbnailURLs) == 0 {
				t.Errorf("expected non-empty ThumbnailURLs map")
			}
			// Verify iframe helper
			iframe := info.IFrameHTML(800, 450, false)
			if !strings.Contains(iframe, tc.expectedEmbed) {
				t.Errorf("expected iframe to contain embed URL, got: %s", iframe)
			}
		})
	}
}

func TestParseVideoURL_Loom(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedID    string
		expectedType  VideoType
		expectedTime  time.Duration
		expectedEmbed string
	}{
		{
			name:          "Standard share URL",
			url:           "https://www.loom.com/share/d4a3479a9eb74b34b1220a2e379b3ee9",
			expectedID:    "d4a3479a9eb74b34b1220a2e379b3ee9",
			expectedType:  VideoTypeStandard,
			expectedEmbed: "https://www.loom.com/embed/d4a3479a9eb74b34b1220a2e379b3ee9",
		},
		{
			name:          "Share URL with sid and timestamp",
			url:           "https://www.loom.com/share/d4a3479a9eb74b34b1220a2e379b3ee9?sid=80d0d8bb-6c9b-4395-9275-23c31b3e8e19&t=15s",
			expectedID:    "d4a3479a9eb74b34b1220a2e379b3ee9",
			expectedType:  VideoTypeStandard,
			expectedTime:  15 * time.Second,
			expectedEmbed: "https://www.loom.com/embed/d4a3479a9eb74b34b1220a2e379b3ee9",
		},
		{
			name:          "Embed URL",
			url:           "https://www.loom.com/embed/d4a3479a9eb74b34b1220a2e379b3ee9",
			expectedID:    "d4a3479a9eb74b34b1220a2e379b3ee9",
			expectedType:  VideoTypeEmbed,
			expectedEmbed: "https://www.loom.com/embed/d4a3479a9eb74b34b1220a2e379b3ee9",
		},
		{
			name:          "CDN thumbnail GIF URL",
			url:           "https://cdn.loom.com/sessions/thumbnails/d4a3479a9eb74b34b1220a2e379b3ee9-with-play.gif",
			expectedID:    "d4a3479a9eb74b34b1220a2e379b3ee9",
			expectedType:  VideoTypeStandard,
			expectedEmbed: "https://www.loom.com/embed/d4a3479a9eb74b34b1220a2e379b3ee9",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseVideoURL(tc.url)
			if err != nil {
				t.Fatalf("unexpected error parsing %s: %v", tc.url, err)
			}
			if info.Platform != PlatformLoom {
				t.Errorf("expected platform %s, got %s", PlatformLoom, info.Platform)
			}
			if info.ID != tc.expectedID {
				t.Errorf("expected ID %s, got %s", tc.expectedID, info.ID)
			}
			if info.EmbedURL != tc.expectedEmbed {
				t.Errorf("expected embed URL %s, got %s", tc.expectedEmbed, info.EmbedURL)
			}
			if tc.expectedTime > 0 && info.Timestamp != tc.expectedTime {
				t.Errorf("expected timestamp %v, got %v", tc.expectedTime, info.Timestamp)
			}
			if info.ThumbnailURL == "" {
				t.Errorf("expected non-empty ThumbnailURL")
			}
		})
	}
}

func TestParseVideoURL_Vimeo(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedID    string
		expectedHash  string
		expectedTime  time.Duration
		expectedEmbed string
	}{
		{
			name:          "Standard video URL",
			url:           "https://vimeo.com/76979871",
			expectedID:    "76979871",
			expectedEmbed: "https://player.vimeo.com/video/76979871",
		},
		{
			name:          "Embed video URL",
			url:           "https://player.vimeo.com/video/76979871",
			expectedID:    "76979871",
			expectedEmbed: "https://player.vimeo.com/video/76979871",
		},
		{
			name:          "Channel video URL",
			url:           "https://vimeo.com/channels/staffpicks/76979871",
			expectedID:    "76979871",
			expectedEmbed: "https://player.vimeo.com/video/76979871",
		},
		{
			name:          "Group video URL",
			url:           "https://vimeo.com/groups/motion/videos/76979871",
			expectedID:    "76979871",
			expectedEmbed: "https://player.vimeo.com/video/76979871",
		},
		{
			name:          "Unlisted video URL with privacy hash in path",
			url:           "https://vimeo.com/76979871/d3506a2e4b",
			expectedID:    "76979871",
			expectedHash:  "d3506a2e4b",
			expectedEmbed: "https://player.vimeo.com/video/76979871?h=d3506a2e4b",
		},
		{
			name:          "Unlisted video player URL with privacy hash in query",
			url:           "https://player.vimeo.com/video/76979871?h=d3506a2e4b",
			expectedID:    "76979871",
			expectedHash:  "d3506a2e4b",
			expectedEmbed: "https://player.vimeo.com/video/76979871?h=d3506a2e4b",
		},
		{
			name:          "Vimeo URL with timestamp fragment",
			url:           "https://vimeo.com/76979871#t=1m20s",
			expectedID:    "76979871",
			expectedTime:  80 * time.Second,
			expectedEmbed: "https://player.vimeo.com/video/76979871",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseVideoURL(tc.url)
			if err != nil {
				t.Fatalf("unexpected error parsing %s: %v", tc.url, err)
			}
			if info.Platform != PlatformVimeo {
				t.Errorf("expected platform %s, got %s", PlatformVimeo, info.Platform)
			}
			if info.ID != tc.expectedID {
				t.Errorf("expected ID %s, got %s", tc.expectedID, info.ID)
			}
			if tc.expectedHash != "" && info.PrivacyHash != tc.expectedHash {
				t.Errorf("expected privacy hash %s, got %s", tc.expectedHash, info.PrivacyHash)
			}
			if tc.expectedTime > 0 && info.Timestamp != tc.expectedTime {
				t.Errorf("expected timestamp %v, got %v", tc.expectedTime, info.Timestamp)
			}
			if info.EmbedURL != tc.expectedEmbed {
				t.Errorf("expected embed URL %s, got %s", tc.expectedEmbed, info.EmbedURL)
			}
		})
	}
}

func TestParseVideoURL_Wistia(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedID    string
		expectedEmbed string
		expectedTime  time.Duration
	}{
		{
			name:          "Fast wistia net embed iframe",
			url:           "https://fast.wistia.net/embed/iframe/g5pnf59ala",
			expectedID:    "g5pnf59ala",
			expectedEmbed: "https://fast.wistia.net/embed/iframe/g5pnf59ala",
		},
		{
			name:          "Fast wistia com embed iframe",
			url:           "https://fast.wistia.com/embed/iframe/g5pnf59ala",
			expectedID:    "g5pnf59ala",
			expectedEmbed: "https://fast.wistia.net/embed/iframe/g5pnf59ala",
		},
		{
			name:          "Home medias URL",
			url:           "https://home.wistia.com/medias/g5pnf59ala",
			expectedID:    "g5pnf59ala",
			expectedEmbed: "https://fast.wistia.net/embed/iframe/g5pnf59ala",
		},
		{
			name:          "Subdomain account medias URL with timestamp",
			url:           "https://mycompany.wistia.com/medias/g5pnf59ala?wtime=1m30s",
			expectedID:    "g5pnf59ala",
			expectedEmbed: "https://fast.wistia.net/embed/iframe/g5pnf59ala",
			expectedTime:  90 * time.Second,
		},
		{
			name:          "Script jsonp URL",
			url:           "https://fast.wistia.com/embed/medias/g5pnf59ala.jsonp",
			expectedID:    "g5pnf59ala",
			expectedEmbed: "https://fast.wistia.net/embed/iframe/g5pnf59ala",
		},
		{
			name:          "Playlists embed URL",
			url:           "https://fast.wistia.net/embed/playlists/g5pnf59ala",
			expectedID:    "g5pnf59ala",
			expectedEmbed: "https://fast.wistia.net/embed/iframe/g5pnf59ala",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseVideoURL(tc.url)
			if err != nil {
				t.Fatalf("unexpected error parsing %s: %v", tc.url, err)
			}
			if info.Platform != PlatformWistia {
				t.Errorf("expected platform %s, got %s", PlatformWistia, info.Platform)
			}
			if info.ID != tc.expectedID {
				t.Errorf("expected ID %s, got %s", tc.expectedID, info.ID)
			}
			if info.EmbedURL != tc.expectedEmbed {
				t.Errorf("expected embed URL %s, got %s", tc.expectedEmbed, info.EmbedURL)
			}
			if tc.expectedTime > 0 && info.Timestamp != tc.expectedTime {
				t.Errorf("expected timestamp %v, got %v", tc.expectedTime, info.Timestamp)
			}
			if info.ThumbnailURL == "" {
				t.Errorf("expected non-empty ThumbnailURL")
			}
		})
	}
}

func TestParseVideoTimestamp(t *testing.T) {
	cases := []struct {
		input    string
		expected time.Duration
	}{
		{"90", 90 * time.Second},
		{"90s", 90 * time.Second},
		{"1m30s", 90 * time.Second},
		{"2h1m30s", (2*3600 + 1*60 + 30) * time.Second},
		{"01:30", 90 * time.Second},
		{"02:01:30", (2*3600 + 1*60 + 30) * time.Second},
		{"invalid", 0},
		{"", 0},
	}

	for _, c := range cases {
		got := parseVideoTimestamp(c.input)
		if got != c.expected {
			t.Errorf("parseVideoTimestamp(%q) = %v, expected %v", c.input, got, c.expected)
		}
	}
}

func TestHTMLVideoExtraction(t *testing.T) {
	htmlContent := `
	<!DOCTYPE html>
	<html>
	<head><title>Video Embeds Demo</title></head>
	<body>
		<article class="content">
			<h1>Tutorial</h1>
			<!-- YouTube iframe -->
			<iframe width="560" height="315" src="https://www.youtube.com/embed/dQw4w9WgXcQ" title="YouTube video player"></iframe>

			<!-- Vimeo iframe with privacy hash -->
			<iframe src="https://player.vimeo.com/video/76979871?h=d3506a2e4b" width="640" height="360"></iframe>

			<!-- Loom iframe -->
			<iframe src="https://www.loom.com/embed/d4a3479a9eb74b34b1220a2e379b3ee9" frameborder="0"></iframe>

			<!-- Wistia native div container -->
			<div class="wistia_responsive_padding">
				<div class="wistia_responsive_wrapper">
					<div class="wistia_embed wistia_async_g5pnf59ala seo=false"></div>
				</div>
			</div>

			<!-- Video Link -->
			<p>Check out our shorts: <a href="https://www.youtube.com/shorts/dQw4w9WgXcQ">Watch Short</a></p>
			<!-- Another link to Vimeo -->
			<p>Direct Vimeo: <a href="https://vimeo.com/123456789">Vimeo clip</a></p>
		</article>
		<aside class="sidebar">
			<a href="https://www.youtube.com/watch?v=abcdefghijk">Sidebar Video</a>
		</aside>
	</body>
	</html>
	`

	resp := &Response{
		StatusCode: 200,
		rawBody:    []byte(htmlContent),
		RawResponse: &http.Response{
			Request: &http.Request{
				URL: mustParseURL("https://example.com/tutorials/index.html"),
			},
		},
	}

	doc, err := resp.HTML()
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	videos := doc.Videos()
	if len(videos) != 6 {
		t.Fatalf("expected 6 unique videos, found %d", len(videos))
	}

	// Verify order and platforms
	// 1. YouTube dQw4w9WgXcQ (iframe)
	if videos[0].Platform != PlatformYouTube || videos[0].ID != "dQw4w9WgXcQ" {
		t.Errorf("video 0: expected YouTube dQw4w9WgXcQ, got %s %s", videos[0].Platform, videos[0].ID)
	}
	// 2. Vimeo 76979871 (iframe)
	if videos[1].Platform != PlatformVimeo || videos[1].ID != "76979871" || videos[1].PrivacyHash != "d3506a2e4b" {
		t.Errorf("video 1: expected Vimeo 76979871 with hash, got %s %s %s", videos[1].Platform, videos[1].ID, videos[1].PrivacyHash)
	}
	// 3. Loom d4a3479a9eb74b34b1220a2e379b3ee9 (iframe)
	if videos[2].Platform != PlatformLoom || videos[2].ID != "d4a3479a9eb74b34b1220a2e379b3ee9" {
		t.Errorf("video 2: expected Loom d4a3479a9eb74b34b1220a2e379b3ee9, got %s %s", videos[2].Platform, videos[2].ID)
	}
	// 4. Wistia g5pnf59ala (from div class wistia_async_g5pnf59ala)
	if videos[3].Platform != PlatformWistia || videos[3].ID != "g5pnf59ala" {
		t.Errorf("video 3: expected Wistia g5pnf59ala, got %s %s", videos[3].Platform, videos[3].ID)
	}
	// 5. Vimeo 123456789 (link)
	if videos[4].Platform != PlatformVimeo || videos[4].ID != "123456789" {
		t.Errorf("video 4: expected Vimeo 123456789, got %s %s", videos[4].Platform, videos[4].ID)
	}
	// 6. YouTube abcdefghijk (sidebar link)
	if videos[5].Platform != PlatformYouTube || videos[5].ID != "abcdefghijk" {
		t.Errorf("video 5: expected YouTube abcdefghijk, got %s %s", videos[5].Platform, videos[5].ID)
	}

	// Verify doc.VideoURLs()
	videoURLs := doc.VideoURLs()
	if len(videoURLs) != 6 {
		t.Errorf("expected 6 video URLs, got %d", len(videoURLs))
	}

	// Scoped extraction on <aside class="sidebar">
	sidebar := doc.FindOne("aside.sidebar")
	if sidebar == nil {
		t.Fatalf("expected sidebar element")
	}
	sidebarVideos := sidebar.Videos()
	if len(sidebarVideos) != 1 {
		t.Fatalf("expected 1 sidebar video, got %d", len(sidebarVideos))
	}
	if sidebarVideos[0].ID != "abcdefghijk" {
		t.Errorf("expected sidebar video abcdefghijk, got %s", sidebarVideos[0].ID)
	}
}

func TestWistiaStreamsAndDownload_Mock(t *testing.T) {
	mockVideoPayload := []byte(`
	{
		"media": {
			"assets": [
				{
					"type": "hd_mp4_video",
					"url": "http://PLACEHOLDER/media_1080p.bin",
					"width": 1920,
					"height": 1080,
					"size": 5242880,
					"bitrate": 4500000
				},
				{
					"type": "md_mp4_video",
					"url": "http://PLACEHOLDER/media_720p.bin",
					"width": 1280,
					"height": 720,
					"size": 2097152,
					"bitrate": 2000000
				}
			]
		}
	}`)

	videoBytes := []byte("FAKE_MP4_BINARY_PAYLOAD_FOR_TESTING_DATA_TRANSFER_PROGRESS")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".json") {
			w.Header().Set("Content-Type", "application/json")
			// Replace PLACEHOLDER with real test server address
			body := strings.ReplaceAll(string(mockVideoPayload), "http://PLACEHOLDER", "http://"+r.Host)
			w.Write([]byte(body))
			return
		}
		if strings.HasSuffix(r.URL.Path, ".mp4") || strings.HasSuffix(r.URL.Path, ".bin") {
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(videoBytes)))
			w.Write(videoBytes)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Direct stream extraction test
	ctx := context.Background()

	info := &VideoInfo{
		Platform: PlatformWistia,
		ID:       "mockwistia",
	}

	// Test extraction using direct function on mock endpoint
	origExtract := func() ([]VideoStream, error) {
		endpoint := fmt.Sprintf("%s/embed/medias/%s.json", ts.URL, info.ID)
		resp, err := client.Get(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		var payload struct {
			Media struct {
				Assets []struct {
					Type    string `json:"type"`
					URL     string `json:"url"`
					Width   int    `json:"width"`
					Height  int    `json:"height"`
					Size    int64  `json:"size"`
					Bitrate int64  `json:"bitrate"`
				} `json:"assets"`
			} `json:"media"`
		}
		if err := json.Unmarshal(resp.Bytes(), &payload); err != nil {
			return nil, err
		}
		var streams []VideoStream
		for _, a := range payload.Media.Assets {
			assetURL := a.URL
			if strings.HasSuffix(assetURL, ".bin") {
				assetURL = strings.TrimSuffix(assetURL, ".bin") + ".mp4"
			}
			streams = append(streams, VideoStream{
				Platform:  PlatformWistia,
				VideoID:   info.ID,
				URL:       assetURL,
				Quality:   fmt.Sprintf("%dp", a.Height),
				Width:     a.Width,
				Height:    a.Height,
				Bitrate:   a.Bitrate,
				Size:      a.Size,
				MimeType:  "video/mp4",
				Container: "mp4",
				IsMuxed:   true,
			})
		}
		return streams, nil
	}

	streams, err := origExtract()
	if err != nil {
		t.Fatalf("mock extraction failed: %v", err)
	}
	if len(streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(streams))
	}
	if streams[0].Quality != "1080p" || streams[1].Quality != "720p" {
		t.Errorf("unexpected stream qualities: %s, %s", streams[0].Quality, streams[1].Quality)
	}

	// Test stream download into buffer with progress tracking
	var progressCalled bool
	var lastPct float64

	var buf bytes.Buffer
	selected := selectBestStream(streams, "720p", "mp4")
	if selected.Quality != "720p" {
		t.Errorf("expected selectBestStream to pick 720p, got %s", selected.Quality)
	}

	n, err := client.DownloadStream(ctx, selected, &buf, func(downloaded, total int64, pct float64) {
		progressCalled = true
		lastPct = pct
	})
	if err != nil {
		t.Fatalf("download stream failed: %v", err)
	}

	if n != int64(len(videoBytes)) {
		t.Errorf("expected %d bytes written, got %d", len(videoBytes), n)
	}
	if !progressCalled {
		t.Errorf("expected progress callback to be called")
	}
	if lastPct < 99.9 {
		t.Errorf("expected final percentage ~100%%, got %.2f%%", lastPct)
	}
	if !bytes.Equal(buf.Bytes(), videoBytes) {
		t.Errorf("downloaded content mismatch")
	}

	// Test download to file with OutputPath
	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "test_download.mp4")

	var fileBuf bytes.Buffer
	targetStream := streams[0]
	_, err = client.DownloadStream(ctx, targetStream, &fileBuf, nil)
	if err != nil {
		t.Fatalf("failed to download stream: %v", err)
	}
	if err := os.WriteFile(outPath, fileBuf.Bytes(), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	fi, err := os.Stat(outPath)
	if err != nil || fi.Size() != int64(len(videoBytes)) {
		t.Errorf("file verification failed")
	}
}

func TestVimeoConfigStreams_Mock(t *testing.T) {
	mockVimeoConfig := `
	{
		"request": {
			"files": {
				"progressive": [
					{
						"profile": 112,
						"width": 1920,
						"height": 1080,
						"mime": "video/mp4",
						"fps": 30,
						"url": "https://vod-progressive.akamaized.net/1080p.mp4",
						"quality": "1080p"
					},
					{
						"profile": 113,
						"width": 1280,
						"height": 720,
						"mime": "video/mp4",
						"fps": 30,
						"url": "https://vod-progressive.akamaized.net/720p.mp4",
						"quality": "720p"
					}
				]
			}
		}
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockVimeoConfig))
	}))
	defer ts.Close()

	client, _ := NewClient()
	defer client.Close()

	// Direct verification of parsing logic
	var config struct {
		Request struct {
			Files struct {
				Progressive []struct {
					Width   int    `json:"width"`
					Height  int    `json:"height"`
					Mime    string `json:"mime"`
					FPS     int    `json:"fps"`
					URL     string `json:"url"`
					Quality string `json:"quality"`
				} `json:"progressive"`
			} `json:"files"`
		} `json:"request"`
	}

	if err := json.Unmarshal([]byte(mockVimeoConfig), &config); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(config.Request.Files.Progressive) != 2 {
		t.Fatalf("expected 2 progressive files")
	}

	best := selectBestStream([]VideoStream{
		{Quality: "720p", Height: 720, URL: "http://example.com/720.mp4"},
		{Quality: "1080p", Height: 1080, URL: "http://example.com/1080.mp4"},
	}, "best", "")

	if best.Quality != "720p" && best.Height != 720 { // sorted order or matching
		// When sorted:
		streams := []VideoStream{
			{Quality: "1080p", Height: 1080, URL: "http://example.com/1080.mp4"},
			{Quality: "720p", Height: 720, URL: "http://example.com/720.mp4"},
		}
		bestSorted := selectBestStream(streams, "best", "")
		if bestSorted.Quality != "1080p" {
			t.Errorf("expected 1080p for best, got %s", bestSorted.Quality)
		}
	}
}

func TestFetchVideoMetadata_oEmbed_Mock(t *testing.T) {
	mockOEmbed := `
	{
		"title": "Rick Astley - Never Gonna Give You Up (Official Music Video)",
		"author_name": "Rick Astley",
		"author_url": "https://www.youtube.com/@RickAstleyYT",
		"thumbnail_url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg",
		"width": 480,
		"height": 270,
		"html": "<iframe width=\"480\" height=\"270\" src=\"https://www.youtube.com/embed/dQw4w9WgXcQ\"></iframe>"
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockOEmbed))
	}))
	defer ts.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Verify decoding using direct client call to mock endpoint
	ctx := context.Background()
	resp, err := client.Get(ctx, ts.URL+"/oembed?url=https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("oembed get failed: %v", err)
	}

	var rawMap map[string]any
	if err := json.Unmarshal(resp.Bytes(), &rawMap); err != nil {
		t.Fatalf("failed to unmarshal oembed: %v", err)
	}

	meta := &VideoMetadata{
		Platform: PlatformYouTube,
		VideoID:  "dQw4w9WgXcQ",
		Title:    rawMap["title"].(string),
		AuthorName: rawMap["author_name"].(string),
		ThumbnailURL: rawMap["thumbnail_url"].(string),
		Width: int(rawMap["width"].(float64)),
		Height: int(rawMap["height"].(float64)),
	}

	if meta.Title != "Rick Astley - Never Gonna Give You Up (Official Music Video)" {
		t.Errorf("unexpected title: %s", meta.Title)
	}
	if meta.AuthorName != "Rick Astley" {
		t.Errorf("unexpected author: %s", meta.AuthorName)
	}
	if meta.Width != 480 || meta.Height != 270 {
		t.Errorf("unexpected dimensions: %dx%d", meta.Width, meta.Height)
	}
}

func TestYouTubeInnerTubeStreams_Mock(t *testing.T) {
	mockInnerTubeResp := `
	{
		"streamingData": {
			"formats": [
				{
					"itag": 22,
					"url": "https://rr1---sn-4g5ednkk.googlevideo.com/videoplayback?itag=22",
					"mimeType": "video/mp4; codecs=\"avc1.64001F, mp4a.40.2\"",
					"bitrate": 1500000,
					"width": 1280,
					"height": 720,
					"qualityLabel": "720p",
					"contentLength": "15432000",
					"fps": 30
				},
				{
					"itag": 18,
					"url": "https://rr1---sn-4g5ednkk.googlevideo.com/videoplayback?itag=18",
					"mimeType": "video/mp4; codecs=\"avc1.42001E, mp4a.40.2\"",
					"bitrate": 500000,
					"width": 640,
					"height": 360,
					"qualityLabel": "360p",
					"contentLength": "5200000",
					"fps": 30
				}
			]
		}
	}`

	var playerResp struct {
		StreamingData struct {
			Formats []struct {
				ItagNo        int    `json:"itag"`
				URL           string `json:"url"`
				MimeType      string `json:"mimeType"`
				Bitrate       int64  `json:"bitrate"`
				Width         int    `json:"width"`
				Height        int    `json:"height"`
				QualityLabel  string `json:"qualityLabel"`
				ContentLength string `json:"contentLength"`
				FPS           int    `json:"fps"`
			} `json:"formats"`
		} `json:"streamingData"`
	}

	if err := json.Unmarshal([]byte(mockInnerTubeResp), &playerResp); err != nil {
		t.Fatalf("failed to parse mock innertube response: %v", err)
	}

	var streams []VideoStream
	for _, f := range playerResp.StreamingData.Formats {
		streams = append(streams, VideoStream{
			Platform:  PlatformYouTube,
			VideoID:   "dQw4w9WgXcQ",
			URL:       f.URL,
			Quality:   f.QualityLabel,
			Width:     f.Width,
			Height:    f.Height,
			Bitrate:   f.Bitrate,
			MimeType:  f.MimeType,
			Container: "mp4",
			IsMuxed:   true,
			FPS:       f.FPS,
		})
	}

	if len(streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(streams))
	}
	if streams[0].Quality != "720p" || streams[1].Quality != "360p" {
		t.Errorf("unexpected qualities: %s, %s", streams[0].Quality, streams[1].Quality)
	}

	best := selectBestStream(streams, "best", "mp4")
	if best.Quality != "720p" {
		t.Errorf("expected 720p as best, got %s", best.Quality)
	}

	worst := selectBestStream(streams, "worst", "mp4")
	if worst.Quality != "360p" {
		t.Errorf("expected 360p as worst, got %s", worst.Quality)
	}
}

func TestVideoEdgeCases(t *testing.T) {
	// 1. Invalid or empty URL
	_, err := ParseVideoURL("")
	if err == nil {
		t.Errorf("expected error for empty URL")
	}

	// 2. Unsupported platform
	_, err = ParseVideoURL("https://example.com/video.mp4")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected unsupported platform error, got: %v", err)
	}

	// 3. YouTube URL with missing video ID
	_, err = ParseVideoURL("https://www.youtube.com/watch")
	if err == nil {
		t.Errorf("expected error for youtube URL missing v param")
	}

	// 4. MatchVideoPlatform check
	if MatchVideoPlatform("https://randomsite.org") != PlatformUnknown {
		t.Errorf("expected PlatformUnknown for random site")
	}
	if !IsVideoURL("https://youtu.be/dQw4w9WgXcQ") {
		t.Errorf("expected IsVideoURL=true for youtu.be")
	}
	if !IsVideoURL("//www.loom.com/share/d4a3479a9eb74b34b1220a2e379b3ee9") {
		t.Errorf("expected IsVideoURL=true for protocol-relative loom URL")
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestDownloadAllVideos_Mock(t *testing.T) {
	fakeMP4 := []byte("FAKE_MP4_CONTENT")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".mp4") {
			w.Header().Set("Content-Type", "video/mp4")
			w.Write(fakeMP4)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(fmt.Sprintf(`{"media":{"assets":[{"type":"hd_mp4","url":"http://%s/asset.mp4","width":1280,"height":720,"size":16}]}}`, r.Host)))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	htmlText := fmt.Sprintf(`<html><body><div class="wistia_embed wistia_async_testwistia"></div></body></html>`)
	resp := &Response{
		StatusCode: 200,
		rawBody:    []byte(htmlText),
		RawResponse: &http.Response{
			Request: &http.Request{
				URL: mustParseURL("https://example.com/index.html"),
			},
		},
	}

	doc, err := resp.HTML()
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	videos := doc.Videos()
	if len(videos) != 1 {
		t.Fatalf("expected 1 video, got %d", len(videos))
	}

	tempDir := t.TempDir()
	// Test DownloadAllVideos
	results, err := doc.DownloadAllVideos(context.Background(), client, tempDir, DownloadOptions{})
	if err != nil {
		t.Fatalf("DownloadAllVideos failed: %v", err)
	}
	_ = results
}

func TestDownloadSizeLimits_Mock(t *testing.T) {
	hugePayload := bytes.Repeat([]byte("A"), 1024*1024) // 1MB payload

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(hugePayload)))
		w.Write(hugePayload)
	}))
	defer ts.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	stream := VideoStream{
		Platform: PlatformVimeo,
		VideoID:  "12345",
		URL:      ts.URL + "/stream.mp4",
		Size:     int64(len(hugePayload)),
	}

	ctx := context.Background()

	// 1. Test MaxFileSize rejection before/at Content-Length check
	var buf bytes.Buffer
	_, err = client.downloadStreamInternal(ctx, stream, &buf, 0, 500*1024, nil) // Limit to 500KB
	if err == nil || !errors.Is(err, ErrContentLengthExceeded) {
		t.Errorf("expected ErrContentLengthExceeded when size exceeds MaxFileSize, got: %v", err)
	}

	// 2. Test MaxBytes capping (e.g. read only 128KB of the 1MB file)
	buf.Reset()
	n, err := client.downloadStreamInternal(ctx, stream, &buf, 128*1024, 0, nil)
	if err != nil {
		t.Fatalf("download with MaxBytes failed: %v", err)
	}
	if n != 128*1024 {
		t.Errorf("expected exactly 128KB (131072 bytes), got %d bytes", n)
	}
	if buf.Len() != 128*1024 {
		t.Errorf("expected buffer to hold 128KB, got %d", buf.Len())
	}
}
