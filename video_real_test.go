package torscraper

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestRealVideoURLs_AllFourPlatforms(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live internet test in short mode")
	}

	client, err := NewClient(
		WithBrowserProfile(ProfileChrome),
		WithTimeout(30*time.Second),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	platforms := []struct {
		platform    VideoPlatform
		rawURL      string
		expectedID  string
		expectEmbed string
	}{
		{
			platform:    PlatformYouTube,
			rawURL:      "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
			expectedID:  "dQw4w9WgXcQ",
			expectEmbed: "https://www.youtube.com/embed/dQw4w9WgXcQ",
		},
		{
			platform:    PlatformVimeo,
			rawURL:      "https://vimeo.com/76979871",
			expectedID:  "76979871",
			expectEmbed: "https://player.vimeo.com/video/76979871",
		},
		{
			platform:    PlatformWistia,
			rawURL:      "https://fast.wistia.net/embed/iframe/26sk4lmiix",
			expectedID:  "26sk4lmiix",
			expectEmbed: "https://fast.wistia.net/embed/iframe/26sk4lmiix",
		},
		{
			platform:    PlatformLoom,
			rawURL:      "https://www.loom.com/share/ea2fff85aaaf4314af3cf72cffcd113a",
			expectedID:  "ea2fff85aaaf4314af3cf72cffcd113a",
			expectEmbed: "https://www.loom.com/embed/ea2fff85aaaf4314af3cf72cffcd113a",
		},
	}

	for _, tc := range platforms {
		t.Run(string(tc.platform), func(t *testing.T) {
			t.Logf("=== Testing platform %s with URL: %s ===", tc.platform, tc.rawURL)

			// 1. URL Parsing & Validation
			info, err := ParseVideoURL(tc.rawURL)
			if err != nil {
				t.Fatalf("[%s] ParseVideoURL failed: %v", tc.platform, err)
			}
			if info.Platform != tc.platform {
				t.Errorf("[%s] expected platform %s, got %s", tc.platform, tc.platform, info.Platform)
			}
			if info.ID != tc.expectedID {
				t.Errorf("[%s] expected ID %s, got %s", tc.platform, tc.expectedID, info.ID)
			}
			if info.EmbedURL != tc.expectEmbed {
				t.Errorf("[%s] expected EmbedURL %s, got %s", tc.platform, tc.expectEmbed, info.EmbedURL)
			}
			t.Logf("[%s] -> Parsed ID=%s, Canonical=%s, Embed=%s", tc.platform, info.ID, info.CanonicalURL, info.EmbedURL)

			// 2. Real oEmbed Metadata Fetching
			meta, err := client.FetchVideoMetadata(ctx, info)
			if err != nil {
				t.Logf("[%s] oEmbed metadata warning (could be region/rate-limited): %v", tc.platform, err)
			} else {
				t.Logf("[%s] -> Live Title: %q", tc.platform, meta.Title)
				t.Logf("[%s] -> Author: %q (%s)", tc.platform, meta.AuthorName, meta.AuthorURL)
				t.Logf("[%s] -> Dimensions: %dx%d, Duration: %v", tc.platform, meta.Width, meta.Height, meta.Duration)
				if meta.Title == "" && meta.AuthorName == "" {
					t.Errorf("[%s] oEmbed returned empty Title and AuthorName", tc.platform)
				}
			}

			// 3. Real Stream Extraction
			streams, err := client.ExtractVideoStreams(ctx, info)
			if err != nil {
				t.Logf("[%s] ExtractVideoStreams warning: %v", tc.platform, err)
			} else if len(streams) > 0 {
				t.Logf("[%s] -> Discovered %d real stream(s):", tc.platform, len(streams))
				for i, s := range streams {
					t.Logf("    [%d] Quality=%s (%dx%d) Bitrate=%d Size=%d Container=%s URL=%s",
						i, s.Quality, s.Width, s.Height, s.Bitrate, s.Size, s.Container, truncateURL(s.URL, 80))
				}

				// Download sample (up to 512KB) from real stream with progress callback
				bestStream := streams[0]
				var buf bytes.Buffer
				var progressFired bool
				var bytesDownloaded int64
				maxSampleBytes := int64(512 * 1024)

				n, dlErr := client.DownloadStreamLimit(ctx, bestStream, &buf, maxSampleBytes, func(downloaded, total int64, pct float64) {
					progressFired = true
					bytesDownloaded = downloaded
				})

				if dlErr != nil {
					t.Logf("[%s] Stream download ended with: %v (downloaded %d bytes)", tc.platform, dlErr, n)
				} else {
					t.Logf("[%s] -> Successfully downloaded %d bytes directly from real stream!", tc.platform, n)
					if progressFired {
						t.Logf("[%s] -> Real-time OnProgress callback fired successfully (tracked %d bytes)", tc.platform, bytesDownloaded)
					}
				}
			} else {
				t.Logf("[%s] No streams extracted directly (may require yt-dlp or internal session)", tc.platform)
			}
		})
	}
}

func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen-3] + "..."
}
