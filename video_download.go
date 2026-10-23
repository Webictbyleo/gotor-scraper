package torscraper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// VideoStream represents a directly downloadable media stream or asset.
type VideoStream struct {
	// Platform identifies the hosting video service (PlatformYouTube, PlatformLoom, PlatformVimeo, PlatformWistia).
	Platform VideoPlatform `json:"platform"`

	// VideoID is the unique identifier of the video.
	VideoID string `json:"video_id"`

	// URL is the direct playable/downloadable CDN media link.
	URL string `json:"url"`

	// Quality indicates the resolution tier or quality label (e.g. "1080p", "720p", "480p", "360p", "original").
	Quality string `json:"quality"`

	// Width is the video frame width in pixels.
	Width int `json:"width"`

	// Height is the video frame height in pixels.
	Height int `json:"height"`

	// Bitrate is the average bitrate in bits per second.
	Bitrate int64 `json:"bitrate"`

	// Size is the declared media file length in bytes (-1 if chunked or unknown).
	Size int64 `json:"size"`

	// MimeType is the media MIME type (e.g. "video/mp4", "video/webm", "application/x-mpegURL").
	MimeType string `json:"mime_type"`

	// Container is the format container type ("mp4", "webm", "m3u8").
	Container string `json:"container"`

	// IsMuxed is true if the stream contains both video and audio tracks combined in a single file.
	IsMuxed bool `json:"is_muxed"`

	// FPS is the frames per second, if reported.
	FPS int `json:"fps,omitempty"`
}

// DownloadProgressFn is called during downloading with progress statistics.
type DownloadProgressFn func(downloaded int64, total int64, percent float64)

// DownloadOptions configures video downloading behavior.
type DownloadOptions struct {
	// Quality specifies preferred resolution ("best", "worst", "1080p", "720p", "480p", "360p").
	// Defaults to "best" if empty.
	Quality string

	// Container filters streams by container format ("mp4", "webm", etc.).
	Container string

	// OutputPath is the file path where the video will be saved on disk.
	OutputPath string

	// Writer allows streaming video data directly into any custom io.Writer (mutually exclusive with OutputPath).
	Writer io.Writer

	// OnProgress is an optional callback receiving real-time download progress.
	OnProgress DownloadProgressFn

	// BufferSize configures the copy chunk buffer in bytes (defaults to 64KB if <= 0).
	BufferSize int

	// AllowYtDlp allows falling back to the external yt-dlp binary if available on the system PATH.
	AllowYtDlp bool

	// MaxBytes limits the maximum downloaded bytes (0 = unlimited). Useful for previews and testing.
	MaxBytes int64
}

// DownloadResult summarizes a successfully completed video download.
type DownloadResult struct {
	// Platform is the video hosting provider.
	Platform VideoPlatform

	// VideoID is the unique identifier of the downloaded video.
	VideoID string

	// Stream is the exact media stream asset that was downloaded.
	Stream VideoStream

	// OutputPath is the file path on disk where the file was written (empty if streaming to io.Writer).
	OutputPath string

	// BytesWritten is the total number of bytes successfully written.
	BytesWritten int64

	// Duration is the total time elapsed during the download process.
	Duration time.Duration
}

// progressTrackingWriter wraps an io.Writer to report byte counts.
type progressTrackingWriter struct {
	writer     io.Writer
	total      int64
	downloaded int64
	onProgress DownloadProgressFn
}

func (pw *progressTrackingWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	if n > 0 {
		pw.downloaded += int64(n)
		if pw.onProgress != nil {
			var pct float64
			if pw.total > 0 {
				pct = (float64(pw.downloaded) / float64(pw.total)) * 100.0
			}
			pw.onProgress(pw.downloaded, pw.total, pct)
		}
	}
	return n, err
}

// ExtractVideoStreams queries the video provider and extracts all direct downloadable streams.
func (c *Client) ExtractVideoStreams(ctx context.Context, target any) ([]VideoStream, error) {
	info, err := resolveVideoInfo(target)
	if err != nil {
		return nil, err
	}

	var streams []VideoStream
	switch info.Platform {
	case PlatformWistia:
		streams, err = c.extractWistiaStreams(ctx, info)
	case PlatformVimeo:
		streams, err = c.extractVimeoStreams(ctx, info)
	case PlatformLoom:
		streams, err = c.extractLoomStreams(ctx, info)
	case PlatformYouTube:
		streams, err = c.extractYouTubeStreams(ctx, info)
	default:
		return nil, ErrUnsupportedPlatform
	}

	if err != nil {
		return nil, err
	}

	// Sort streams by resolution / height descending
	sort.SliceStable(streams, func(i, j int) bool {
		if streams[i].Height != streams[j].Height {
			return streams[i].Height > streams[j].Height
		}
		if streams[i].Bitrate != streams[j].Bitrate {
			return streams[i].Bitrate > streams[j].Bitrate
		}
		return streams[i].Size > streams[j].Size
	})

	return streams, nil
}

// DownloadVideo downloads the selected video to OutputPath or Writer with progress callbacks.
func (c *Client) DownloadVideo(ctx context.Context, target any, opts DownloadOptions) (*DownloadResult, error) {
	startTime := time.Now()

	info, err := resolveVideoInfo(target)
	if err != nil {
		return nil, err
	}

	if opts.OutputPath == "" && opts.Writer == nil {
		return nil, fmt.Errorf("must specify either OutputPath or Writer in DownloadOptions")
	}

	streams, extractErr := c.ExtractVideoStreams(ctx, info)
	if (extractErr != nil || len(streams) == 0) && opts.AllowYtDlp {
		// Attempt yt-dlp fallback if enabled
		if ytDlpPath, lpErr := exec.LookPath("yt-dlp"); lpErr == nil && ytDlpPath != "" {
			return c.downloadWithYtDlp(ctx, info, opts, startTime)
		}
	}

	if extractErr != nil {
		return nil, fmt.Errorf("failed to extract video streams: %w", extractErr)
	}
	if len(streams) == 0 {
		return nil, ErrNoStreamsFound
	}

	// Select best matching stream
	selectedStream := selectBestStream(streams, opts.Quality, opts.Container)

	var destWriter io.Writer
	var targetFile *os.File

	if opts.OutputPath != "" {
		dir := filepath.Dir(opts.OutputPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create destination directory: %w", err)
			}
		}

		f, err := os.Create(opts.OutputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		targetFile = f
		destWriter = f
	} else {
		destWriter = opts.Writer
	}

	bytesWritten, err := c.DownloadStreamLimit(ctx, selectedStream, destWriter, opts.MaxBytes, opts.OnProgress)
	if err != nil {
		if targetFile != nil {
			_ = os.Remove(opts.OutputPath) // Clean up partial file on failure
		}
		return nil, fmt.Errorf("download failed: %w", err)
	}

	return &DownloadResult{
		Platform:     info.Platform,
		VideoID:      info.ID,
		Stream:       selectedStream,
		OutputPath:   opts.OutputPath,
		BytesWritten: bytesWritten,
		Duration:     time.Since(startTime),
	}, nil
}

// DownloadStream streams the content of a specific VideoStream directly to destination io.Writer.
func (c *Client) DownloadStream(ctx context.Context, stream VideoStream, w io.Writer, onProgress DownloadProgressFn) (int64, error) {
	return c.DownloadStreamLimit(ctx, stream, w, 0, onProgress)
}

// DownloadStreamLimit streams up to maxBytes of a VideoStream to destination io.Writer (maxBytes <= 0 for unlimited).
func (c *Client) DownloadStreamLimit(ctx context.Context, stream VideoStream, w io.Writer, maxBytes int64, onProgress DownloadProgressFn) (int64, error) {
	if stream.URL == "" {
		return 0, fmt.Errorf("video stream URL is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stream.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create HTTP request for stream: %w", err)
	}

	// Add standard media download headers
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity") // prevent gzip on raw video stream
	if stream.Platform == PlatformVimeo {
		req.Header.Set("Referer", fmt.Sprintf("https://vimeo.com/%s", stream.VideoID))
	} else if stream.Platform == PlatformWistia {
		req.Header.Set("Referer", fmt.Sprintf("https://fast.wistia.net/embed/iframe/%s", stream.VideoID))
	}

	httpResp, err := c.httpCli.Do(req)
	if err != nil {
		return 0, fmt.Errorf("stream HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return 0, fmt.Errorf("stream server returned status %d %s", httpResp.StatusCode, httpResp.Status)
	}

	totalSize := httpResp.ContentLength
	if totalSize <= 0 && stream.Size > 0 {
		totalSize = stream.Size
	}
	if maxBytes > 0 && (totalSize <= 0 || maxBytes < totalSize) {
		totalSize = maxBytes
	}

	pw := &progressTrackingWriter{
		writer:     w,
		total:      totalSize,
		onProgress: onProgress,
	}

	var reader io.Reader = httpResp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(httpResp.Body, maxBytes)
	}

	buf := make([]byte, 64*1024)
	bytesWritten, err := io.CopyBuffer(pw, reader, buf)
	if err != nil {
		return bytesWritten, err
	}

	return bytesWritten, nil
}

// --- Platform-Specific Stream Extractors ---

// extractWistiaStreams fetches and parses direct media assets from Wistia's JSON endpoint.
func (c *Client) extractWistiaStreams(ctx context.Context, info *VideoInfo) ([]VideoStream, error) {
	endpoint := fmt.Sprintf("https://fast.wistia.com/embed/medias/%s.json", info.ID)

	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("wistia metadata request failed: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("wistia returned HTTP %d: %s", resp.StatusCode, resp.Text())
	}

	var payload struct {
		Media struct {
			Assets []struct {
				Type        string  `json:"type"`
				URL         string  `json:"url"`
				Width       int     `json:"width"`
				Height      int     `json:"height"`
				Size        int64   `json:"size"`
				Bitrate     int64   `json:"bitrate"`
				DisplayName string  `json:"display_name"`
				ContentType string  `json:"contentType"`
				OptID       string  `json:"opt_id"`
			} `json:"assets"`
		} `json:"media"`
	}

	if err := json.Unmarshal(resp.Bytes(), &payload); err != nil {
		return nil, fmt.Errorf("failed to decode wistia media JSON: %w", err)
	}

	var streams []VideoStream
	for _, asset := range payload.Media.Assets {
		if asset.URL == "" {
			continue
		}

		// Normalize URL: Wistia assets often end in .bin, which are standard MP4 containers
		assetURL := asset.URL
		if strings.HasSuffix(assetURL, ".bin") {
			assetURL = strings.TrimSuffix(assetURL, ".bin") + ".mp4"
		}

		quality := "unknown"
		if asset.Height > 0 {
			quality = fmt.Sprintf("%dp", asset.Height)
		} else if asset.DisplayName != "" {
			quality = asset.DisplayName
		} else if asset.Type != "" {
			quality = asset.Type
		}

		streams = append(streams, VideoStream{
			Platform:  PlatformWistia,
			VideoID:   info.ID,
			URL:       assetURL,
			Quality:   quality,
			Width:     asset.Width,
			Height:    asset.Height,
			Bitrate:   asset.Bitrate,
			Size:      asset.Size,
			MimeType:  "video/mp4",
			Container: "mp4",
			IsMuxed:   true,
		})
	}

	return streams, nil
}

// extractVimeoStreams fetches and parses direct progressive MP4 stream configurations from Vimeo.
func (c *Client) extractVimeoStreams(ctx context.Context, info *VideoInfo) ([]VideoStream, error) {
	configURL := fmt.Sprintf("https://player.vimeo.com/video/%s/config", info.ID)
	if info.PrivacyHash != "" {
		configURL += fmt.Sprintf("?h=%s", info.PrivacyHash)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Referer", fmt.Sprintf("https://vimeo.com/%s", info.ID))

	httpResp, err := c.httpCli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vimeo config request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("vimeo config returned HTTP %d", httpResp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	var config struct {
		Request struct {
			Files struct {
				Progressive []struct {
					Profile int    `json:"profile"`
					Width   int    `json:"width"`
					Height  int    `json:"height"`
					Mime    string `json:"mime"`
					FPS     int    `json:"fps"`
					URL     string `json:"url"`
					Quality string `json:"quality"`
				} `json:"progressive"`
				HLS struct {
					DefaultCDN string            `json:"default_cdn"`
					CDNs       map[string]struct {
						URL string `json:"url"`
					} `json:"cdns"`
				} `json:"hls"`
			} `json:"files"`
		} `json:"request"`
	}

	if err := json.Unmarshal(bodyBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to decode vimeo config JSON: %w", err)
	}

	var streams []VideoStream
	for _, prog := range config.Request.Files.Progressive {
		if prog.URL == "" {
			continue
		}
		quality := prog.Quality
		if quality == "" && prog.Height > 0 {
			quality = fmt.Sprintf("%dp", prog.Height)
		}

		streams = append(streams, VideoStream{
			Platform:  PlatformVimeo,
			VideoID:   info.ID,
			URL:       prog.URL,
			Quality:   quality,
			Width:     prog.Width,
			Height:    prog.Height,
			FPS:       prog.FPS,
			MimeType:  prog.Mime,
			Container: "mp4",
			IsMuxed:   true,
			Size:      -1,
		})
	}

	// If no progressive files, check master HLS playlist
	if len(streams) == 0 && len(config.Request.Files.HLS.CDNs) > 0 {
		hlsURL := ""
		if def, ok := config.Request.Files.HLS.CDNs[config.Request.Files.HLS.DefaultCDN]; ok {
			hlsURL = def.URL
		} else {
			for _, cdn := range config.Request.Files.HLS.CDNs {
				hlsURL = cdn.URL
				break
			}
		}

		if hlsURL != "" {
			streams = append(streams, VideoStream{
				Platform:  PlatformVimeo,
				VideoID:   info.ID,
				URL:       hlsURL,
				Quality:   "adaptive_hls",
				Container: "m3u8",
				MimeType:  "application/x-mpegURL",
				IsMuxed:   true,
				Size:      -1,
			})
		}
	}

	return streams, nil
}

// extractLoomStreams extracts direct MP4 transcoded streams from Loom.
func (c *Client) extractLoomStreams(ctx context.Context, info *VideoInfo) ([]VideoStream, error) {
	// Method 1: Query Loom transcoded-url endpoint
	transcodedAPI := fmt.Sprintf("https://www.loom.com/api/campaigns/sessions/%s/transcoded-url", info.ID)
	postBody, _ := json.Marshal(map[string]string{"videoId": info.ID})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, transcodedAPI, bytes.NewReader(postBody))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if httpResp, err := c.httpCli.Do(req); err == nil && httpResp.StatusCode == http.StatusOK {
			defer httpResp.Body.Close()
			var res struct {
				URL string `json:"url"`
			}
			if json.NewDecoder(httpResp.Body).Decode(&res) == nil && res.URL != "" {
				return []VideoStream{{
					Platform:  PlatformLoom,
					VideoID:   info.ID,
					URL:       res.URL,
					Quality:   "720p",
					Container: "mp4",
					MimeType:  "video/mp4",
					IsMuxed:   true,
					Size:      -1,
				}}, nil
			}
		}
	}

	// Method 2: Scrape Loom Share page and extract direct video asset URLs
	shareURL := fmt.Sprintf("https://www.loom.com/share/%s", info.ID)
	resp, err := c.Get(ctx, shareURL)
	if err == nil && resp.IsSuccess() {
		text := resp.Text()

		// Look for signed CloudFront CDN or cdn.loom.com URLs
		reLoomMP4 := regexp.MustCompile(`https://(?:cdn\.loom\.com|[a-zA-Z0-9.-]+\.cloudfront\.net)/[^"'\s\\]+\.mp4[^"'\s\\]*`)
		if match := reLoomMP4.FindString(text); match != "" {
			return []VideoStream{{
				Platform:  PlatformLoom,
				VideoID:   info.ID,
				URL:       match,
				Quality:   "720p",
				Container: "mp4",
				MimeType:  "video/mp4",
				IsMuxed:   true,
				Size:      -1,
			}}, nil
		}

		reLoomM3U8 := regexp.MustCompile(`https://(?:cdn\.loom\.com|[a-zA-Z0-9.-]+\.cloudfront\.net)/[^"'\s\\]+\.m3u8[^"'\s\\]*`)
		if match := reLoomM3U8.FindString(text); match != "" {
			return []VideoStream{{
				Platform:  PlatformLoom,
				VideoID:   info.ID,
				URL:       match,
				Quality:   "adaptive_hls",
				Container: "m3u8",
				MimeType:  "application/x-mpegURL",
				IsMuxed:   true,
				Size:      -1,
			}}, nil
		}
	}

	return nil, fmt.Errorf("no direct stream URLs could be extracted for Loom video %s", info.ID)
}

// extractYouTubeStreams extracts media streams from YouTube via watch page or InnerTube.
func (c *Client) extractYouTubeStreams(ctx context.Context, info *VideoInfo) ([]VideoStream, error) {
	// Method 1: Scrape YouTube Watch Page using browser profile (extracts ytInitialPlayerResponse)
	watchURL := fmt.Sprintf("https://www.youtube.com/watch?v=%s", info.ID)
	resp, err := c.Get(ctx, watchURL)
	if err == nil && resp.IsSuccess() {
		text := resp.Text()
		streams := parseYouTubeWatchPageStreams(text, info.ID)
		if len(streams) > 0 {
			return streams, nil
		}
	}

	// Method 2: InnerTube Player API fallback
	playerURL := "https://www.youtube.com/youtubei/v1/player"

	// Android client context provides direct progressive muxed formats without cipher scrambling
	reqPayload := map[string]any{
		"context": map[string]any{
			"client": map[string]any{
				"clientName":        "ANDROID",
				"clientVersion":     "19.09.37",
				"androidSdkVersion": 30,
				"hl":                "en",
				"gl":                "US",
			},
		},
		"videoId": info.ID,
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, playerURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "com.google.android.youtube/19.09.37 (Linux; U; Android 11) gzip")

	httpResp, err := c.httpCli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("youtube player request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("youtube player returned HTTP %d", httpResp.StatusCode)
	}

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

	if err := json.NewDecoder(httpResp.Body).Decode(&playerResp); err != nil {
		return nil, fmt.Errorf("failed to decode youtube player response: %w", err)
	}

	var streams []VideoStream
	for _, f := range playerResp.StreamingData.Formats {
		if f.URL == "" {
			continue
		}

		container := "mp4"
		if strings.Contains(f.MimeType, "webm") {
			container = "webm"
		}

		var size int64 = -1
		if f.ContentLength != "" {
			if s, err := strconv.ParseInt(f.ContentLength, 10, 64); err == nil {
				size = s
			}
		}

		quality := f.QualityLabel
		if quality == "" && f.Height > 0 {
			quality = fmt.Sprintf("%dp", f.Height)
		}

		streams = append(streams, VideoStream{
			Platform:  PlatformYouTube,
			VideoID:   info.ID,
			URL:       f.URL,
			Quality:   quality,
			Width:     f.Width,
			Height:    f.Height,
			Bitrate:   f.Bitrate,
			Size:      size,
			MimeType:  f.MimeType,
			Container: container,
			IsMuxed:   true,
			FPS:       f.FPS,
		})
	}

	return streams, nil
}

// parseYouTubeWatchPageStreams parses streaming formats from the watch page's ytInitialPlayerResponse.
func parseYouTubeWatchPageStreams(text, videoID string) []VideoStream {
	pattern := "ytInitialPlayerResponse = "
	idx := strings.Index(text, pattern)
	if idx == -1 {
		pattern = "var ytInitialPlayerResponse = "
		idx = strings.Index(text, pattern)
	}
	if idx == -1 {
		return nil
	}

	rawJSON := text[idx+len(pattern):]
	firstBrace := strings.Index(rawJSON, "{")
	if firstBrace == -1 {
		return nil
	}
	rawJSON = rawJSON[firstBrace:]

	var parsed struct {
		StreamingData struct {
			Formats []struct {
				ItagNo          int    `json:"itag"`
				URL             string `json:"url"`
				SignatureCipher string `json:"signatureCipher"`
				Cipher          string `json:"cipher"`
				MimeType        string `json:"mimeType"`
				Bitrate         int64  `json:"bitrate"`
				Width           int    `json:"width"`
				Height          int    `json:"height"`
				QualityLabel    string `json:"qualityLabel"`
				ContentLength   string `json:"contentLength"`
				FPS             int    `json:"fps"`
			} `json:"formats"`
			AdaptiveFormats []struct {
				ItagNo          int    `json:"itag"`
				URL             string `json:"url"`
				SignatureCipher string `json:"signatureCipher"`
				Cipher          string `json:"cipher"`
				MimeType        string `json:"mimeType"`
				Bitrate         int64  `json:"bitrate"`
				Width           int    `json:"width"`
				Height          int    `json:"height"`
				QualityLabel    string `json:"qualityLabel"`
				ContentLength   string `json:"contentLength"`
				FPS             int    `json:"fps"`
			} `json:"adaptiveFormats"`
		} `json:"streamingData"`
	}

	decoder := json.NewDecoder(strings.NewReader(rawJSON))
	if err := decoder.Decode(&parsed); err != nil {
		return nil
	}

	var streams []VideoStream
	type rawFmt struct {
		ItagNo          int    `json:"itag"`
		URL             string `json:"url"`
		SignatureCipher string `json:"signatureCipher"`
		Cipher          string `json:"cipher"`
		MimeType        string `json:"mimeType"`
		Bitrate         int64  `json:"bitrate"`
		Width           int    `json:"width"`
		Height          int    `json:"height"`
		QualityLabel    string `json:"qualityLabel"`
		ContentLength   string `json:"contentLength"`
		FPS             int    `json:"fps"`
	}

	processFormat := func(f rawFmt, muxed bool) {
		streamURL := f.URL
		if streamURL == "" {
			cipherData := f.SignatureCipher
			if cipherData == "" {
				cipherData = f.Cipher
			}
			if cipherData != "" {
				if q, err := url.ParseQuery(cipherData); err == nil {
					streamURL = q.Get("url")
					if sp := q.Get("sp"); sp != "" && q.Get("s") != "" {
						streamURL += "&" + sp + "=" + url.QueryEscape(q.Get("s"))
					}
				}
			}
		}

		if streamURL == "" {
			return
		}

		container := "mp4"
		if strings.Contains(f.MimeType, "webm") {
			container = "webm"
		}

		var size int64 = -1
		if f.ContentLength != "" {
			if s, err := strconv.ParseInt(f.ContentLength, 10, 64); err == nil {
				size = s
			}
		}

		quality := f.QualityLabel
		if quality == "" && f.Height > 0 {
			quality = fmt.Sprintf("%dp", f.Height)
		}

		streams = append(streams, VideoStream{
			Platform:  PlatformYouTube,
			VideoID:   videoID,
			URL:       streamURL,
			Quality:   quality,
			Width:     f.Width,
			Height:    f.Height,
			Bitrate:   f.Bitrate,
			Size:      size,
			MimeType:  f.MimeType,
			Container: container,
			IsMuxed:   muxed,
			FPS:       f.FPS,
		})
	}

	for _, f := range parsed.StreamingData.Formats {
		processFormat(rawFmt(f), true)
	}
	for _, f := range parsed.StreamingData.AdaptiveFormats {
		processFormat(rawFmt(f), false)
	}

	return streams
}

// downloadWithYtDlp delegates downloading to yt-dlp binary if available on system.
func (c *Client) downloadWithYtDlp(ctx context.Context, info *VideoInfo, opts DownloadOptions, startTime time.Time) (*DownloadResult, error) {
	qualityArg := "best"
	if opts.Quality != "" && opts.Quality != "best" {
		qualityArg = fmt.Sprintf("bestvideo[height<=?%s]+bestaudio/best[height<=?%s]/best", opts.Quality, opts.Quality)
	}

	args := []string{
		"--no-playlist",
		"-f", qualityArg,
	}

	if opts.OutputPath != "" {
		args = append(args, "-o", opts.OutputPath, info.CanonicalURL)
		cmd := exec.CommandContext(ctx, "yt-dlp", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("yt-dlp failed: %w (output: %s)", err, string(output))
		}

		fi, err := os.Stat(opts.OutputPath)
		var size int64 = -1
		if err == nil {
			size = fi.Size()
		}

		return &DownloadResult{
			Platform:     info.Platform,
			VideoID:      info.ID,
			OutputPath:   opts.OutputPath,
			BytesWritten: size,
			Duration:     time.Since(startTime),
		}, nil
	}

	if opts.Writer != nil {
		args = append(args, "-o", "-", info.CanonicalURL)
		cmd := exec.CommandContext(ctx, "yt-dlp", args...)
		cmd.Stdout = opts.Writer
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("yt-dlp stream pipe failed: %w (stderr: %s)", err, stderr.String())
		}

		return &DownloadResult{
			Platform: info.Platform,
			VideoID:  info.ID,
			Duration: time.Since(startTime),
		}, nil
	}

	return nil, fmt.Errorf("no output destination provided")
}

// selectBestStream picks the best stream matching quality and container preferences.
func selectBestStream(streams []VideoStream, preferredQuality, preferredContainer string) VideoStream {
	if len(streams) == 1 {
		return streams[0]
	}

	preferredQuality = strings.ToLower(strings.TrimSpace(preferredQuality))
	preferredContainer = strings.ToLower(strings.TrimSpace(preferredContainer))

	// Filter by container if requested
	candidates := streams
	if preferredContainer != "" {
		var matched []VideoStream
		for _, s := range streams {
			if strings.EqualFold(s.Container, preferredContainer) {
				matched = append(matched, s)
			}
		}
		if len(matched) > 0 {
			candidates = matched
		}
	}

	if preferredQuality == "worst" {
		return candidates[len(candidates)-1]
	}

	if preferredQuality != "" && preferredQuality != "best" {
		// Try exact match on quality string (e.g. "720p")
		for _, s := range candidates {
			if strings.EqualFold(s.Quality, preferredQuality) {
				return s
			}
		}
		// Try numeric height match
		numStr := strings.TrimRight(preferredQuality, "pP")
		if targetHeight, err := strconv.Atoi(numStr); err == nil {
			for _, s := range candidates {
				if s.Height == targetHeight {
					return s
				}
			}
		}
	}

	// Default: return highest quality (first candidate after sorting)
	return candidates[0]
}

// resolveVideoInfo normalizes string URL, VideoInfo, or *VideoInfo to *VideoInfo.
func resolveVideoInfo(target any) (*VideoInfo, error) {
	switch v := target.(type) {
	case *VideoInfo:
		return v, nil
	case VideoInfo:
		return &v, nil
	case string:
		return ParseVideoURL(v)
	default:
		return nil, fmt.Errorf("target must be string URL or *VideoInfo, got %T", target)
	}
}
