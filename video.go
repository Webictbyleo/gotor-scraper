package torscraper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VideoPlatform identifies the video hosting platform.
type VideoPlatform string

const (
	PlatformYouTube VideoPlatform = "youtube"
	PlatformLoom    VideoPlatform = "loom"
	PlatformVimeo   VideoPlatform = "vimeo"
	PlatformWistia  VideoPlatform = "wistia"
	PlatformUnknown VideoPlatform = "unknown"
)

// VideoType identifies the category or format of the video URL.
type VideoType string

const (
	VideoTypeStandard VideoType = "standard"
	VideoTypeShorts   VideoType = "shorts"
	VideoTypeLive     VideoType = "live"
	VideoTypePlaylist VideoType = "playlist"
	VideoTypeClip     VideoType = "clip"
	VideoTypeEmbed    VideoType = "embed"
)

// Common errors for video parsing and processing.
var (
	ErrUnsupportedPlatform = errors.New("unsupported or unrecognized video platform")
	ErrInvalidVideoURL     = errors.New("invalid or unparseable video URL")
	ErrVideoIDNotFound     = errors.New("video ID could not be identified from URL")
	ErrNoStreamsFound      = errors.New("no downloadable video streams found")
)

// VideoInfo holds structured information parsed from a video URL or embed.
type VideoInfo struct {
	Platform      VideoPlatform     `json:"platform"`
	ID            string            `json:"id"`
	Type          VideoType         `json:"type"`
	OriginalURL   string            `json:"original_url"`
	CanonicalURL  string            `json:"canonical_url"`
	EmbedURL      string            `json:"embed_url"`
	ThumbnailURL  string            `json:"thumbnail_url,omitempty"`
	ThumbnailURLs map[string]string `json:"thumbnail_urls,omitempty"`
	Timestamp     time.Duration     `json:"timestamp,omitempty"`
	TimestampSec  int               `json:"timestamp_sec,omitempty"`
	PlaylistID    string            `json:"playlist_id,omitempty"`
	Account       string            `json:"account,omitempty"`
	PrivacyHash   string            `json:"privacy_hash,omitempty"`
	Params        map[string]string `json:"params,omitempty"`
	Element       *HTMLElement      `json:"-"`
}

// VideoMetadata represents oEmbed metadata retrieved from the video provider.
type VideoMetadata struct {
	Platform     VideoPlatform `json:"platform"`
	VideoID      string        `json:"video_id"`
	Title        string        `json:"title"`
	AuthorName   string        `json:"author_name"`
	AuthorURL    string        `json:"author_url"`
	ThumbnailURL string        `json:"thumbnail_url"`
	HTML         string        `json:"html"`
	Width        int           `json:"width"`
	Height       int           `json:"height"`
	Duration     time.Duration `json:"duration,omitempty"`
	Description  string        `json:"description,omitempty"`
}

var (
	// Regular expressions for platform identification
	reYouTubeDomain = regexp.MustCompile(`(?i)^(?:[a-z0-9_-]+\.)?(youtube\.com|youtube-nocookie\.com|youtu\.be)$`)
	reLoomDomain    = regexp.MustCompile(`(?i)^(?:[a-z0-9_-]+\.)?loom\.com$`)
	reVimeoDomain   = regexp.MustCompile(`(?i)^(?:[a-z0-9_-]+\.)?(vimeo\.com|player\.vimeo\.com)$`)
	reWistiaDomain  = regexp.MustCompile(`(?i)^(?:[a-z0-9_-]+\.)?(wistia\.com|wistia\.net)$`)

	// YouTube Video ID format (11 chars, alphanumeric with - and _)
	reYouTubeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{11}$`)

	// Loom Video ID format (UUID or 32-char hex)
	reLoomID = regexp.MustCompile(`^[0-9a-fA-F-]{32,36}$`)

	// Vimeo Video ID format (numeric)
	reVimeoID = regexp.MustCompile(`^\d{6,12}$`)

	// Wistia Video ID format (typically 10 alphanumeric chars)
	reWistiaID = regexp.MustCompile(`^[a-zA-Z0-9]{8,12}$`)

	// Timestamp regex (e.g. 1h2m3s, 90s, 90, 01:30:15)
	reTimestampColon = regexp.MustCompile(`^(\d+):(\d{2})(?::(\d{2}))?$`)
	reTimestampUnits = regexp.MustCompile(`(?i)(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?`)
)

// MatchVideoPlatform returns the VideoPlatform matching the given URL or domain.
func MatchVideoPlatform(rawURL string) VideoPlatform {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return PlatformUnknown
	}

	// Fast pre-check for protocol-less URLs
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") && !strings.HasPrefix(rawURL, "//") {
		rawURL = "https://" + rawURL
	} else if strings.HasPrefix(rawURL, "//") {
		rawURL = "https:" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return PlatformUnknown
	}

	host := strings.ToLower(u.Hostname())

	if reYouTubeDomain.MatchString(host) {
		return PlatformYouTube
	}
	if reLoomDomain.MatchString(host) {
		return PlatformLoom
	}
	if reVimeoDomain.MatchString(host) {
		return PlatformVimeo
	}
	if reWistiaDomain.MatchString(host) {
		return PlatformWistia
	}

	return PlatformUnknown
}

// IsVideoURL returns true if the given URL corresponds to YouTube, Loom, Vimeo, or Wistia.
func IsVideoURL(rawURL string) bool {
	return MatchVideoPlatform(rawURL) != PlatformUnknown
}

// ParseVideoURL parses a URL into a structured VideoInfo object.
func ParseVideoURL(rawURL string) (*VideoInfo, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, ErrInvalidVideoURL
	}

	// Normalize protocol
	normURL := rawURL
	if strings.HasPrefix(normURL, "//") {
		normURL = "https:" + normURL
	} else if !strings.HasPrefix(normURL, "http://") && !strings.HasPrefix(normURL, "https://") {
		normURL = "https://" + normURL
	}

	u, err := url.Parse(normURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidVideoURL, err)
	}

	platform := MatchVideoPlatform(normURL)
	switch platform {
	case PlatformYouTube:
		return parseYouTube(u, rawURL)
	case PlatformLoom:
		return parseLoom(u, rawURL)
	case PlatformVimeo:
		return parseVimeo(u, rawURL)
	case PlatformWistia:
		return parseWistia(u, rawURL)
	default:
		return nil, ErrUnsupportedPlatform
	}
}

// parseYouTube parses YouTube URLs across all formats.
func parseYouTube(u *url.URL, originalURL string) (*VideoInfo, error) {
	host := strings.ToLower(u.Hostname())
	path := strings.Trim(u.Path, "/")
	q := u.Query()

	info := &VideoInfo{
		Platform:      PlatformYouTube,
		OriginalURL:   originalURL,
		Type:          VideoTypeStandard,
		ThumbnailURLs: make(map[string]string),
		Params:        make(map[string]string),
	}

	// Store query params
	for k, v := range q {
		if len(v) > 0 {
			info.Params[k] = v[0]
		}
	}

	// Parse timestamps
	if tVal := q.Get("t"); tVal != "" {
		info.Timestamp = parseVideoTimestamp(tVal)
		info.TimestampSec = int(info.Timestamp.Seconds())
	} else if startVal := q.Get("start"); startVal != "" {
		info.Timestamp = parseVideoTimestamp(startVal)
		info.TimestampSec = int(info.Timestamp.Seconds())
	}

	// Parse playlist
	if listVal := q.Get("list"); listVal != "" {
		info.PlaylistID = listVal
	}

	pathParts := strings.Split(path, "/")

	if host == "youtu.be" {
		// Short URL: youtu.be/{id}
		if len(pathParts) > 0 && pathParts[0] != "" {
			info.ID = pathParts[0]
		}
	} else {
		// youtube.com, m.youtube.com, etc.
		if len(pathParts) > 0 {
			switch strings.ToLower(pathParts[0]) {
			case "watch":
				info.ID = q.Get("v")
			case "embed":
				info.Type = VideoTypeEmbed
				if len(pathParts) > 1 {
					info.ID = pathParts[1]
				}
			case "v", "e":
				if len(pathParts) > 1 {
					info.ID = pathParts[1]
				}
			case "shorts":
				info.Type = VideoTypeShorts
				if len(pathParts) > 1 {
					info.ID = pathParts[1]
				}
			case "live":
				info.Type = VideoTypeLive
				if len(pathParts) > 1 {
					info.ID = pathParts[1]
				}
			case "clip":
				info.Type = VideoTypeClip
				if len(pathParts) > 1 {
					info.ID = pathParts[1]
				}
			case "playlist":
				info.Type = VideoTypePlaylist
				if info.PlaylistID != "" && info.ID == "" {
					info.ID = info.PlaylistID
				}
			default:
				if info.ID == "" {
					info.ID = q.Get("v")
				}
			}
		} else {
			info.ID = q.Get("v")
		}
	}

	// Handle attribution_link redirect wrappers
	if info.ID == "" && strings.Contains(path, "attribution_link") {
		if uParam := q.Get("u"); uParam != "" {
			if decoded, err := url.QueryUnescape(uParam); err == nil {
				if subU, err := url.Parse("https://youtube.com" + decoded); err == nil {
					info.ID = subU.Query().Get("v")
				}
			}
		}
	}

	if info.ID == "" {
		return nil, ErrVideoIDNotFound
	}

	// Clean up any trailing query or parameters from ID
	if idx := strings.IndexAny(info.ID, "?&#"); idx != -1 {
		info.ID = info.ID[:idx]
	}

	// Canonical & Embed URLs
	if info.Type == VideoTypePlaylist && info.ID == info.PlaylistID {
		info.CanonicalURL = fmt.Sprintf("https://www.youtube.com/playlist?list=%s", info.PlaylistID)
		info.EmbedURL = fmt.Sprintf("https://www.youtube.com/embed/videoseries?list=%s", info.PlaylistID)
	} else {
		info.CanonicalURL = fmt.Sprintf("https://www.youtube.com/watch?v=%s", info.ID)
		if info.TimestampSec > 0 {
			info.EmbedURL = fmt.Sprintf("https://www.youtube.com/embed/%s?start=%d", info.ID, info.TimestampSec)
		} else {
			info.EmbedURL = fmt.Sprintf("https://www.youtube.com/embed/%s", info.ID)
		}
	}

	// Standard YouTube Thumbnails
	info.ThumbnailURLs["default"] = fmt.Sprintf("https://img.youtube.com/vi/%s/default.jpg", info.ID)
	info.ThumbnailURLs["mqdefault"] = fmt.Sprintf("https://img.youtube.com/vi/%s/mqdefault.jpg", info.ID)
	info.ThumbnailURLs["hqdefault"] = fmt.Sprintf("https://img.youtube.com/vi/%s/hqdefault.jpg", info.ID)
	info.ThumbnailURLs["sddefault"] = fmt.Sprintf("https://img.youtube.com/vi/%s/sddefault.jpg", info.ID)
	info.ThumbnailURLs["maxresdefault"] = fmt.Sprintf("https://img.youtube.com/vi/%s/maxresdefault.jpg", info.ID)
	info.ThumbnailURL = info.ThumbnailURLs["hqdefault"]

	return info, nil
}

// parseLoom parses Loom URLs (share, embed, cdn).
func parseLoom(u *url.URL, originalURL string) (*VideoInfo, error) {
	path := strings.Trim(u.Path, "/")
	q := u.Query()

	info := &VideoInfo{
		Platform:      PlatformLoom,
		OriginalURL:   originalURL,
		Type:          VideoTypeStandard,
		ThumbnailURLs: make(map[string]string),
		Params:        make(map[string]string),
	}

	for k, v := range q {
		if len(v) > 0 {
			info.Params[k] = v[0]
		}
	}

	if tVal := q.Get("t"); tVal != "" {
		info.Timestamp = parseVideoTimestamp(tVal)
		info.TimestampSec = int(info.Timestamp.Seconds())
	}

	pathParts := strings.Split(path, "/")
	if len(pathParts) > 0 {
		first := strings.ToLower(pathParts[0])
		if first == "share" || first == "embed" {
			if first == "embed" {
				info.Type = VideoTypeEmbed
			}
			if len(pathParts) > 1 {
				info.ID = pathParts[1]
			}
		} else if first == "sessions" || first == "v1" {
			// e.g. cdn.loom.com/sessions/thumbnails/{id}-with-play.gif
			for _, part := range pathParts {
				clean := strings.TrimSuffix(part, "-with-play.gif")
				clean = strings.TrimSuffix(clean, "-00001.jpg")
				if reLoomID.MatchString(clean) {
					info.ID = clean
					break
				}
			}
		} else if reLoomID.MatchString(pathParts[0]) {
			info.ID = pathParts[0]
		}
	}

	if info.ID == "" {
		return nil, ErrVideoIDNotFound
	}

	// Clean trailing params
	if idx := strings.IndexAny(info.ID, "?&#"); idx != -1 {
		info.ID = info.ID[:idx]
	}

	info.CanonicalURL = fmt.Sprintf("https://www.loom.com/share/%s", info.ID)
	info.EmbedURL = fmt.Sprintf("https://www.loom.com/embed/%s", info.ID)

	info.ThumbnailURLs["animated"] = fmt.Sprintf("https://cdn.loom.com/sessions/thumbnails/%s-with-play.gif", info.ID)
	info.ThumbnailURLs["poster"] = fmt.Sprintf("https://cdn.loom.com/sessions/thumbnails/%s-00001.jpg", info.ID)
	info.ThumbnailURL = info.ThumbnailURLs["poster"]

	return info, nil
}

// parseVimeo parses Vimeo URLs (standard, channels, groups, embed, unlisted with privacy hash).
func parseVimeo(u *url.URL, originalURL string) (*VideoInfo, error) {
	host := strings.ToLower(u.Hostname())
	path := strings.Trim(u.Path, "/")
	q := u.Query()

	info := &VideoInfo{
		Platform:      PlatformVimeo,
		OriginalURL:   originalURL,
		Type:          VideoTypeStandard,
		ThumbnailURLs: make(map[string]string),
		Params:        make(map[string]string),
	}

	for k, v := range q {
		if len(v) > 0 {
			info.Params[k] = v[0]
		}
	}

	// Check hash from query param (e.g. player.vimeo.com/video/123?h=abc456)
	if h := q.Get("h"); h != "" {
		info.PrivacyHash = h
	}

	// Check timestamps from query or fragment
	if tVal := q.Get("t"); tVal != "" {
		info.Timestamp = parseVideoTimestamp(tVal)
		info.TimestampSec = int(info.Timestamp.Seconds())
	} else if u.Fragment != "" {
		frag := strings.TrimPrefix(u.Fragment, "t=")
		info.Timestamp = parseVideoTimestamp(frag)
		info.TimestampSec = int(info.Timestamp.Seconds())
	}

	pathParts := strings.Split(path, "/")

	if host == "player.vimeo.com" {
		info.Type = VideoTypeEmbed
		if len(pathParts) > 1 && pathParts[0] == "video" {
			info.ID = pathParts[1]
		}
	} else {
		// vimeo.com
		if len(pathParts) > 0 {
			first := strings.ToLower(pathParts[0])
			switch first {
			case "channels":
				if len(pathParts) > 2 {
					info.Account = pathParts[1]
					info.ID = pathParts[2]
				}
			case "groups":
				if len(pathParts) > 3 && strings.ToLower(pathParts[2]) == "videos" {
					info.Account = pathParts[1]
					info.ID = pathParts[3]
				}
			case "showcase":
				if len(pathParts) > 3 && strings.ToLower(pathParts[2]) == "video" {
					info.ID = pathParts[3]
				}
			default:
				if reVimeoID.MatchString(pathParts[0]) {
					info.ID = pathParts[0]
					// Check unlisted hash in path: vimeo.com/123456789/abcdef0123
					if len(pathParts) > 1 && pathParts[1] != "" {
						info.PrivacyHash = pathParts[1]
					}
				}
			}
		}
	}

	if info.ID == "" {
		return nil, ErrVideoIDNotFound
	}

	if idx := strings.IndexAny(info.ID, "?&#"); idx != -1 {
		info.ID = info.ID[:idx]
	}

	if info.PrivacyHash != "" {
		info.CanonicalURL = fmt.Sprintf("https://vimeo.com/%s/%s", info.ID, info.PrivacyHash)
		info.EmbedURL = fmt.Sprintf("https://player.vimeo.com/video/%s?h=%s", info.ID, info.PrivacyHash)
	} else {
		info.CanonicalURL = fmt.Sprintf("https://vimeo.com/%s", info.ID)
		info.EmbedURL = fmt.Sprintf("https://player.vimeo.com/video/%s", info.ID)
	}

	return info, nil
}

// parseWistia parses Wistia URLs (fast.wistia.net/com, embed, account media pages, playlists).
func parseWistia(u *url.URL, originalURL string) (*VideoInfo, error) {
	host := strings.ToLower(u.Hostname())
	path := strings.Trim(u.Path, "/")
	q := u.Query()

	info := &VideoInfo{
		Platform:      PlatformWistia,
		OriginalURL:   originalURL,
		Type:          VideoTypeStandard,
		ThumbnailURLs: make(map[string]string),
		Params:        make(map[string]string),
	}

	for k, v := range q {
		if len(v) > 0 {
			info.Params[k] = v[0]
		}
	}

	if tVal := q.Get("wtime"); tVal != "" {
		info.Timestamp = parseVideoTimestamp(tVal)
		info.TimestampSec = int(info.Timestamp.Seconds())
	}

	// Extract account subdomain if present
	hostParts := strings.Split(host, ".")
	if len(hostParts) >= 3 && hostParts[0] != "fast" && hostParts[0] != "home" && hostParts[0] != "www" {
		info.Account = hostParts[0]
	}

	pathParts := strings.Split(path, "/")
	if len(pathParts) > 0 {
		first := strings.ToLower(pathParts[0])
		if first == "embed" && len(pathParts) > 1 {
			sub := strings.ToLower(pathParts[1])
			if sub == "iframe" || sub == "medias" {
				info.Type = VideoTypeEmbed
				if len(pathParts) > 2 {
					info.ID = strings.TrimSuffix(pathParts[2], ".jsonp")
					info.ID = strings.TrimSuffix(info.ID, ".json")
					info.ID = strings.TrimSuffix(info.ID, ".bin")
				}
			} else if sub == "playlists" {
				info.Type = VideoTypePlaylist
				if len(pathParts) > 2 {
					info.PlaylistID = pathParts[2]
					info.ID = pathParts[2]
				}
			}
		} else if (first == "medias" || first == "projects") && len(pathParts) > 1 {
			info.ID = pathParts[1]
		} else if reWistiaID.MatchString(pathParts[0]) {
			info.ID = pathParts[0]
		}
	}

	if info.ID == "" {
		return nil, ErrVideoIDNotFound
	}

	if idx := strings.IndexAny(info.ID, "?&#"); idx != -1 {
		info.ID = info.ID[:idx]
	}

	if info.Account != "" {
		info.CanonicalURL = fmt.Sprintf("https://%s.wistia.com/medias/%s", info.Account, info.ID)
	} else {
		info.CanonicalURL = fmt.Sprintf("https://home.wistia.com/medias/%s", info.ID)
	}

	info.EmbedURL = fmt.Sprintf("https://fast.wistia.net/embed/iframe/%s", info.ID)
	info.ThumbnailURLs["swatch"] = fmt.Sprintf("https://fast.wistia.net/embed/medias/%s/swatch", info.ID)
	info.ThumbnailURL = info.ThumbnailURLs["swatch"]

	return info, nil
}

// parseVideoTimestamp parses timestamp strings like "1h2m3s", "90s", "90", "01:30", "01:02:03".
func parseVideoTimestamp(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	// 1. Colon format: mm:ss or hh:mm:ss
	if matches := reTimestampColon.FindStringSubmatch(s); len(matches) > 0 {
		if matches[3] != "" {
			// hh:mm:ss
			h, _ := strconv.Atoi(matches[1])
			m, _ := strconv.Atoi(matches[2])
			sec, _ := strconv.Atoi(matches[3])
			return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
		}
		// mm:ss
		m, _ := strconv.Atoi(matches[1])
		sec, _ := strconv.Atoi(matches[2])
		return time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
	}

	// 2. Unit format: 1h2m3s
	if strings.ContainsAny(s, "hmsHMS") {
		matches := reTimestampUnits.FindStringSubmatch(s)
		if len(matches) > 0 {
			var d time.Duration
			if matches[1] != "" {
				h, _ := strconv.Atoi(matches[1])
				d += time.Duration(h) * time.Hour
			}
			if matches[2] != "" {
				m, _ := strconv.Atoi(matches[2])
				d += time.Duration(m) * time.Minute
			}
			if matches[3] != "" {
				sec, _ := strconv.Atoi(matches[3])
				d += time.Duration(sec) * time.Second
			}
			if d > 0 {
				return d
			}
		}
	}

	// 3. Plain numeric seconds
	clean := strings.TrimRight(s, "sS")
	if sec, err := strconv.ParseFloat(clean, 64); err == nil && sec > 0 {
		return time.Duration(sec * float64(time.Second))
	}

	return 0
}

// IFrameHTML returns a responsive or fixed HTML <iframe> snippet for embedding this video.
func (v *VideoInfo) IFrameHTML(width, height int, responsive bool) string {
	if width <= 0 {
		width = 640
	}
	if height <= 0 {
		height = 360
	}

	embedURL := v.EmbedURL
	if embedURL == "" {
		embedURL = v.CanonicalURL
	}

	if responsive {
		return fmt.Sprintf(`<div style="position:relative;padding-bottom:56.25%%;height:0;overflow:hidden;"><iframe src="%s" style="position:absolute;top:0;left:0;width:100%%;height:100%%;" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></div>`, embedURL)
	}

	return fmt.Sprintf(`<iframe width="%d" height="%d" src="%s" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`, width, height, embedURL)
}

// GetThumbnail returns the thumbnail URL for the requested quality ("default", "high", "maxres", etc.).
func (v *VideoInfo) GetThumbnail(quality string) string {
	if len(v.ThumbnailURLs) == 0 {
		return v.ThumbnailURL
	}
	if thumb, ok := v.ThumbnailURLs[quality]; ok && thumb != "" {
		return thumb
	}
	return v.ThumbnailURL
}

// FetchVideoMetadata retrieves official oEmbed metadata for this video using the client.
func (c *Client) FetchVideoMetadata(ctx context.Context, target any) (*VideoMetadata, error) {
	var info *VideoInfo
	switch v := target.(type) {
	case *VideoInfo:
		info = v
	case VideoInfo:
		info = &v
	case string:
		parsed, err := ParseVideoURL(v)
		if err != nil {
			return nil, err
		}
		info = parsed
	default:
		return nil, fmt.Errorf("target must be string URL or *VideoInfo, got %T", target)
	}

	var endpoint string
	switch info.Platform {
	case PlatformYouTube:
		endpoint = fmt.Sprintf("https://www.youtube.com/oembed?url=%s&format=json", url.QueryEscape(info.CanonicalURL))
	case PlatformVimeo:
		endpoint = fmt.Sprintf("https://vimeo.com/api/oembed.json?url=%s", url.QueryEscape(info.CanonicalURL))
	case PlatformWistia:
		endpoint = fmt.Sprintf("https://fast.wistia.com/oembed.json?url=%s", url.QueryEscape(info.CanonicalURL))
	case PlatformLoom:
		endpoint = fmt.Sprintf("https://www.loom.com/v1/oembed?url=%s", url.QueryEscape(info.CanonicalURL))
	default:
		return nil, ErrUnsupportedPlatform
	}

	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch oEmbed metadata: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("oEmbed request returned HTTP %d: %s", resp.StatusCode, resp.Text())
	}

	var rawMap map[string]any
	if err := json.Unmarshal(resp.Bytes(), &rawMap); err != nil {
		return nil, fmt.Errorf("failed to decode oEmbed JSON: %w", err)
	}

	meta := &VideoMetadata{
		Platform: info.Platform,
		VideoID:  info.ID,
	}

	if t, ok := rawMap["title"].(string); ok {
		meta.Title = t
	}
	if a, ok := rawMap["author_name"].(string); ok {
		meta.AuthorName = a
	}
	if u, ok := rawMap["author_url"].(string); ok {
		meta.AuthorURL = u
	}
	if thumb, ok := rawMap["thumbnail_url"].(string); ok {
		meta.ThumbnailURL = thumb
	}
	if h, ok := rawMap["html"].(string); ok {
		meta.HTML = h
	}
	if w, ok := rawMap["width"].(float64); ok {
		meta.Width = int(w)
	}
	if h, ok := rawMap["height"].(float64); ok {
		meta.Height = int(h)
	}
	if d, ok := rawMap["duration"].(float64); ok {
		meta.Duration = time.Duration(d) * time.Second
	}
	if desc, ok := rawMap["description"].(string); ok {
		meta.Description = desc
	}

	return meta, nil
}
