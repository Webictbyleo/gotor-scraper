package torscraper

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
)

// Response wraps standard *http.Response with convenient aiohttp-style helper methods.
type Response struct {
	StatusCode  int
	Status      string
	Headers     http.Header
	Cookies     []*http.Cookie
	RawResponse *http.Response
	ContentInfo *ContentInfo

	rawBody []byte
	bodyErr error
	once    sync.Once
}

type responseConfig struct {
	maxContentLength    int64
	allowedContentTypes []string
	blockedContentTypes []string
	contentFilter       ContentFilter
	urlPath             string
}

// newResponse creates a Response from an *http.Response with two-stage content detection and safety limits.
func newResponse(raw *http.Response, cfg *responseConfig) (*Response, error) {
	if raw == nil {
		return nil, fmt.Errorf("nil http.Response")
	}

	resp := &Response{
		StatusCode:  raw.StatusCode,
		Status:      raw.Status,
		Headers:     raw.Header.Clone(),
		Cookies:     raw.Cookies(),
		RawResponse: raw,
	}

	maxLimit := DefaultMaxContentLength
	var allowed []string
	var blocked []string
	var filter ContentFilter
	var urlPath string

	if cfg != nil {
		maxLimit = cfg.maxContentLength
		allowed = cfg.allowedContentTypes
		blocked = cfg.blockedContentTypes
		filter = cfg.contentFilter
		urlPath = cfg.urlPath
	}

	// -----------------------------------------------------------------
	// Stage 1: Zero-Byte Header Preflight (Instant Abort)
	// -----------------------------------------------------------------
	// 1a. Check declared Content-Length
	if maxLimit > 0 && raw.ContentLength > maxLimit {
		_ = raw.Body.Close()
		return resp, ErrContentLengthExceeded
	}

	// 1b. Check declared Content-Type against blocked/allowed lists
	declaredType := raw.Header.Get("Content-Type")
	if declaredType != "" {
		mediaType, _, err := mime.ParseMediaType(declaredType)
		if err == nil {
			mediaType = strings.ToLower(mediaType)
		} else {
			mediaType = strings.ToLower(strings.TrimSpace(strings.Split(declaredType, ";")[0]))
		}

		// Check blocked list
		for _, pattern := range blocked {
			if MatchesContentType(mediaType, pattern) {
				_ = raw.Body.Close()
				return resp, ErrContentTypeBlocked
			}
		}

		// Check allowed list (unless generic octet-stream/text-plain, which we verify in Stage 2)
		if len(allowed) > 0 && mediaType != "application/octet-stream" && mediaType != "text/plain" {
			matched := false
			for _, pattern := range allowed {
				if MatchesContentType(mediaType, pattern) {
					matched = true
					break
				}
			}
			if !matched {
				_ = raw.Body.Close()
				return resp, ErrContentTypeNotAllowed
			}
		}
	}

	// -----------------------------------------------------------------
	// Stage 2: Streaming Magic-Byte Sniffing (Peek first 512b)
	// -----------------------------------------------------------------
	defer raw.Body.Close()

	rawBr := bufio.NewReader(raw.Body)
	decompressedReader, err := decompressReader(rawBr, raw.Header.Get("Content-Encoding"))
	if err != nil {
		decompressedReader = io.NopCloser(rawBr)
	} else {
		defer decompressedReader.Close()
	}

	// Wrap in bufio.Reader to peek without consuming the stream
	br := bufio.NewReader(decompressedReader)
	peeked, _ := br.Peek(512)

	// Detect content info from headers + peeked magic bytes + urlPath
	contentInfo := DetectContent(raw, peeked, urlPath)
	resp.ContentInfo = contentInfo

	// Check blocked list against verified sniffed/media type
	for _, pattern := range blocked {
		if MatchesContentType(contentInfo.MediaType, pattern) || (contentInfo.SniffedType != "" && MatchesContentType(contentInfo.SniffedType, pattern)) {
			return resp, ErrContentTypeBlocked
		}
	}

	// Check allowed list against verified sniffed/media type
	if len(allowed) > 0 {
		matched := false
		for _, pattern := range allowed {
			if MatchesContentType(contentInfo.MediaType, pattern) || (contentInfo.SniffedType != "" && MatchesContentType(contentInfo.SniffedType, pattern)) {
				matched = true
				break
			}
		}
		if !matched {
			return resp, ErrContentTypeNotAllowed
		}
	}

	// Run custom user middleware hook if set
	if filter != nil {
		if err := filter(contentInfo, raw); err != nil {
			return resp, fmt.Errorf("%w: %v", ErrContentRejected, err)
		}
	}

	// -----------------------------------------------------------------
	// Stage 3: Read stream with MaxContentLength limit protection
	// -----------------------------------------------------------------
	if maxLimit > 0 {
		// Read at most maxLimit + 1 bytes to detect overflow on chunked streams
		limitedReader := io.LimitReader(br, maxLimit+1)
		resp.rawBody, resp.bodyErr = io.ReadAll(limitedReader)
		if int64(len(resp.rawBody)) > maxLimit {
			resp.rawBody = nil
			return resp, ErrContentLengthExceeded
		}
	} else {
		resp.rawBody, resp.bodyErr = io.ReadAll(br)
	}

	if resp.ContentInfo != nil {
		resp.ContentInfo.EmptyBody = len(resp.rawBody) == 0
		if len(resp.rawBody) > len(peeked) {
			fullAB := DetectAntiBot(raw, resp.rawBody)
			resp.ContentInfo.AntiBot = fullAB
			if fullAB != nil && fullAB.Detected {
				resp.ContentInfo.MismatchDetected = true
				resp.ContentInfo.MismatchReason = "Anti-bot challenge or block detected: " + fullAB.Reason
			}
		}
	}

	return resp, resp.bodyErr
}

// decompressReader decodes gzip, deflate (RFC 1950 zlib or raw RFC 1951 flate), or brotli encodings if present.
func decompressReader(r io.Reader, encoding string) (io.ReadCloser, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		br := bufio.NewReader(r)
		if _, err := br.Peek(2); err != nil {
			return io.NopCloser(br), nil
		}
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		return gz, nil
	case "deflate":
		br := bufio.NewReader(r)
		hdr, err := br.Peek(2)
		if err == nil && len(hdr) == 2 {
			// RFC 1950 zlib header check: CM == 8 (deflate), CINFO <= 7, and FCHECK divisible by 31
			if (hdr[0]&0x0f) == 8 && (hdr[0]>>4) <= 7 && ((int(hdr[0])<<8)|int(hdr[1]))%31 == 0 {
				zr, zErr := zlib.NewReader(br)
				if zErr == nil {
					return zr, nil
				}
			}
		}
		return flate.NewReader(br), nil
	case "br":
		return io.NopCloser(brotli.NewReader(r)), nil
	default:
		return io.NopCloser(r), nil
	}
}

// Bytes returns the full response body as bytes.
func (r *Response) Bytes() []byte {
	return r.rawBody
}

// Text returns the response body as a UTF-8 string, similar to aiohttp's await resp.text().
func (r *Response) Text() string {
	return string(r.rawBody)
}

// JSON deserializes the response body into the destination target, similar to aiohttp's await resp.json().
func (r *Response) JSON(v any) error {
	if r.bodyErr != nil {
		return fmt.Errorf("cannot parse JSON due to body read error: %w", r.bodyErr)
	}
	decoder := json.NewDecoder(bytes.NewReader(r.rawBody))
	return decoder.Decode(v)
}

// IsSuccess returns true if the status code is in the 2xx range (200-299).
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsRedirect returns true if the status code is a redirect (300-399).
func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

// RedirectURL returns the target URL from the Location header, if present.
func (r *Response) RedirectURL() string {
	return r.Header("Location")
}

// FinalURL returns the final effective URL after all redirects were followed.
func (r *Response) FinalURL() string {
	if r.RawResponse != nil && r.RawResponse.Request != nil && r.RawResponse.Request.URL != nil {
		return r.RawResponse.Request.URL.String()
	}
	return ""
}

// Header returns the value of a specific response header.
func (r *Response) Header(key string) string {
	if r.Headers == nil {
		return ""
	}
	return r.Headers.Get(key)
}
