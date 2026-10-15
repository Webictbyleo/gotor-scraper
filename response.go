package torscraper

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
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

	rawBody []byte
	bodyErr error
	once    sync.Once
}

// newResponse creates a Response from an *http.Response, buffering the body safely.
func newResponse(raw *http.Response) (*Response, error) {
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

	// Decompress and read body immediately, then close raw body
	defer raw.Body.Close()
	decompressedReader, err := decompressReader(raw.Body, raw.Header.Get("Content-Encoding"))
	if err != nil {
		// Fallback to reading raw body if decompression stream fails to initialize
		resp.rawBody, resp.bodyErr = io.ReadAll(raw.Body)
	} else {
		defer decompressedReader.Close()
		resp.rawBody, resp.bodyErr = io.ReadAll(decompressedReader)
	}

	return resp, resp.bodyErr
}

// decompressReader decodes gzip, deflate, or brotli encodings if present.
func decompressReader(r io.Reader, encoding string) (io.ReadCloser, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return gz, nil
	case "deflate":
		return flate.NewReader(r), nil
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
