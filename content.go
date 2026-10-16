package torscraper

import (
	"bytes"
	"errors"
	"mime"
	"net/http"
	"path"
	"strings"
	"unicode"
)

// Typed errors for content detection and filtering.
var (
	// ErrContentLengthExceeded is returned when the response size exceeds the configured maximum limit.
	ErrContentLengthExceeded = errors.New("response content length exceeded maximum allowed limit")

	// ErrContentTypeBlocked is returned when the response Content-Type is in the blocked list.
	ErrContentTypeBlocked = errors.New("response content-type is blocked")

	// ErrContentTypeNotAllowed is returned when the response Content-Type is not in the allowed list.
	ErrContentTypeNotAllowed = errors.New("response content-type is not permitted by allowed list")

	// ErrContentRejected is returned when a custom ContentFilter rejects the response.
	ErrContentRejected = errors.New("response rejected by content filter middleware")
)

// DefaultMaxContentLength is 10 Megabytes (10 * 1024 * 1024).
const DefaultMaxContentLength int64 = 10 * 1024 * 1024

// ContentInfo contains metadata and verified MIME classification of an HTTP response.
type ContentInfo struct {
	// DeclaredType is the raw Content-Type header from the server (e.g. "application/json; charset=utf-8").
	DeclaredType string

	// MediaType is the parsed, normalized MIME type without params (e.g. "application/json").
	MediaType string

	// Charset is the extracted character set (e.g. "utf-8"), if present.
	Charset string

	// SniffedType is the verified MIME type detected via magic byte sniffing.
	SniffedType string

	// ContentLength is the declared Content-Length in bytes (-1 if chunked/unknown).
	ContentLength int64

	// IsHTML is true if the content is verified as HTML.
	IsHTML bool

	// IsJSON is true if the content is verified as JSON.
	IsJSON bool

	// IsXML is true if the content is verified as XML.
	IsXML bool

	// IsBinary is true if the content is a binary format (image, audio, video, archive, document).
	IsBinary bool

	// IsAttachment is true if the Content-Disposition header specifies an attachment.
	IsAttachment bool

	// MismatchDetected is true if the declared Content-Type conflicts with the sniffed magic bytes
	// (e.g. server claimed "application/json" but magic bytes show a Cloudflare HTML page).
	MismatchDetected bool

	// MismatchReason describes any detected conflict between declared and sniffed content.
	MismatchReason string

	// EmptyBody is true if the response payload has 0 bytes.
	EmptyBody bool

	// AntiBot contains the full verdict of the anti-bot and WAF challenge detector.
	AntiBot *AntiBotDetection
}

// ContentFilter is a middleware function that evaluates ContentInfo before downloading the body.
// Returning an error aborts the download immediately and closes the connection.
type ContentFilter func(info *ContentInfo, raw *http.Response) error

// DetectContent analyzes response headers, URL path, and initial peeked bytes (up to 512b).
func DetectContent(raw *http.Response, peeked []byte, urlPath string) *ContentInfo {
	info := &ContentInfo{
		DeclaredType:  raw.Header.Get("Content-Type"),
		ContentLength: raw.ContentLength,
		EmptyBody:     len(peeked) == 0 && raw.ContentLength == 0,
	}

	// Parse declared Content-Type and charset
	if info.DeclaredType != "" {
		mediaType, params, err := mime.ParseMediaType(info.DeclaredType)
		if err == nil {
			info.MediaType = strings.ToLower(mediaType)
			info.Charset = strings.ToLower(params["charset"])
		} else {
			info.MediaType = strings.ToLower(strings.TrimSpace(strings.Split(info.DeclaredType, ";")[0]))
		}
	}

	// Check Content-Disposition for attachment
	disp := raw.Header.Get("Content-Disposition")
	if strings.Contains(strings.ToLower(disp), "attachment") {
		info.IsAttachment = true
	}

	// Perform magic byte sniffing on peeked bytes
	info.SniffedType = SniffMagicBytes(peeked, info.MediaType, urlPath)

	// If declared media type was empty or generic octet-stream/text-plain, adopt sniffed type
	if info.MediaType == "" || info.MediaType == "application/octet-stream" {
		if info.SniffedType != "" && info.SniffedType != "application/octet-stream" {
			info.MediaType = info.SniffedType
		}
	}

	// Categorize content
	effectiveType := info.MediaType
	if info.SniffedType != "" {
		effectiveType = info.SniffedType
	}

	info.IsHTML = effectiveType == "text/html" || info.SniffedType == "text/html"
	info.IsJSON = effectiveType == "application/json" || info.SniffedType == "application/json"
	info.IsXML = effectiveType == "text/xml" || effectiveType == "application/xml" || strings.HasSuffix(effectiveType, "+xml")
	info.IsBinary = isBinaryMediaType(effectiveType)

	// Run deep anti-bot and WAF detection
	info.AntiBot = DetectAntiBot(raw, peeked)
	if info.AntiBot != nil && info.AntiBot.Detected {
		info.MismatchDetected = true
		info.MismatchReason = "Anti-bot challenge or block detected: " + info.AntiBot.Reason
	}

	// Detect mismatches (e.g. server claimed JSON/image but returned HTML challenge)
	if info.MediaType != "" && info.SniffedType != "" {
		if strings.Contains(info.MediaType, "json") && info.SniffedType == "text/html" {
			info.MismatchDetected = true
			info.MismatchReason = "declared application/json but magic bytes indicate HTML page"
		} else if strings.HasPrefix(info.MediaType, "image/") && info.SniffedType == "text/html" {
			info.MismatchDetected = true
			info.MismatchReason = "declared image but magic bytes indicate HTML page"
		}
	}

	return info
}

// SniffMagicBytes inspects up to 512 bytes with robust edge-case handling.
func SniffMagicBytes(buf []byte, declaredType string, urlPath string) string {
	if len(buf) == 0 {
		return ""
	}

	// Strip Byte Order Marks (UTF-8, UTF-16)
	data := stripBOM(buf)

	// 1. Text checks: JSON, HTML, XML (skipping leading whitespace)
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)
	if len(trimmed) > 0 {
		// JSON Object or Array
		if isJSONSignature(trimmed) {
			return "application/json"
		}

		// HTML Tags
		if isHTMLSignature(trimmed) {
			return "text/html"
		}

		// SVG (including XML-declared SVG documents)
		if len(trimmed) > 4 && (bytes.HasPrefix(trimmed, []byte("<svg")) || (bytes.HasPrefix(trimmed, []byte("<?xml")) && bytes.Contains(trimmed, []byte("<svg")))) {
			return "image/svg+xml"
		}

		// XML declaration
		if bytes.HasPrefix(trimmed, []byte("<?xml")) {
			return "text/xml"
		}
	}

	// 2. Binary signatures: Images
	if bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		return "image/png"
	}
	if bytes.HasPrefix(data, []byte("\xff\xd8\xff")) {
		return "image/jpeg"
	}
	if bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")) {
		return "image/gif"
	}
	// WebP: RIFF at 0..3 and WEBP at 8..11
	if len(data) >= 12 && bytes.HasPrefix(data, []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")) {
		return "image/webp"
	}
	// AVIF / HEIC / MP4 (ISOBMFF): ftyp at 4..7
	if len(data) >= 12 && bytes.Equal(data[4:8], []byte("ftyp")) {
		brand := string(data[8:12])
		if brand == "avif" || brand == "avis" {
			return "image/avif"
		}
		if brand == "heic" || brand == "heix" {
			return "image/heic"
		}
		if brand == "qt  " {
			return "video/quicktime"
		}
		return "video/mp4"
	}
	if bytes.HasPrefix(data, []byte("\x00\x00\x01\x00")) {
		return "image/x-icon"
	}
	if bytes.HasPrefix(data, []byte("BM")) {
		return "image/bmp"
	}

	// 3. Audio / Video (WAV, AVI, WebM/MKV, OGG, FLAC, MP3)
	if len(data) >= 12 && bytes.HasPrefix(data, []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WAVE")) {
		return "audio/wav"
	}
	if len(data) >= 12 && bytes.HasPrefix(data, []byte("RIFF")) && bytes.Equal(data[8:12], []byte("AVI ")) {
		return "video/x-msvideo"
	}
	if bytes.HasPrefix(data, []byte("\x1a\x45\xdf\xa3")) {
		if bytes.Contains(data, []byte("webm")) {
			return "video/webm"
		}
		return "video/x-matroska"
	}
	if bytes.HasPrefix(data, []byte("OggS")) {
		return "audio/ogg"
	}
	if bytes.HasPrefix(data, []byte("fLaC")) {
		return "audio/flac"
	}
	if bytes.HasPrefix(data, []byte("ID3")) || (len(data) >= 2 && data[0] == 0xFF && (data[1]&0xE0) == 0xE0) {
		return "audio/mpeg"
	}

	// 4. Documents & Archives
	if bytes.HasPrefix(data, []byte("%PDF-")) {
		return "application/pdf"
	}
	// ZIP-based archives: ZIP, DOCX, XLSX, PPTX, APK, EPUB
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		if bytes.Contains(data, []byte("word/")) || bytes.Contains(data, []byte("[Content_Types].xml")) {
			if strings.HasSuffix(urlPath, ".xlsx") {
				return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
			}
			if strings.HasSuffix(urlPath, ".pptx") {
				return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
			}
			return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		}
		if bytes.Contains(data, []byte("mimetypeapplication/epub+zip")) {
			return "application/epub+zip"
		}
		return "application/zip"
	}
	if bytes.HasPrefix(data, []byte("\x1f\x8b")) {
		return "application/gzip"
	}
	if bytes.HasPrefix(data, []byte("7z\xbc\xaf\x27\x1c")) {
		return "application/x-7z-compressed"
	}
	if bytes.HasPrefix(data, []byte("Rar!\x1a\x07")) {
		return "application/vnd.rar"
	}
	if bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		return "application/vnd.sqlite3"
	}
	if bytes.HasPrefix(data, []byte("\x00asm")) {
		return "application/wasm"
	}

	// 5. Apache Extension Fallback for generic text (CSV, TSV, Markdown, Parquet)
	if urlPath != "" {
		extMime := LookupMIMEByExt(path.Ext(urlPath))
		if extMime != "" {
			return extMime
		}
	}

	// Fallback to Go's standard sniffer if unclassified
	return http.DetectContentType(buf)
}

// isJSONSignature checks whether bytes start with structured JSON markers.
func isJSONSignature(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	// JSON Object: {"key"... or {}
	if b[0] == '{' {
		rest := bytes.TrimLeftFunc(b[1:], unicode.IsSpace)
		if len(rest) == 0 || rest[0] == '"' || rest[0] == '}' {
			return true
		}
	}
	// JSON Array: [{"key"... or [123... or []
	if b[0] == '[' {
		rest := bytes.TrimLeftFunc(b[1:], unicode.IsSpace)
		if len(rest) == 0 || rest[0] == '{' || rest[0] == '"' || rest[0] == ']' || unicode.IsDigit(rune(rest[0])) {
			return true
		}
	}
	return false
}

// isHTMLSignature searches for common HTML start tags in a case-insensitive manner.
func isHTMLSignature(b []byte) bool {
	lower := bytes.ToLower(b)
	markers := [][]byte{
		[]byte("<!doctype html"),
		[]byte("<html"),
		[]byte("<head"),
		[]byte("<body"),
		[]byte("<div"),
		[]byte("<script"),
		[]byte("<title"),
		[]byte("<!--"),
	}
	for _, m := range markers {
		if bytes.HasPrefix(lower, m) {
			return true
		}
	}
	return false
}

// stripBOM removes UTF-8, UTF-16LE, and UTF-16BE Byte Order Marks.
func stripBOM(b []byte) []byte {
	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) { // UTF-8 BOM
		return b[3:]
	}
	if bytes.HasPrefix(b, []byte("\xff\xfe")) || bytes.HasPrefix(b, []byte("\xfe\xff")) { // UTF-16 BOM
		return b[2:]
	}
	return b
}

// isBinaryMediaType determines whether a MIME type represents binary media or documents.
func isBinaryMediaType(mt string) bool {
	if mt == "" {
		return false
	}
	if strings.HasPrefix(mt, "image/") && mt != "image/svg+xml" {
		return true
	}
	if strings.HasPrefix(mt, "video/") || strings.HasPrefix(mt, "audio/") {
		return true
	}
	binaryApps := []string{
		"application/pdf",
		"application/zip",
		"application/x-7z-compressed",
		"application/vnd.rar",
		"application/octet-stream",
		"application/vnd.openxmlformats-officedocument",
		"application/vnd.sqlite3",
		"application/wasm",
	}
	for _, b := range binaryApps {
		if strings.HasPrefix(mt, b) {
			return true
		}
	}
	return false
}

// MatchesContentType checks if a media type satisfies a pattern (e.g. "image/*", "text/html", "application/json").
func MatchesContentType(target string, pattern string) bool {
	if idx := strings.IndexByte(target, ';'); idx != -1 {
		target = target[:idx]
	}
	if idx := strings.IndexByte(pattern, ';'); idx != -1 {
		pattern = pattern[:idx]
	}
	target = strings.ToLower(strings.TrimSpace(target))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	if pattern == "*" || pattern == "*/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(target, prefix+"/")
	}
	return target == pattern
}

// LookupMIMEByExt maps common file extensions to Apache/IANA MIME types.
func LookupMIMEByExt(ext string) string {
	ext = strings.ToLower(strings.TrimPrefix(ext, "."))
	switch ext {
	case "html", "htm":
		return "text/html"
	case "json":
		return "application/json"
	case "xml":
		return "application/xml"
	case "csv":
		return "text/csv"
	case "tsv":
		return "text/tab-separated-values"
	case "txt":
		return "text/plain"
	case "md":
		return "text/markdown"
	case "pdf":
		return "application/pdf"
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	case "avif":
		return "image/avif"
	case "svg":
		return "image/svg+xml"
	case "zip":
		return "application/zip"
	case "gz", "gzip":
		return "application/gzip"
	case "parquet":
		return "application/vnd.apache.parquet"
	case "wasm":
		return "application/wasm"
	case "docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "pptx":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	default:
		return ""
	}
}
