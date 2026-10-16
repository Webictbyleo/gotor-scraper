package torscraper

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

var reHTMLComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// selectorCache caches compiled Cascadia CSS selectors for optimal query performance.
var selectorCache sync.Map

func getOrCompileSelector(selector string) (cascadia.Selector, error) {
	if cached, ok := selectorCache.Load(selector); ok {
		return cached.(cascadia.Selector), nil
	}
	sel, err := cascadia.Compile(selector)
	if err != nil {
		return nil, fmt.Errorf("invalid CSS selector %q: %w", selector, err)
	}
	selectorCache.Store(selector, sel)
	return sel, nil
}

// HTMLDocument represents a parsed HTML page with rich CSS selector querying and text extraction.
type HTMLDocument struct {
	root     *html.Node
	finalURL *url.URL
}

// HTMLElement wraps an individual html.Node with text, attribute, and scoped traversal helpers.
type HTMLElement struct {
	node     *html.Node
	finalURL *url.URL
}

// HTML parses the response body into an HTMLDocument.
func (r *Response) HTML() (*HTMLDocument, error) {
	node, err := html.Parse(bytes.NewReader(r.rawBody))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML body: %w", err)
	}

	var base *url.URL
	final := r.FinalURL()
	if final != "" {
		base, _ = url.Parse(final)
	}

	return &HTMLDocument{
		root:     node,
		finalURL: base,
	}, nil
}

// AbsoluteURL resolves a relative URL against the response's final destination URL.
func (r *Response) AbsoluteURL(target string) string {
	final := r.FinalURL()
	if final == "" {
		return target
	}
	base, err := url.Parse(final)
	if err != nil {
		return target
	}
	ref, err := url.Parse(target)
	if err != nil {
		return target
	}
	return base.ResolveReference(ref).String()
}

// Node returns the underlying *html.Node for direct low-level AST manipulation.
func (doc *HTMLDocument) Node() *html.Node {
	return doc.root
}

// Node returns the underlying *html.Node for direct low-level AST manipulation.
func (el *HTMLElement) Node() *html.Node {
	return el.node
}

// Title returns the page title (<title> text), properly formatted with entity decoding and clean text.
func (doc *HTMLDocument) Title() string {
	if doc == nil || doc.root == nil {
		return ""
	}
	titleEl := doc.FindOne("title")
	if titleEl != nil {
		raw := titleEl.Text()
		cleaned := reHTMLComment.ReplaceAllString(raw, "")
		return strings.TrimSpace(strings.Join(strings.Fields(cleaned), " "))
	}
	return ""
}

// Find evaluates a CSS selector across the entire document and returns all matching elements.
// Supports full CSS3 selector syntax: tag, class (.foo), id (#bar), attributes ([target=_blank]),
// combinators (div > p, a + span), pseudo-classes (:first-child, :last-child, :nth-child(2), :not(.ignore)).
func (doc *HTMLDocument) Find(selector string) []*HTMLElement {
	if doc == nil || doc.root == nil {
		return nil
	}
	sel, err := getOrCompileSelector(selector)
	if err != nil {
		return nil
	}
	nodes := cascadia.QueryAll(doc.root, sel)
	elements := make([]*HTMLElement, len(nodes))
	for i, n := range nodes {
		elements[i] = &HTMLElement{node: n, finalURL: doc.finalURL}
	}
	return elements
}

// FindOne returns the first element in the document matching the given CSS selector, or nil if none match.
func (doc *HTMLDocument) FindOne(selector string) *HTMLElement {
	if doc == nil || doc.root == nil {
		return nil
	}
	sel, err := getOrCompileSelector(selector)
	if err != nil {
		return nil
	}
	node := cascadia.Query(doc.root, sel)
	if node == nil {
		return nil
	}
	return &HTMLElement{node: node, finalURL: doc.finalURL}
}

// Find evaluates a scoped CSS selector inside this element's subtree.
func (el *HTMLElement) Find(selector string) []*HTMLElement {
	if el == nil || el.node == nil {
		return nil
	}
	sel, err := getOrCompileSelector(selector)
	if err != nil {
		return nil
	}
	nodes := cascadia.QueryAll(el.node, sel)
	elements := make([]*HTMLElement, len(nodes))
	for i, n := range nodes {
		elements[i] = &HTMLElement{node: n, finalURL: el.finalURL}
	}
	return elements
}

// FindOne returns the first child element matching the given CSS selector, or nil if none match.
func (el *HTMLElement) FindOne(selector string) *HTMLElement {
	if el == nil || el.node == nil {
		return nil
	}
	sel, err := getOrCompileSelector(selector)
	if err != nil {
		return nil
	}
	node := cascadia.Query(el.node, sel)
	if node == nil {
		return nil
	}
	return &HTMLElement{node: node, finalURL: el.finalURL}
}

// FindByTag returns all elements with the specified tag name.
func (doc *HTMLDocument) FindByTag(tag string) []*HTMLElement {
	return doc.Find(strings.ToLower(tag))
}

// FindByID returns the single element matching the given id attribute.
func (doc *HTMLDocument) FindByID(id string) *HTMLElement {
	return doc.FindOne("#" + id)
}

// FindByClass returns all elements containing the specified CSS class.
func (doc *HTMLDocument) FindByClass(className string) []*HTMLElement {
	return doc.Find("." + className)
}

// Links extracts all <a href="..."> links from the document, resolved to absolute URLs.
func (doc *HTMLDocument) Links() []string {
	var links []string
	for _, el := range doc.Find("a[href]") {
		href := el.Attr("href")
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			continue
		}
		links = append(links, el.AbsoluteURL("href"))
	}
	return links
}

// Images extracts all <img src="..."> image URLs from the document, resolved to absolute URLs.
func (doc *HTMLDocument) Images() []string {
	var images []string
	for _, el := range doc.Find("img[src]") {
		src := el.Attr("src")
		if src == "" || strings.HasPrefix(src, "data:") {
			continue
		}
		images = append(images, el.AbsoluteURL("src"))
	}
	return images
}

// Attr returns the value of an attribute on this element, or an empty string if not found.
func (el *HTMLElement) Attr(key string) string {
	if el == nil || el.node == nil {
		return ""
	}
	key = strings.ToLower(key)
	for _, a := range el.node.Attr {
		if strings.ToLower(a.Key) == key {
			return a.Val
		}
	}
	return ""
}

// Attrs returns a key-value map of all HTML attributes present on this element.
func (el *HTMLElement) Attrs() map[string]string {
	if el == nil || el.node == nil {
		return nil
	}
	m := make(map[string]string, len(el.node.Attr))
	for _, a := range el.node.Attr {
		m[a.Key] = a.Val
	}
	return m
}

// HasAttr returns true if this element has the specified attribute.
func (el *HTMLElement) HasAttr(key string) bool {
	if el == nil || el.node == nil {
		return false
	}
	key = strings.ToLower(key)
	for _, a := range el.node.Attr {
		if strings.ToLower(a.Key) == key {
			return true
		}
	}
	return false
}

// Tag returns the HTML tag name of this element (e.g. "div", "a", "h1").
func (el *HTMLElement) Tag() string {
	if el == nil || el.node == nil {
		return ""
	}
	return el.node.Data
}

// AbsoluteURL resolves an attribute containing a URL (e.g. "href", "src")
// against the response's final destination URL.
func (el *HTMLElement) AbsoluteURL(attrKey string) string {
	val := el.Attr(attrKey)
	if val == "" || el.finalURL == nil {
		return val
	}
	ref, err := url.Parse(val)
	if err != nil {
		return val
	}
	return el.finalURL.ResolveReference(ref).String()
}

// Text extracts clean, beautifully formatted human-readable text from this element and its children.
// Unlike naive text strippers, this method:
//   - Inserts newlines for block elements (<h1>-<h6>, <p>, <div>, <li>, <tr>, <article>, <section>)
//   - Converts <br> and <hr> into real newlines
//   - Adds spaces between inline boundaries (cells, spans) so words never collide
//   - Excludes non-content tags entirely (<script>, <style>, <noscript>, <svg>, <canvas>)
//   - Normalizes excessive whitespace while preserving meaningful paragraph breaks
func (el *HTMLElement) Text() string {
	if el == nil || el.node == nil {
		return ""
	}
	return formatNodeText(el.node)
}

// Text extracts clean, beautifully formatted text from the entire document body.
func (doc *HTMLDocument) Text() string {
	if doc == nil || doc.root == nil {
		return ""
	}
	// Focus on <body> if present, otherwise root
	bodyEl := doc.FindOne("body")
	if bodyEl != nil {
		return bodyEl.Text()
	}
	return formatNodeText(doc.root)
}

// RawText returns raw, unformatted text without synthesized block newlines.
func (el *HTMLElement) RawText() string {
	if el == nil || el.node == nil {
		return ""
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if tag == "script" || tag == "style" || tag == "noscript" || tag == "svg" || tag == "canvas" {
				return
			}
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(el.node)
	return strings.TrimSpace(b.String())
}

// InnerHTML serializes the inner child nodes of this element to an HTML string.
func (el *HTMLElement) InnerHTML() (string, error) {
	if el == nil || el.node == nil {
		return "", nil
	}
	var b bytes.Buffer
	for c := el.node.FirstChild; c != nil; c = c.NextSibling {
		if err := html.Render(&b, c); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// OuterHTML serializes this element including its tag, attributes, and children to an HTML string.
func (el *HTMLElement) OuterHTML() (string, error) {
	if el == nil || el.node == nil {
		return "", nil
	}
	var b bytes.Buffer
	if err := html.Render(&b, el.node); err != nil {
		return "", err
	}
	return b.String(), nil
}

// formatNodeText walks the HTML DOM tree and formats readable text respecting layout semantics.
func formatNodeText(root *html.Node) string {
	var b strings.Builder

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n == nil {
			return
		}

		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)

			// Skip non-visible / non-content elements
			if isIgnoredTag(tag) {
				return
			}

			// Pre-block line break
			if isBlockTag(tag) {
				ensureTrailingNewline(&b)
			} else if tag == "br" || tag == "hr" {
				b.WriteString("\n")
				return
			} else if tag == "td" || tag == "th" {
				// Separate table columns with space/tab
				if b.Len() > 0 && !endsWithWhitespace(b.String()) {
					b.WriteString(" ")
				}
			}
		} else if n.Type == html.TextNode {
			text := normalizeTextChunk(n.Data)
			if text == "" {
				// Pure whitespace node between inline elements (e.g. <b>Hello</b> <i>world</i>)
				if len(n.Data) > 0 && b.Len() > 0 && !endsWithWhitespace(b.String()) {
					b.WriteString(" ")
				}
			} else {
				if startsWithWhitespace(n.Data) && b.Len() > 0 && !endsWithWhitespace(b.String()) {
					b.WriteString(" ")
				}
				b.WriteString(text)
				if endsWithWhitespace(n.Data) {
					b.WriteString(" ")
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}

		// Post-block line break
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if isDoubleBreakBlock(tag) {
				ensureTrailingDoubleNewline(&b)
			} else if isBlockTag(tag) {
				ensureTrailingNewline(&b)
			}
		}
	}

	walk(root)
	return cleanResultText(b.String())
}

func isIgnoredTag(tag string) bool {
	switch tag {
	case "script", "style", "noscript", "svg", "canvas", "iframe", "template", "head":
		return true
	default:
		return false
	}
}

func isBlockTag(tag string) bool {
	switch tag {
	case "div", "p", "h1", "h2", "h3", "h4", "h5", "h6",
		"article", "section", "header", "footer", "nav", "aside",
		"li", "ul", "ol", "tr", "table", "blockquote", "pre", "form":
		return true
	default:
		return false
	}
}

func isDoubleBreakBlock(tag string) bool {
	switch tag {
	case "p", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "article", "section":
		return true
	default:
		return false
	}
}

func ensureTrailingNewline(b *strings.Builder) {
	s := b.String()
	if len(s) > 0 && !strings.HasSuffix(s, "\n") {
		b.WriteString("\n")
	}
}

func ensureTrailingDoubleNewline(b *strings.Builder) {
	s := b.String()
	if len(s) == 0 {
		return
	}
	if strings.HasSuffix(s, "\n\n") {
		return
	}
	if strings.HasSuffix(s, "\n") {
		b.WriteString("\n")
	} else {
		b.WriteString("\n\n")
	}
}

func endsWithWhitespace(s string) bool {
	if len(s) == 0 {
		return false
	}
	last := s[len(s)-1]
	return last == ' ' || last == '\t' || last == '\n' || last == '\r'
}

func startsWithWhitespace(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := s[0]
	return first == ' ' || first == '\t' || first == '\n' || first == '\r'
}

func normalizeTextChunk(s string) string {
	// Collapse multiple spaces/tabs into a single space
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

func cleanResultText(s string) string {
	lines := strings.Split(s, "\n")
	var cleaned []string
	consecutiveEmpty := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			consecutiveEmpty++
			if consecutiveEmpty <= 1 && len(cleaned) > 0 {
				cleaned = append(cleaned, "")
			}
		} else {
			consecutiveEmpty = 0
			cleaned = append(cleaned, trimmed)
		}
	}

	return strings.TrimSpace(strings.Join(cleaned, "\n"))
}
