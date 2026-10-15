package torscraper

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// HTMLDocument represents a parsed HTML page with convenient traversal methods.
type HTMLDocument struct {
	root     *html.Node
	finalURL *url.URL
}

// HTMLElement wraps an individual html.Node with text and attribute helpers.
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

// Title returns the page title (<title> text).
func (doc *HTMLDocument) Title() string {
	var title string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.ToLower(n.Data) == "title" {
			if n.FirstChild != nil {
				title = strings.TrimSpace(n.FirstChild.Data)
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc.root)
	return title
}

// FindByTag returns all elements with the specified tag name.
func (doc *HTMLDocument) FindByTag(tag string) []*HTMLElement {
	tag = strings.ToLower(tag)
	var matches []*HTMLElement
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.ToLower(n.Data) == tag {
			matches = append(matches, &HTMLElement{node: n, finalURL: doc.finalURL})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc.root)
	return matches
}

// FindByID returns the single element matching the given id attribute.
func (doc *HTMLDocument) FindByID(id string) *HTMLElement {
	var match *HTMLElement
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if match != nil {
			return
		}
		if n.Type == html.ElementNode {
			for _, a := range n.Attr {
				if a.Key == "id" && a.Val == id {
					match = &HTMLElement{node: n, finalURL: doc.finalURL}
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc.root)
	return match
}

// FindByClass returns all elements containing the specified CSS class.
func (doc *HTMLDocument) FindByClass(className string) []*HTMLElement {
	var matches []*HTMLElement
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, a := range n.Attr {
				if a.Key == "class" {
					classes := strings.Fields(a.Val)
					for _, c := range classes {
						if c == className {
							matches = append(matches, &HTMLElement{node: n, finalURL: doc.finalURL})
							break
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc.root)
	return matches
}

// Links extracts all <a href="..."> links, resolved to absolute URLs.
func (doc *HTMLDocument) Links() []string {
	var links []string
	elements := doc.FindByTag("a")
	for _, el := range elements {
		href := el.Attr("href")
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			continue
		}
		if doc.finalURL != nil {
			ref, err := url.Parse(href)
			if err == nil {
				links = append(links, doc.finalURL.ResolveReference(ref).String())
				continue
			}
		}
		links = append(links, href)
	}
	return links
}

// Images extracts all <img src="..."> image URLs, resolved to absolute URLs.
func (doc *HTMLDocument) Images() []string {
	var images []string
	elements := doc.FindByTag("img")
	for _, el := range elements {
		src := el.Attr("src")
		if src == "" || strings.HasPrefix(src, "data:") {
			continue
		}
		if doc.finalURL != nil {
			ref, err := url.Parse(src)
			if err == nil {
				images = append(images, doc.finalURL.ResolveReference(ref).String())
				continue
			}
		}
		images = append(images, src)
	}
	return images
}

// Text extracts all inner text content from this element and its children.
func (el *HTMLElement) Text() string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
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

// Attr returns the value of an attribute on this element, or empty string.
func (el *HTMLElement) Attr(key string) string {
	key = strings.ToLower(key)
	for _, a := range el.node.Attr {
		if strings.ToLower(a.Key) == key {
			return a.Val
		}
	}
	return ""
}

// Tag returns the HTML tag name of this element.
func (el *HTMLElement) Tag() string {
	return el.node.Data
}
