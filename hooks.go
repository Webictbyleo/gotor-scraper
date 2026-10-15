package torscraper

import (
	"net/http"
	"time"
)

// Hooks provides lifecycle callbacks for observability, structured logging, and metrics.
type Hooks struct {
	// OnRequest is invoked immediately before an HTTP request is transmitted.
	OnRequest func(req *http.Request)

	// OnResponse is invoked when an HTTP response is successfully received and parsed.
	OnResponse func(resp *Response, duration time.Duration)

	// OnError is invoked when an HTTP request fails.
	OnError func(req *http.Request, err error, attempt int)

	// OnRetry is invoked before waiting and retrying a failed request.
	OnRetry func(req *http.Request, err error, attempt int, backoff time.Duration)

	// OnProxyRotate is invoked when traffic switches to a different proxy node.
	OnProxyRotate func(oldProxy, newProxy string)
}

// Clone creates a shallow copy of Hooks.
func (h *Hooks) Clone() *Hooks {
	if h == nil {
		return nil
	}
	cpy := *h
	return &cpy
}
