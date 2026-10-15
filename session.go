package torscraper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// SerializableCookie represents an individual cookie formatted for JSON serialization.
type SerializableCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path"`
	Domain   string    `json:"domain"`
	HostOnly bool      `json:"host_only,omitempty"`
	Scheme   string    `json:"scheme,omitempty"`
	Expires  time.Time `json:"expires"`
	MaxAge   int       `json:"max_age"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"http_only"`
}

// PersistentCookieJar implements http.CookieJar with automatic disk persistence.
type PersistentCookieJar struct {
	jar      *cookiejar.Jar
	filePath string
	autoSave bool
	mu       sync.Mutex

	// In-memory cookie registry for export/serialization: map[host]map[cookieName]*http.Cookie
	registry map[string]map[string]*http.Cookie
}

// NewPersistentCookieJar creates or loads a persistent cookie jar from a JSON file.
func NewPersistentCookieJar(filePath string, autoSave bool) (*PersistentCookieJar, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create base cookie jar: %w", err)
	}

	pj := &PersistentCookieJar{
		jar:      jar,
		filePath: filePath,
		autoSave: autoSave,
		registry: make(map[string]map[string]*http.Cookie),
	}

	// Auto-load if file exists
	if filePath != "" {
		if _, err := os.Stat(filePath); err == nil {
			if err := pj.Load(); err != nil {
				return nil, fmt.Errorf("failed to load existing session from %s: %w", filePath, err)
			}
		}
	}

	return pj, nil
}

// NewSessionDirJar creates a persistent cookie jar stored inside a session directory.
func NewSessionDirJar(dirPath, sessionName string, autoSave bool) (*PersistentCookieJar, error) {
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory %s: %w", dirPath, err)
	}
	if sessionName == "" {
		sessionName = "default_session"
	}
	if !strings.HasSuffix(sessionName, ".json") {
		sessionName += ".json"
	}
	return NewPersistentCookieJar(filepath.Join(dirPath, sessionName), autoSave)
}

// SetCookies stores cookies in the jar and optionally auto-saves to disk.
func (pj *PersistentCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	pj.mu.Lock()
	defer pj.mu.Unlock()

	pj.jar.SetCookies(u, cookies)

	// Update registry for persistence
	host := u.Host
	if host != "" {
		if pj.registry[host] == nil {
			pj.registry[host] = make(map[string]*http.Cookie)
		}
		for _, c := range cookies {
			pj.registry[host][c.Name] = c
		}
	}

	if pj.autoSave && pj.filePath != "" {
		_ = pj.saveLocked()
	}
}

// Cookies returns the cookies to send in a request for the given URL.
func (pj *PersistentCookieJar) Cookies(u *url.URL) []*http.Cookie {
	pj.mu.Lock()
	defer pj.mu.Unlock()
	return pj.jar.Cookies(u)
}

// Save flushes current cookies to disk as formatted JSON.
func (pj *PersistentCookieJar) Save() error {
	pj.mu.Lock()
	defer pj.mu.Unlock()
	return pj.saveLocked()
}

func (pj *PersistentCookieJar) saveLocked() error {
	if pj.filePath == "" {
		return nil
	}

	// Ensure parent directory exists
	dir := filepath.Dir(pj.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	flatList := make([]SerializableCookie, 0)
	for host, cookies := range pj.registry {
		for _, c := range cookies {
			isHostOnly := (c.Domain == "")
			domain := c.Domain
			if domain == "" {
				domain = host
			}
			flatList = append(flatList, SerializableCookie{
				Name:     c.Name,
				Value:    c.Value,
				Path:     c.Path,
				Domain:   domain,
				HostOnly: isHostOnly,
				Expires:  c.Expires,
				MaxAge:   c.MaxAge,
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
			})
		}
	}

	data, err := json.MarshalIndent(flatList, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode cookies to JSON: %w", err)
	}

	// Write atomically via temporary file
	tmpFile := pj.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, pj.filePath)
}

// Load reads cookies from disk and populates the jar.
func (pj *PersistentCookieJar) Load() error {
	pj.mu.Lock()
	defer pj.mu.Unlock()

	data, err := os.ReadFile(pj.filePath)
	if err != nil {
		return err
	}

	var flatList []SerializableCookie
	if err := json.Unmarshal(data, &flatList); err != nil {
		return fmt.Errorf("invalid cookie JSON in %s: %w", pj.filePath, err)
	}

	for _, sc := range flatList {
		cookieDomain := sc.Domain
		if sc.HostOnly {
			cookieDomain = ""
		}

		c := &http.Cookie{
			Name:     sc.Name,
			Value:    sc.Value,
			Path:     sc.Path,
			Domain:   cookieDomain,
			Expires:  sc.Expires,
			MaxAge:   sc.MaxAge,
			Secure:   sc.Secure,
			HttpOnly: sc.HttpOnly,
		}

		cookiePath := sc.Path
		if cookiePath == "" {
			cookiePath = "/"
		}

		// Inject for HTTP (needed for non-TLS test servers or unencrypted endpoints)
		uHTTP := &url.URL{
			Scheme: "http",
			Host:   sc.Domain,
			Path:   cookiePath,
		}
		pj.jar.SetCookies(uHTTP, []*http.Cookie{c})

		// Inject for HTTPS if not restricted to plain HTTP
		if !sc.Secure {
			uHTTPS := &url.URL{
				Scheme: "https",
				Host:   sc.Domain,
				Path:   cookiePath,
			}
			pj.jar.SetCookies(uHTTPS, []*http.Cookie{c})
		}

		if pj.registry[sc.Domain] == nil {
			pj.registry[sc.Domain] = make(map[string]*http.Cookie)
		}
		pj.registry[sc.Domain][sc.Name] = c
	}

	return nil
}

// FilePath returns the file path of this persistent session.
func (pj *PersistentCookieJar) FilePath() string {
	return pj.filePath
}
