package torscraper

import (
	"math/rand"

	utls "github.com/refraction-networking/utls"
)

// BrowserProfile identifies a specific browser fingerprint to emulate.
type BrowserProfile int

const (
	// ProfileNone uses standard Go net/http TLS and does not inject browser headers.
	ProfileNone BrowserProfile = iota

	// ProfileChrome emulates modern Google Chrome (ClientHello + Chrome headers).
	ProfileChrome

	// ProfileFirefox emulates modern Mozilla Firefox (ClientHello + Firefox headers).
	ProfileFirefox

	// ProfileSafari emulates Apple Safari (ClientHello + Safari headers).
	ProfileSafari

	// ProfileEdge emulates Microsoft Edge (ClientHello + Edge headers).
	ProfileEdge
)

// ProfileConfig holds browser-specific settings for TLS and HTTP headers.
type ProfileConfig struct {
	ClientHelloID utls.ClientHelloID
	UserAgent     string
	DefaultHeaders map[string]string
}

// GetProfileConfig returns the profile configuration for a given BrowserProfile.
func GetProfileConfig(profile BrowserProfile) ProfileConfig {
	switch profile {
	case ProfileChrome:
		return ProfileConfig{
			ClientHelloID: utls.HelloChrome_120,
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			DefaultHeaders: map[string]string{
				"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
				"sec-ch-ua-mobile":          "?0",
				"sec-ch-ua-platform":        `"Windows"`,
				"upgrade-insecure-requests": "1",
				"user-agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"sec-fetch-site":            "none",
				"sec-fetch-mode":            "navigate",
				"sec-fetch-user":            "?1",
				"sec-fetch-dest":            "document",
				"accept-language":           "en-US,en;q=0.9",
				"accept-encoding":           "gzip, deflate, br",
			},
		}
	case ProfileFirefox:
		return ProfileConfig{
			ClientHelloID: utls.HelloFirefox_120,
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			DefaultHeaders: map[string]string{
				"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
				"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
				"accept-language": "en-US,en;q=0.5",
				"accept-encoding": "gzip, deflate, br",
				"upgrade-insecure-requests": "1",
				"sec-fetch-dest":  "document",
				"sec-fetch-mode":  "navigate",
				"sec-fetch-site":  "none",
				"sec-fetch-user":  "?1",
			},
		}
	case ProfileSafari:
		return ProfileConfig{
			ClientHelloID: utls.HelloSafari_16_0,
			UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
			DefaultHeaders: map[string]string{
				"user-agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
				"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"accept-language": "en-US,en;q=0.9",
				"accept-encoding": "gzip, deflate, br",
			},
		}
	case ProfileEdge:
		return ProfileConfig{
			ClientHelloID: utls.HelloEdge_106,
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			DefaultHeaders: map[string]string{
				"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
				"sec-ch-ua-mobile":          "?0",
				"sec-ch-ua-platform":        `"Windows"`,
				"upgrade-insecure-requests": "1",
				"user-agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
				"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
				"sec-fetch-site":            "none",
				"sec-fetch-mode":            "navigate",
				"sec-fetch-user":            "?1",
				"sec-fetch-dest":            "document",
				"accept-language":           "en-US,en;q=0.9",
				"accept-encoding":           "gzip, deflate, br",
			},
		}
	default:
		return ProfileConfig{
			ClientHelloID:  utls.ClientHelloID{},
			DefaultHeaders: map[string]string{},
		}
	}
}

// ProfileRotationMode defines how browser fingerprints and User-Agents are rotated.
type ProfileRotationMode int

const (
	// RotateDisabled keeps the configured profile static.
	RotateDisabled ProfileRotationMode = iota

	// RotatePerRequest picks a new synchronized profile for every request.
	RotatePerRequest

	// RotatePerSession picks a random profile on client initialization.
	RotatePerSession
)

// activeRotationProfiles contains synchronized browser profiles for rotation.
var activeRotationProfiles = []BrowserProfile{
	ProfileChrome,
	ProfileFirefox,
	ProfileSafari,
	ProfileEdge,
}

// GetRandomProfileConfig returns a randomly selected synchronized browser profile.
func GetRandomProfileConfig() ProfileConfig {
	profile := activeRotationProfiles[rand.Intn(len(activeRotationProfiles))]
	return GetProfileConfig(profile)
}
