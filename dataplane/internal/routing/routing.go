// Package routing normalizes the attacker-controlled Host value and resolves
// it against the static route table. This parser is fuzzed: it sits directly
// on unauthenticated input (spec section 11 test strategy).
package routing

import (
	"strings"

	"hyproxy/dataplane/internal/config"
)

// Kind classifies a lookup result.
type Kind int

const (
	KindNone Kind = iota // unknown host: reveal nothing, route nowhere
	KindAuth             // the gateway host (control-plane auth endpoints)
	KindApp              // an allowlisted application route
)

// NormalizeHost lowercases, strips an optional :port and trailing dot, and
// rejects anything that is not a plausible DNS name or IPv4 literal.
// Bracketed IPv6 literals are rejected outright (IPv6 is disabled at the
// edge by design).
func NormalizeHost(raw string) (string, bool) {
	if raw == "" || len(raw) > 255 {
		return "", false
	}
	host := raw
	if strings.HasPrefix(host, "[") {
		return "", false // IPv6 disabled at the edge
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		port := host[i+1:]
		if port == "" || len(port) > 5 {
			return "", false
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", false
			}
		}
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", false
	}
	host = strings.ToLower(host)
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
			if !ok {
				return "", false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
	}
	return host, true
}

// Table is the immutable routing table built from config at startup.
type Table struct {
	authHost string
	routes   map[string]config.Route
}

func NewTable(cfg *config.Config) *Table {
	return &Table{authHost: cfg.AuthHost, routes: cfg.Routes}
}

// Lookup resolves a raw Host header. Unknown or malformed hosts return
// KindNone; callers must respond minimally (421) without touching backends.
func (t *Table) Lookup(rawHost string) (config.Route, string, Kind) {
	host, ok := NormalizeHost(rawHost)
	if !ok {
		return config.Route{}, "", KindNone
	}
	if host == t.authHost {
		return config.Route{}, host, KindAuth
	}
	if route, found := t.routes[host]; found {
		return route, host, KindApp
	}
	return config.Route{}, "", KindNone
}
