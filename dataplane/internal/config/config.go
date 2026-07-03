// Package config loads and validates the data-plane configuration.
//
// SSRF invariant (spec section 11): the proxy dials ONLY the backends listed
// here, selected by the normalized Host header. Nothing about the target is
// ever taken from client input.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Route maps one public host to one allowlisted internal backend.
type Route struct {
	// Backend is the internal origin, e.g. "http://10.0.0.5:32400".
	Backend string `json:"backend"`
	// BackendPort is reported to the policy engine; derived from Backend if 0.
	BackendPort int `json:"backend_port"`
	// Auth gates the route behind forward-auth (default true; only the auth
	// host itself should ever disable it).
	Auth *bool `json:"auth,omitempty"`
	// GuacTunnel marks a Guacamole WebSocket tunnel backend (the Node
	// guacamole-lite service). Such routes are authorized by single-use grant
	// consumption (/guac/consume) instead of the per-request /authz/check.
	GuacTunnel bool `json:"guac_tunnel,omitempty"`
}

func (r Route) AuthRequired() bool { return r.Auth == nil || *r.Auth }

type Config struct {
	// Listen is the single public ingress, e.g. ":443".
	Listen  string `json:"listen"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// AuthzURL is the control plane's authz service, e.g. "http://127.0.0.1:8500".
	AuthzURL string `json:"authz_url"`
	// AuthHost is the public hostname for the gateway endpoints.
	AuthHost string `json:"auth_host"`
	// AuthBackend serves /gateway/* for AuthHost (usually the authz service).
	AuthBackend string `json:"auth_backend"`
	// GatewayCookieName is extracted for authz checks and stripped upstream.
	GatewayCookieName string `json:"gateway_cookie_name"`
	// Routes are the STATIC infra routes (idp/admin), read once at startup. App
	// routes are DB-driven and fetched from the control plane at runtime; static
	// routes win on host conflict. May be empty.
	Routes map[string]Route `json:"routes"`
	// GuacBackend is the origin the data plane routes Guacamole tunnel resources
	// (vnc/rdp/ssh) to (the Node guacamole-lite service). DB guac routes carry no
	// backend of their own; this supplies it. Empty disables DB guac routes.
	GuacBackend string `json:"guac_backend"`
	// RoutesRefreshSecs is how often to poll the control plane for DB routes.
	// Zero uses DefaultRoutesRefreshSecs.
	RoutesRefreshSecs int `json:"routes_refresh_secs"`
}

// DefaultRoutesRefreshSecs is the DB-route poll interval when unset.
const DefaultRoutesRefreshSecs = 10

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		return fmt.Errorf("tls_cert and tls_key are required")
	}
	if c.AuthzURL == "" || c.AuthHost == "" || c.AuthBackend == "" {
		return fmt.Errorf("authz_url, auth_host, and auth_backend are required")
	}
	if c.GatewayCookieName == "" {
		c.GatewayCookieName = "__Secure-gw"
	}
	if c.RoutesRefreshSecs == 0 {
		c.RoutesRefreshSecs = DefaultRoutesRefreshSecs
	}
	if c.GuacBackend != "" {
		if _, err := parseBackend(c.GuacBackend); err != nil {
			return fmt.Errorf("guac_backend: %w", err)
		}
	}
	c.AuthHost = strings.ToLower(c.AuthHost)
	if _, err := parseBackend(c.AuthBackend); err != nil {
		return fmt.Errorf("auth_backend: %w", err)
	}
	if _, err := parseBackend(c.AuthzURL); err != nil {
		return fmt.Errorf("authz_url: %w", err)
	}
	normalized := make(map[string]Route, len(c.Routes))
	for host, route := range c.Routes {
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		if h == "" || strings.ContainsAny(h, " /?#@\\") {
			return fmt.Errorf("invalid route host %q", host)
		}
		u, err := parseBackend(route.Backend)
		if err != nil {
			return fmt.Errorf("route %s: %w", host, err)
		}
		if route.BackendPort == 0 {
			route.BackendPort = portOf(u)
		}
		normalized[h] = route
	}
	c.Routes = normalized
	return nil
}

func parseBackend(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("backend must be an absolute http(s) URL, got %q", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("backend must not carry a path, got %q", raw)
	}
	return u, nil
}

func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		var n int
		fmt.Sscanf(p, "%d", &n)
		return n
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
