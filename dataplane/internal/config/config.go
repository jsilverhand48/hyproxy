// Package config loads and validates the data-plane configuration.
//
// SSRF invariant (spec section 11): the proxy dials ONLY the backends listed
// here, selected by the normalized Host header. Nothing about the target is
// ever taken from client input.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
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
	// GuacTunnelPath serves the Guacamole WebSocket tunnel on this route's
	// fixed /guac/tunnel path (everything else proxies to Backend as usual).
	// Set on the apps portal route only; guac resources carry no public host
	// of their own.
	GuacTunnelPath bool `json:"guac_tunnel_path,omitempty"`
	// LanOnly restricts the route to clients whose TCP peer address is inside
	// the LAN networks (Config.LanCidrs, or the host's own interface subnets
	// when unset). Blocked browsers are redirected to Config.LanOnlyRedirect.
	// Set on the admin console route: it must never be reachable from the
	// internet, even by an authenticated admin.
	LanOnly bool `json:"lan_only,omitempty"`
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
	// LanCidrs is the explicit allowlist of client networks for lan_only routes
	// (e.g. ["10.0.0.0/24"]). Empty means the data plane auto-detects the
	// subnets of the host's own network interfaces at startup, so "LAN" is
	// "the same subnet(s) as this server".
	LanCidrs []string `json:"lan_cidrs,omitempty"`
	// LanOnlyRedirect is where browsers (GET/HEAD) blocked by a lan_only route
	// are sent, typically the IdP login page. Non-GET/HEAD requests and an
	// empty value get a plain 403.
	LanOnlyRedirect string `json:"lan_only_redirect,omitempty"`
	// LogDir is the centralized log directory (e.g. "/var/log/hyproxy").
	// When set, the data plane writes dataplane.log (service log, also still
	// mirrored to stderr for journald) and dataplane-access.log (per-request
	// access log, file only). Empty keeps stderr-only logging.
	LogDir string `json:"log_dir,omitempty"`
	// LogLevel is one of debug|info|warn|error. Empty means info.
	LogLevel string `json:"log_level,omitempty"`
	// LogMaxBytes rotates a log file once it reaches this size. Zero uses
	// DefaultLogMaxBytes.
	LogMaxBytes int64 `json:"log_max_bytes,omitempty"`
	// LogBackupCount is how many rotated archives to keep (x.log.1 ... x.log.N);
	// older archives are deleted. Zero uses DefaultLogBackupCount.
	LogBackupCount int `json:"log_backup_count,omitempty"`
	// UpstreamInsecureSkipVerify disables TLS certificate verification when the
	// proxy dials https backends. Operator escape hatch for backends with
	// self-signed or IP-only certs (e.g. Plex on a bare IP); it does NOT relax
	// the public listener's TLS or the SSRF allowlist. Leave false in any
	// setting where upstream traffic can be tampered with.
	UpstreamInsecureSkipVerify bool `json:"upstream_insecure_skip_verify,omitempty"`

	// --- Bot / robot traffic filter (dropped at the edge before routing) ---

	// BlockedUserAgents are regular expressions matched against the request
	// User-Agent header; any match drops the connection. Compiled at startup.
	BlockedUserAgents []string `json:"blocked_user_agents,omitempty"`
	// BlockEmptyUserAgent drops requests that carry no User-Agent header.
	BlockEmptyUserAgent bool `json:"block_empty_user_agent,omitempty"`
	// BlockedASNs are autonomous system numbers (typically cloud/hosting
	// providers) to drop. Requires GeoIPASNDB.
	BlockedASNs []uint `json:"blocked_asns,omitempty"`
	// BlockedPTRSuffixes are reverse-DNS hostname suffixes (e.g.
	// "amazonaws.com") whose IPs are dropped: an IP that resolves to a hosting
	// domain is almost never a residential client.
	BlockedPTRSuffixes []string `json:"blocked_ptr_suffixes,omitempty"`
	// BlockAnyResolvablePTR is the aggressive mode: drop ANY source IP that
	// returns a PTR record at all. Caveat: many residential ISPs also assign
	// PTRs (comcast.net, rr.com, ...), so this over-blocks real users. Off by
	// default; prefer BlockedPTRSuffixes.
	BlockAnyResolvablePTR bool `json:"block_any_resolvable_ptr,omitempty"`
	// BlockedCountries are ISO 3166-1 alpha-2 country codes to drop by
	// IP geolocation. Requires GeoIPCountryDB.
	BlockedCountries []string `json:"blocked_countries,omitempty"`
	// GeoIPASNDB is the path to a MaxMind GeoLite2-ASN .mmdb. Required when
	// BlockedASNs is non-empty.
	GeoIPASNDB string `json:"geoip_asn_db,omitempty"`
	// GeoIPCountryDB is the path to a MaxMind GeoLite2-Country .mmdb. Required
	// when BlockedCountries is non-empty.
	GeoIPCountryDB string `json:"geoip_country_db,omitempty"`
	// BotFilterCacheTTLSecs is how long a per-source-IP verdict (ASN/geo/PTR) is
	// cached. Zero uses DefaultBotFilterCacheTTLSecs.
	BotFilterCacheTTLSecs int `json:"botfilter_cache_ttl_secs,omitempty"`
}

// DefaultRoutesRefreshSecs is the DB-route poll interval when unset.
const DefaultRoutesRefreshSecs = 10

// Rotation defaults shared with the control plane (HYPROXY_LOG_MAX_BYTES /
// HYPROXY_LOG_BACKUP_COUNT): 50 MB per file, 2 archives kept.
const (
	DefaultLogMaxBytes    = 52428800
	DefaultLogBackupCount = 2
)

// DefaultBotFilterCacheTTLSecs is the per-source-IP verdict cache lifetime when
// unset (5 minutes: ASN/geo/PTR of an IP are stable over that window).
const DefaultBotFilterCacheTTLSecs = 300

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
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug|info|warn|error, got %q", c.LogLevel)
	}
	if c.LogMaxBytes == 0 {
		c.LogMaxBytes = DefaultLogMaxBytes
	}
	if c.LogBackupCount == 0 {
		c.LogBackupCount = DefaultLogBackupCount
	}
	if c.GuacBackend != "" {
		if _, err := parseBackend(c.GuacBackend); err != nil {
			return fmt.Errorf("guac_backend: %w", err)
		}
	}
	for _, cidr := range c.LanCidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("lan_cidrs: %w", err)
		}
	}
	if c.LanOnlyRedirect != "" {
		u, err := url.Parse(c.LanOnlyRedirect)
		if err != nil {
			return fmt.Errorf("lan_only_redirect: %w", err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("lan_only_redirect must be an absolute http(s) URL, got %q", c.LanOnlyRedirect)
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
		if route.GuacTunnelPath && c.GuacBackend == "" {
			return fmt.Errorf("route %s: guac_tunnel_path requires guac_backend", host)
		}
		normalized[h] = route
	}
	c.Routes = normalized
	if err := c.validateBotFilter(); err != nil {
		return err
	}
	return nil
}

// validateBotFilter checks the bot-filter config: user-agent patterns must
// compile, country codes must be alpha-2, and a MaxMind database path is
// required (and must exist) whenever its corresponding block list is used.
func (c *Config) validateBotFilter() error {
	for _, pat := range c.BlockedUserAgents {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("blocked_user_agents: bad pattern %q: %w", pat, err)
		}
	}
	normCountries := make([]string, 0, len(c.BlockedCountries))
	for _, code := range c.BlockedCountries {
		code = strings.ToUpper(strings.TrimSpace(code))
		if len(code) != 2 {
			return fmt.Errorf("blocked_countries: %q is not a 2-letter ISO code", code)
		}
		normCountries = append(normCountries, code)
	}
	c.BlockedCountries = normCountries
	if len(c.BlockedASNs) > 0 {
		if err := statMMDB("geoip_asn_db", c.GeoIPASNDB); err != nil {
			return err
		}
	}
	if len(c.BlockedCountries) > 0 {
		if err := statMMDB("geoip_country_db", c.GeoIPCountryDB); err != nil {
			return err
		}
	}
	if c.BotFilterCacheTTLSecs == 0 {
		c.BotFilterCacheTTLSecs = DefaultBotFilterCacheTTLSecs
	}
	return nil
}

func statMMDB(field, path string) error {
	if path == "" {
		return fmt.Errorf("%s is required when its block list is non-empty", field)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
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
