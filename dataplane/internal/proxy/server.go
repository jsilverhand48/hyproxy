// Package proxy is the data plane's HTTP handler: normalize the routing key,
// forward-auth every app request, enforce identity-header hygiene, and
// reverse-proxy only to allowlisted backends.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyproxy/dataplane/internal/authz"
	"hyproxy/dataplane/internal/botfilter"
	"hyproxy/dataplane/internal/config"
	"hyproxy/dataplane/internal/routing"
)

// Identity headers only the control plane may set. Client-supplied copies are
// stripped unconditionally (spec section 6: spoofed X-Forwarded-User is a
// full auth bypass).
var identityHeaders = []string{"X-Forwarded-User", "X-Auth-User-Id", "X-Auth-Roles"}

type AuthzChecker interface {
	Check(ctx context.Context, req authz.CheckRequest) (authz.CheckResponse, error)
	ConsumeGuac(ctx context.Context, req authz.ConsumeRequest) (bool, error)
}

// routeSet is one immutable routing snapshot: a lookup table and the reverse
// proxies for its app routes, always built together so a Host lookup and its
// backend proxy come from the same generation. Swapped atomically when the
// DB-driven route table changes (SwapRoutes); ServeHTTP loads it once per
// request.
type routeSet struct {
	table   *routing.Table
	proxies map[string]*httputil.ReverseProxy
}

type Server struct {
	authz      AuthzChecker
	cookieName string
	authProxy  *httputil.ReverseProxy
	routes     atomic.Pointer[routeSet]
	log        *slog.Logger

	// Host-scope allow decisions cached per control-plane hint; purged
	// whenever the route table actually changes.
	authzCache *authzCache
	// swapMu serializes SwapRoutes so lastDBRoutes and the snapshot/cache
	// purge stay consistent; lastDBRoutes detects no-op swaps from the
	// periodic route poller (an unconditional purge would cap the decision
	// cache's effective lifetime at the poll interval).
	swapMu       sync.Mutex
	lastDBRoutes map[string]config.Route

	// Fixed at startup, used to rebuild routeSets on swap.
	authHost     string
	staticRoutes map[string]config.Route
	guacBackend  string
	// guacProxy serves the fixed /guac/tunnel path on routes flagged
	// guac_tunnel_path (the apps portal host). Nil when guac_backend is unset;
	// config.Validate guarantees no route carries the flag in that case.
	guacProxy *httputil.ReverseProxy
	// LAN client allowlist for lan_only routes (config lan_cidrs, or the
	// host's own interface subnets when unset) and where blocked browsers
	// are redirected (the IdP login page).
	lanNets         []*net.IPNet
	lanOnlyRedirect string
	// transport backs every upstream proxy: one shared pool tuned for
	// streaming (see newUpstreamTransport). TLS verification is disabled
	// only when upstream_insecure_skip_verify is set.
	transport http.RoundTripper
	// botFilter drops robot/bot traffic (bad User-Agent, cloud/hosting source
	// networks) at the top of ServeHTTP. Nil when no bot-filter signal is
	// configured, in which case the check is skipped entirely.
	botFilter *botfilter.Filter
}

func NewServer(cfg *config.Config, checker AuthzChecker, log *slog.Logger) (*Server, error) {
	authBackend, err := url.Parse(cfg.AuthBackend)
	if err != nil {
		return nil, err
	}
	transport := newUpstreamTransport(cfg.UpstreamInsecureSkipVerify)
	if cfg.UpstreamInsecureSkipVerify {
		log.Warn("upstream TLS verification disabled for https backends (upstream_insecure_skip_verify=true)")
	}
	lanNets, err := resolveLanNets(cfg, log)
	if err != nil {
		return nil, err
	}
	bf, err := botfilter.New(cfg)
	if err != nil {
		return nil, err
	}
	if bf != nil {
		log.Info("bot filter enabled")
	}
	s := &Server{
		authz:           checker,
		cookieName:      cfg.GatewayCookieName,
		authProxy:       newReverseProxy(authBackend, log, transport),
		log:             log,
		authzCache:      newAuthzCache(),
		authHost:        cfg.AuthHost,
		staticRoutes:    cfg.Routes,
		guacBackend:     cfg.GuacBackend,
		lanNets:         lanNets,
		lanOnlyRedirect: cfg.LanOnlyRedirect,
		transport:       transport,
		botFilter:       bf,
	}
	if cfg.GuacBackend != "" {
		u, err := url.Parse(cfg.GuacBackend)
		if err != nil {
			return nil, err
		}
		s.guacProxy = newReverseProxy(u, log, transport)
	}
	// Initial snapshot: static infra routes only. The management plane
	// (idp/admin) is reachable even if the control plane is down at boot; DB
	// app routes are layered on by the first successful SwapRoutes.
	rs, err := s.buildRouteSet(nil)
	if err != nil {
		return nil, err
	}
	s.routes.Store(rs)
	return s, nil
}

// buildRouteSet merges the static infra routes with dbRoutes (static wins on
// host conflict), resolves Guacamole tunnel backends to guacBackend, and
// constructs a reverse proxy per app route. A route with an unparseable or
// missing backend is skipped (logged), never fatal: one bad DB row must not
// take down the whole table.
func (s *Server) buildRouteSet(dbRoutes map[string]config.Route) (*routeSet, error) {
	merged := make(map[string]config.Route, len(dbRoutes)+len(s.staticRoutes))
	for host, r := range dbRoutes {
		merged[host] = r
	}
	for host, r := range s.staticRoutes {
		merged[host] = r // static infra routes take precedence
	}
	proxies := make(map[string]*httputil.ReverseProxy, len(merged))
	for host, route := range merged {
		backend := route.Backend
		if backend == "" && route.GuacTunnel {
			backend = s.guacBackend // DB guac routes carry no backend of their own
		}
		if backend == "" {
			s.log.Warn("skipping route with no backend", "host", host, "guac", route.GuacTunnel)
			delete(merged, host)
			continue
		}
		u, err := url.Parse(backend)
		if err != nil {
			s.log.Warn("skipping route with bad backend", "host", host, "backend", backend, "err", err)
			delete(merged, host)
			continue
		}
		proxies[host] = newReverseProxy(u, s.log, s.transport)
	}
	return &routeSet{table: routing.NewTableFrom(s.authHost, merged), proxies: proxies}, nil
}

// SwapRoutes rebuilds the routing snapshot from a fresh set of DB routes and
// installs it atomically. In-flight requests keep using the previous snapshot.
// An unchanged table is a no-op so the periodic poller doesn't churn the
// snapshot or flush the authz decision cache; any real change purges the
// cache (route policy may have moved underneath cached decisions).
func (s *Server) SwapRoutes(dbRoutes map[string]config.Route) error {
	s.swapMu.Lock()
	defer s.swapMu.Unlock()
	if s.lastDBRoutes != nil && reflect.DeepEqual(dbRoutes, s.lastDBRoutes) {
		return nil
	}
	rs, err := s.buildRouteSet(dbRoutes)
	if err != nil {
		return fmt.Errorf("build route set: %w", err)
	}
	s.routes.Store(rs)
	s.lastDBRoutes = dbRoutes
	s.authzCache.purge()
	return nil
}

func newReverseProxy(backend *url.URL, log *slog.Logger, transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: transport,
		// Flush after every write so known-length responses (media segments,
		// progressive downloads) stream instead of pooling in the 32KB copy
		// buffer; chunked/SSE responses already flush immediately.
		FlushInterval: -1,
		BufferPool:    copyBufPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)         // never derived from the client (SSRF invariant)
			pr.SetXForwarded()         // replaces inbound X-Forwarded-*, no spoof passthrough
			pr.Out.Host = backend.Host // backends see their own vhost
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream error", "host", r.Host, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

// resolveLanNets builds the client allowlist for lan_only routes: the
// configured lan_cidrs, or (when unset) the IPv4 subnets of the host's own
// up interfaces, so "LAN" defaults to "the same subnet(s) as this server".
// Fails closed: a lan_only route with no resolvable networks is a startup
// error, never an open route.
func resolveLanNets(cfg *config.Config, log *slog.Logger) ([]*net.IPNet, error) {
	lanOnly := false
	for _, r := range cfg.Routes {
		if r.LanOnly {
			lanOnly = true
			break
		}
	}
	var nets []*net.IPNet
	if len(cfg.LanCidrs) > 0 {
		for _, cidr := range cfg.LanCidrs {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("lan_cidrs: %w", err)
			}
			nets = append(nets, n)
		}
	} else {
		ifaces, err := net.Interfaces()
		if err != nil {
			if lanOnly {
				return nil, fmt.Errorf("lan_only route configured but interface detection failed: %w", err)
			}
			return nil, nil
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipn, ok := addr.(*net.IPNet)
				if !ok || ipn.IP.To4() == nil {
					continue
				}
				nets = append(nets, &net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask})
			}
		}
	}
	if lanOnly {
		if len(nets) == 0 {
			return nil, fmt.Errorf("lan_only route configured but no LAN networks resolved; set lan_cidrs")
		}
		printable := make([]string, len(nets))
		for i, n := range nets {
			printable[i] = n.String()
		}
		log.Info("lan_only routes restricted to", "networks", strings.Join(printable, ", "))
	}
	return nets, nil
}

// isLAN reports whether ip (a bare address string) falls inside any resolved
// LAN network. Unparseable input is never LAN.
func (s *Server) isLAN(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range s.lanNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// stripIdentityHeaders removes any client-supplied identity headers.
func stripIdentityHeaders(h http.Header) {
	for _, name := range identityHeaders {
		h.Del(name)
	}
}

// gatewayCookie returns the gateway session cookie value and removes it from
// the outgoing Cookie header (backends never see gateway credentials).
func (s *Server) gatewayCookie(r *http.Request) string {
	cookies := r.Cookies()
	var value string
	kept := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c.Name == s.cookieName {
			value = c.Value
			continue
		}
		kept = append(kept, c.String())
	}
	if value != "" {
		if len(kept) == 0 {
			r.Header.Del("Cookie")
		} else {
			r.Header.Set("Cookie", strings.Join(kept, "; "))
		}
	}
	return value
}

// Close releases resources held by the Server (currently the bot filter's
// MaxMind readers). Call once on shutdown.
func (s *Server) Close() error {
	return s.botFilter.Close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Bot/robot filter before any routing or authz work: covers every host
	// (app, auth, and unknown) and spends nothing on traffic we drop. A blocked
	// request has its connection closed with no response via ErrAbortHandler.
	if s.botFilter != nil {
		if blocked, reason := s.botFilter.Decide(clientIP(r), r.UserAgent()); blocked {
			s.log.Info("bot_filter drop", "site", r.Host, "src", clientIP(r),
				"action", "blocked", "reason", reason, "http_user_agent", r.UserAgent())
			panic(http.ErrAbortHandler)
		}
	}

	rs := s.routes.Load()
	route, host, kind := rs.table.Lookup(r.Host)
	switch kind {
	case routing.KindNone:
		// Unknown/hostile Host: reveal nothing, route nowhere (spec section 11).
		http.Error(w, "", http.StatusMisdirectedRequest)
		return
	case routing.KindAuth:
		s.serveAuthHost(w, r)
		return
	case routing.KindApp:
		s.serveApp(w, r, rs, host, route)
	}
}

func (s *Server) serveAuthHost(w http.ResponseWriter, r *http.Request) {
	// Only the gateway and guac-broker surfaces are reachable on the auth host;
	// /authz/check, /guac/consume, and everything else on the control plane
	// stay internal.
	if !strings.HasPrefix(r.URL.Path, "/gateway/") && !isPublicGuacPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	stripIdentityHeaders(r.Header)
	s.authProxy.ServeHTTP(w, r)
}

// isPublicGuacPath allows only the browser-facing guac broker path. /guac/consume
// is an internal data-plane->authz call and must NOT be reachable from clients.
func isPublicGuacPath(path string) bool {
	return path == "/guac/token"
}

func (s *Server) serveApp(
	w http.ResponseWriter, r *http.Request, rs *routeSet, host string, route config.Route,
) {
	// Network ACL before anything else: a lan_only route (the admin console)
	// is invisible from outside the LAN regardless of authentication state.
	// Browsers are bounced to the login page; the IdP stays internet-reachable
	// so admins can still authenticate, they just never get the console.
	if route.LanOnly && !s.isLAN(clientIP(r)) {
		s.log.Info("lan_only deny", "site", host, "src", clientIP(r), "action", "blocked")
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && s.lanOnlyRedirect != "" {
			http.Redirect(w, r, s.lanOnlyRedirect, http.StatusFound)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	stripIdentityHeaders(r.Header)
	upstream := rs.proxies[host]
	cookie := s.gatewayCookie(r) // always strip the gateway cookie from upstream

	if route.GuacTunnel {
		s.serveGuacTunnel(w, r, upstream, cookie)
		return
	}

	// Fixed tunnel path on the portal host: guac resources carry no public
	// host of their own, so their WebSocket tunnel rides here. Everything
	// else on the route proxies to the normal backend below.
	if route.GuacTunnelPath && r.URL.Path == "/guac/tunnel" {
		s.serveGuacTunnel(w, r, s.guacProxy, cookie)
		return
	}

	if !route.AuthRequired() {
		upstream.ServeHTTP(w, r)
		return
	}

	// Host-scope decision cache: only allows the control plane explicitly
	// marked path/time-independent land here, so a hit can skip the
	// per-request check. Anonymous requests (no gateway cookie) never touch
	// the cache.
	now := time.Now()
	srcIP := clientIP(r)
	var cacheKey string
	if cookie != "" {
		cacheKey = authzCacheKey(host, route.BackendPort, srcIP, cookie)
		if hdrs, ok := s.authzCache.get(cacheKey, now); ok {
			for name, value := range hdrs {
				r.Header.Set(name, value)
			}
			upstream.ServeHTTP(w, r)
			return
		}
	}

	decision, err := s.authz.Check(r.Context(), authz.CheckRequest{
		Host:          host,
		Method:        r.Method,
		URI:           r.URL.RequestURI(),
		SourceIP:      srcIP,
		BackendPort:   route.BackendPort,
		GatewayCookie: cookie,
	})
	if err != nil {
		// Fail closed: no decision, no proxying.
		s.log.Error("authz unavailable", "err", err)
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}

	switch decision.Decision {
	case "allow":
		if cacheKey != "" && decision.CacheScope == "host" && decision.CacheTTLSecs > 0 {
			s.authzCache.put(cacheKey, decision.Headers,
				time.Duration(decision.CacheTTLSecs)*time.Second, now)
		}
		for name, value := range decision.Headers {
			r.Header.Set(name, value)
		}
		upstream.ServeHTTP(w, r)
	case "auth_required":
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && decision.Redirect != "" {
			http.Redirect(w, r, decision.Redirect, http.StatusFound)
			return
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

// serveGuacTunnel authorizes and proxies a Guacamole tunnel WebSocket connect.
// Authorization is a single-use grant consumption (bound to the browser IP and
// a live gateway session), not the per-request policy check: the broker already
// evaluated policy when it minted the token. ReverseProxy handles the WebSocket
// upgrade to the Node guacamole-lite backend. Fails closed.
func (s *Server) serveGuacTunnel(
	w http.ResponseWriter, r *http.Request, upstream *httputil.ReverseProxy, cookie string,
) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	allowed, err := s.authz.ConsumeGuac(r.Context(), authz.ConsumeRequest{
		Token:         token,
		SourceIP:      clientIP(r),
		GatewayCookie: cookie,
	})
	if err != nil {
		s.log.Error("guac consume unavailable", "err", err)
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	upstream.ServeHTTP(w, r)
}
