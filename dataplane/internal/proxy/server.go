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
	"strings"
	"sync/atomic"

	"hyproxy/dataplane/internal/authz"
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

	// Fixed at startup, used to rebuild routeSets on swap.
	authHost     string
	staticRoutes map[string]config.Route
	guacBackend  string
}

func NewServer(cfg *config.Config, checker AuthzChecker, log *slog.Logger) (*Server, error) {
	authBackend, err := url.Parse(cfg.AuthBackend)
	if err != nil {
		return nil, err
	}
	s := &Server{
		authz:        checker,
		cookieName:   cfg.GatewayCookieName,
		authProxy:    newReverseProxy(authBackend, log),
		log:          log,
		authHost:     cfg.AuthHost,
		staticRoutes: cfg.Routes,
		guacBackend:  cfg.GuacBackend,
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
		proxies[host] = newReverseProxy(u, s.log)
	}
	return &routeSet{table: routing.NewTableFrom(s.authHost, merged), proxies: proxies}, nil
}

// SwapRoutes rebuilds the routing snapshot from a fresh set of DB routes and
// installs it atomically. In-flight requests keep using the previous snapshot.
func (s *Server) SwapRoutes(dbRoutes map[string]config.Route) error {
	rs, err := s.buildRouteSet(dbRoutes)
	if err != nil {
		return fmt.Errorf("build route set: %w", err)
	}
	s.routes.Store(rs)
	return nil
}

func newReverseProxy(backend *url.URL, log *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	stripIdentityHeaders(r.Header)
	upstream := rs.proxies[host]
	cookie := s.gatewayCookie(r) // always strip the gateway cookie from upstream

	if route.GuacTunnel {
		s.serveGuacTunnel(w, r, upstream, cookie)
		return
	}

	if !route.AuthRequired() {
		upstream.ServeHTTP(w, r)
		return
	}

	decision, err := s.authz.Check(r.Context(), authz.CheckRequest{
		Host:          host,
		Method:        r.Method,
		URI:           r.URL.RequestURI(),
		SourceIP:      clientIP(r),
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
