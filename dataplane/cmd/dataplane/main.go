// The hyproxy data plane: one public port, TLS termination, Host routing,
// forward-auth against the control plane, allowlisted backends only.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"hyproxy/dataplane/internal/authz"
	"hyproxy/dataplane/internal/config"
	"hyproxy/dataplane/internal/httpsl"
	"hyproxy/dataplane/internal/listener"
	"hyproxy/dataplane/internal/proxy"
	"hyproxy/dataplane/internal/tlsconf"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the data-plane config")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	certs, err := tlsconf.NewCertReloader(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		log.Error("tls", "err", err)
		os.Exit(1)
	}
	authzClient := authz.NewClient(cfg.AuthzURL)
	handler, err := proxy.NewServer(cfg, authzClient, log)
	if err != nil {
		log.Error("proxy", "err", err)
		os.Exit(1)
	}

	var l listener.Listener = httpsl.New(cfg.Listen, handler, certs)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Keep the DB-driven app routes fresh. Static infra routes already serve;
	// this layers app routes on top and hot-swaps as resources change.
	go pollRoutes(ctx, authzClient, handler, time.Duration(cfg.RoutesRefreshSecs)*time.Second, log)

	log.Info("data plane up", "listener", l.Name(), "addr", cfg.Listen,
		"static_routes", len(cfg.Routes), "auth_host", cfg.AuthHost,
		"routes_refresh_secs", cfg.RoutesRefreshSecs)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = l.Shutdown(shutdownCtx)
	}()
	if err := l.Serve(ctx); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// pollRoutes refreshes the DB-driven route table on an interval and hot-swaps it
// into the running server. Fail-closed: a failed fetch or swap keeps the current
// (last-good) table rather than dropping routes. Runs until ctx is cancelled.
func pollRoutes(
	ctx context.Context, client *authz.Client, srv *proxy.Server, interval time.Duration, log *slog.Logger,
) {
	if interval <= 0 {
		interval = config.DefaultRoutesRefreshSecs * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	refresh := func() {
		fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		routes, err := client.Routes(fetchCtx)
		if err != nil {
			log.Warn("routes refresh failed; keeping last-good table", "err", err)
			return
		}
		if err := srv.SwapRoutes(routes); err != nil {
			log.Warn("routes swap failed; keeping last-good table", "err", err)
			return
		}
		log.Debug("routes refreshed", "db_routes", len(routes))
	}
	refresh() // prime immediately; don't wait a full interval for app routes
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
