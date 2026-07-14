// The hyproxy data plane: one public port, TLS termination, Host routing,
// forward-auth against the control plane, allowlisted backends only.
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"hyproxy/dataplane/internal/accesslog"
	"hyproxy/dataplane/internal/authz"
	"hyproxy/dataplane/internal/config"
	"hyproxy/dataplane/internal/httpsl"
	"hyproxy/dataplane/internal/listener"
	"hyproxy/dataplane/internal/logrotate"
	"hyproxy/dataplane/internal/proxy"
	"hyproxy/dataplane/internal/tlsconf"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the data-plane config")
	flag.Parse()

	// Bootstrap stderr logger: the file destination lives in the config, so
	// config-load errors can only go to stderr/journald.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	log, accessLog, closeLogs, err := newLoggers(cfg)
	if err != nil {
		log.Error("logging", "err", err)
		os.Exit(1)
	}
	defer closeLogs()
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

	var public http.Handler = handler
	if accessLog != nil {
		public = accesslog.Wrap(handler, accessLog)
	}
	var l listener.Listener = httpsl.New(cfg.Listen, public, certs)

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

// newLoggers builds the service logger and the access logger from the config.
// Service log: stderr always (journald), plus rotating dataplane.log when
// log_dir is set. Access log: rotating dataplane-access.log only (nil when
// log_dir is unset; file-only because per-request lines at media-streaming
// volume would drown journald). Both emit the stack-wide JSON scheme:
// ts (RFC3339 UTC), level (lowercase), service, msg.
func newLoggers(cfg *config.Config) (*slog.Logger, *slog.Logger, func(), error) {
	opts := &slog.HandlerOptions{
		Level: slogLevel(cfg.LogLevel),
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				return slog.String("ts", a.Value.Time().UTC().Format(time.RFC3339))
			case slog.LevelKey:
				return slog.String("level", strings.ToLower(a.Value.String()))
			}
			return a
		},
	}
	if cfg.LogDir == "" {
		log := slog.New(slog.NewJSONHandler(os.Stderr, opts)).With("service", "dataplane")
		return log, nil, func() {}, nil
	}
	serviceOut, err := logrotate.New(
		filepath.Join(cfg.LogDir, "dataplane.log"), cfg.LogMaxBytes, cfg.LogBackupCount)
	if err != nil {
		return nil, nil, nil, err
	}
	accessOut, err := logrotate.New(
		filepath.Join(cfg.LogDir, "dataplane-access.log"), cfg.LogMaxBytes, cfg.LogBackupCount)
	if err != nil {
		serviceOut.Close()
		return nil, nil, nil, err
	}
	log := slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stderr, serviceOut), opts)).
		With("service", "dataplane")
	accessLog := slog.New(slog.NewJSONHandler(accessOut, opts)).With("service", "dataplane")
	closeLogs := func() {
		serviceOut.Close()
		accessOut.Close()
	}
	return log, accessLog, closeLogs, nil
}

func slogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
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
