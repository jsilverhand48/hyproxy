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
	handler, err := proxy.NewServer(cfg, authz.NewClient(cfg.AuthzURL), log)
	if err != nil {
		log.Error("proxy", "err", err)
		os.Exit(1)
	}

	var l listener.Listener = httpsl.New(cfg.Listen, handler, certs)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("data plane up", "listener", l.Name(), "addr", cfg.Listen,
		"routes", len(cfg.Routes), "auth_host", cfg.AuthHost)
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
