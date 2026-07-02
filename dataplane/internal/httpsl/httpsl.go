// Package httpsl is the v1 HTTPS listener: TLS termination on the single
// public port with hot-reloadable certificates, dispatching to the proxy
// handler. Implements the listener seam from spec section 12.
package httpsl

import (
	"context"
	"errors"
	"net/http"
	"time"

	"hyproxy/dataplane/internal/tlsconf"
)

type HTTPSListener struct {
	server *http.Server
}

func New(addr string, handler http.Handler, certs *tlsconf.CertReloader) *HTTPSListener {
	return &HTTPSListener{
		server: &http.Server{
			Addr:              addr,
			Handler:           handler,
			TLSConfig:         tlsconf.ServerConfig(certs),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    64 << 10,
		},
	}
}

func (l *HTTPSListener) Name() string { return "https" }

func (l *HTTPSListener) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		// Cert/key come from TLSConfig.GetCertificate.
		errCh <- l.server.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (l *HTTPSListener) Shutdown(ctx context.Context) error {
	return l.server.Shutdown(ctx)
}
