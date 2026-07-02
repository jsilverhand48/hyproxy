// Package tlsconf provides certificate loading with hot reload, the seam the
// Phase 5 ACME integration slots into (GetCertificate re-reads renewed cert
// files without dropping connections).
package tlsconf

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type CertReloader struct {
	certPath, keyPath string

	mu        sync.Mutex
	cached    *tls.Certificate
	certMtime time.Time
	lastCheck time.Time
}

func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	r := &CertReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CertReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return err
	}
	info, err := os.Stat(r.certPath)
	if err != nil {
		return err
	}
	r.cached = &cert
	r.certMtime = info.ModTime()
	return nil
}

// GetCertificate serves the cached cert, re-reading the files at most once
// per second when the cert file's mtime changes. Errors keep the old cert.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.lastCheck) > time.Second {
		r.lastCheck = now
		if info, err := os.Stat(r.certPath); err == nil && info.ModTime() != r.certMtime {
			_ = r.reload() // on failure, keep serving the previous cert
		}
	}
	return r.cached, nil
}

// ServerConfig is the data plane's TLS posture: 1.2 floor, 1.3 preferred.
func ServerConfig(r *CertReloader) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: r.GetCertificate,
	}
}
