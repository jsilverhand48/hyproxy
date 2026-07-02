// Package listener defines the pluggable transport seam (spec section 12).
//
// v1 ships the HTTPS listener; a future raw-L4 transport (games behind a
// WireGuard boundary) becomes another implementation of this interface
// without touching the policy engine, which stays transport-agnostic.
package listener

import "context"

type Listener interface {
	// Name identifies the listener in logs.
	Name() string
	// Serve blocks until the context is cancelled or a fatal error occurs.
	Serve(ctx context.Context) error
	// Shutdown drains gracefully.
	Shutdown(ctx context.Context) error
}
