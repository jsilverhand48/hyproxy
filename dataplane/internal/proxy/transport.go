package proxy

import (
	"crypto/tls"
	"net/http"
	"sync"
)

// newUpstreamTransport is the single transport shared by every route proxy:
// one connection pool sized for concurrent media segment fetches, HTTP/1.1
// only so streaming backpressure stays plain TCP flow control, and larger
// socket buffers to cut syscall counts at video bitrates.
func newUpstreamTransport(insecureSkipVerify bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ForceAttemptHTTP2 = false // no h2 flow-control layer on the backend leg
	t.MaxIdleConns = 128
	t.MaxIdleConnsPerHost = 32 // the default of 2 starves concurrent segment fetches
	t.ReadBufferSize = 64 << 10
	t.WriteBufferSize = 64 << 10
	if insecureSkipVerify {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opt-in for backends without valid certs
	}
	return t
}

// copyBufPool hands ReverseProxy 64KB body-copy buffers; the stdlib default
// is a fresh 32KB allocation per response.
var copyBufPool = &bufferPool{}

type bufferPool struct {
	pool sync.Pool
}

func (p *bufferPool) Get() []byte {
	if b, ok := p.pool.Get().(*[]byte); ok {
		return *b
	}
	return make([]byte, 64<<10)
}

func (p *bufferPool) Put(b []byte) {
	p.pool.Put(&b)
}
