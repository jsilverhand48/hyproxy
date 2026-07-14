// Package logrotate is a minimal size-based rotating file writer, matching
// the rotation policy used across the stack: when the live file would exceed
// maxBytes the chain shifts (x.log -> x.log.1 -> x.log.2) and anything older
// is deleted, so at most `backups` archives exist. Hand-rolled to keep the
// data plane dependency-free (go.mod has no external modules and the binary
// is built on the target host at install time).
package logrotate

import (
	"fmt"
	"os"
	"sync"
)

type Writer struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	maxBytes int64
	backups  int
	size     int64
}

func New(path string, maxBytes int64, backups int) (*Writer, error) {
	w := &Writer{path: path, maxBytes: maxBytes, backups: backups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f = f
	w.size = st.Size()
	return nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.maxBytes > 0 && w.size+int64(len(p)) > w.maxBytes && w.size > 0 {
		if err := w.rotate(); err != nil {
			// Never drop the log line over a rotation failure; keep appending.
			fmt.Fprintf(os.Stderr, "logrotate: rotate %s: %v\n", w.path, err)
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate shifts path -> path.1 -> ... -> path.<backups>, dropping the oldest.
// Single-process writer, so the mutex held by Write suffices.
func (w *Writer) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	os.Remove(fmt.Sprintf("%s.%d", w.path, w.backups))
	for i := w.backups - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.open()
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
