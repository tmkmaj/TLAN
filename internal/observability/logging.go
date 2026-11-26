package observability

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

// NewLogger returns the single structured logger used by server components.
// TextHandler keeps journald output greppable while preserving typed fields.
func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// HTTPMiddleware logs only the route and method, never the query string or
// request headers. The response writer delegates optional interfaces so the
// relay's HTTP/1.1 Upgrade path remains functional.
func HTTPMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		logger.InfoContext(r.Context(), "http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration_ms", time.Since(started).Milliseconds(),
			"client_ip", remoteIP(r.RemoteAddr),
		)
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *responseRecorder) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *responseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseRecorder) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	if !w.wroteHeader {
		w.status = http.StatusSwitchingProtocols
		w.wroteHeader = true
	}
	return hijacker.Hijack()
}

func (w *responseRecorder) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}

func remoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
