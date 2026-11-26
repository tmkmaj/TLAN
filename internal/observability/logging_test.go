package observability

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewLoggerEmitsStructuredFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, slog.LevelInfo)
	logger.InfoContext(context.Background(), "path switched", "peer", "10.240.0.2", "path", "direct", "rtt_ms", int64(28), "reason", "probe_recovered")
	out := buf.String()
	for _, want := range []string{"level=INFO", "msg=\"path switched\"", "peer=10.240.0.2", "path=direct", "rtt_ms=28", "reason=probe_recovered"} {
		if !strings.Contains(out, want) {
			t.Fatalf("structured log %q missing %q", out, want)
		}
	}
}

func TestHTTPMiddlewareLogsMethodPathStatusAndDuration(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, slog.LevelInfo)
	handler := HTTPMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/health?token=must-not-leak", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	out := buf.String()
	for _, want := range []string{"msg=http_request", "method=GET", "path=/health", "status=204", "duration_ms="} {
		if !strings.Contains(out, want) {
			t.Fatalf("http log %q missing %q", out, want)
		}
	}
	if strings.Contains(out, "must-not-leak") || strings.Contains(out, "?") {
		t.Fatalf("http log leaked query string: %q", out)
	}
}
