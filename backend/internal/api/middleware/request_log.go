package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

func RequestLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(wrapped, r)
			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"latencyMs", time.Since(start).Milliseconds(),
				"remoteAddr", r.RemoteAddr,
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
