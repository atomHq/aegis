package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type reqIDKeyType string

const reqIDKey reqIDKeyType = "aegis_request_id"

// RequestIDFromContext retrieves the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(reqIDKey).(string)
	return id
}

// RequestID generates a unique request ID and adds it to headers, response, and context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		r.Header.Set("X-Request-ID", reqID)
		w.Header().Set("X-Request-ID", reqID)

		// Propagate via context
		ctx := context.WithValue(r.Context(), reqIDKey, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logger logs request details using zerolog, including latency.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get("X-Request-ID")
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(ww, r)

		latency := time.Since(start)

		event := log.Info()
		if ww.statusCode >= 400 {
			event = log.Warn()
		}
		if ww.statusCode >= 500 {
			event = log.Error()
		}

		logEvent := event.
			Str("request_id", reqID).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", ww.statusCode).
			Dur("latency", latency).
			Str("remote_addr", r.RemoteAddr)

		tenant := TenantFromContext(r.Context())
		if tenant != nil {
			logEvent = logEvent.Str("tenant_id", tenant.ID.String())
		}

		logEvent.Msg("request")
	})
}

// SetupLogger configures zerolog defaults.
func SetupLogger(level string) {
	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
