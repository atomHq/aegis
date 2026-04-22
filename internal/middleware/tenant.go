package middleware

import (
	"net/http"
	"strings"
)

// RealIP extracts the real client IP from X-Forwarded-For or X-Real-IP headers.
func RealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			if len(parts) > 0 {
				r.RemoteAddr = strings.TrimSpace(parts[0])
			}
		} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
			r.RemoteAddr = xri
		}
		next.ServeHTTP(w, r)
	})
}
