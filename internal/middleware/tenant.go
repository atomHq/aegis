package middleware

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxies holds the list of trusted proxy CIDRs.
// Only requests from these IPs will have X-Forwarded-For / X-Real-IP honoured.
// If empty, proxy headers are NEVER trusted (direct connection only).
var TrustedProxies []*net.IPNet

// SetTrustedProxies parses CIDR strings and sets the trusted proxy list.
// Common values: "127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
func SetTrustedProxies(cidrs []string) {
	TrustedProxies = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as a single IP (add /32 or /128)
			ip := net.ParseIP(cidr)
			if ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
			} else {
				continue
			}
		}
		TrustedProxies = append(TrustedProxies, network)
	}
}

// isTrustedProxy checks if the given address is from a trusted proxy.
func isTrustedProxy(remoteAddr string) bool {
	if len(TrustedProxies) == 0 {
		return false
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, network := range TrustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// RealIP extracts the real client IP from X-Forwarded-For or X-Real-IP headers,
// but ONLY if the request comes from a trusted proxy. This prevents IP spoofing
// by untrusted clients sending fake headers.
func RealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isTrustedProxy(r.RemoteAddr) {
			// Not from a trusted proxy — ignore forwarding headers
			next.ServeHTTP(w, r)
			return
		}

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
