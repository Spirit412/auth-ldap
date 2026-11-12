// Package middleware contains the chi middleware stack: trusted-proxy real
// IP, request id + structured logging + panic recovery, JWT authentication
// with role checks, and the Redis GCRA rate limiter (S-06).
package middleware

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type ctxKeyRealIP struct{}

// RealIP resolves the client IP. X-Forwarded-For is honoured ONLY when the
// direct peer (r.RemoteAddr) is within TRUSTED_PROXIES (S-06/F-10): with an
// untrusted peer the header is ignored, so clients cannot spoof their IP to
// bypass rate limiting.
type RealIP struct {
	trusted []*net.IPNet
}

func NewRealIP(cidrs []string) (*RealIP, error) {
	m := &RealIP{}
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		// Bare IPs are allowed as /32 (or /128).
		if !strings.Contains(cidr, "/") {
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr += "/" + strconv.Itoa(bits)
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		m.trusted = append(m.trusted, n)
	}
	return m, nil
}

func itoa(v int) string {
	if v == 32 {
		return "32"
	}
	return "128"
}

func (m *RealIP) isTrusted(ip net.IP) bool {
	for _, n := range m.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// RealIPFromContext returns the resolved client IP.
func RealIPFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRealIP{}).(string); ok {
		return v
	}
	return ""
}

// Middleware implements chi's func(http.Handler) http.Handler.
func (m *RealIP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
		if err != nil {
			host = strings.TrimSpace(r.RemoteAddr)
		}
		ip := net.ParseIP(host)

		clientIP := host
		if ip != nil && m.isTrusted(ip) {
			// Walk XFF from the right; take the first address that is NOT a
			// trusted proxy — this defeats spoofed leftmost entries.
			xff := r.Header.Get("X-Forwarded-For")
			if xff != "" {
				parts := strings.Split(xff, ",")
				found := ""
				for i := len(parts) - 1; i >= 0; i-- {
					cand := net.ParseIP(strings.TrimSpace(parts[i]))
					if cand == nil {
						break
					}
					if !m.isTrusted(cand) {
						found = cand.String()
						break
					}
				}
				if found != "" {
					clientIP = found
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRealIP{}, clientIP)))
	})
}
