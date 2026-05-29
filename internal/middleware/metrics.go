package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/dayaneroot/auth-service/pkg/httputil"
)

func MetricsAuth(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token != "" {
				if bearerToken(r.Header.Get("Authorization")) == token {
					next.ServeHTTP(w, r)
					return
				}
				httputil.WriteError(w, domain.ErrUnauthorized)
				return
			}
			if isLoopback(r) {
				next.ServeHTTP(w, r)
				return
			}
			httputil.WriteError(w, domain.ErrForbidden)
		})
	}
}

func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
