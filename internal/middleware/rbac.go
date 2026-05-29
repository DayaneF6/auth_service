package middleware

import (
	"net/http"
	"slices"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/dayaneroot/auth-service/pkg/httputil"
)

// RequirePermission denies the request when the JWT lacks the named permission.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFrom(r.Context())
			if claims == nil {
				httputil.WriteError(w, domain.ErrUnauthorized)
				return
			}
			if !slices.Contains(claims.Permissions, permission) {
				httputil.WriteError(w, domain.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
