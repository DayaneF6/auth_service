package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/dayaneroot/auth-service/internal/domain"
	jwtsvc "github.com/dayaneroot/auth-service/internal/infrastructure/jwt"
	"github.com/dayaneroot/auth-service/internal/usecase"
	"github.com/dayaneroot/auth-service/pkg/httputil"
)

type claimsKey struct{}

// Authenticate validates the Bearer access token and stores claims in request context.
func Authenticate(auth *usecase.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r.Header.Get("Authorization"))
			if raw == "" {
				httputil.WriteError(w, domain.ErrUnauthorized)
				return
			}

			claims, err := auth.ParseAccess(r.Context(), raw)
			if err != nil {
				httputil.WriteError(w, err)
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFrom returns JWT claims injected by Authenticate middleware.
func ClaimsFrom(ctx context.Context) *jwtsvc.Claims {
	claims, _ := ctx.Value(claimsKey{}).(*jwtsvc.Claims)
	return claims
}

func bearerToken(header string) string {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
