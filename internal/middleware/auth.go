package middleware

import (
	"context"
	"net/http"

	"github.com/dayaneroot/auth-service/internal/domain"
	jwtsvc "github.com/dayaneroot/auth-service/internal/infrastructure/jwt"
	"github.com/dayaneroot/auth-service/internal/usecase"
	"github.com/dayaneroot/auth-service/pkg/httputil"
	"github.com/google/uuid"
)

type claimsKey struct{}

// Authenticate validates the Bearer access token and stores claims in request context.
func Authenticate(auth *usecase.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := httputil.BearerToken(r.Header.Get("Authorization"))
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

// SessionIDs parses user and session IDs from JWT claims in context.
func SessionIDs(ctx context.Context) (userID, sessionID uuid.UUID, err error) {
	c := ClaimsFrom(ctx)
	if c == nil {
		return uuid.Nil, uuid.Nil, domain.ErrUnauthorized
	}
	userID, err = uuid.Parse(c.UserID)
	if err != nil {
		return uuid.Nil, uuid.Nil, domain.ErrUnauthorized
	}
	sessionID, err = uuid.Parse(c.SessionID)
	if err != nil {
		return uuid.Nil, uuid.Nil, domain.ErrUnauthorized
	}
	return userID, sessionID, nil
}

// UserIDFromClaims parses the subject user id from context.
func UserIDFromClaims(ctx context.Context) (uuid.UUID, error) {
	c := ClaimsFrom(ctx)
	if c == nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	id, err := uuid.Parse(c.UserID)
	if err != nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	return id, nil
}
