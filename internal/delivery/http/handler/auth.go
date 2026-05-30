// Package handler contains thin HTTP adapters that delegate to use cases.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/domain"
	redisinfra "github.com/dayaneroot/auth-service/internal/infrastructure/redis"
	"github.com/dayaneroot/auth-service/internal/middleware"
	"github.com/dayaneroot/auth-service/internal/usecase"
	"github.com/dayaneroot/auth-service/pkg/httputil"
	"github.com/google/uuid"
)

type Auth struct {
	svc  *usecase.AuthService
	cfg  *config.Config
	idem *redisinfra.Idempotency
}

func NewAuth(cfg *config.Config, svc *usecase.AuthService, idem *redisinfra.Idempotency) *Auth {
	return &Auth{cfg: cfg, svc: svc, idem: idem}
}

func (h *Auth) Register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	raw, bodyHash, ok := httputil.ReadBodyHash(w, r)
	if !ok {
		return
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		httputil.WriteDecodeError(w)
		return
	}

	run := func() ([]byte, error) {
		token, err := h.svc.Register(r.Context(), usecase.RegisterInput{
			Email: body.Email, Password: body.Password,
		}, httputil.ClientIP(r), r.UserAgent())
		if err != nil {
			return nil, err
		}
		out, err := json.Marshal(httputil.WithDevToken(h.cfg.IsProduction(),
			map[string]string{"message": "user created"}, "verification_token", token))
		if err != nil {
			return nil, err
		}
		return out, nil
	}

	if key := r.Header.Get("Idempotency-Key"); key != "" && h.idem != nil {
		withIdempotency(w, r.Context(), h.idem, "register:"+key+":"+bodyHash, run)
		return
	}
	resp, err := run()
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.WriteBytes(w, http.StatusCreated, resp)
}

func (h *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !httputil.Decode(w, r, &body) {
		return
	}
	pair, err := h.svc.Login(r.Context(), usecase.LoginInput{
		Email: body.Email, Password: body.Password,
	}, httputil.ClientIP(r), r.UserAgent())
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	h.writeSession(w, pair)
}

func (h *Auth) Refresh(w http.ResponseWriter, r *http.Request) {
	refresh := httputil.RefreshFromCookie(r, h.cfg.JWT)
	if refresh == "" {
		httputil.WriteError(w, domain.ErrUnauthorized)
		return
	}
	pair, err := h.svc.Refresh(r.Context(), refresh, httputil.ClientIP(r), r.UserAgent())
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	h.writeSession(w, pair)
}

func (h *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r.Context())
	var accessExp time.Time
	if claims.ExpiresAt != nil {
		accessExp = claims.ExpiresAt.Time
	}
	userID, err := userIDFromRequest(r)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	_ = h.svc.Logout(r.Context(), userID, sessionID, claims.ID, accessExp,
		httputil.RefreshFromCookie(r, h.cfg.JWT), httputil.ClientIP(r), r.UserAgent())
	httputil.ClearRefreshCookie(w, h.cfg.JWT)
	httputil.Message(w, http.StatusOK, "logged out")
}

func (h *Auth) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, err := userIDFromRequest(r)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	if err := h.svc.LogoutAll(r.Context(), userID); err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.Message(w, http.StatusOK, "all sessions revoked")
}

func (h *Auth) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !httputil.Decode(w, r, &body) {
		return
	}
	token, err := h.svc.ForgotPassword(r.Context(), usecase.ForgotPasswordInput{Email: body.Email})
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.JSON(w, http.StatusOK, httputil.WithDevToken(h.cfg.IsProduction(),
		map[string]string{"message": "if the email exists, a reset link was sent"}, "reset_token", token))
}

func (h *Auth) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if !httputil.Decode(w, r, &body) {
		return
	}
	if err := h.svc.ResetPassword(r.Context(), usecase.ResetPasswordInput{
		Token: body.Token, NewPassword: body.NewPassword,
	}); err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.Message(w, http.StatusOK, "password updated")
}

func (h *Auth) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !httputil.Decode(w, r, &body) {
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), body.Token); err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.Message(w, http.StatusOK, "email verified")
}

func (h *Auth) Me(w http.ResponseWriter, r *http.Request) {
	userID, err := userIDFromRequest(r)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	profile, err := h.svc.GetProfile(r.Context(), userID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.JSON(w, http.StatusOK, profile)
}

func (h *Auth) writeSession(w http.ResponseWriter, pair *domain.TokenPair) {
	httputil.SetRefreshCookie(w, h.cfg.JWT, pair.RefreshToken)
	httputil.WriteTokenPair(w, pair)
}

func userIDFromRequest(r *http.Request) (uuid.UUID, error) {
	return parseClaimUUID(middleware.ClaimsFrom(r.Context()).UserID)
}

func sessionIDFromRequest(r *http.Request) (uuid.UUID, error) {
	return parseClaimUUID(middleware.ClaimsFrom(r.Context()).SessionID)
}

func parseClaimUUID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	return id, nil
}

const idemTTL = 5 * time.Minute

func withIdempotency(w http.ResponseWriter, ctx context.Context, store *redisinfra.Idempotency, cacheKey string, fn func() ([]byte, error)) {
	if replyCached(w, ctx, store, cacheKey) {
		return
	}
	lockKey := cacheKey + ":lock"
	acquired, _ := store.SetNX(ctx, lockKey, []byte("1"), idemTTL)
	if !acquired {
		if replyCached(w, ctx, store, cacheKey) {
			return
		}
		httputil.WriteError(w, domain.ErrConflict)
		return
	}
	body, err := fn()
	if err != nil {
		_ = store.Delete(ctx, lockKey)
		httputil.WriteError(w, err)
		return
	}
	_ = store.Set(ctx, cacheKey, body, idemTTL)
	_ = store.Delete(ctx, lockKey)
	httputil.WriteBytes(w, http.StatusCreated, body)
}

func replyCached(w http.ResponseWriter, ctx context.Context, store *redisinfra.Idempotency, key string) bool {
	b, found, _ := store.Get(ctx, key)
	if !found || len(b) == 0 || b[0] != '{' {
		return false
	}
	httputil.WriteBytes(w, http.StatusCreated, b)
	return true
}
