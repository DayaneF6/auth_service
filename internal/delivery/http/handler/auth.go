// Package handler contains thin HTTP adapters that delegate to use cases.
package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/domain"
	redisinfra "github.com/dayaneroot/auth-service/internal/infrastructure/redis"
	"github.com/dayaneroot/auth-service/internal/middleware"
	"github.com/dayaneroot/auth-service/internal/usecase"
	"github.com/dayaneroot/auth-service/pkg/httputil"
)

// Auth maps HTTP routes to the auth use case (thin adapter, no business rules).
type Auth struct {
	svc  *usecase.AuthService
	cfg  *config.Config
	idem *redisinfra.Idempotency
}

func NewAuth(cfg *config.Config, svc *usecase.AuthService, idem *redisinfra.Idempotency) *Auth {
	return &Auth{cfg: cfg, svc: svc, idem: idem}
}

func (h *Auth) Register(w http.ResponseWriter, r *http.Request) {
	var body credentialsBody
	raw, bodyHash, ok := httputil.ReadBodyHash(w, r)
	if !ok {
		return
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		httputil.WriteDecodeError(w)
		return
	}
	ip, ua := peer(r)
	run := func() ([]byte, error) {
		tok, err := h.svc.Register(r.Context(), usecase.RegisterInput{
			Email: body.Email, Password: body.Password,
		}, ip, ua)
		if err != nil {
			return nil, err
		}
		return json.Marshal(httputil.MessageWithDevToken(h.cfg.ExposeDevTokens(),
			"user created", "verification_token", tok))
	}
	key := httputil.SanitizeIdempotencyKey(r.Header.Get("Idempotency-Key"))
	if key != "" && h.idem != nil {
		httputil.RunIdempotent(w, r.Context(), h.idem, "register:"+key+":"+bodyHash, run)
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
	var body credentialsBody
	if !httputil.Decode(w, r, &body) {
		return
	}
	ip, ua := peer(r)
	pair, err := h.svc.Login(r.Context(), usecase.LoginInput{
		Email: body.Email, Password: body.Password,
	}, ip, ua)
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
	ip, ua := peer(r)
	pair, err := h.svc.Refresh(r.Context(), refresh, ip, ua)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	h.writeSession(w, pair)
}

func (h *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r.Context())
	userID, sessionID, err := middleware.SessionIDs(r.Context())
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	var exp time.Time
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	ip, ua := peer(r)
	_ = h.svc.Logout(r.Context(), userID, sessionID, claims.ID, exp,
		httputil.RefreshFromCookie(r, h.cfg.JWT), ip, ua)
	httputil.ClearRefreshCookie(w, h.cfg.JWT)
	httputil.Message(w, http.StatusOK, "logged out")
}

func (h *Auth) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.UserIDFromClaims(r.Context())
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
	var body struct{ Email string `json:"email"` }
	if !httputil.Decode(w, r, &body) {
		return
	}
	tok, err := h.svc.ForgotPassword(r.Context(), usecase.ForgotPasswordInput{Email: body.Email})
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.JSON(w, http.StatusOK, httputil.MessageWithDevToken(h.cfg.ExposeDevTokens(),
		"if the email exists, a reset link was sent", "reset_token", tok))
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
		TokenInput: usecase.TokenInput{Token: body.Token}, NewPassword: body.NewPassword,
	}); err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.Message(w, http.StatusOK, "password updated")
}

func (h *Auth) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body usecase.TokenInput
	if !httputil.Decode(w, r, &body) {
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), body); err != nil {
		httputil.WriteError(w, err)
		return
	}
	httputil.Message(w, http.StatusOK, "email verified")
}

func (h *Auth) Me(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.UserIDFromClaims(r.Context())
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

type credentialsBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func peer(r *http.Request) (ip, ua string) {
	return httputil.ClientIP(r), r.UserAgent()
}

func (h *Auth) writeSession(w http.ResponseWriter, pair *domain.TokenPair) {
	httputil.SetRefreshCookie(w, h.cfg.JWT, pair.RefreshToken)
	httputil.WriteTokenPair(w, pair)
}
