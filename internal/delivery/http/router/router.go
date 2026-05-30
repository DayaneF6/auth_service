// Package router mounts HTTP routes, middleware, and rate limits.
package router

import (
	"net/http"
	"time"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/delivery/http/handler"
	"github.com/dayaneroot/auth-service/internal/infrastructure/postgres"
	redisinfra "github.com/dayaneroot/auth-service/internal/infrastructure/redis"
	"github.com/dayaneroot/auth-service/internal/middleware"
	"github.com/dayaneroot/auth-service/internal/usecase"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

type Deps struct {
	Config  *config.Config
	Logger  *zap.Logger
	DB      *postgres.DB
	Redis   *redisinfra.Client
	Auth    *usecase.AuthService
	Limiter *redisinfra.RateLimiter
	Idem    *redisinfra.Idempotency
}

func New(deps Deps) http.Handler {
	r := chi.NewRouter()
	sec := deps.Config.Security

	middleware.Stack{
		Logger:         deps.Logger,
		AllowedOrigins: deps.Config.HTTP.AllowedOrigins,
		Timeout:        deps.Config.HTTP.ReadTimeout,
		Production:     deps.Config.IsProduction(),
		TrustProxy:     deps.Config.HTTP.TrustProxy,
	}.Use(r)

	health := handler.NewHealth(deps.Config.App.Name, deps.DB, deps.Redis)
	mountHealth(r, health)

	if deps.Config.Telemetry.MetricsEnabled {
		r.With(middleware.MetricsAuth(deps.Config.HTTP.MetricsToken)).
			Handle("/metrics", promhttp.Handler())
	}

	r.Get("/docs", handler.DocsRedoc("/openapi.yaml"))
	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "docs/openapi.yaml")
	})

	authH := handler.NewAuth(deps.Config, deps.Auth, deps.Idem)
	authMw := middleware.Authenticate(deps.Auth)

	r.Route("/api/v1", func(v1 chi.Router) {
		v1.Use(deps.rateLimit("global", sec.RateLimitRPM))
		mountHealth(v1, health)

		v1.Route("/auth", func(auth chi.Router) {
			auth.With(deps.rateLimit("register", sec.RegisterRateLimitRPM)).
				Post("/register", authH.Register)
			auth.With(deps.rateLimit("login", sec.LoginRateLimitRPM)).
				Post("/login", authH.Login)
			auth.With(deps.rateLimit("refresh", sec.RefreshRateLimitRPM)).
				Post("/refresh", authH.Refresh)
			auth.With(deps.rateLimit("forgot-password", sec.SensitiveRateLimitRPM)).
				Post("/forgot-password", authH.ForgotPassword)
			auth.With(deps.rateLimit("reset-password", sec.SensitiveRateLimitRPM)).
				Post("/reset-password", authH.ResetPassword)
			auth.With(deps.rateLimit("verify-email", sec.SensitiveRateLimitRPM)).
				Post("/verify-email", authH.VerifyEmail)

			auth.Group(func(protected chi.Router) {
				protected.Use(authMw)
				protected.Post("/logout", authH.Logout)
				protected.Post("/logout-all", authH.LogoutAll)
			})
		})

		v1.Group(func(protected chi.Router) {
			protected.Use(authMw)
			protected.With(middleware.RequirePermission("read_profile")).Get("/me", authH.Me)
		})
	})

	return r
}

func mountHealth(r chi.Router, h *handler.Health) {
	r.Get("/health", h.Liveness)
	r.Get("/ready", h.Readiness)
}

func (d Deps) rateLimit(scope string, rpm int) func(http.Handler) http.Handler {
	return middleware.RateLimit{
		Limiter: d.Limiter,
		Scope:   scope,
		Limit:   rpm,
		Window:  time.Minute,
	}.Middleware
}
