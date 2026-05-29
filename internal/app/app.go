// Package app wires dependencies and runs the HTTP server with graceful shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/delivery/http/router"
	jwtsvc "github.com/dayaneroot/auth-service/internal/infrastructure/jwt"
	"github.com/dayaneroot/auth-service/internal/infrastructure/postgres"
	redisinfra "github.com/dayaneroot/auth-service/internal/infrastructure/redis"
	"github.com/dayaneroot/auth-service/internal/infrastructure/telemetry"
	repo "github.com/dayaneroot/auth-service/internal/repository/postgres"
	"github.com/dayaneroot/auth-service/internal/usecase"
	"go.uber.org/zap"
)

type App struct {
	cfg             *config.Config
	log             *zap.Logger
	db              *postgres.DB
	redis           *redisinfra.Client
	server          *http.Server
	shutdownTracing func(context.Context) error
}

// New connects infrastructure, builds the auth service, and configures net/http.Server.
func New(ctx context.Context, cfg *config.Config, log *zap.Logger) (*App, error) {
	shutdownTracing, err := telemetry.InitTracing(ctx, cfg.Telemetry, cfg.App.Name, cfg.App.Version)
	if err != nil {
		return nil, fmt.Errorf("init tracing: %w", err)
	}
	cleanup := func() { _ = shutdownTracing(ctx) }

	db, err := postgres.New(ctx, cfg.Postgres, log)
	if err != nil {
		cleanup()
		return nil, err
	}

	rdb, err := redisinfra.New(ctx, cfg.Redis, log)
	if err != nil {
		db.Close()
		cleanup()
		return nil, err
	}

	jwt := jwtsvc.NewService(cfg.JWT)
	auth := usecase.NewAuthService(usecase.AuthDeps{
		Config: cfg, JWT: jwt,
		Users:     repo.NewUserRepo(db),
		Refresh:   repo.NewRefreshRepo(db),
		Resets:    repo.NewPasswordResetRepo(db),
		Verify:    repo.NewEmailVerificationRepo(db),
		Audit:     repo.NewAuditRepo(db),
		Sessions:  redisinfra.NewSessionStore(rdb),
		Blacklist: redisinfra.NewBlacklist(rdb),
		Lockout:   redisinfra.NewLockout(rdb),
	})

	maxHeader := cfg.HTTP.MaxHeaderBytes
	if maxHeader <= 0 {
		maxHeader = 1 << 20
	}

	server := &http.Server{
		Addr: cfg.HTTP.Addr(),
		Handler: router.New(router.Deps{
			Config: cfg, Logger: log, DB: db, Redis: rdb,
			Auth:    auth,
			Limiter: redisinfra.NewRateLimiter(rdb),
			Idem:    redisinfra.NewIdempotency(rdb),
		}),
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		MaxHeaderBytes:    maxHeader,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout, // mitigates slowloris (net/http best practice)
	}

	return &App{
		cfg: cfg, log: log, db: db, redis: rdb,
		server: server, shutdownTracing: shutdownTracing,
	}, nil
}

func (a *App) Run() error {
	a.log.Info("server starting",
		zap.String("addr", a.server.Addr),
		zap.String("environment", a.cfg.App.Environment),
		zap.String("version", a.cfg.App.Version),
	)
	if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen and serve: %w", err)
	}
	return nil
}

// Shutdown stops accepting requests, then closes Redis, tracing, and Postgres.
func (a *App) Shutdown(ctx context.Context) error {
	a.log.Info("shutting down server")
	err := errors.Join(
		a.server.Shutdown(ctx),
		a.redis.Close(),
		a.shutdownTracing(ctx),
	)
	a.db.Close()
	if err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	a.log.Info("shutdown complete")
	return nil
}
