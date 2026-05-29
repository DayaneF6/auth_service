// Package postgres provides a pgx connection pool and health checks.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/infrastructure/dial"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const name = "postgres"

type DB struct {
	Pool *pgxpool.Pool
}

func (db *DB) Name() string { return name }

func (db *DB) Ping(ctx context.Context) error {
	return db.Pool.Ping(ctx)
}

func (db *DB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

// New builds a pgxpool.Pool from config and verifies connectivity before returning.
// Pool settings follow jackc/pgx pool recommendations (max conns, idle time, health check).
func New(ctx context.Context, cfg config.PostgresConfig, log *zap.Logger) (*DB, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxOpenConns
	poolCfg.MinConns = cfg.MaxIdleConns
	poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
	poolCfg.MaxConnIdleTime = cfg.ConnMaxIdleTime
	poolCfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	db := &DB{Pool: pool}
	if err := dial.Ping(ctx, name, dial.DefaultPingTimeout, db.Ping); err != nil {
		db.Close()
		return nil, err
	}

	log.Info("postgres connected",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("database", cfg.Database),
	)
	return db, nil
}
