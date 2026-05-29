// Package redis wraps go-redis/v9 with connection setup and health checks.
package redis

import (
	"context"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/infrastructure/dial"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const name = "redis"

type Client struct {
	*goredis.Client
}

func (c *Client) Name() string { return name }

func (c *Client) Ping(ctx context.Context) error {
	return c.Client.Ping(ctx).Err()
}

// New dials Redis with pool/timeouts from config and verifies PING before returning.
func New(ctx context.Context, cfg config.RedisConfig, log *zap.Logger) (*Client, error) {
	client := goredis.NewClient(&goredis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	c := &Client{Client: client}
	if err := dial.Ping(ctx, name, dial.DefaultPingTimeout, c.Ping); err != nil {
		_ = client.Close()
		return nil, err
	}

	log.Info("redis connected", zap.String("addr", cfg.Addr))
	return c, nil
}

func (c *Client) Close() error {
	if c.Client == nil {
		return nil
	}
	return c.Client.Close()
}
