// Package dial provides shared connectivity helpers for infrastructure clients.
package dial

import (
	"context"
	"fmt"
	"time"
)

const DefaultPingTimeout = 5 * time.Second

// Ping runs fn with a bounded context so startup/readiness checks do not hang.
func Ping(ctx context.Context, name string, timeout time.Duration, ping func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := ping(ctx); err != nil {
		return fmt.Errorf("ping %s: %w", name, err)
	}
	return nil
}
