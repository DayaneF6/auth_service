// Entry point: load config, start HTTP server, graceful shutdown on SIGINT/SIGTERM.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dayaneroot/auth-service/internal/app"
	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log, err := logger.New(cfg.Telemetry.LogLevel, cfg.App.Name, cfg.App.Environment)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()

	ctx := context.Background()
	application, err := app.New(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- application.Run()
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server: %w", err)
		}
	case <-quit:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()

	if err := application.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", zap.Error(err))
		return err
	}
	return nil
}
