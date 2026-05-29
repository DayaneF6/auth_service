package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/dayaneroot/auth-service/pkg/httputil"
)

type Checker interface {
	Name() string
	Ping(context.Context) error
}

type Health struct {
	service  string
	checkers []Checker
}

func NewHealth(service string, checkers ...Checker) *Health {
	return &Health{service: service, checkers: checkers}
}

func (h *Health) Liveness(w http.ResponseWriter, _ *http.Request) {
	httputil.JSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": h.service,
	})
}

func (h *Health) Readiness(w http.ResponseWriter, r *http.Request) {
	// Bound dependency checks so /ready responds within a predictable window.
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string, len(h.checkers))
	status := http.StatusOK
	overall := "ok"

	for _, c := range h.checkers {
		checks[c.Name()] = "ok"
		if err := c.Ping(ctx); err != nil {
			checks[c.Name()] = "unavailable"
			overall = "degraded"
			status = http.StatusServiceUnavailable
		}
	}

	httputil.JSON(w, status, map[string]any{
		"status":   overall,
		"checks":   checks,
		"duration": time.Since(start).String(),
	})
}
