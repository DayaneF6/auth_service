// Package middleware wires cross-cutting HTTP concerns (logging, security, rate limits).
package middleware

import (
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"
)

// Stack configures global middleware applied to every route.
type Stack struct {
	Logger         *zap.Logger
	AllowedOrigins []string
	Timeout        time.Duration
	Production     bool
	TrustProxy     bool
}

func (s Stack) Use(r chi.Router) {
	r.Use(Recovery(s.Logger))
	r.Use(TraceContext)
	r.Use(SecurityHeaders(s.Production))
	r.Use(Logging(s.Logger))
	if s.TrustProxy {
		r.Use(chimw.RealIP)
	}
	r.Use(chimw.Timeout(s.Timeout))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "X-Correlation-ID"},
		ExposedHeaders:   []string{"X-Request-ID", "X-Correlation-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
}
