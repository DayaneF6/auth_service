package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/dayaneroot/auth-service/pkg/httputil"
)

// RateLimit enforces a fixed-window counter per scope + client IP (Redis-backed).
type RateLimit struct {
	Limiter domain.RateLimiter
	Scope   string // isolates counters per route group (e.g. login vs register)
	Limit   int
	Window  time.Duration
}

func (rl RateLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rl.Limiter == nil || rl.Limit < 1 {
			next.ServeHTTP(w, r)
			return
		}
		key := fmt.Sprintf("%s:ip:%s", rl.Scope, httputil.ClientIP(r))
		ok, err := rl.Limiter.Allow(r.Context(), key, rl.Limit, rl.Window)
		if err != nil || !ok {
			if rl.Window > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(rl.Window.Seconds())))
			}
			httputil.WriteError(w, domain.ErrRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}
