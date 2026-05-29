package middleware

import (
	"context"
	"net/http"
	"regexp"

	"github.com/google/uuid"
)

type ctxKey string

const (
	requestIDKey     ctxKey = "request_id"
	correlationIDKey ctxKey = "correlation_id"
)

var traceIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func TraceContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := sanitizeTraceID(r.Header.Get("X-Request-ID"))
		corrID := sanitizeTraceID(r.Header.Get("X-Correlation-ID"))

		ctx := r.Context()
		ctx = context.WithValue(ctx, requestIDKey, reqID)
		ctx = context.WithValue(ctx, correlationIDKey, corrID)

		w.Header().Set("X-Request-ID", reqID)
		w.Header().Set("X-Correlation-ID", corrID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sanitizeTraceID(value string) string {
	if traceIDPattern.MatchString(value) {
		return value
	}
	return uuid.NewString()
}

func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

func CorrelationID(ctx context.Context) string {
	v, _ := ctx.Value(correlationIDKey).(string)
	return v
}
