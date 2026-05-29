// Package httputil provides HTTP helpers for JSON responses and stable API errors.
package httputil

import (
	"errors"
	"net/http"

	"github.com/dayaneroot/auth-service/internal/domain"
)

type APIError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// WriteError maps internal errors to a stable public error schema.
// Do not leak internal messages in Message/Details.
func WriteError(w http.ResponseWriter, err error) {
	status, apiErr := MapError(err)
	JSON(w, status, apiErr)
}

func MapError(err error) (int, APIError) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		return http.StatusBadRequest, APIError{Code: "invalid_request", Message: "Invalid request"}
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict, APIError{Code: "conflict", Message: "Resource already exists"}
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrTokenInvalid), errors.Is(err, domain.ErrTokenExpired):
		return http.StatusUnauthorized, APIError{Code: "unauthorized", Message: "Unauthorized"}
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden, APIError{Code: "forbidden", Message: "Forbidden"}
	case errors.Is(err, domain.ErrAccountLocked):
		return http.StatusTooManyRequests, APIError{Code: "account_locked", Message: "Account temporarily locked"}
	case errors.Is(err, domain.ErrRateLimited):
		return http.StatusTooManyRequests, APIError{Code: "rate_limited", Message: "Rate limit exceeded"}
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, APIError{Code: "not_found", Message: "Not found"}
	default:
		return http.StatusInternalServerError, APIError{Code: "internal", Message: "Internal server error"}
	}
}

func WriteDecodeError(w http.ResponseWriter) {
	JSON(w, http.StatusBadRequest, APIError{
		Code:    "invalid_json",
		Message: "Invalid JSON body",
	})
}
