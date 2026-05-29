package domain

import "errors"

// Sentinel errors map to stable HTTP codes in httputil.MapError.
var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
	ErrInvalidInput  = errors.New("invalid input")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrTokenExpired  = errors.New("token expired")
	ErrAccountLocked = errors.New("account locked")
	ErrRateLimited   = errors.New("rate limited")
)
