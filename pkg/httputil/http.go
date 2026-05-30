// Package httputil provides JSON helpers, client IP, Bearer parsing, and idempotency support.
package httputil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/dayaneroot/auth-service/internal/domain"
)

const MaxBody = 1 << 20

// ClientIP returns RemoteAddr (use chi RealIP + trust_proxy behind a reverse proxy).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]")
	}
	return strings.Trim(host, "[]")
}

// BearerToken extracts the token from Authorization: Bearer.
func BearerToken(header string) string {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func JSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteBytes(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func Message(w http.ResponseWriter, status int, msg string) {
	JSON(w, status, map[string]string{"message": msg})
}

// Decode parses JSON with a 1 MiB cap; rejects unknown fields and trailing values.
func Decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		WriteDecodeError(w)
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		WriteDecodeError(w)
		return false
	}
	return true
}

// ReadBodyHash reads the raw body (idempotency) and returns a SHA-256 hex digest.
func ReadBodyHash(w http.ResponseWriter, r *http.Request) (raw []byte, hash string, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		WriteDecodeError(w)
		return nil, "", false
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), true
}

func WriteTokenPair(w http.ResponseWriter, pair *domain.TokenPair) {
	JSON(w, http.StatusOK, map[string]any{
		"access_token": pair.AccessToken,
		"expires_in":   pair.ExpiresIn,
		"token_type":   "Bearer",
	})
}

// MessageWithDevToken builds a message JSON map; optional token when expose is true.
func MessageWithDevToken(expose bool, message, tokenKey, token string) map[string]string {
	m := map[string]string{"message": message}
	if expose && token != "" {
		m[tokenKey] = token
	}
	return m
}

// IdempotencyStore is the subset of Redis idempotency used by register.
type IdempotencyStore interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	Delete(ctx context.Context, key string) error
}

const idemTTL = 5 * time.Minute

// RunIdempotent executes fn once per cacheKey or returns a cached JSON body.
func RunIdempotent(w http.ResponseWriter, ctx context.Context, store IdempotencyStore, cacheKey string, fn func() ([]byte, error)) {
	if writeCached(w, ctx, store, cacheKey) {
		return
	}
	lockKey := cacheKey + ":lock"
	acquired, _ := store.SetNX(ctx, lockKey, []byte("1"), idemTTL)
	if !acquired {
		if writeCached(w, ctx, store, cacheKey) {
			return
		}
		WriteError(w, domain.ErrConflict)
		return
	}
	body, err := fn()
	if err != nil {
		_ = store.Delete(ctx, lockKey)
		WriteError(w, err)
		return
	}
	_ = store.Set(ctx, cacheKey, body, idemTTL)
	_ = store.Delete(ctx, lockKey)
	WriteBytes(w, http.StatusCreated, body)
}

func writeCached(w http.ResponseWriter, ctx context.Context, store IdempotencyStore, key string) bool {
	b, found, _ := store.Get(ctx, key)
	if !found || len(b) == 0 || b[0] != '{' {
		return false
	}
	WriteBytes(w, http.StatusCreated, b)
	return true
}

const maxIdempotencyKey = 128

// SanitizeIdempotencyKey keeps only safe ASCII for Redis keys (no shell metacharacters).
func SanitizeIdempotencyKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range strings.TrimSpace(key) {
		if b.Len() >= maxIdempotencyKey {
			break
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
