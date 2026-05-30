package httputil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/dayaneroot/auth-service/internal/domain"
)

const MaxBody = 1 << 20

// ClientIP returns the client address from RemoteAddr (set by chi RealIP only when trust_proxy is enabled).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]")
	}
	return strings.Trim(host, "[]")
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

// ReadBodyHash reads the raw body (for idempotency) and returns a SHA-256 hex digest.
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

// WithDevToken adds a token field to the response only outside production.
func WithDevToken(production bool, base map[string]string, tokenKey, token string) map[string]string {
	if !production && token != "" {
		base[tokenKey] = token
	}
	return base
}
