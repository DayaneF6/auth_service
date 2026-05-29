package httputil

import (
	"net/http"

	"github.com/dayaneroot/auth-service/internal/config"
)

func SetRefreshCookie(w http.ResponseWriter, cfg config.JWTConfig, refresh string) {
	if refresh == "" {
		return
	}
	http.SetCookie(w, refreshCookie(cfg, refresh, int(cfg.RefreshTTL.Seconds())))
}

func ClearRefreshCookie(w http.ResponseWriter, cfg config.JWTConfig) {
	http.SetCookie(w, refreshCookie(cfg, "", -1))
}

func RefreshFromCookie(r *http.Request, cfg config.JWTConfig) string {
	c, err := r.Cookie(cfg.RefreshCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func refreshCookie(cfg config.JWTConfig, value string, maxAge int) *http.Cookie {
	path := cfg.RefreshCookiePath
	if path == "" {
		path = "/"
	}
	// Secure and SameSite come from config (production uses Secure=true).
	return &http.Cookie{ //nolint:gosec // G124 — HttpOnly always on; Secure is env-driven via JWTConfig
		Name: cfg.RefreshCookieName, Value: value, Path: path,
		Domain: cfg.RefreshCookieDomain, Secure: cfg.RefreshCookieSecure,
		HttpOnly: true, SameSite: parseSameSite(cfg.RefreshCookieSameSite), MaxAge: maxAge,
	}
}

func parseSameSite(v string) http.SameSite {
	switch v {
	case "Lax", "lax":
		return http.SameSiteLaxMode
	case "None", "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}
