// Package config loads and validates application settings from env and YAML.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	App       AppConfig       `mapstructure:"app"`
	HTTP      HTTPConfig      `mapstructure:"http"`
	Postgres  PostgresConfig  `mapstructure:"postgres"`
	Redis     RedisConfig     `mapstructure:"redis"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	Email     EmailConfig     `mapstructure:"email"`
	Security  SecurityConfig  `mapstructure:"security"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
}

type AppConfig struct {
	Name        string `mapstructure:"name"`
	Environment string `mapstructure:"environment"`
	Version     string `mapstructure:"version"`
}

type HTTPConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	AllowedOrigins  []string      `mapstructure:"allowed_origins"`
	MaxHeaderBytes  int           `mapstructure:"max_header_bytes"`
	MetricsToken    string        `mapstructure:"metrics_token"`
	// TrustProxy enables chi RealIP (X-Forwarded-For / X-Real-IP). Only set behind a trusted reverse proxy.
	TrustProxy bool `mapstructure:"trust_proxy"`
}

func (h HTTPConfig) Addr() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

type PostgresConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Database        string        `mapstructure:"database"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int32         `mapstructure:"max_open_conns"`
	MaxIdleConns    int32         `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

func (p PostgresConfig) DSN() string {
	u := &url.URL{
		Scheme: "postgres",
		Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
		Path:   p.Database,
	}
	if p.User != "" {
		u.User = url.UserPassword(p.User, p.Password)
	}
	q := u.Query()
	q.Set("sslmode", p.SSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type JWTConfig struct {
	AccessSecret          string        `mapstructure:"access_secret"`
	// RefreshSecret is unused (refresh tokens are opaque); kept for backward-compatible env files.
	RefreshSecret         string        `mapstructure:"refresh_secret"`
	AccessTTL             time.Duration `mapstructure:"access_ttl"`
	RefreshTTL            time.Duration `mapstructure:"refresh_ttl"`
	Issuer                string        `mapstructure:"issuer"`
	RefreshCookieName     string        `mapstructure:"refresh_cookie_name"`
	RefreshCookieSecure   bool          `mapstructure:"refresh_cookie_secure"`
	RefreshCookieDomain   string        `mapstructure:"refresh_cookie_domain"`
	RefreshCookiePath     string        `mapstructure:"refresh_cookie_path"`
	RefreshCookieSameSite string        `mapstructure:"refresh_cookie_samesite"`
}

type EmailConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	APIKey             string        `mapstructure:"api_key"`
	From               string        `mapstructure:"from"`
	VerifyLinkBase     string        `mapstructure:"verify_link_base"`
	ResetLinkBase      string        `mapstructure:"reset_link_base"`
	PerRecipientLimit  int           `mapstructure:"per_recipient_limit"`
	PerRecipientWindow time.Duration `mapstructure:"per_recipient_window"`
}

type SecurityConfig struct {
	BcryptCost             int           `mapstructure:"bcrypt_cost"`
	RateLimitRPM             int           `mapstructure:"rate_limit_rpm"` // global ceiling per IP on /api/v1
	LoginRateLimitRPM        int           `mapstructure:"login_rate_limit_rpm"`
	RegisterRateLimitRPM     int           `mapstructure:"register_rate_limit_rpm"`
	RefreshRateLimitRPM      int           `mapstructure:"refresh_rate_limit_rpm"`
	SensitiveRateLimitRPM    int           `mapstructure:"sensitive_rate_limit_rpm"` // forgot / reset / verify
	LoginMaxAttempts         int           `mapstructure:"login_max_attempts"`
	LoginLockoutDuration     time.Duration `mapstructure:"login_lockout_duration"`
}

type TelemetryConfig struct {
	LogLevel       string `mapstructure:"log_level"`
	OTLPEndpoint   string `mapstructure:"otlp_endpoint"`
	OTLPInsecure   bool   `mapstructure:"otlp_insecure"`
	TracingEnabled bool   `mapstructure:"tracing_enabled"`
	MetricsEnabled bool   `mapstructure:"metrics_enabled"`
}

func (c *Config) IsProduction() bool {
	return strings.EqualFold(c.App.Environment, "production")
}

// ExposeDevTokens is true when one-time tokens may be returned in API JSON (local / email off).
func (c *Config) ExposeDevTokens() bool {
	return !c.Email.Enabled || !c.IsProduction()
}

// Load reads .env, config files, and AUTH_* environment variables.
func Load() (*Config, error) {
	_ = godotenv.Load()

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	_ = v.ReadInConfig()

	v.SetEnvPrefix("AUTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	defaults := setDefaults(v)
	for key := range defaults {
		_ = v.BindEnv(key)
	}
	for _, key := range []string{"jwt.access_secret", "jwt.refresh_secret", "email.api_key"} {
		_ = v.BindEnv(key)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate enforces security-related constraints before the server starts.
func (c *Config) Validate() error {
	if err := requireMinLen("jwt.access_secret", c.JWT.AccessSecret, 32); err != nil {
		return err
	}
	if c.IsProduction() {
		if !c.JWT.RefreshCookieSecure {
			return fmt.Errorf("jwt.refresh_cookie_secure must be true in production")
		}
		if len(c.HTTP.AllowedOrigins) == 0 {
			return fmt.Errorf("http.allowed_origins must be set in production")
		}
		for _, o := range c.HTTP.AllowedOrigins {
			if o == "*" {
				return fmt.Errorf("http.allowed_origins must not contain wildcard when credentials are allowed")
			}
		}
	}
	if c.Postgres.User == "" || c.Postgres.Database == "" {
		return fmt.Errorf("postgres.user and postgres.database are required")
	}
	if c.Redis.Addr == "" {
		return fmt.Errorf("redis.addr is required")
	}
	if c.IsProduction() && c.Postgres.SSLMode == "disable" {
		return fmt.Errorf("postgres.sslmode must not be disable in production")
	}
	if c.Security.BcryptCost < 10 || c.Security.BcryptCost > 14 {
		return fmt.Errorf("security.bcrypt_cost must be between 10 and 14")
	}
	if c.Email.Enabled {
		if c.Email.APIKey == "" {
			return fmt.Errorf("email.api_key is required when email.enabled is true")
		}
		if c.Email.From == "" {
			return fmt.Errorf("email.from is required when email.enabled is true")
		}
		if c.Email.VerifyLinkBase == "" || c.Email.ResetLinkBase == "" {
			return fmt.Errorf("email.verify_link_base and email.reset_link_base are required when email.enabled is true")
		}
		if err := requireHTTPSURL("email.verify_link_base", c.Email.VerifyLinkBase); err != nil {
			return err
		}
		if err := requireHTTPSURL("email.reset_link_base", c.Email.ResetLinkBase); err != nil {
			return err
		}
		if c.Email.PerRecipientLimit < 1 {
			return fmt.Errorf("email.per_recipient_limit must be >= 1")
		}
		if c.Email.PerRecipientWindow < time.Minute {
			return fmt.Errorf("email.per_recipient_window must be >= 1m")
		}
	}
	for _, lim := range []struct {
		name string
		v    int
	}{
		{"security.rate_limit_rpm", c.Security.RateLimitRPM},
		{"security.login_rate_limit_rpm", c.Security.LoginRateLimitRPM},
		{"security.register_rate_limit_rpm", c.Security.RegisterRateLimitRPM},
		{"security.refresh_rate_limit_rpm", c.Security.RefreshRateLimitRPM},
		{"security.sensitive_rate_limit_rpm", c.Security.SensitiveRateLimitRPM},
	} {
		if lim.v < 1 {
			return fmt.Errorf("%s must be >= 1", lim.name)
		}
	}
	return nil
}

func requireMinLen(field, value string, min int) error {
	if len(value) < min {
		return fmt.Errorf("%s must be at least %d characters", field, min)
	}
	return nil
}

func requireHTTPSURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s: invalid url", field)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s: scheme must be http or https", field)
	}
	return nil
}

func setDefaults(v *viper.Viper) map[string]any {
	defaults := map[string]any{
		"app.name": "auth-service", "app.environment": "development", "app.version": "0.1.0",
		"http.host": "0.0.0.0", "http.port": 8080,
		"http.read_timeout": "15s", "http.write_timeout": "15s", "http.idle_timeout": "60s",
		"http.shutdown_timeout": "10s", "http.allowed_origins": []string{"http://localhost:3000"},
		"http.max_header_bytes": 1048576, "http.trust_proxy": false,
		"postgres.host":         "localhost", "postgres.port": 5432, "postgres.user": "auth",
		"postgres.password": "auth", "postgres.database": "auth", "postgres.sslmode": "disable",
		"postgres.max_open_conns": 25, "postgres.max_idle_conns": 10,
		"postgres.conn_max_lifetime": "30m", "postgres.conn_max_idle_time": "5m",
		"redis.addr": "localhost:6379", "redis.db": 0, "redis.pool_size": 10,
		"redis.min_idle_conns": 2, "redis.dial_timeout": "5s",
		"redis.read_timeout": "3s", "redis.write_timeout": "3s",
		"jwt.access_ttl": "15m", "jwt.refresh_ttl": "168h", "jwt.issuer": "auth-service",
		"jwt.refresh_cookie_name": "refresh_token", "jwt.refresh_cookie_secure": false,
		"jwt.refresh_cookie_domain": "", "jwt.refresh_cookie_path": "/",
		"jwt.refresh_cookie_samesite": "Strict",
		"email.enabled": false, "email.from": "",
		"email.verify_link_base": "http://localhost:3000/verify-email",
		"email.reset_link_base":  "http://localhost:3000/reset-password",
		"email.per_recipient_limit": 5, "email.per_recipient_window": "1h",
		"security.bcrypt_cost": 12,
		"security.rate_limit_rpm": 120, "security.login_rate_limit_rpm": 10,
		"security.register_rate_limit_rpm": 30, "security.refresh_rate_limit_rpm": 20,
		"security.sensitive_rate_limit_rpm": 5,
		"security.login_max_attempts": 5, "security.login_lockout_duration": "15m",
		"telemetry.log_level": "info", "telemetry.tracing_enabled": false,
		"telemetry.otlp_insecure": true, "telemetry.metrics_enabled": true,
	}
	for key, val := range defaults {
		v.SetDefault(key, val)
	}
	return defaults
}
