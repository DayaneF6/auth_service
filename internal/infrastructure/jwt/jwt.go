// Package jwt signs and validates short-lived access tokens (HS256).
package jwt

import (
	"fmt"
	"time"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims are embedded in every access token.
type Claims struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	SessionID   string   `json:"session_id"`
	jwt.RegisteredClaims
}

type Service struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	issuer     string
}

func NewService(cfg config.JWTConfig) *Service {
	return &Service{
		secret:     []byte(cfg.AccessSecret),
		accessTTL:  cfg.AccessTTL,
		refreshTTL: cfg.RefreshTTL,
		issuer:     cfg.Issuer,
	}
}

type IssueInput struct {
	UserID      uuid.UUID
	Email       string
	Role        string
	Permissions []string
	SessionID   uuid.UUID
}

func (s *Service) IssueAccess(in IssueInput) (token string, exp time.Time, err error) {
	now := time.Now()
	exp = now.Add(s.accessTTL)

	claims := Claims{
		UserID:      in.UserID.String(),
		Email:       in.Email,
		Role:        in.Role,
		Permissions: in.Permissions,
		SessionID:   in.SessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    s.issuer,
			Subject:   in.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	return signed, exp, err
}

func (s *Service) ParseAccess(token string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (s *Service) RefreshTTL() time.Duration { return s.refreshTTL }
