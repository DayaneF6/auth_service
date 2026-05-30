// Package domain holds core entities, sentinel errors, and repository contracts.
package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type UserRepository interface {
	// CreateWithRole inserts the user and role assignment in one transaction.
	CreateWithRole(ctx context.Context, email, passwordHash, roleName string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	MarkEmailVerified(ctx context.Context, userID uuid.UUID) error
	GetAuthProfile(ctx context.Context, userID uuid.UUID) (*AuthProfile, error)
}

type RefreshTokenRepository interface {
	Save(ctx context.Context, rec RefreshRecord) error
	GetByHash(ctx context.Context, hash string) (*RefreshRecord, error)
	GetRevokedFamily(ctx context.Context, hash string) (*uuid.UUID, error)
	Revoke(ctx context.Context, hash string) error
	RevokeFamily(ctx context.Context, familyID uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

type OneTimeTokenRepository interface {
	Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	Consume(ctx context.Context, tokenHash string) (*uuid.UUID, error)
}

type AuditRepository interface {
	Log(ctx context.Context, entry AuditEntry) error
}

type SessionStore interface {
	Save(ctx context.Context, session Session, ttl time.Duration) error
	Delete(ctx context.Context, sessionID, userID uuid.UUID) error
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
}

type TokenBlacklist interface {
	Add(ctx context.Context, jti string, ttl time.Duration) error
	Exists(ctx context.Context, jti string) (bool, error)
}

type LoginLockout interface {
	IsLocked(ctx context.Context, key string) (bool, error)
	RecordFailure(ctx context.Context, key string, max int, lockout time.Duration) error
	Clear(ctx context.Context, key string) error
}

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

// EmailMessage is a transactional email (verification or password reset).
type EmailMessage struct {
	To, Subject, Text, HTML string
}

// Mailer delivers outbound email (Resend when enabled).
type Mailer interface {
	Send(ctx context.Context, msg EmailMessage) error
}
