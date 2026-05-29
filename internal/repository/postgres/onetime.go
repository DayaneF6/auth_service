package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/dayaneroot/auth-service/internal/infrastructure/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OneTimeRepo stores hashed single-use tokens (password reset or email verification).
// table is allowlisted at construction time — never pass user-controlled table names.
type OneTimeRepo struct {
	db    *postgres.DB
	table string
}

func NewPasswordResetRepo(db *postgres.DB) *OneTimeRepo {
	return &OneTimeRepo{db: db, table: "password_resets"}
}

func NewEmailVerificationRepo(db *postgres.DB) *OneTimeRepo {
	return &OneTimeRepo{db: db, table: "email_verifications"}
}

func (r *OneTimeRepo) Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	q := fmt.Sprintf(`INSERT INTO %s (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`, r.table)
	_, err := r.db.Pool.Exec(ctx, q, userID, tokenHash, expiresAt)
	return err
}

// Consume marks a token as used and returns the owner in one statement (atomic).
func (r *OneTimeRepo) Consume(ctx context.Context, tokenHash string) (*uuid.UUID, error) {
	q := fmt.Sprintf(`
		UPDATE %s SET used_at = NOW()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING user_id`, r.table)
	var userID uuid.UUID
	err := r.db.Pool.QueryRow(ctx, q, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrTokenInvalid
	}
	return &userID, err
}
