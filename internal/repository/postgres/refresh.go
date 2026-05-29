package postgres

import (
	"context"
	"errors"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/dayaneroot/auth-service/internal/infrastructure/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RefreshRepo struct{ db *postgres.DB }

func NewRefreshRepo(db *postgres.DB) *RefreshRepo { return &RefreshRepo{db: db} }

func (r *RefreshRepo) Save(ctx context.Context, rec domain.RefreshRecord) error {
	const q = `
		INSERT INTO refresh_tokens (user_id, session_id, token_hash, family_id, expires_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.Pool.Exec(ctx, q, rec.UserID, rec.SessionID, rec.TokenHash, rec.FamilyID, rec.ExpiresAt)
	return err
}

func (r *RefreshRepo) GetByHash(ctx context.Context, hash string) (*domain.RefreshRecord, error) {
	const q = `
		SELECT id, user_id, session_id, token_hash, family_id, expires_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()`
	return r.scan(ctx, q, hash)
}

// GetRevokedFamily supports refresh-token replay detection after rotation.
func (r *RefreshRepo) GetRevokedFamily(ctx context.Context, hash string) (*uuid.UUID, error) {
	const q = `SELECT family_id FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NOT NULL`
	var familyID uuid.UUID
	err := r.db.Pool.QueryRow(ctx, q, hash).Scan(&familyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &familyID, err
}

func (r *RefreshRepo) Revoke(ctx context.Context, hash string) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL`, hash)
	return err
}

func (r *RefreshRepo) RevokeFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL`, familyID)
	return err
}

func (r *RefreshRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func (r *RefreshRepo) scan(ctx context.Context, q, hash string) (*domain.RefreshRecord, error) {
	var rec domain.RefreshRecord
	err := r.db.Pool.QueryRow(ctx, q, hash).Scan(
		&rec.ID, &rec.UserID, &rec.SessionID, &rec.TokenHash, &rec.FamilyID, &rec.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return &rec, err
}
