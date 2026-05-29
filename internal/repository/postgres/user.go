// Package postgres implements domain repository interfaces with pgx parameterized queries.
package postgres

import (
	"context"
	"errors"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/dayaneroot/auth-service/internal/infrastructure/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type UserRepo struct{ db *postgres.DB }

func NewUserRepo(db *postgres.DB) *UserRepo { return &UserRepo{db: db} }

func (r *UserRepo) Create(ctx context.Context, email, passwordHash string) (*domain.User, error) {
	const q = `
		INSERT INTO users (email, password_hash)
		VALUES (LOWER($1), $2)
		RETURNING id, email, password_hash, email_verified, is_active, created_at, updated_at`
	var u domain.User
	err := r.db.Pool.QueryRow(ctx, q, email, passwordHash).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, domain.ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	const q = `
		SELECT id, email, password_hash, email_verified, is_active, created_at, updated_at
		FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`
	return r.scanOne(ctx, q, email)
}

func (r *UserRepo) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	tag, err := r.db.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`,
		userID, passwordHash,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserRepo) MarkEmailVerified(ctx context.Context, userID uuid.UUID) error {
	tag, err := r.db.Pool.Exec(ctx,
		`UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserRepo) AssignRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	const q = `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name = $2
		ON CONFLICT DO NOTHING`
	_, err := r.db.Pool.Exec(ctx, q, userID, roleName)
	return err
}

func (r *UserRepo) GetAuthProfile(ctx context.Context, userID uuid.UUID) (*domain.AuthProfile, error) {
	const q = `
		SELECT u.id, u.email,
			COALESCE(array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '{}'),
			COALESCE(array_agg(DISTINCT p.name) FILTER (WHERE p.name IS NOT NULL), '{}')
		FROM users u
		LEFT JOIN user_roles ur ON ur.user_id = u.id
		LEFT JOIN roles r ON r.id = ur.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id
		WHERE u.id = $1 AND u.deleted_at IS NULL
		GROUP BY u.id, u.email`
	var profile domain.AuthProfile
	err := r.db.Pool.QueryRow(ctx, q, userID).Scan(&profile.UserID, &profile.Email, &profile.Roles, &profile.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return &profile, err
}

func (r *UserRepo) scanOne(ctx context.Context, q string, arg any) (*domain.User, error) {
	var u domain.User
	err := r.db.Pool.QueryRow(ctx, q, arg).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return &u, err
}

// isUniqueViolation maps Postgres SQLSTATE 23505 to a domain conflict error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
