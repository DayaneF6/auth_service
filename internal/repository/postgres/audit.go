package postgres

import (
	"context"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/dayaneroot/auth-service/internal/infrastructure/postgres"
)

type AuditRepo struct{ db *postgres.DB }

func NewAuditRepo(db *postgres.DB) *AuditRepo { return &AuditRepo{db: db} }

func (r *AuditRepo) Log(ctx context.Context, entry domain.AuditEntry) error {
	const q = `
		INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata)
		VALUES ($1, $2, NULLIF($3, '')::inet, NULLIF($4, ''), COALESCE($5, '{}'))`
	_, err := r.db.Pool.Exec(ctx, q, entry.UserID, entry.Action, entry.IPAddress, entry.UserAgent, entry.Metadata)
	return err
}
