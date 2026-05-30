// Private auth implementation: validation, tokens, audit, email (paired with auth.go).
package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/dayaneroot/auth-service/internal/domain"
	jwtsvc "github.com/dayaneroot/auth-service/internal/infrastructure/jwt"
	"github.com/dayaneroot/auth-service/pkg/token"
	"github.com/dayaneroot/auth-service/pkg/uri"
	"github.com/dayaneroot/auth-service/pkg/validate"
	"github.com/google/uuid"
)

type mailKind int

const (
	mailVerify mailKind = iota
	mailReset
)

var mailCopy = [...]struct{ subject, plain string }{
	{"Verify your email", "Open this link to verify your email (expires in 24h):\n%s"},
	{"Reset your password", "Open this link to reset your password (expires in 1h):\n%s"},
}

// Validation and email normalization.

func requireInput(in any) error {
	if err := validate.Struct(in); err != nil {
		return domain.ErrInvalidInput
	}
	return nil
}

func normEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *AuthService) devToken(raw string) string {
	if s.cfg.ExposeDevTokens() {
		return raw
	}
	return ""
}

func (s *AuthService) failLogin(ctx context.Context, email, ip, ua string) (*domain.TokenPair, error) {
	_ = s.lockout.RecordFailure(ctx, email, s.cfg.Security.LoginMaxAttempts, s.cfg.Security.LoginLockoutDuration)
	s.logAudit(ctx, nil, "auth.login_failed", ip, ua, nil)
	return nil, domain.ErrUnauthorized
}

func (s *AuthService) revokeAllSessions(ctx context.Context, userID uuid.UUID) {
	_ = s.refresh.RevokeAllForUser(ctx, userID)
	_ = s.sessions.DeleteAllForUser(ctx, userID)
}

func (s *AuthService) logAudit(ctx context.Context, userID *uuid.UUID, action, ip, ua string, meta map[string]string) {
	var raw json.RawMessage
	if meta != nil {
		raw, _ = json.Marshal(meta)
	}
	_ = s.audit.Log(ctx, domain.AuditEntry{
		UserID: userID, Action: action,
		IPAddress: validate.SanitizeLogValue(ip, 45),
		UserAgent: validate.SanitizeLogValue(ua, 512),
		Metadata:  raw,
	})
}

func (s *AuthService) issueOneTime(ctx context.Context, repo domain.OneTimeTokenRepository, userID uuid.UUID, ttl time.Duration) (string, error) {
	raw, err := token.Random(32)
	if err != nil {
		return "", err
	}
	if err := repo.Create(ctx, userID, token.Hash(raw), time.Now().Add(ttl)); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *AuthService) issueTokens(ctx context.Context, userID, sessionID, familyID uuid.UUID) (*domain.TokenPair, error) {
	profile, err := s.users.GetAuthProfile(ctx, userID)
	if err != nil {
		return nil, err
	}
	ttl := s.jwt.RefreshTTL()
	if err := s.sessions.Save(ctx, domain.Session{
		ID: sessionID, UserID: userID, Email: profile.Email,
		Roles: profile.Roles, Permissions: profile.Permissions, FamilyID: familyID,
	}, ttl); err != nil {
		return nil, err
	}
	role := defaultRole
	if len(profile.Roles) > 0 {
		role = profile.Roles[0]
	}
	access, exp, err := s.jwt.IssueAccess(jwtsvc.IssueInput{
		UserID: userID, Email: profile.Email, Role: role,
		Permissions: profile.Permissions, SessionID: sessionID,
	})
	if err != nil {
		return nil, err
	}
	refreshRaw, err := token.Random(32)
	if err != nil {
		return nil, err
	}
	if err := s.refresh.Save(ctx, domain.RefreshRecord{
		UserID: userID, SessionID: sessionID,
		TokenHash: token.Hash(refreshRaw), FamilyID: familyID,
		ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		return nil, err
	}
	return &domain.TokenPair{
		AccessToken: access, RefreshToken: refreshRaw,
		ExpiresIn: int64(time.Until(exp).Seconds()),
	}, nil
}

// Outbound email via Resend (skipped when email.enabled is false).

func (s *AuthService) sendActionEmail(ctx context.Context, to, rawToken string, kind mailKind) error {
	base := s.cfg.Email.VerifyLinkBase
	if kind == mailReset {
		base = s.cfg.Email.ResetLinkBase
	}
	link, err := uri.ActionLink(base, rawToken)
	if err != nil {
		return err
	}
	mc := mailCopy[kind]
	esc := html.EscapeString(link)
	htmlBody := fmt.Sprintf(`<p><a href="%s">%s</a></p>`, esc, esc)
	return s.sendTransactional(ctx, to, mc.subject, fmt.Sprintf(mc.plain, link), htmlBody)
}

func (s *AuthService) consumeEmailQuota(ctx context.Context, to string) error {
	if !s.cfg.Email.Enabled {
		return nil
	}
	ok, err := s.emailLimit.Allow(ctx, "email:"+normEmail(to),
		s.cfg.Email.PerRecipientLimit, s.cfg.Email.PerRecipientWindow)
	if err != nil {
		return err
	}
	if !ok {
		return domain.ErrRateLimited
	}
	return nil
}

func (s *AuthService) sendTransactional(ctx context.Context, to, subject, text, htmlBody string) error {
	if !s.cfg.Email.Enabled || s.mailer == nil {
		return nil
	}
	return s.mailer.Send(ctx, domain.EmailMessage{
		To: normEmail(to), Subject: subject, Text: text, HTML: htmlBody,
	})
}
