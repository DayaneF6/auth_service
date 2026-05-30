// Package usecase implements application services (auth flows, token lifecycle, audit).
package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/domain"
	jwtsvc "github.com/dayaneroot/auth-service/internal/infrastructure/jwt"
	"github.com/dayaneroot/auth-service/pkg/password"
	"github.com/dayaneroot/auth-service/pkg/token"
	"github.com/dayaneroot/auth-service/pkg/validate"
	"github.com/google/uuid"
)

type AuthService struct {
	cfg       *config.Config
	jwt       *jwtsvc.Service
	users     domain.UserRepository
	refresh   domain.RefreshTokenRepository
	resets    domain.OneTimeTokenRepository
	verify    domain.OneTimeTokenRepository
	audit     domain.AuditRepository
	sessions  domain.SessionStore
	blacklist domain.TokenBlacklist
	lockout   domain.LoginLockout
}

type AuthDeps struct {
	Config    *config.Config
	JWT       *jwtsvc.Service
	Users     domain.UserRepository
	Refresh   domain.RefreshTokenRepository
	Resets    domain.OneTimeTokenRepository
	Verify    domain.OneTimeTokenRepository
	Audit     domain.AuditRepository
	Sessions  domain.SessionStore
	Blacklist domain.TokenBlacklist
	Lockout   domain.LoginLockout
}

func NewAuthService(d AuthDeps) *AuthService {
	return &AuthService{
		cfg: d.Config, jwt: d.JWT,
		users: d.Users, refresh: d.Refresh,
		resets: d.Resets, verify: d.Verify,
		audit: d.Audit, sessions: d.Sessions,
		blacklist: d.Blacklist, lockout: d.Lockout,
	}
}

type RegisterInput struct {
	Email    string `validate:"required,email,max=255"`
	Password string `validate:"required,min=8,max=72"`
}

type LoginInput struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

type ForgotPasswordInput struct {
	Email string `validate:"required,email"`
}

type ResetPasswordInput struct {
	Token       string `validate:"required"`
	NewPassword string `validate:"required,min=8,max=72"`
}

func (s *AuthService) Register(ctx context.Context, in RegisterInput, ip, ua string) (string, error) {
	if err := validate.Struct(in); err != nil {
		return "", domain.ErrInvalidInput
	}
	hash, err := password.Hash(in.Password, s.cfg.Security.BcryptCost)
	if err != nil {
		return "", err
	}
	user, err := s.users.CreateWithRole(ctx, normEmail(in.Email), hash, "user")
	if err != nil {
		return "", err
	}
	verifyToken, err := s.issueOneTime(ctx, s.verify, user.ID, 24*time.Hour)
	if err != nil {
		return "", err
	}
	s.logAudit(ctx, &user.ID, "user.registered", ip, ua, nil)
	return verifyToken, nil
}

func (s *AuthService) Login(ctx context.Context, in LoginInput, ip, ua string) (*domain.TokenPair, error) {
	if err := validate.Struct(in); err != nil {
		return nil, domain.ErrInvalidInput
	}
	email := normEmail(in.Email)
	locked, err := s.lockout.IsLocked(ctx, email)
	if err != nil {
		return nil, err
	}
	if locked {
		return nil, domain.ErrAccountLocked
	}
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			_ = s.lockout.RecordFailure(ctx, email, s.cfg.Security.LoginMaxAttempts, s.cfg.Security.LoginLockoutDuration)
			s.logAudit(ctx, nil, "auth.login_failed", ip, ua, nil)
			return nil, domain.ErrUnauthorized
		}
		return nil, err
	}
	if !user.IsActive || password.Compare(user.PasswordHash, in.Password) != nil {
		_ = s.lockout.RecordFailure(ctx, email, s.cfg.Security.LoginMaxAttempts, s.cfg.Security.LoginLockoutDuration)
		s.logAudit(ctx, nil, "auth.login_failed", ip, ua, nil)
		return nil, domain.ErrUnauthorized
	}
	_ = s.lockout.Clear(ctx, email)
	pair, err := s.issueTokens(ctx, user.ID, uuid.New(), uuid.New())
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, &user.ID, "auth.login", ip, ua, nil)
	return pair, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshRaw, ip, ua string) (*domain.TokenPair, error) {
	if refreshRaw == "" {
		return nil, domain.ErrInvalidInput
	}
	hash := token.Hash(refreshRaw)
	rec, err := s.refresh.GetByHash(ctx, hash)
	if err != nil {
		if familyID, _ := s.refresh.GetRevokedFamily(ctx, hash); familyID != nil {
			_ = s.refresh.RevokeFamily(ctx, *familyID)
		}
		return nil, domain.ErrUnauthorized
	}
	if err := s.refresh.Revoke(ctx, hash); err != nil {
		return nil, err
	}
	pair, err := s.issueTokens(ctx, rec.UserID, rec.SessionID, rec.FamilyID)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, &rec.UserID, "auth.refresh", ip, ua, nil)
	return pair, nil
}

func (s *AuthService) Logout(ctx context.Context, userID, sessionID uuid.UUID, accessJTI string, accessExp time.Time, refreshRaw, ip, ua string) error {
	if ttl := time.Until(accessExp); accessJTI != "" && ttl > 0 {
		_ = s.blacklist.Add(ctx, accessJTI, ttl)
	}
	if refreshRaw != "" {
		_ = s.refresh.Revoke(ctx, token.Hash(refreshRaw))
	}
	_ = s.sessions.Delete(ctx, sessionID, userID)
	s.logAudit(ctx, &userID, "auth.logout", ip, ua, nil)
	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	_ = s.refresh.RevokeAllForUser(ctx, userID)
	_ = s.sessions.DeleteAllForUser(ctx, userID)
	s.logAudit(ctx, &userID, "auth.logout_all", "", "", nil)
	return nil
}

func (s *AuthService) ForgotPassword(ctx context.Context, in ForgotPasswordInput) (string, error) {
	if err := validate.Struct(in); err != nil {
		return "", domain.ErrInvalidInput
	}
	user, err := s.users.GetByEmail(ctx, normEmail(in.Email))
	if err != nil {
		return "", nil // same response whether the email exists or not
	}
	resetToken, err := s.issueOneTime(ctx, s.resets, user.ID, time.Hour)
	if err != nil {
		return "", err
	}
	s.logAudit(ctx, &user.ID, "auth.password_reset_requested", "", "", nil)
	return resetToken, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if err := validate.Struct(in); err != nil {
		return domain.ErrInvalidInput
	}
	userID, err := s.resets.Consume(ctx, token.Hash(in.Token))
	if err != nil {
		return err
	}
	hash, err := password.Hash(in.NewPassword, s.cfg.Security.BcryptCost)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, *userID, hash); err != nil {
		return err
	}
	_ = s.refresh.RevokeAllForUser(ctx, *userID)
	_ = s.sessions.DeleteAllForUser(ctx, *userID)
	s.logAudit(ctx, userID, "auth.password_reset", "", "", nil)
	return nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, raw string) error {
	if raw == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.verify.Consume(ctx, token.Hash(raw))
	if err != nil {
		return err
	}
	if err := s.users.MarkEmailVerified(ctx, *userID); err != nil {
		return err
	}
	s.logAudit(ctx, userID, "auth.email_verified", "", "", nil)
	return nil
}

func (s *AuthService) GetProfile(ctx context.Context, userID uuid.UUID) (*domain.AuthProfile, error) {
	return s.users.GetAuthProfile(ctx, userID)
}

func (s *AuthService) ParseAccess(ctx context.Context, raw string) (*jwtsvc.Claims, error) {
	claims, err := s.jwt.ParseAccess(raw)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	blacklisted, err := s.blacklist.Exists(ctx, claims.ID)
	if err != nil || blacklisted {
		return nil, domain.ErrUnauthorized
	}
	return claims, nil
}

func normEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *AuthService) logAudit(ctx context.Context, userID *uuid.UUID, action, ip, ua string, meta map[string]string) {
	var raw json.RawMessage
	if meta != nil {
		raw, _ = json.Marshal(meta)
	}
	_ = s.audit.Log(ctx, domain.AuditEntry{
		UserID: userID, Action: action, IPAddress: ip, UserAgent: ua, Metadata: raw,
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
	role := "user"
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
