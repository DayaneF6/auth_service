// Package usecase implements application services (auth flows, token lifecycle, audit).
package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/dayaneroot/auth-service/internal/config"
	"github.com/dayaneroot/auth-service/internal/domain"
	jwtsvc "github.com/dayaneroot/auth-service/internal/infrastructure/jwt"
	"github.com/dayaneroot/auth-service/pkg/password"
	"github.com/dayaneroot/auth-service/pkg/token"
	"github.com/google/uuid"
)

const defaultRole = "user"

// AuthService orchestrates auth flows; it never invokes a shell or interprets user input as commands.
type AuthService struct {
	cfg        *config.Config
	jwt        *jwtsvc.Service
	users      domain.UserRepository
	refresh    domain.RefreshTokenRepository
	resets     domain.OneTimeTokenRepository
	verify     domain.OneTimeTokenRepository
	audit      domain.AuditRepository
	sessions   domain.SessionStore
	blacklist  domain.TokenBlacklist
	lockout    domain.LoginLockout
	mailer     domain.Mailer
	emailLimit domain.RateLimiter
}

// Repos groups Postgres-backed repositories.
type Repos struct {
	Users   domain.UserRepository
	Refresh domain.RefreshTokenRepository
	Resets  domain.OneTimeTokenRepository
	Verify  domain.OneTimeTokenRepository
	Audit   domain.AuditRepository
}

// Infra groups Redis, email, and rate-limit adapters.
type Infra struct {
	Sessions   domain.SessionStore
	Blacklist  domain.TokenBlacklist
	Lockout    domain.LoginLockout
	Mailer     domain.Mailer
	EmailLimit domain.RateLimiter
}

func NewAuthService(cfg *config.Config, jwt *jwtsvc.Service, repos Repos, infra Infra) *AuthService {
	return &AuthService{
		cfg: cfg, jwt: jwt,
		users: repos.Users, refresh: repos.Refresh,
		resets: repos.Resets, verify: repos.Verify, audit: repos.Audit,
		sessions: infra.Sessions, blacklist: infra.Blacklist, lockout: infra.Lockout,
		mailer: infra.Mailer, emailLimit: infra.EmailLimit,
	}
}

// Input DTOs carry validator tags (safe_text / safe_password / hex token format).

type RegisterInput struct {
	Email    string `validate:"required,email,max=255,safe_text"`
	Password string `validate:"required,min=8,max=72,safe_password"`
}

type LoginInput struct {
	Email    string `validate:"required,email,safe_text"`
	Password string `validate:"required,max=72,safe_password"`
}

type ForgotPasswordInput struct {
	Email string `validate:"required,email,safe_text"`
}

type TokenInput struct {
	Token string `validate:"required,len=64,hexadecimal"`
}

type ResetPasswordInput struct {
	TokenInput
	NewPassword string `validate:"required,min=8,max=72,safe_password"`
}

func (s *AuthService) Register(ctx context.Context, in RegisterInput, ip, ua string) (string, error) {
	if err := requireInput(in); err != nil {
		return "", err
	}
	email := normEmail(in.Email)
	if err := s.consumeEmailQuota(ctx, email); err != nil {
		return "", err
	}
	hash, err := password.Hash(in.Password, s.cfg.Security.BcryptCost)
	if err != nil {
		return "", err
	}
	user, err := s.users.CreateWithRole(ctx, email, hash, defaultRole)
	if err != nil {
		return "", err
	}
	verifyToken, err := s.issueOneTime(ctx, s.verify, user.ID, 24*time.Hour)
	if err != nil {
		return "", err
	}
	if err := s.sendActionEmail(ctx, email, verifyToken, mailVerify); err != nil {
		return "", err
	}
	s.logAudit(ctx, &user.ID, "user.registered", ip, ua, nil)
	return s.devToken(verifyToken), nil
}

func (s *AuthService) Login(ctx context.Context, in LoginInput, ip, ua string) (*domain.TokenPair, error) {
	if err := requireInput(in); err != nil {
		return nil, err
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
			return s.failLogin(ctx, email, ip, ua)
		}
		return nil, err
	}
	if !user.IsActive || password.Compare(user.PasswordHash, in.Password) != nil {
		return s.failLogin(ctx, email, ip, ua)
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

// Logout blacklists the current access jti and revokes the refresh cookie token.
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

// LogoutAll revokes every refresh token and Redis session for the user.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	s.revokeAllSessions(ctx, userID)
	s.logAudit(ctx, &userID, "auth.logout_all", "", "", nil)
	return nil
}

// ForgotPassword always returns success; email is sent only when the account exists.
func (s *AuthService) ForgotPassword(ctx context.Context, in ForgotPasswordInput) (string, error) {
	if err := requireInput(in); err != nil {
		return "", err
	}
	user, err := s.users.GetByEmail(ctx, normEmail(in.Email))
	if err != nil {
		return "", nil
	}
	if err := s.consumeEmailQuota(ctx, user.Email); err != nil {
		return "", nil
	}
	resetToken, err := s.issueOneTime(ctx, s.resets, user.ID, time.Hour)
	if err != nil {
		return "", nil
	}
	_ = s.sendActionEmail(ctx, user.Email, resetToken, mailReset)
	s.logAudit(ctx, &user.ID, "auth.password_reset_requested", "", "", nil)
	return s.devToken(resetToken), nil
}

// ResetPassword consumes a one-time token and invalidates all active sessions.
func (s *AuthService) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if err := requireInput(in); err != nil {
		return err
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
	s.revokeAllSessions(ctx, *userID)
	s.logAudit(ctx, userID, "auth.password_reset", "", "", nil)
	return nil
}

// VerifyEmail marks the account verified after consuming the registration token.
func (s *AuthService) VerifyEmail(ctx context.Context, in TokenInput) error {
	if err := requireInput(in); err != nil {
		return err
	}
	userID, err := s.verify.Consume(ctx, token.Hash(in.Token))
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
	ok, err := s.blacklist.Exists(ctx, claims.ID)
	if err != nil || ok {
		return nil, domain.ErrUnauthorized
	}
	return claims, nil
}
