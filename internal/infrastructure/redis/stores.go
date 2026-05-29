package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dayaneroot/auth-service/internal/domain"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

// Key prefixes keep namespaces isolated per concern.
const (
	keySession     = "session:%s"
	keyUserSession = "user_sessions:%s"
	keyBlacklist   = "blacklist:%s"
	keyLockout     = "lockout:%s"
	keyIdem        = "idem:%s"
)

// incrWithExpire atomically INCR + EXPIRE on first hit (Redis rate-limit pattern).
var incrWithExpire = goredis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if n == 1 then redis.call("EXPIRE", KEYS[1], ARGV[1]) end
return n
`)

func runIncrExpire(ctx context.Context, c *Client, key string, ttl time.Duration) (int64, error) {
	secs := int(ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	return incrWithExpire.Run(ctx, c, []string{key}, secs).Int64()
}

// --- Session (JSON blob + user index set) ---

type sessionDTO struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	FamilyID    string   `json:"family_id"`
}

type SessionStore struct{ client *Client }

func NewSessionStore(c *Client) *SessionStore { return &SessionStore{client: c} }

// Save stores session metadata and indexes it under the user for bulk revocation.
func (s *SessionStore) Save(ctx context.Context, session domain.Session, ttl time.Duration) error {
	b, err := json.Marshal(sessionDTO{
		UserID: session.UserID.String(), Email: session.Email,
		Roles: session.Roles, Permissions: session.Permissions,
		FamilyID: session.FamilyID.String(),
	})
	if err != nil {
		return err
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, fmt.Sprintf(keySession, session.ID), b, ttl)
	pipe.SAdd(ctx, fmt.Sprintf(keyUserSession, session.UserID), session.ID.String())
	pipe.Expire(ctx, fmt.Sprintf(keyUserSession, session.UserID), ttl)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *SessionStore) Delete(ctx context.Context, sessionID, userID uuid.UUID) error {
	pipe := s.client.Pipeline()
	pipe.Del(ctx, fmt.Sprintf(keySession, sessionID))
	pipe.SRem(ctx, fmt.Sprintf(keyUserSession, userID), sessionID.String())
	_, err := pipe.Exec(ctx)
	return err
}

func (s *SessionStore) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	userKey := fmt.Sprintf(keyUserSession, userID)
	ids, err := s.client.SMembers(ctx, userKey).Result()
	if err != nil || len(ids) == 0 {
		return err
	}

	pipe := s.client.Pipeline()
	for _, id := range ids {
		pipe.Del(ctx, fmt.Sprintf(keySession, id))
	}
	pipe.Del(ctx, userKey)
	_, err = pipe.Exec(ctx)
	return err
}

// --- JWT jti blacklist (TTL matches remaining access token lifetime) ---

type Blacklist struct{ client *Client }

func NewBlacklist(c *Client) *Blacklist { return &Blacklist{client: c} }

func (b *Blacklist) Add(ctx context.Context, jti string, ttl time.Duration) error {
	return b.client.Set(ctx, fmt.Sprintf(keyBlacklist, jti), "1", ttl).Err()
}

func (b *Blacklist) Exists(ctx context.Context, jti string) (bool, error) {
	n, err := b.client.Exists(ctx, fmt.Sprintf(keyBlacklist, jti)).Result()
	return n > 0, err
}

// --- Login lockout (per normalized email) ---

type Lockout struct{ client *Client }

func NewLockout(c *Client) *Lockout { return &Lockout{client: c} }

func (l *Lockout) IsLocked(ctx context.Context, key string) (bool, error) {
	n, err := l.client.Exists(ctx, fmt.Sprintf(keyLockout, key)).Result()
	return n > 0, err
}

func (l *Lockout) RecordFailure(ctx context.Context, key string, max int, lockout time.Duration) error {
	count, err := runIncrExpire(ctx, l.client, "login_fail:"+key, lockout)
	if err != nil {
		return err
	}
	if int(count) >= max {
		return l.client.Set(ctx, fmt.Sprintf(keyLockout, key), "1", lockout).Err()
	}
	return nil
}

func (l *Lockout) Clear(ctx context.Context, key string) error {
	pipe := l.client.Pipeline()
	pipe.Del(ctx, fmt.Sprintf(keyLockout, key))
	pipe.Del(ctx, "login_fail:"+key)
	_, err := pipe.Exec(ctx)
	return err
}

// --- Fixed-window rate limit (per scope + IP) ---

type RateLimiter struct{ client *Client }

func NewRateLimiter(c *Client) *RateLimiter { return &RateLimiter{client: c} }

// Allow returns false when the counter exceeds limit within the window.
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := runIncrExpire(ctx, r.client, "ratelimit:"+key, window)
	if err != nil {
		return false, err
	}
	return int(count) <= limit, nil
}

// --- Idempotency cache (register) ---

type Idempotency struct{ client *Client }

func NewIdempotency(c *Client) *Idempotency { return &Idempotency{client: c} }

func (i *Idempotency) Get(ctx context.Context, key string) ([]byte, bool, error) {
	b, err := i.client.Get(ctx, fmt.Sprintf(keyIdem, key)).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

func (i *Idempotency) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return i.client.SetNX(ctx, fmt.Sprintf(keyIdem, key), value, ttl).Result()
}

func (i *Idempotency) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return i.client.Set(ctx, fmt.Sprintf(keyIdem, key), value, ttl).Err()
}

func (i *Idempotency) Delete(ctx context.Context, key string) error {
	return i.client.Del(ctx, fmt.Sprintf(keyIdem, key)).Err()
}
