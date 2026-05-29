package domain

import (
	"time"

	"github.com/google/uuid"
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type Session struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Email       string
	Roles       []string
	Permissions []string
	FamilyID    uuid.UUID
}

type RefreshRecord struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	SessionID uuid.UUID
	TokenHash string
	FamilyID  uuid.UUID
	ExpiresAt time.Time
}
