package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  string
	EmailVerified bool
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type AuthProfile struct {
	UserID      uuid.UUID
	Email       string
	Roles       []string
	Permissions []string
}
