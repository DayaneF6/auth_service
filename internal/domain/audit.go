package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AuditEntry struct {
	UserID    *uuid.UUID
	Action    string
	IPAddress string
	UserAgent string
	Metadata  json.RawMessage
	CreatedAt time.Time
}
