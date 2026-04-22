package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// APIKey represents an API key for authenticating requests.
type APIKey struct {
	ID         uuid.UUID   `json:"id"`
	TenantID   uuid.UUID   `json:"tenant_id"`
	Name       string      `json:"name"`
	KeyHash    string      `json:"-"`       // Never serialize
	KeyPrefix  string      `json:"key_prefix"`
	Scopes     []string    `json:"scopes"`
	ProjectIDs []uuid.UUID `json:"project_ids,omitempty"`
	IsActive   bool        `json:"is_active"`
	LastUsedAt *time.Time  `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time  `json:"expires_at,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
}

// CreateAPIKeyInput holds the input for creating a new API key.
type CreateAPIKeyInput struct {
	Name       string      `json:"name" validate:"required,min=2,max=255"`
	Scopes     []string    `json:"scopes" validate:"required,min=1,dive,oneof=secrets:read secrets:write secrets:admin projects:manage api_keys:manage audit:read"`
	ProjectIDs []uuid.UUID `json:"project_ids,omitempty"`
	ExpiresAt  *time.Time  `json:"expires_at,omitempty"`
}

// ValidScopes defines all valid API key scopes.
var ValidScopes = map[string]bool{
	"secrets:read":    true,
	"secrets:write":   true,
	"secrets:admin":   true,
	"projects:manage": true,
	"api_keys:manage": true,
	"audit:read":      true,
}

// APIKeyRepository defines the interface for API key data access.
type APIKeyRepository interface {
	Create(ctx context.Context, key *APIKey) error
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]*APIKey, error)
	Revoke(ctx context.Context, tenantID, keyID uuid.UUID) error
	UpdateLastUsed(ctx context.Context, keyID uuid.UUID) error
}
