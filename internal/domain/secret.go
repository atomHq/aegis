package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Secret represents an encrypted secret stored in Aegis.
type Secret struct {
	ID             uuid.UUID              `json:"id"`
	TenantID       uuid.UUID              `json:"tenant_id"`
	ProjectID      uuid.UUID              `json:"project_id"`
	Key            string                 `json:"key"`
	EncryptedValue []byte                 `json:"-"` // Never serialize
	EncryptedDEK   []byte                 `json:"-"` // Never serialize
	Nonce          []byte                 `json:"-"` // Never serialize
	DEKNonce       []byte                 `json:"-"` // Never serialize
	Version        int                    `json:"version"`
	IsActive       bool                   `json:"is_active"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	Tags           map[string]interface{} `json:"tags,omitempty"`
	CreatedBy      string                 `json:"created_by,omitempty"`
	UpdatedBy      string                 `json:"updated_by,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// SecretKeyItem represents a secret key in list responses (no value).
type SecretKeyItem struct {
	Key            string    `json:"key"`
	LatestVersion  int       `json:"latest_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PutSecretInput holds the input for creating or updating a secret.
type PutSecretInput struct {
	Key       string                 `json:"key" validate:"required,min=1,max=255"`
	Value     string                 `json:"value" validate:"required,max=65536"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	Tags      map[string]interface{} `json:"tags,omitempty"`
}

// BulkGetSecretsInput holds the input for bulk secret retrieval.
type BulkGetSecretsInput struct {
	Keys []string `json:"keys" validate:"required,min=1,max=50,dive,min=1,max=255"`
}

// SecretRepository defines the interface for secret data access.
type SecretRepository interface {
	Upsert(ctx context.Context, secret *Secret) error
	GetLatest(ctx context.Context, tenantID, projectID uuid.UUID, key string) (*Secret, error)
	GetVersion(ctx context.Context, tenantID, projectID uuid.UUID, key string, version int) (*Secret, error)
	ListVersions(ctx context.Context, tenantID, projectID uuid.UUID, key string) ([]*Secret, error)
	ListKeys(ctx context.Context, tenantID, projectID uuid.UUID, limit int, cursor *time.Time) ([]*SecretKeyItem, error)
	SoftDelete(ctx context.Context, tenantID, projectID uuid.UUID, key string) error
	CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
	GetBulk(ctx context.Context, tenantID, projectID uuid.UUID, keys []string) ([]*Secret, error)
}
