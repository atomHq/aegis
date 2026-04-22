package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Tenant represents an organization using the Aegis platform.
type Tenant struct {
	ID              uuid.UUID              `json:"id"`
	Name            string                 `json:"name"`
	Slug            string                 `json:"slug"`
	Plan            string                 `json:"plan"`
	MaxSecrets      int                    `json:"max_secrets"`
	MaxProjects     int                    `json:"max_projects"`
	RateLimitPerMin int                    `json:"rate_limit_per_min"`
	IsActive        bool                   `json:"is_active"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// CreateTenantInput holds the input for creating a new tenant.
type CreateTenantInput struct {
	Name string `json:"name" validate:"required,min=2,max=255"`
	Slug string `json:"slug" validate:"required,min=2,max=100,alphanum"`
	Plan string `json:"plan,omitempty"`
}

// UpdateTenantInput holds the input for tenant-facing updates.
// Only name can be changed by the tenant. Plan/limits require admin access.
type UpdateTenantInput struct {
	Name *string `json:"name,omitempty" validate:"omitempty,min=2,max=255"`
}

// AdminUpdateTenantInput holds the input for platform admin updates (not exposed to tenants).
type AdminUpdateTenantInput struct {
	Name            *string `json:"name,omitempty" validate:"omitempty,min=2,max=255"`
	Plan            *string `json:"plan,omitempty" validate:"omitempty,oneof=free pro enterprise"`
	MaxSecrets      *int    `json:"max_secrets,omitempty" validate:"omitempty,min=1"`
	MaxProjects     *int    `json:"max_projects,omitempty" validate:"omitempty,min=1"`
	RateLimitPerMin *int    `json:"rate_limit_per_min,omitempty" validate:"omitempty,min=1"`
	IsActive        *bool   `json:"is_active,omitempty"`
}

// TenantRepository defines the interface for tenant data access.
type TenantRepository interface {
	Create(ctx context.Context, tenant *Tenant) error
	GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error)
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)
	Update(ctx context.Context, id uuid.UUID, input *UpdateTenantInput) (*Tenant, error)
	CountProjects(ctx context.Context, tenantID uuid.UUID) (int, error)
	CountSecrets(ctx context.Context, tenantID uuid.UUID) (int, error)
}
