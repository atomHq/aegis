package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Project represents a project within a tenant, scoped to an environment.
type Project struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	Environment string    `json:"environment"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateProjectInput holds the input for creating a new project.
type CreateProjectInput struct {
	Name        string `json:"name" validate:"required,min=2,max=255"`
	Slug        string `json:"slug" validate:"required,min=2,max=100"`
	Description string `json:"description,omitempty" validate:"omitempty,max=1000"`
	Environment string `json:"environment" validate:"required,oneof=development staging production"`
}

// UpdateProjectInput holds the input for updating a project.
type UpdateProjectInput struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=2,max=255"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=1000"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

// ProjectRepository defines the interface for project data access.
type ProjectRepository interface {
	Create(ctx context.Context, project *Project) error
	GetByID(ctx context.Context, tenantID, projectID uuid.UUID) (*Project, error)
	List(ctx context.Context, tenantID uuid.UUID, limit int, cursor *time.Time) ([]*Project, error)
	Update(ctx context.Context, tenantID, projectID uuid.UUID, input *UpdateProjectInput) (*Project, error)
	SoftDelete(ctx context.Context, tenantID, projectID uuid.UUID) error
}
