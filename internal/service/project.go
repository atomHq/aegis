package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/domain"
)

// ProjectService handles project business logic.
type ProjectService struct {
	projectRepo domain.ProjectRepository
	tenantRepo  domain.TenantRepository
}

// NewProjectService creates a new project service.
func NewProjectService(projectRepo domain.ProjectRepository, tenantRepo domain.TenantRepository) *ProjectService {
	return &ProjectService{projectRepo: projectRepo, tenantRepo: tenantRepo}
}

// Create creates a new project within a tenant, enforcing plan limits.
func (s *ProjectService) Create(ctx context.Context, tenantID uuid.UUID, input *domain.CreateProjectInput) (*domain.Project, error) {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	count, err := s.tenantRepo.CountProjects(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to count projects: %w", err)
	}
	if count >= tenant.MaxProjects {
		return nil, fmt.Errorf("project limit (%d) reached for plan '%s'", tenant.MaxProjects, tenant.Plan)
	}

	project := &domain.Project{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        input.Name,
		Slug:        input.Slug,
		Description: input.Description,
		Environment: input.Environment,
		IsActive:    true,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	if err := s.projectRepo.Create(ctx, project); err != nil {
		return nil, fmt.Errorf("failed to create project: %w", err)
	}

	return project, nil
}

// GetByID retrieves a project by ID within a tenant.
func (s *ProjectService) GetByID(ctx context.Context, tenantID, projectID uuid.UUID) (*domain.Project, error) {
	return s.projectRepo.GetByID(ctx, tenantID, projectID)
}

// List lists projects for a tenant.
func (s *ProjectService) List(ctx context.Context, tenantID uuid.UUID, limit int, cursor *time.Time) ([]*domain.Project, error) {
	return s.projectRepo.List(ctx, tenantID, limit, cursor)
}

// Update updates a project.
func (s *ProjectService) Update(ctx context.Context, tenantID, projectID uuid.UUID, input *domain.UpdateProjectInput) (*domain.Project, error) {
	return s.projectRepo.Update(ctx, tenantID, projectID, input)
}

// SoftDelete soft-deletes a project.
func (s *ProjectService) SoftDelete(ctx context.Context, tenantID, projectID uuid.UUID) error {
	return s.projectRepo.SoftDelete(ctx, tenantID, projectID)
}
