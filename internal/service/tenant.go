package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oluwasemilore/aegis/internal/crypto"
	"github.com/oluwasemilore/aegis/internal/domain"
)

// TenantService handles tenant business logic.
type TenantService struct {
	tenantRepo  domain.TenantRepository
	projectRepo domain.ProjectRepository
	apiKeyRepo  domain.APIKeyRepository
	pool        *pgxpool.Pool
}

// NewTenantService creates a new tenant service.
func NewTenantService(tenantRepo domain.TenantRepository, projectRepo domain.ProjectRepository, apiKeyRepo domain.APIKeyRepository, pool *pgxpool.Pool) *TenantService {
	return &TenantService{tenantRepo: tenantRepo, projectRepo: projectRepo, apiKeyRepo: apiKeyRepo, pool: pool}
}

// TenantCreateResult holds the result of tenant creation.
type TenantCreateResult struct {
	Tenant  *domain.Tenant  `json:"tenant"`
	Project *domain.Project `json:"project"`
	APIKey  string          `json:"api_key"` // Plaintext, shown only once
}

// Create creates a new tenant with a default project and admin API key.
func (s *TenantService) Create(ctx context.Context, input *domain.CreateTenantInput) (*TenantCreateResult, error) {
	existing, err := s.tenantRepo.GetBySlug(ctx, input.Slug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("tenant with slug '%s' already exists", input.Slug)
	}

	tenant := &domain.Tenant{
		ID:       uuid.New(),
		Name:     input.Name,
		Slug:     input.Slug,
		Plan:     "free",
		IsActive: true,
		Metadata: map[string]interface{}{},
	}
	if input.Plan != "" {
		tenant.Plan = input.Plan
	}

	if err := s.tenantRepo.Create(ctx, tenant); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Create default project
	project := &domain.Project{
		ID:          uuid.New(),
		TenantID:    tenant.ID,
		Name:        "Default",
		Slug:        "default",
		Description: "Default project",
		Environment: "development",
		IsActive:    true,
	}
	if err := s.projectRepo.Create(ctx, project); err != nil {
		return nil, fmt.Errorf("failed to create default project: %w", err)
	}

	// Generate admin API key
	plaintext, hash, prefix, err := crypto.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	apiKey := &domain.APIKey{
		ID:        uuid.New(),
		TenantID:  tenant.ID,
		Name:      "Admin Key",
		KeyHash:   hash,
		KeyPrefix: prefix,
		Scopes:    []string{"secrets:read", "secrets:write", "secrets:admin", "projects:manage", "api_keys:manage", "audit:read"},
		IsActive:  true,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.apiKeyRepo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to create api key: %w", err)
	}

	return &TenantCreateResult{Tenant: tenant, Project: project, APIKey: plaintext}, nil
}

// GetByID retrieves a tenant by ID.
func (s *TenantService) GetByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	return s.tenantRepo.GetByID(ctx, id)
}

// Update updates a tenant.
func (s *TenantService) Update(ctx context.Context, id uuid.UUID, input *domain.UpdateTenantInput) (*domain.Tenant, error) {
	return s.tenantRepo.Update(ctx, id, input)
}
