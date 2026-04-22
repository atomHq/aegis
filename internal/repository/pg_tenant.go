package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oluwasemilore/aegis/internal/domain"
)

// PgTenantRepository implements domain.TenantRepository using PostgreSQL.
type PgTenantRepository struct {
	pool *pgxpool.Pool
}

// NewPgTenantRepository creates a new PostgreSQL tenant repository.
func NewPgTenantRepository(pool *pgxpool.Pool) *PgTenantRepository {
	return &PgTenantRepository{pool: pool}
}

func (r *PgTenantRepository) Create(ctx context.Context, tenant *domain.Tenant) error {
	query := `
		INSERT INTO tenants (id, name, slug, plan, max_secrets, max_projects, rate_limit_per_min, is_active, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	now := time.Now().UTC()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now

	if tenant.ID == uuid.Nil {
		tenant.ID = uuid.New()
	}
	if tenant.Plan == "" {
		tenant.Plan = "free"
	}
	if tenant.MaxSecrets == 0 {
		tenant.MaxSecrets = 100
	}
	if tenant.MaxProjects == 0 {
		tenant.MaxProjects = 5
	}
	if tenant.RateLimitPerMin == 0 {
		tenant.RateLimitPerMin = 60
	}
	if tenant.Metadata == nil {
		tenant.Metadata = map[string]interface{}{}
	}

	_, err := r.pool.Exec(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.Plan,
		tenant.MaxSecrets, tenant.MaxProjects, tenant.RateLimitPerMin,
		tenant.IsActive, tenant.Metadata, tenant.CreatedAt, tenant.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

func (r *PgTenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	query := `
		SELECT id, name, slug, plan, max_secrets, max_projects, rate_limit_per_min, is_active, metadata, created_at, updated_at
		FROM tenants WHERE id = $1`

	tenant := &domain.Tenant{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Plan,
		&tenant.MaxSecrets, &tenant.MaxProjects, &tenant.RateLimitPerMin,
		&tenant.IsActive, &tenant.Metadata, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by ID: %w", err)
	}

	return tenant, nil
}

func (r *PgTenantRepository) GetBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	query := `
		SELECT id, name, slug, plan, max_secrets, max_projects, rate_limit_per_min, is_active, metadata, created_at, updated_at
		FROM tenants WHERE slug = $1`

	tenant := &domain.Tenant{}
	err := r.pool.QueryRow(ctx, query, slug).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Plan,
		&tenant.MaxSecrets, &tenant.MaxProjects, &tenant.RateLimitPerMin,
		&tenant.IsActive, &tenant.Metadata, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by slug: %w", err)
	}

	return tenant, nil
}

func (r *PgTenantRepository) Update(ctx context.Context, id uuid.UUID, input *domain.UpdateTenantInput) (*domain.Tenant, error) {
	// Build dynamic update query — only Name is allowed for tenant-facing updates
	setClauses := []string{}
	args := []interface{}{}
	argIdx := 1

	if input.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *input.Name)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now().UTC())
	argIdx++

	args = append(args, id)
	query := fmt.Sprintf(
		`UPDATE tenants SET %s WHERE id = $%d
		RETURNING id, name, slug, plan, max_secrets, max_projects, rate_limit_per_min, is_active, metadata, created_at, updated_at`,
		joinStrings(setClauses, ", "), argIdx,
	)

	tenant := &domain.Tenant{}
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Plan,
		&tenant.MaxSecrets, &tenant.MaxProjects, &tenant.RateLimitPerMin,
		&tenant.IsActive, &tenant.Metadata, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	return tenant, nil
}

func (r *PgTenantRepository) CountProjects(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM projects WHERE tenant_id = $1 AND is_active = true`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count projects: %w", err)
	}
	return count, nil
}

func (r *PgTenantRepository) CountSecrets(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT key) FROM secrets WHERE tenant_id = $1 AND is_active = true`, tenantID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count secrets: %w", err)
	}
	return count, nil
}

// joinStrings joins string slices with a separator.
func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
