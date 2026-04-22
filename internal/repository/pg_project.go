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

// PgProjectRepository implements domain.ProjectRepository using PostgreSQL.
type PgProjectRepository struct {
	pool *pgxpool.Pool
}

// NewPgProjectRepository creates a new PostgreSQL project repository.
func NewPgProjectRepository(pool *pgxpool.Pool) *PgProjectRepository {
	return &PgProjectRepository{pool: pool}
}

func (r *PgProjectRepository) Create(ctx context.Context, project *domain.Project) error {
	query := `
		INSERT INTO projects (id, tenant_id, name, slug, description, environment, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	now := time.Now().UTC()
	project.CreatedAt = now
	project.UpdatedAt = now

	if project.ID == uuid.Nil {
		project.ID = uuid.New()
	}

	_, err := r.pool.Exec(ctx, query,
		project.ID, project.TenantID, project.Name, project.Slug,
		project.Description, project.Environment, project.IsActive,
		project.CreatedAt, project.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}

	return nil
}

func (r *PgProjectRepository) GetByID(ctx context.Context, tenantID, projectID uuid.UUID) (*domain.Project, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, environment, is_active, created_at, updated_at
		FROM projects WHERE id = $1 AND tenant_id = $2`

	project := &domain.Project{}
	err := r.pool.QueryRow(ctx, query, projectID, tenantID).Scan(
		&project.ID, &project.TenantID, &project.Name, &project.Slug,
		&project.Description, &project.Environment, &project.IsActive,
		&project.CreatedAt, &project.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get project: %w", err)
	}

	return project, nil
}

func (r *PgProjectRepository) List(ctx context.Context, tenantID uuid.UUID, limit int, cursor *time.Time) ([]*domain.Project, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	var query string
	var args []interface{}

	if cursor != nil {
		query = `
			SELECT id, tenant_id, name, slug, description, environment, is_active, created_at, updated_at
			FROM projects WHERE tenant_id = $1 AND is_active = true AND created_at < $2
			ORDER BY created_at DESC LIMIT $3`
		args = []interface{}{tenantID, *cursor, limit}
	} else {
		query = `
			SELECT id, tenant_id, name, slug, description, environment, is_active, created_at, updated_at
			FROM projects WHERE tenant_id = $1 AND is_active = true
			ORDER BY created_at DESC LIMIT $2`
		args = []interface{}{tenantID, limit}
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	defer rows.Close()

	var projects []*domain.Project
	for rows.Next() {
		p := &domain.Project{}
		err := rows.Scan(
			&p.ID, &p.TenantID, &p.Name, &p.Slug,
			&p.Description, &p.Environment, &p.IsActive,
			&p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan project row: %w", err)
		}
		projects = append(projects, p)
	}

	return projects, nil
}

func (r *PgProjectRepository) Update(ctx context.Context, tenantID, projectID uuid.UUID, input *domain.UpdateProjectInput) (*domain.Project, error) {
	setClauses := []string{}
	args := []interface{}{}
	argIdx := 1

	if input.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *input.Name)
		argIdx++
	}
	if input.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *input.Description)
		argIdx++
	}
	if input.IsActive != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *input.IsActive)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, tenantID, projectID)
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now().UTC())
	argIdx++

	args = append(args, projectID)
	argIdx++
	args = append(args, tenantID)

	query := fmt.Sprintf(
		`UPDATE projects SET %s WHERE id = $%d AND tenant_id = $%d
		RETURNING id, tenant_id, name, slug, description, environment, is_active, created_at, updated_at`,
		joinStrings(setClauses, ", "), argIdx-1, argIdx,
	)

	project := &domain.Project{}
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&project.ID, &project.TenantID, &project.Name, &project.Slug,
		&project.Description, &project.Environment, &project.IsActive,
		&project.CreatedAt, &project.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to update project: %w", err)
	}

	return project, nil
}

func (r *PgProjectRepository) SoftDelete(ctx context.Context, tenantID, projectID uuid.UUID) error {
	query := `UPDATE projects SET is_active = false, updated_at = $1 WHERE id = $2 AND tenant_id = $3`
	result, err := r.pool.Exec(ctx, query, time.Now().UTC(), projectID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to soft-delete project: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}
