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

type PgAPIKeyRepository struct {
	pool *pgxpool.Pool
}

func NewPgAPIKeyRepository(pool *pgxpool.Pool) *PgAPIKeyRepository {
	return &PgAPIKeyRepository{pool: pool}
}

func (r *PgAPIKeyRepository) Create(ctx context.Context, key *domain.APIKey) error {
	now := time.Now().UTC()
	key.CreatedAt = now
	if key.ID == uuid.Nil {
		key.ID = uuid.New()
	}

	_, err := r.pool.Exec(ctx, `
		INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, project_ids, is_active, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		key.ID, key.TenantID, key.Name, key.KeyHash, key.KeyPrefix,
		key.Scopes, key.ProjectIDs, true, key.ExpiresAt, key.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create api key: %w", err)
	}
	return nil
}

func (r *PgAPIKeyRepository) GetByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	key := &domain.APIKey{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, key_hash, key_prefix, scopes, project_ids, is_active, last_used_at, expires_at, created_at
		FROM api_keys WHERE key_hash=$1`, keyHash,
	).Scan(&key.ID, &key.TenantID, &key.Name, &key.KeyHash, &key.KeyPrefix,
		&key.Scopes, &key.ProjectIDs, &key.IsActive, &key.LastUsedAt, &key.ExpiresAt, &key.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get api key: %w", err)
	}
	return key, nil
}

func (r *PgAPIKeyRepository) List(ctx context.Context, tenantID uuid.UUID) ([]*domain.APIKey, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, name, key_hash, key_prefix, scopes, project_ids, is_active, last_used_at, expires_at, created_at
		FROM api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*domain.APIKey
	for rows.Next() {
		k := &domain.APIKey{}
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Name, &k.KeyHash, &k.KeyPrefix,
			&k.Scopes, &k.ProjectIDs, &k.IsActive, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan api key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (r *PgAPIKeyRepository) Revoke(ctx context.Context, tenantID, keyID uuid.UUID) error {
	result, err := r.pool.Exec(ctx, `UPDATE api_keys SET is_active=false WHERE id=$1 AND tenant_id=$2`, keyID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to revoke api key: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *PgAPIKeyRepository) UpdateLastUsed(ctx context.Context, keyID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE api_keys SET last_used_at=$1 WHERE id=$2`, time.Now().UTC(), keyID)
	return err
}
