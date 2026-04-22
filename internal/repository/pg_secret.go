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

type PgSecretRepository struct {
	pool *pgxpool.Pool
}

func NewPgSecretRepository(pool *pgxpool.Pool) *PgSecretRepository {
	return &PgSecretRepository{pool: pool}
}

func (r *PgSecretRepository) Upsert(ctx context.Context, secret *domain.Secret) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var maxVersion int
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM secrets WHERE tenant_id = $1 AND project_id = $2 AND key = $3`,
		secret.TenantID, secret.ProjectID, secret.Key,
	).Scan(&maxVersion)
	if err != nil {
		return fmt.Errorf("failed to get max version: %w", err)
	}

	secret.Version = maxVersion + 1
	now := time.Now().UTC()
	secret.CreatedAt = now
	secret.UpdatedAt = now
	if secret.ID == uuid.Nil {
		secret.ID = uuid.New()
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO secrets (id, tenant_id, project_id, key, encrypted_value, encrypted_dek, nonce, dek_nonce, version, is_active, expires_at, tags, created_by, updated_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		secret.ID, secret.TenantID, secret.ProjectID, secret.Key,
		secret.EncryptedValue, secret.EncryptedDEK, secret.Nonce, secret.DEKNonce,
		secret.Version, true, secret.ExpiresAt, secret.Tags,
		secret.CreatedBy, secret.UpdatedBy, secret.CreatedAt, secret.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert secret: %w", err)
	}

	return tx.Commit(ctx)
}

func (r *PgSecretRepository) GetLatest(ctx context.Context, tenantID, projectID uuid.UUID, key string) (*domain.Secret, error) {
	query := `SELECT id, tenant_id, project_id, key, encrypted_value, encrypted_dek, nonce, dek_nonce, version, is_active, expires_at, tags, created_by, updated_by, created_at, updated_at
		FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND key=$3 AND is_active=true ORDER BY version DESC LIMIT 1`
	return r.scanSecret(r.pool.QueryRow(ctx, query, tenantID, projectID, key))
}

func (r *PgSecretRepository) GetVersion(ctx context.Context, tenantID, projectID uuid.UUID, key string, version int) (*domain.Secret, error) {
	query := `SELECT id, tenant_id, project_id, key, encrypted_value, encrypted_dek, nonce, dek_nonce, version, is_active, expires_at, tags, created_by, updated_by, created_at, updated_at
		FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND key=$3 AND version=$4`
	return r.scanSecret(r.pool.QueryRow(ctx, query, tenantID, projectID, key, version))
}

func (r *PgSecretRepository) ListVersions(ctx context.Context, tenantID, projectID uuid.UUID, key string) ([]*domain.Secret, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, tenant_id, project_id, key, encrypted_value, encrypted_dek, nonce, dek_nonce, version, is_active, expires_at, tags, created_by, updated_by, created_at, updated_at
		FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND key=$3 ORDER BY version DESC`, tenantID, projectID, key)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}
	defer rows.Close()
	return r.scanRows(rows)
}

func (r *PgSecretRepository) ListKeys(ctx context.Context, tenantID, projectID uuid.UUID, limit int, cursor *time.Time) ([]*domain.SecretKeyItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var args []interface{}
	var query string
	if cursor != nil {
		query = `SELECT key, MAX(version), MIN(created_at), MAX(updated_at) FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND is_active=true AND updated_at<$3 GROUP BY key ORDER BY MAX(updated_at) DESC LIMIT $4`
		args = []interface{}{tenantID, projectID, *cursor, limit}
	} else {
		query = `SELECT key, MAX(version), MIN(created_at), MAX(updated_at) FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND is_active=true GROUP BY key ORDER BY MAX(updated_at) DESC LIMIT $3`
		args = []interface{}{tenantID, projectID, limit}
	}
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close()
	var items []*domain.SecretKeyItem
	for rows.Next() {
		item := &domain.SecretKeyItem{}
		if err := rows.Scan(&item.Key, &item.LatestVersion, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}

func (r *PgSecretRepository) SoftDelete(ctx context.Context, tenantID, projectID uuid.UUID, key string) error {
	result, err := r.pool.Exec(ctx, `UPDATE secrets SET is_active=false, updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND key=$4`, time.Now().UTC(), tenantID, projectID, key)
	if err != nil {
		return fmt.Errorf("failed to soft-delete: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("secret not found")
	}
	return nil
}

func (r *PgSecretRepository) CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(DISTINCT key) FROM secrets WHERE tenant_id=$1 AND is_active=true`, tenantID).Scan(&count)
	return count, err
}

func (r *PgSecretRepository) GetBulk(ctx context.Context, tenantID, projectID uuid.UUID, keys []string) ([]*domain.Secret, error) {
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT ON (s.key) s.id, s.tenant_id, s.project_id, s.key, s.encrypted_value, s.encrypted_dek, s.nonce, s.dek_nonce, s.version, s.is_active, s.expires_at, s.tags, s.created_by, s.updated_by, s.created_at, s.updated_at
		FROM secrets s WHERE s.tenant_id=$1 AND s.project_id=$2 AND s.key=ANY($3) AND s.is_active=true ORDER BY s.key, s.version DESC`, tenantID, projectID, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk get: %w", err)
	}
	defer rows.Close()
	return r.scanRows(rows)
}

func (r *PgSecretRepository) scanSecret(row pgx.Row) (*domain.Secret, error) {
	s := &domain.Secret{}
	err := row.Scan(&s.ID, &s.TenantID, &s.ProjectID, &s.Key, &s.EncryptedValue, &s.EncryptedDEK, &s.Nonce, &s.DEKNonce, &s.Version, &s.IsActive, &s.ExpiresAt, &s.Tags, &s.CreatedBy, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan secret: %w", err)
	}
	return s, nil
}

func (r *PgSecretRepository) scanRows(rows pgx.Rows) ([]*domain.Secret, error) {
	var secrets []*domain.Secret
	for rows.Next() {
		s := &domain.Secret{}
		err := rows.Scan(&s.ID, &s.TenantID, &s.ProjectID, &s.Key, &s.EncryptedValue, &s.EncryptedDEK, &s.Nonce, &s.DEKNonce, &s.Version, &s.IsActive, &s.ExpiresAt, &s.Tags, &s.CreatedBy, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}
