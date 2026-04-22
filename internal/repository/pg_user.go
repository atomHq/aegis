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

type PgUserRepository struct {
	pool *pgxpool.Pool
}

func NewPgUserRepository(pool *pgxpool.Pool) *PgUserRepository {
	return &PgUserRepository{pool: pool}
}

func (r *PgUserRepository) Create(ctx context.Context, user *domain.User) error {
	now := time.Now().UTC()
	user.CreatedAt = now
	user.UpdatedAt = now
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	_, err := r.pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, first_name, last_name, tenant_id, is_verified, verification_code, verification_expires_at, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		user.ID, user.Email, user.PasswordHash, user.FirstName, user.LastName,
		user.TenantID, user.IsVerified, user.VerificationCode, user.VerificationExpiresAt,
		user.IsActive, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (r *PgUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return r.scanUser(r.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, first_name, last_name, tenant_id, is_verified, verification_code, verification_expires_at, verification_attempts, is_active, last_login_at, created_at, updated_at
		FROM users WHERE id = $1`, id))
}

func (r *PgUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.scanUser(r.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, first_name, last_name, tenant_id, is_verified, verification_code, verification_expires_at, verification_attempts, is_active, last_login_at, created_at, updated_at
		FROM users WHERE email = $1`, email))
}

func (r *PgUserRepository) SetVerified(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET is_verified = true, verification_code = NULL, verification_expires_at = NULL, updated_at = $1
		WHERE id = $2`, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("failed to set user verified: %w", err)
	}
	return nil
}

func (r *PgUserRepository) UpdateVerificationCode(ctx context.Context, id uuid.UUID, code string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET verification_code = $1, verification_expires_at = $2, updated_at = $3
		WHERE id = $4`, code, expiresAt, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("failed to update verification code: %w", err)
	}
	return nil
}

func (r *PgUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	_, err := r.pool.Exec(ctx, `UPDATE users SET last_login_at = $1, updated_at = $1 WHERE id = $2`, now, id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

func (r *PgUserRepository) IncrementVerificationAttempts(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET verification_attempts = verification_attempts + 1, updated_at = $1
		WHERE id = $2`, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("failed to increment verification attempts: %w", err)
	}
	return nil
}

func (r *PgUserRepository) ResetVerificationAttempts(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET verification_attempts = 0, updated_at = $1
		WHERE id = $2`, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("failed to reset verification attempts: %w", err)
	}
	return nil
}

func (r *PgUserRepository) scanUser(row pgx.Row) (*domain.User, error) {
	u := &domain.User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.TenantID, &u.IsVerified, &u.VerificationCode, &u.VerificationExpiresAt,
		&u.VerificationAttempts, &u.IsActive, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}
	return u, nil
}
