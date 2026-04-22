package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oluwasemilore/aegis/internal/domain"
)

type PgAuditLogRepository struct {
	pool *pgxpool.Pool
}

func NewPgAuditLogRepository(pool *pgxpool.Pool) *PgAuditLogRepository {
	return &PgAuditLogRepository{pool: pool}
}

func (r *PgAuditLogRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}

	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_logs (id, tenant_id, actor, action, resource_type, resource_id, metadata, ip_address, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::inet,NOW())`,
		log.ID, log.TenantID, log.Actor, log.Action, log.ResourceType,
		log.ResourceID, log.Metadata, nullableString(log.IPAddress),
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

func (r *PgAuditLogRepository) List(ctx context.Context, tenantID uuid.UUID, filter *domain.AuditLogFilter) ([]*domain.AuditLog, error) {
	query := `SELECT id, tenant_id, actor, action, resource_type, resource_id, metadata, ip_address, created_at FROM audit_logs WHERE tenant_id=$1`
	args := []interface{}{tenantID}
	argIdx := 2

	if filter.Action != "" {
		query += fmt.Sprintf(" AND action=$%d", argIdx)
		args = append(args, filter.Action)
		argIdx++
	}
	if filter.ResourceType != "" {
		query += fmt.Sprintf(" AND resource_type=$%d", argIdx)
		args = append(args, filter.ResourceType)
		argIdx++
	}
	if filter.ResourceID != nil {
		query += fmt.Sprintf(" AND resource_id=$%d", argIdx)
		args = append(args, *filter.ResourceID)
		argIdx++
	}
	if filter.StartTime != nil {
		query += fmt.Sprintf(" AND created_at>=$%d", argIdx)
		args = append(args, *filter.StartTime)
		argIdx++
	}
	if filter.EndTime != nil {
		query += fmt.Sprintf(" AND created_at<=$%d", argIdx)
		args = append(args, *filter.EndTime)
		argIdx++
	}
	if filter.Cursor != nil {
		query += fmt.Sprintf(" AND created_at<$%d", argIdx)
		args = append(args, *filter.Cursor)
		argIdx++
	}

	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		l := &domain.AuditLog{}
		var ipAddr *string
		if err := rows.Scan(&l.ID, &l.TenantID, &l.Actor, &l.Action, &l.ResourceType, &l.ResourceID, &l.Metadata, &ipAddr, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		if ipAddr != nil {
			l.IPAddress = *ipAddr
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
