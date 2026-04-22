package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AuditLog represents an immutable audit trail entry.
type AuditLog struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	Actor        string                 `json:"actor"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// AuditAction constants.
const (
	AuditActionSecretCreate = "secret.create"
	AuditActionSecretRead   = "secret.read"
	AuditActionSecretUpdate = "secret.update"
	AuditActionSecretDelete = "secret.delete"
	AuditActionSecretBulk   = "secret.bulk_read"

	AuditActionProjectCreate = "project.create"
	AuditActionProjectUpdate = "project.update"
	AuditActionProjectDelete = "project.delete"

	AuditActionAPIKeyCreate = "api_key.create"
	AuditActionAPIKeyRevoke = "api_key.revoke"

	AuditActionTenantCreate = "tenant.create"
	AuditActionTenantUpdate = "tenant.update"
)

// AuditLogFilter holds filter parameters for querying audit logs.
type AuditLogFilter struct {
	Action       string     `json:"action,omitempty"`
	ResourceType string     `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty"`
	StartTime    *time.Time `json:"start_time,omitempty"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	Limit        int        `json:"limit,omitempty"`
	Cursor       *time.Time `json:"cursor,omitempty"`
}

// AuditLogRepository defines the interface for audit log data access.
type AuditLogRepository interface {
	Create(ctx context.Context, log *AuditLog) error
	List(ctx context.Context, tenantID uuid.UUID, filter *AuditLogFilter) ([]*AuditLog, error)
}
