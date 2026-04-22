package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/domain"
)

// AuditService handles audit log operations.
type AuditService struct {
	repo domain.AuditLogRepository
}

// NewAuditService creates a new audit service.
func NewAuditService(repo domain.AuditLogRepository) *AuditService {
	return &AuditService{repo: repo}
}

// Log creates an audit log entry.
func (s *AuditService) Log(ctx context.Context, tenantID uuid.UUID, actor, action, resourceType string, resourceID *uuid.UUID, ipAddress string, metadata map[string]interface{}) {
	log := &domain.AuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Actor:        actor,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Metadata:     metadata,
		IPAddress:    ipAddress,
		CreatedAt:    time.Now().UTC(),
	}

	// Fire and forget — audit logging should not block the request.
	// In production, consider using a buffered channel.
	go func() {
		_ = s.repo.Create(context.Background(), log)
	}()
}

// List retrieves audit logs for a tenant with optional filters.
func (s *AuditService) List(ctx context.Context, tenantID uuid.UUID, filter *domain.AuditLogFilter) ([]*domain.AuditLog, error) {
	return s.repo.List(ctx, tenantID, filter)
}
