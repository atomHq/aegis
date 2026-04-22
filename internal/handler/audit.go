package handler

import (
	"net/http"
	"time"

	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
	"github.com/oluwasemilore/aegis/internal/pkg/pagination"
)

// AuditLogFilterFromRequest builds an AuditLogFilter from query params.
func AuditLogFilterFromRequest(r *http.Request) domain.AuditLogFilter {
	p := pagination.Parse(r)
	filter := domain.AuditLogFilter{
		Limit:  p.Limit,
		Cursor: p.Cursor,
	}

	if action := r.URL.Query().Get("action"); action != "" {
		filter.Action = action
	}
	if resType := r.URL.Query().Get("resource_type"); resType != "" {
		filter.ResourceType = resType
	}
	if startStr := r.URL.Query().Get("start_time"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			filter.StartTime = &t
		}
	}
	if endStr := r.URL.Query().Get("end_time"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			filter.EndTime = &t
		}
	}

	return filter
}

// WriteAuditLogsResponse writes audit logs as a success response.
func WriteAuditLogsResponse(w http.ResponseWriter, reqID string, logs []*domain.AuditLog) {
	apierror.WriteSuccess(w, reqID, logs, http.StatusOK)
}
