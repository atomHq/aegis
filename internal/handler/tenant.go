package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/middleware"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
	"github.com/oluwasemilore/aegis/internal/service"
)

// TenantHandler handles tenant management requests.
// Note: Tenant creation is handled by AuthHandler.Signup — no public Create endpoint.
type TenantHandler struct {
	svc      *service.TenantService
	auditSvc *service.AuditService
}

// NewTenantHandler creates a new tenant handler.
func NewTenantHandler(svc *service.TenantService, auditSvc *service.AuditService) *TenantHandler {
	return &TenantHandler{svc: svc, auditSvc: auditSvc}
}

// Get handles GET /api/v1/tenants/{id}.
func (h *TenantHandler) Get(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid tenant ID"))
		return
	}

	// Tenants can only access their own data
	if id != tenant.ID {
		apierror.WriteError(w, reqID, apierror.Forbidden("cannot access other tenant"))
		return
	}

	t, err := h.svc.GetByID(r.Context(), id)
	if err != nil || t == nil {
		apierror.WriteError(w, reqID, apierror.NotFound("tenant", idStr))
		return
	}

	apierror.WriteSuccess(w, reqID, t, http.StatusOK)
}

// Update handles PATCH /api/v1/tenants/{id}.
// Only Name can be updated by the tenant — plan/limits require admin access (C2 fix).
func (h *TenantHandler) Update(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid tenant ID"))
		return
	}

	if id != tenant.ID {
		apierror.WriteError(w, reqID, apierror.Forbidden("cannot modify other tenant"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024) // 4KB max

	var input domain.UpdateTenantInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	updated, err := h.svc.Update(r.Context(), id, &input)
	if err != nil || updated == nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}

	// Determine actor from JWT or API key context
	actor := "unknown"
	if claims := middleware.UserFromContext(r.Context()); claims != nil {
		actor = claims.Email
	} else if apiKey := middleware.APIKeyFromContext(r.Context()); apiKey != nil {
		actor = apiKey.KeyPrefix
	}
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionTenantUpdate, "tenant", &id, r.RemoteAddr, nil)

	apierror.WriteSuccess(w, reqID, updated, http.StatusOK)
}
