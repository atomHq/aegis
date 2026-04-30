package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/middleware"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
	"github.com/oluwasemilore/aegis/internal/pkg/pagination"
	"github.com/oluwasemilore/aegis/internal/pkg/validator"
	"github.com/oluwasemilore/aegis/internal/service"
)

type SecretHandler struct {
	svc      *service.SecretService
	auditSvc *service.AuditService
}

func NewSecretHandler(svc *service.SecretService, auditSvc *service.AuditService) *SecretHandler {
	return &SecretHandler{svc: svc, auditSvc: auditSvc}
}

func (h *SecretHandler) getActor(r *http.Request) string {
	apiKey := middleware.APIKeyFromContext(r.Context())
	if apiKey != nil {
		return apiKey.KeyPrefix
	}
	return "unknown"
}

// Put handles PUT /api/v1/projects/{id}/secrets.
func (h *SecretHandler) Put(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	var input domain.PutSecretInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	if err := validator.ValidateSecretKey(input.Key); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError(err.Error()))
		return
	}
	if err := validator.ValidateSecretValue(input.Value); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError(err.Error()))
		return
	}

	actor := h.getActor(r)
	result, err := h.svc.Put(r.Context(), tenant.ID, projectID, &input, actor)
	if err != nil {
		apierror.WriteError(w, reqID, &apierror.APIError{Code: "SECRET_WRITE_FAILED", Message: err.Error(), Status: http.StatusBadRequest})
		return
	}

	action := domain.AuditActionSecretCreate
	if result.Version > 1 {
		action = domain.AuditActionSecretUpdate
	}
	h.auditSvc.Log(r.Context(), tenant.ID, actor, action, "secret", &result.ID, r.RemoteAddr,
		map[string]interface{}{"key": input.Key, "version": result.Version})

	// Don't return value in response for security — just confirm storage
	apierror.WriteSuccess(w, reqID, map[string]interface{}{
		"id": result.ID, "key": result.Key, "version": result.Version, "created_at": result.CreatedAt,
	}, http.StatusOK)
}

// Get handles GET /api/v1/projects/{id}/secrets/{key}.
func (h *SecretHandler) Get(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	key := chi.URLParam(r, "key")
	result, err := h.svc.Get(r.Context(), tenant.ID, projectID, key)
	if err != nil {
		if err.Error() == "secret '"+key+"' has expired" {
			apierror.WriteError(w, reqID, apierror.SecretExpired(key))
			return
		}
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}
	if result == nil {
		apierror.WriteError(w, reqID, apierror.NotFound("secret", key))
		return
	}

	actor := h.getActor(r)
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionSecretRead, "secret", &result.ID, r.RemoteAddr,
		map[string]interface{}{"key": key})

	apierror.WriteSuccess(w, reqID, result, http.StatusOK)
}

// GetVersion handles GET /api/v1/projects/{id}/secrets/{key}/versions/{version}.
func (h *SecretHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	key := chi.URLParam(r, "key")
	versionStr := chi.URLParam(r, "version")
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid version number"))
		return
	}

	result, err := h.svc.GetVersion(r.Context(), tenant.ID, projectID, key, version)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}
	if result == nil {
		apierror.WriteError(w, reqID, apierror.NotFound("secret version", key+"/v"+versionStr))
		return
	}

	actor := h.getActor(r)
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionSecretRead, "secret", &result.ID, r.RemoteAddr,
		map[string]interface{}{"key": key, "version": version})

	apierror.WriteSuccess(w, reqID, result, http.StatusOK)
}

// ListVersions handles GET /api/v1/projects/{id}/secrets/{key}/versions.
func (h *SecretHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	key := chi.URLParam(r, "key")
	versions, err := h.svc.ListVersions(r.Context(), tenant.ID, projectID, key)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}

	// Return metadata only — no encrypted values
	items := make([]map[string]interface{}, 0, len(versions))
	for _, v := range versions {
		items = append(items, map[string]interface{}{
			"id": v.ID, "version": v.Version, "is_active": v.IsActive,
			"created_by": v.CreatedBy, "created_at": v.CreatedAt,
		})
	}

	apierror.WriteSuccess(w, reqID, items, http.StatusOK)
}

// ListKeys handles GET /api/v1/projects/{id}/secrets.
func (h *SecretHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	p := pagination.Parse(r)
	keys, err := h.svc.ListKeys(r.Context(), tenant.ID, projectID, p.Limit, p.Cursor)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}

	apierror.WriteSuccess(w, reqID, keys, http.StatusOK)
}

// Delete handles DELETE /api/v1/projects/{id}/secrets/{key}.
func (h *SecretHandler) Delete(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	key := chi.URLParam(r, "key")
	if err := h.svc.Delete(r.Context(), tenant.ID, projectID, key); err != nil {
		apierror.WriteError(w, reqID, apierror.NotFound("secret", key))
		return
	}

	actor := h.getActor(r)
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionSecretDelete, "secret", nil, r.RemoteAddr,
		map[string]interface{}{"key": key})

	apierror.WriteSuccess(w, reqID, map[string]string{"message": "secret deleted"}, http.StatusOK)
}

// BulkGet handles POST /api/v1/projects/{id}/secrets/bulk.
func (h *SecretHandler) BulkGet(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	var input domain.BulkGetSecretsInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}
	if len(input.Keys) == 0 || len(input.Keys) > 50 {
		apierror.WriteError(w, reqID, apierror.ValidationError("keys must contain 1-50 items"))
		return
	}

	result, err := h.svc.BulkGet(r.Context(), tenant.ID, projectID, input.Keys)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}

	actor := h.getActor(r)
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionSecretBulk, "secret", nil, r.RemoteAddr,
		map[string]interface{}{"keys": input.Keys, "count": len(result)})

	apierror.WriteSuccess(w, reqID, result, http.StatusOK)
}

// BulkPut handles PUT /api/v1/projects/{id}/secrets/bulk.
func (h *SecretHandler) BulkPut(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
		return
	}

	var input domain.BulkPutSecretsInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	if len(input.Secrets) == 0 || len(input.Secrets) > 50 {
		apierror.WriteError(w, reqID, apierror.ValidationError("secrets must contain 1-50 items"))
		return
	}

	for _, sec := range input.Secrets {
		if err := validator.ValidateSecretKey(sec.Key); err != nil {
			apierror.WriteError(w, reqID, apierror.ValidationError("key '"+sec.Key+"': "+err.Error()))
			return
		}
		if err := validator.ValidateSecretValue(sec.Value); err != nil {
			apierror.WriteError(w, reqID, apierror.ValidationError("value for key '"+sec.Key+"': "+err.Error()))
			return
		}
	}

	actor := h.getActor(r)
	result, err := h.svc.BulkPut(r.Context(), tenant.ID, projectID, &input, actor)
	if err != nil {
		apierror.WriteError(w, reqID, &apierror.APIError{Code: "SECRET_BULK_WRITE_FAILED", Message: err.Error(), Status: http.StatusBadRequest})
		return
	}

	keys := make([]string, 0, len(result))
	items := make([]map[string]interface{}, 0, len(result))
	for _, res := range result {
		keys = append(keys, res.Key)
		items = append(items, map[string]interface{}{
			"id": res.ID, "key": res.Key, "version": res.Version, "created_at": res.CreatedAt,
		})
	}

	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionSecretBulkCreate, "secret", nil, r.RemoteAddr,
		map[string]interface{}{"keys": keys, "count": len(result)})

	apierror.WriteSuccess(w, reqID, items, http.StatusOK)
}
