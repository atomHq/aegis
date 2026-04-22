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

type APIKeyHandler struct {
	svc      *service.APIKeyService
	auditSvc *service.AuditService
}

func NewAPIKeyHandler(svc *service.APIKeyService, auditSvc *service.AuditService) *APIKeyHandler {
	return &APIKeyHandler{svc: svc, auditSvc: auditSvc}
}

// Create handles POST /api/v1/api-keys.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	var input domain.CreateAPIKeyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}
	if input.Name == "" || len(input.Scopes) == 0 {
		apierror.WriteError(w, reqID, apierror.ValidationError("name and scopes are required"))
		return
	}

	// Validate scopes
	for _, scope := range input.Scopes {
		if !domain.ValidScopes[scope] {
			apierror.WriteError(w, reqID, apierror.ValidationError("invalid scope: "+scope))
			return
		}
	}

	result, err := h.svc.Create(r.Context(), tenant.ID, &input)
	if err != nil {
		apierror.WriteError(w, reqID, &apierror.APIError{Code: "KEY_CREATE_FAILED", Message: err.Error(), Status: http.StatusBadRequest})
		return
	}

	apiKey := middleware.APIKeyFromContext(r.Context())
	actor := "unknown"
	if apiKey != nil {
		actor = apiKey.KeyPrefix
	}
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionAPIKeyCreate, "api_key", &result.Key.ID, r.RemoteAddr, nil)

	apierror.WriteSuccess(w, reqID, map[string]interface{}{
		"key":           result.Key,
		"plaintext_key": result.Plaintext,
		"warning":       "Store this key securely. It will not be shown again.",
	}, http.StatusCreated)
}

// List handles GET /api/v1/api-keys.
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	keys, err := h.svc.List(r.Context(), tenant.ID)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}

	apierror.WriteSuccess(w, reqID, keys, http.StatusOK)
}

// Revoke handles DELETE /api/v1/api-keys/{id}.
func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	keyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid key ID"))
		return
	}

	if err := h.svc.Revoke(r.Context(), tenant.ID, keyID); err != nil {
		apierror.WriteError(w, reqID, apierror.NotFound("api_key", keyID.String()))
		return
	}

	apiKey := middleware.APIKeyFromContext(r.Context())
	actor := "unknown"
	if apiKey != nil {
		actor = apiKey.KeyPrefix
	}
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionAPIKeyRevoke, "api_key", &keyID, r.RemoteAddr, nil)

	apierror.WriteSuccess(w, reqID, map[string]string{"message": "api key revoked"}, http.StatusOK)
}
