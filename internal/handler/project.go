package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/middleware"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
	"github.com/oluwasemilore/aegis/internal/pkg/pagination"
	"github.com/oluwasemilore/aegis/internal/service"
)

type ProjectHandler struct {
	svc      *service.ProjectService
	auditSvc *service.AuditService
}

func NewProjectHandler(svc *service.ProjectService, auditSvc *service.AuditService) *ProjectHandler {
	return &ProjectHandler{svc: svc, auditSvc: auditSvc}
}

func (h *ProjectHandler) Create(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	var input domain.CreateProjectInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}
	if input.Name == "" || input.Slug == "" || input.Environment == "" {
		apierror.WriteError(w, reqID, apierror.ValidationError("name, slug, and environment are required"))
		return
	}

	project, err := h.svc.Create(r.Context(), tenant.ID, &input)
	if err != nil {
		apierror.WriteError(w, reqID, &apierror.APIError{Code: "CREATE_FAILED", Message: err.Error(), Status: http.StatusBadRequest})
		return
	}

	actor := "unknown"
	if claims := middleware.UserFromContext(r.Context()); claims != nil {
		actor = claims.Email
	} else if apiKey := middleware.APIKeyFromContext(r.Context()); apiKey != nil {
		actor = apiKey.KeyPrefix
	}
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionProjectCreate, "project", &project.ID, r.RemoteAddr, nil)

	apierror.WriteSuccess(w, reqID, project, http.StatusCreated)
}

func (h *ProjectHandler) List(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	tenant := middleware.TenantFromContext(r.Context())
	if tenant == nil {
		apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
		return
	}

	p := pagination.Parse(r)
	projects, err := h.svc.List(r.Context(), tenant.ID, p.Limit, p.Cursor)
	if err != nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}

	apierror.WriteSuccess(w, reqID, projects, http.StatusOK)
}

func (h *ProjectHandler) Get(w http.ResponseWriter, r *http.Request) {
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

	project, err := h.svc.GetByID(r.Context(), tenant.ID, projectID)
	if err != nil || project == nil {
		apierror.WriteError(w, reqID, apierror.NotFound("project", projectID.String()))
		return
	}

	apierror.WriteSuccess(w, reqID, project, http.StatusOK)
}

func (h *ProjectHandler) Update(w http.ResponseWriter, r *http.Request) {
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

	var input domain.UpdateProjectInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	updated, err := h.svc.Update(r.Context(), tenant.ID, projectID, &input)
	if err != nil || updated == nil {
		apierror.WriteError(w, reqID, apierror.InternalError())
		return
	}

	actor := "unknown"
	if claims := middleware.UserFromContext(r.Context()); claims != nil {
		actor = claims.Email
	} else if apiKey := middleware.APIKeyFromContext(r.Context()); apiKey != nil {
		actor = apiKey.KeyPrefix
	}
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionProjectUpdate, "project", &projectID, r.RemoteAddr, nil)

	apierror.WriteSuccess(w, reqID, updated, http.StatusOK)
}

func (h *ProjectHandler) Delete(w http.ResponseWriter, r *http.Request) {
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

	if err := h.svc.SoftDelete(r.Context(), tenant.ID, projectID); err != nil {
		apierror.WriteError(w, reqID, apierror.NotFound("project", projectID.String()))
		return
	}

	actor := "unknown"
	if claims := middleware.UserFromContext(r.Context()); claims != nil {
		actor = claims.Email
	} else if apiKey := middleware.APIKeyFromContext(r.Context()); apiKey != nil {
		actor = apiKey.KeyPrefix
	}
	h.auditSvc.Log(r.Context(), tenant.ID, actor, domain.AuditActionProjectDelete, "project", &projectID, r.RemoteAddr, nil)

	apierror.WriteSuccess(w, reqID, map[string]string{"message": "project deleted"}, http.StatusOK)
}
