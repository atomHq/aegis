package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
	"github.com/oluwasemilore/aegis/internal/service"
)

type contextKey string

const (
	tenantCtxKey contextKey = "aegis_tenant"
	apiKeyCtxKey contextKey = "aegis_apikey"
)

// TenantFromContext retrieves the tenant from request context.
func TenantFromContext(ctx context.Context) *domain.Tenant {
	tenant, _ := ctx.Value(tenantCtxKey).(*domain.Tenant)
	return tenant
}

// APIKeyFromContext retrieves the API key from request context.
func APIKeyFromContext(ctx context.Context) *domain.APIKey {
	key, _ := ctx.Value(apiKeyCtxKey).(*domain.APIKey)
	return key
}

// Auth returns middleware that validates API keys and injects tenant context.
func Auth(apiKeySvc *service.APIKeyService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get("X-Request-ID")

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				apierror.WriteError(w, reqID, apierror.Unauthorized("missing Authorization header"))
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				apierror.WriteError(w, reqID, apierror.Unauthorized("invalid Authorization format, expected: Bearer <key>"))
				return
			}

			plaintextKey := parts[1]
			if !strings.HasPrefix(plaintextKey, "aegis_") {
				apierror.WriteError(w, reqID, apierror.Unauthorized("invalid API key format"))
				return
			}

			apiKey, tenant, err := apiKeySvc.ValidateKey(r.Context(), plaintextKey)
			if err != nil {
				apierror.WriteError(w, reqID, apierror.Unauthorized(err.Error()))
				return
			}

			ctx := context.WithValue(r.Context(), tenantCtxKey, tenant)
			ctx = context.WithValue(ctx, apiKeyCtxKey, apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns middleware that checks if the API key has the required scope.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get("X-Request-ID")
			apiKey := APIKeyFromContext(r.Context())
			if apiKey == nil {
				apierror.WriteError(w, reqID, apierror.Unauthorized("no API key in context"))
				return
			}

			hasScope := false
			for _, s := range apiKey.Scopes {
				if s == scope {
					hasScope = true
					break
				}
			}

			if !hasScope {
				apierror.WriteError(w, reqID, apierror.Forbidden("insufficient scope, requires: "+scope))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireProjectAccess returns middleware that enforces API key project_ids scoping.
// If the API key has ProjectIDs set, the request's project ID (from chi URL param "id")
// must be in that list. Keys with empty ProjectIDs have access to all projects.
func RequireProjectAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := APIKeyFromContext(r.Context())
		// Skip check if no API key (JWT-authed) or no project restriction
		if apiKey == nil || len(apiKey.ProjectIDs) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		projectIDStr := chi.URLParam(r, "id")
		if projectIDStr == "" {
			next.ServeHTTP(w, r)
			return
		}

		projectID, err := uuid.Parse(projectIDStr)
		if err != nil {
			reqID := r.Header.Get("X-Request-ID")
			apierror.WriteError(w, reqID, apierror.ValidationError("invalid project ID"))
			return
		}

		for _, allowed := range apiKey.ProjectIDs {
			if allowed == projectID {
				next.ServeHTTP(w, r)
				return
			}
		}

		reqID := r.Header.Get("X-Request-ID")
		apierror.WriteError(w, reqID, apierror.Forbidden("API key does not have access to this project"))
	})
}
