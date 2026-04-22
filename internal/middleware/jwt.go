package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/oluwasemilore/aegis/internal/crypto"
	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
)

const (
	userCtxKey contextKey = "aegis_user"
)

// UserFromContext retrieves the authenticated user from request context.
func UserFromContext(ctx context.Context) *crypto.Claims {
	claims, _ := ctx.Value(userCtxKey).(*crypto.Claims)
	return claims
}

// JWTAuth returns middleware that validates JWT tokens and injects user claims into context.
// It also loads the tenant and user into context so downstream handlers work seamlessly.
// The user lookup ensures deactivated users are immediately locked out (not after token expiry).
func JWTAuth(jwtSecret []byte, tenantRepo domain.TenantRepository, userRepo domain.UserRepository) func(http.Handler) http.Handler {
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
				apierror.WriteError(w, reqID, apierror.Unauthorized("invalid Authorization format"))
				return
			}

			tokenStr := parts[1]

			// Distinguish JWT from API key: API keys start with "aegis_"
			if strings.HasPrefix(tokenStr, "aegis_") {
				apierror.WriteError(w, reqID, apierror.Unauthorized("this endpoint requires a JWT token, not an API key"))
				return
			}

			claims, err := crypto.ValidateToken(tokenStr, jwtSecret)
			if err != nil {
				apierror.WriteError(w, reqID, apierror.Unauthorized("invalid or expired token"))
				return
			}

			// Load user and check active status (immediate revocation on deactivation)
			user, err := userRepo.GetByID(r.Context(), claims.UserID)
			if err != nil || user == nil || !user.IsActive {
				apierror.WriteError(w, reqID, apierror.Unauthorized("user account is deactivated or not found"))
				return
			}

			// Load tenant for context
			tenant, err := tenantRepo.GetByID(r.Context(), claims.TenantID)
			if err != nil || tenant == nil || !tenant.IsActive {
				apierror.WriteError(w, reqID, apierror.Unauthorized("tenant not found or inactive"))
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, claims)
			ctx = context.WithValue(ctx, tenantCtxKey, tenant)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
