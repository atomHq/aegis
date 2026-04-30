package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/handler"
	"github.com/oluwasemilore/aegis/internal/middleware"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
	"github.com/oluwasemilore/aegis/internal/service"
)

// NewRouter creates the chi router with all routes and middleware.
func NewRouter(
	healthHandler *handler.HealthHandler,
	authHandler *handler.AuthHandler,
	tenantHandler *handler.TenantHandler,
	projectHandler *handler.ProjectHandler,
	secretHandler *handler.SecretHandler,
	apiKeyHandler *handler.APIKeyHandler,
	auditSvc *service.AuditService,
	apiKeySvc *service.APIKeyService,
	rateLimiter *middleware.RateLimiter,
	jwtSecret []byte,
	tenantRepo domain.TenantRepository,
	userRepo domain.UserRepository,
	corsOrigins []string,
) http.Handler {
	r := chi.NewRouter()

	// Global middleware — CORS must be first so preflight requests
	// are handled before auth middleware rejects them.
	corsCfg := middleware.DefaultCORSConfig()
	corsCfg.AllowedOrigins = corsOrigins
	r.Use(middleware.CORS(corsCfg))
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)

	// Health check (no auth required)
	r.Get("/health", healthHandler.Check)

	r.Route("/api/v1", func(r chi.Router) {

		// ──────────────────────────────────────────────
		// Public auth routes (no authentication)
		// Rate-limited by IP to prevent brute-force
		// ──────────────────────────────────────────────
		r.Route("/auth", func(r chi.Router) {
			r.With(rateLimiter.IPRateLimit(5)).Post("/signup", authHandler.Signup)
			r.With(rateLimiter.IPRateLimit(10)).Post("/login", authHandler.Login)
			r.With(rateLimiter.IPRateLimit(10)).Post("/verify-email", authHandler.VerifyEmail)
			r.With(rateLimiter.IPRateLimit(5)).Post("/resend-verification", authHandler.ResendVerification)
		})

		// ──────────────────────────────────────────────
		// JWT-authenticated routes (user dashboard)
		// ──────────────────────────────────────────────
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(jwtSecret, tenantRepo, userRepo))

			// Tenant management (JWT auth — user can only view/update name)
			r.Route("/tenants/{id}", func(r chi.Router) {
				r.Get("/", tenantHandler.Get)
				r.Patch("/", tenantHandler.Update)
			})

			// API Key management (JWT auth — users manage their keys via dashboard)
			r.Route("/api-keys", func(r chi.Router) {
				r.Post("/", apiKeyHandler.Create)
				r.Get("/", apiKeyHandler.List)
				r.Delete("/{id}", apiKeyHandler.Revoke)
			})

			// Project management (JWT auth — dashboard users)
			r.Route("/auth/projects", func(r chi.Router) {
				r.Post("/", projectHandler.Create)
				r.Get("/", projectHandler.List)

				r.Route("/{id}", func(r chi.Router) {
					r.Get("/", projectHandler.Get)
					r.Patch("/", projectHandler.Update)
					r.Delete("/", projectHandler.Delete)
				})
			})
		})

		// ──────────────────────────────────────────────
		// API key-authenticated routes (programmatic access)
		// ──────────────────────────────────────────────
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(apiKeySvc))
			r.Use(rateLimiter.Middleware())

			// Projects
			r.Route("/projects", func(r chi.Router) {
				r.With(middleware.RequireScope("projects:manage")).Post("/", projectHandler.Create)
				r.Get("/", projectHandler.List)

				r.Route("/{id}", func(r chi.Router) {
					r.Get("/", projectHandler.Get)
					r.With(middleware.RequireScope("projects:manage")).Patch("/", projectHandler.Update)
					r.With(middleware.RequireScope("projects:manage")).Delete("/", projectHandler.Delete)

					// Secrets under project
					r.Route("/secrets", func(r chi.Router) {
						r.With(middleware.RequireScope("secrets:read")).Get("/", secretHandler.ListKeys)
						r.With(middleware.RequireScope("secrets:write")).Put("/", secretHandler.Put)
						r.With(middleware.RequireScope("secrets:write")).Put("/bulk", secretHandler.BulkPut)
						r.With(middleware.RequireScope("secrets:read")).Post("/bulk", secretHandler.BulkGet)
						r.With(middleware.RequireScope("secrets:write")).Post("/import", secretHandler.Import)

						r.Route("/{key}", func(r chi.Router) {
							r.With(middleware.RequireScope("secrets:read")).Get("/", secretHandler.Get)
							r.With(middleware.RequireScope("secrets:admin")).Delete("/", secretHandler.Delete)

							r.Route("/versions", func(r chi.Router) {
								r.With(middleware.RequireScope("secrets:read")).Get("/", secretHandler.ListVersions)
								r.With(middleware.RequireScope("secrets:read")).Get("/{version}", secretHandler.GetVersion)
							})
						})
					})
				})
			})

			// Audit Logs
			r.With(middleware.RequireScope("audit:read")).Get("/audit-logs", func(w http.ResponseWriter, req *http.Request) {
				tenant := middleware.TenantFromContext(req.Context())
				if tenant == nil {
					reqID := req.Header.Get("X-Request-ID")
					apierror.WriteError(w, reqID, apierror.Unauthorized("no tenant context"))
					return
				}
				filter := handler.AuditLogFilterFromRequest(req)
				logs, err := auditSvc.List(req.Context(), tenant.ID, &filter)
				if err != nil {
					reqID := req.Header.Get("X-Request-ID")
					apierror.WriteError(w, reqID, apierror.InternalError())
					return
				}
				reqID := req.Header.Get("X-Request-ID")

				apiKey := middleware.APIKeyFromContext(req.Context())
				actor := "unknown"
				if apiKey != nil {
					actor = apiKey.KeyPrefix
				}
				auditSvc.Log(req.Context(), tenant.ID, actor, domain.AuditActionSecretRead, "audit_log", nil, req.RemoteAddr, nil)

				handler.WriteAuditLogsResponse(w, reqID, logs)
			})
		})
	})

	return r
}
