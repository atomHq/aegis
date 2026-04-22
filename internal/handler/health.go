package handler

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
)

// HealthHandler handles health check requests.
type HealthHandler struct {
	pool *pgxpool.Pool
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler(pool *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{pool: pool}
}

// Check handles GET /health.
func (h *HealthHandler) Check(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")

	err := h.pool.Ping(r.Context())
	if err != nil {
		apierror.WriteError(w, reqID, &apierror.APIError{
			Code: "UNHEALTHY", Message: "database connection failed", Status: http.StatusServiceUnavailable,
		})
		return
	}

	apierror.WriteSuccess(w, reqID, map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
	}, http.StatusOK)
}
