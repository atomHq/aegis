package handler

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
	"github.com/oluwasemilore/aegis/internal/service"
	"github.com/rs/zerolog/log"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// AuthHandler handles authentication requests.
type AuthHandler struct {
	userSvc  *service.UserService
	auditSvc *service.AuditService
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(userSvc *service.UserService, auditSvc *service.AuditService) *AuthHandler {
	return &AuthHandler{userSvc: userSvc, auditSvc: auditSvc}
}

// Signup handles POST /api/v1/auth/signup.
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024) // 4KB max

	var input domain.SignupInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	// Validate fields
	if input.Email == "" || !emailRegex.MatchString(input.Email) {
		apierror.WriteError(w, reqID, apierror.ValidationError("valid email is required"))
		return
	}
	if len(input.Password) < 8 {
		apierror.WriteError(w, reqID, apierror.ValidationError("password must be at least 8 characters"))
		return
	}
	if len(input.Password) > 72 {
		apierror.WriteError(w, reqID, apierror.ValidationError("password must be at most 72 characters"))
		return
	}
	if input.FirstName == "" || input.LastName == "" {
		apierror.WriteError(w, reqID, apierror.ValidationError("first_name and last_name are required"))
		return
	}
	if input.OrgName == "" || input.OrgSlug == "" {
		apierror.WriteError(w, reqID, apierror.ValidationError("org_name and org_slug are required"))
		return
	}
	if len(input.OrgSlug) < 2 || len(input.OrgSlug) > 100 {
		apierror.WriteError(w, reqID, apierror.ValidationError("org_slug must be 2-100 characters"))
		return
	}

	result, err := h.userSvc.Signup(r.Context(), &input)
	if err != nil {
		apierror.WriteError(w, reqID, &apierror.APIError{
			Code: "SIGNUP_FAILED", Message: err.Error(), Status: http.StatusBadRequest,
		})
		return
	}

	h.auditSvc.Log(r.Context(), result.Tenant.ID, result.User.Email, domain.AuditActionTenantCreate,
		"user", &result.User.ID, r.RemoteAddr, nil)

	apierror.WriteSuccess(w, reqID, map[string]interface{}{
		"user":    result.User,
		"tenant":  result.Tenant,
		"api_key": result.APIKey,
		"message": "Account created. Please check your email for the verification code.",
		"warning": "Store the api_key securely. It will not be shown again.",
	}, http.StatusCreated)
}

// Login handles POST /api/v1/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024) // 2KB max

	var input domain.LoginInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Error().
			Err(err).
			Str("request_id", reqID).
			Str("remote_addr", r.RemoteAddr).
			Msg("failed to decode login request body")
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	email := strings.ToLower(strings.TrimSpace(input.Email))
	input.Email = email
	log.Info().
		Str("request_id", reqID).
		Str("email", email).
		Bool("password_provided", input.Password != "").
		Int("password_length", len(input.Password)).
		Str("remote_addr", r.RemoteAddr).
		Msg("login request received")

	if input.Email == "" || input.Password == "" {
		log.Warn().
			Str("request_id", reqID).
			Str("email", email).
			Bool("email_provided", input.Email != "").
			Bool("password_provided", input.Password != "").
			Msg("login request validation failed")
		apierror.WriteError(w, reqID, apierror.ValidationError("email and password are required"))
		return
	}

	token, user, err := h.userSvc.Login(r.Context(), &input)
	if err != nil {
		log.Warn().
			Err(err).
			Str("request_id", reqID).
			Str("email", email).
			Str("remote_addr", r.RemoteAddr).
			Msg("login failed")
		// Generic error message to prevent user enumeration
		apierror.WriteError(w, reqID, apierror.Unauthorized("invalid email or password"))
		return
	}

	log.Info().
		Str("request_id", reqID).
		Str("user_id", user.ID.String()).
		Str("tenant_id", user.TenantID.String()).
		Str("email", user.Email).
		Msg("login succeeded")

	apierror.WriteSuccess(w, reqID, map[string]interface{}{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": 86400, // 24 hours in seconds
		"user":       user,
	}, http.StatusOK)
}

// VerifyEmail handles POST /api/v1/auth/verify-email.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024)

	var input domain.VerifyEmailInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	if input.Email == "" || input.Code == "" {
		apierror.WriteError(w, reqID, apierror.ValidationError("email and code are required"))
		return
	}
	if len(input.Code) != 5 {
		apierror.WriteError(w, reqID, apierror.ValidationError("code must be 5 digits"))
		return
	}

	user, err := h.userSvc.VerifyEmail(r.Context(), &input)
	if err != nil {
		apierror.WriteError(w, reqID, &apierror.APIError{
			Code: "VERIFICATION_FAILED", Message: err.Error(), Status: http.StatusBadRequest,
		})
		return
	}

	apierror.WriteSuccess(w, reqID, map[string]interface{}{
		"user":    user,
		"message": "Email verified successfully. You can now log in.",
	}, http.StatusOK)
}

// ResendVerification handles POST /api/v1/auth/resend-verification.
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024)

	var input domain.ResendVerificationInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.WriteError(w, reqID, apierror.ValidationError("invalid request body"))
		return
	}

	if input.Email == "" {
		apierror.WriteError(w, reqID, apierror.ValidationError("email is required"))
		return
	}

	// Always return success to prevent email enumeration
	_ = h.userSvc.ResendVerification(r.Context(), &input)

	apierror.WriteSuccess(w, reqID, map[string]interface{}{
		"message": "If the email is registered and not verified, a new code has been sent.",
	}, http.StatusOK)
}
