package apierror

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// APIError represents a structured API error.
type APIError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Status  int         `json:"-"`
	Details interface{} `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	return e.Message
}

// Standard error constructors.

func NotFound(resource, identifier string) *APIError {
	return &APIError{Code: "NOT_FOUND", Message: resource + " '" + identifier + "' not found", Status: http.StatusNotFound}
}

func ValidationError(message string) *APIError {
	return &APIError{Code: "VALIDATION_ERROR", Message: message, Status: http.StatusBadRequest}
}

func Forbidden(message string) *APIError {
	return &APIError{Code: "FORBIDDEN", Message: message, Status: http.StatusForbidden}
}

func Unauthorized(message string) *APIError {
	return &APIError{Code: "UNAUTHORIZED", Message: message, Status: http.StatusUnauthorized}
}

func RateLimited() *APIError {
	return &APIError{Code: "RATE_LIMITED", Message: "rate limit exceeded", Status: http.StatusTooManyRequests}
}

func LimitExceeded(resource string, limit int) *APIError {
	return &APIError{Code: "LIMIT_EXCEEDED", Message: resource + " limit reached", Status: http.StatusForbidden, Details: map[string]int{"limit": limit}}
}

func SecretExpired(key string) *APIError {
	return &APIError{Code: "SECRET_EXPIRED", Message: "secret '" + key + "' has expired", Status: http.StatusGone}
}

func InternalError() *APIError {
	return &APIError{Code: "INTERNAL_ERROR", Message: "an internal error occurred", Status: http.StatusInternalServerError}
}

// Response types.

type SuccessResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
	Meta   Meta        `json:"meta"`
}

type ErrorResponse struct {
	Status string   `json:"status"`
	Error  APIError `json:"error"`
	Meta   Meta     `json:"meta"`
}

type Meta struct {
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

func newMeta(requestID string) Meta {
	if requestID == "" {
		requestID = uuid.New().String()
	}
	return Meta{RequestID: requestID, Timestamp: time.Now().UTC().Format(time.RFC3339)}
}

// WriteSuccess writes a success JSON response.
func WriteSuccess(w http.ResponseWriter, requestID string, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(SuccessResponse{Status: "success", Data: data, Meta: newMeta(requestID)})
}

// WriteError writes an error JSON response.
func WriteError(w http.ResponseWriter, requestID string, apiErr *APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiErr.Status)
	json.NewEncoder(w).Encode(ErrorResponse{Status: "error", Error: *apiErr, Meta: newMeta(requestID)})
}
