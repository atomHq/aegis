package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated user in the Aegis platform.
type User struct {
	ID                    uuid.UUID  `json:"id"`
	Email                 string     `json:"email"`
	PasswordHash          string     `json:"-"` // Never expose
	FirstName             string     `json:"first_name"`
	LastName              string     `json:"last_name"`
	TenantID              *uuid.UUID `json:"tenant_id,omitempty"`
	IsVerified            bool       `json:"is_verified"`
	VerificationCode      *string    `json:"-"` // Never expose
	VerificationExpiresAt *time.Time `json:"-"` // Never expose
	VerificationAttempts  int        `json:"-"` // Never expose — brute-force protection
	IsActive              bool       `json:"is_active"`
	LastLoginAt           *time.Time `json:"last_login_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// SignupInput holds the input for user registration.
type SignupInput struct {
	Email     string `json:"email" validate:"required,email,max=255"`
	Password  string `json:"password" validate:"required,min=8,max=128"`
	FirstName string `json:"first_name" validate:"required,min=1,max=100"`
	LastName  string `json:"last_name" validate:"required,min=1,max=100"`
	// Tenant info
	OrgName string `json:"org_name" validate:"required,min=2,max=255"`
	OrgSlug string `json:"org_slug" validate:"required,min=2,max=100"`
}

// LoginInput holds the input for user login.
type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// VerifyEmailInput holds the input for email verification.
type VerifyEmailInput struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required,len=5"`
}

// ResendVerificationInput holds the input for resending verification email.
type ResendVerificationInput struct {
	Email string `json:"email" validate:"required,email"`
}

// UserRepository defines the interface for user data access.
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	SetVerified(ctx context.Context, id uuid.UUID) error
	UpdateVerificationCode(ctx context.Context, id uuid.UUID, code string, expiresAt time.Time) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	IncrementVerificationAttempts(ctx context.Context, id uuid.UUID) error
	ResetVerificationAttempts(ctx context.Context, id uuid.UUID) error
}
