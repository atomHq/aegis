package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oluwasemilore/aegis/internal/crypto"
	"github.com/oluwasemilore/aegis/internal/domain"
	"github.com/rs/zerolog/log"
)

// UserService handles user authentication and registration.
type UserService struct {
	userRepo    domain.UserRepository
	tenantRepo  domain.TenantRepository
	projectRepo domain.ProjectRepository
	apiKeyRepo  domain.APIKeyRepository
	pool        *pgxpool.Pool
	emailSvc    *EmailService
	jwtSecret   []byte
}

// NewUserService creates a new user service.
func NewUserService(
	userRepo domain.UserRepository,
	tenantRepo domain.TenantRepository,
	projectRepo domain.ProjectRepository,
	apiKeyRepo domain.APIKeyRepository,
	pool *pgxpool.Pool,
	emailSvc *EmailService,
	jwtSecret []byte,
) *UserService {
	return &UserService{
		userRepo: userRepo, tenantRepo: tenantRepo, projectRepo: projectRepo,
		apiKeyRepo: apiKeyRepo, pool: pool, emailSvc: emailSvc, jwtSecret: jwtSecret,
	}
}

// SignupResult holds the result of user registration.
type SignupResult struct {
	User   *domain.User   `json:"user"`
	Tenant *domain.Tenant `json:"tenant"`
	APIKey string         `json:"api_key"` // Plaintext admin key — shown only once
}

// Signup creates a new user with tenant, default project, and admin API key atomically.
func (s *UserService) Signup(ctx context.Context, input *domain.SignupInput) (*SignupResult, error) {
	// Check if email already exists
	existing, err := s.userRepo.GetByEmail(ctx, strings.ToLower(input.Email))
	if err != nil {
		return nil, fmt.Errorf("signup failed, please try again")
	}
	if existing != nil {
		return nil, fmt.Errorf("signup failed, please try again or contact support")
	}

	// Check if tenant slug already exists
	existingTenant, err := s.tenantRepo.GetBySlug(ctx, input.OrgSlug)
	if err != nil {
		return nil, fmt.Errorf("signup failed, please try again")
	}
	if existingTenant != nil {
		return nil, fmt.Errorf("signup failed, please try again or contact support")
	}

	// Hash password
	passwordHash, err := crypto.HashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate verification code
	code, err := generateVerificationCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification code: %w", err)
	}
	expiresAt := time.Now().UTC().Add(15 * time.Minute)

	// === BEGIN ATOMIC TRANSACTION ===
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Create tenant
	tenantID := uuid.New()
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		INSERT INTO tenants (id, name, slug, plan, max_secrets, max_projects, rate_limit_per_min, is_active, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, 'free', 100, 5, 60, true, '{}', $4, $4)`,
		tenantID, input.OrgName, input.OrgSlug, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// 2. Create default project
	projectID := uuid.New()
	_, err = tx.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, name, slug, description, environment, is_active, created_at, updated_at)
		VALUES ($1, $2, 'Default', 'default', 'Default project', 'development', true, $3, $3)`,
		projectID, tenantID, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create default project: %w", err)
	}

	// 3. Generate admin API key
	plaintext, hash, prefix, err := crypto.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	apiKeyID := uuid.New()
	_, err = tx.Exec(ctx, `
		INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, is_active, created_at)
		VALUES ($1, $2, 'Admin Key', $3, $4, $5, true, $6)`,
		apiKeyID, tenantID, hash, prefix,
		[]string{"secrets:read", "secrets:write", "secrets:admin", "projects:manage", "api_keys:manage", "audit:read"},
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create api key: %w", err)
	}

	// 4. Create user
	userID := uuid.New()
	email := strings.ToLower(input.Email)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, first_name, last_name, tenant_id, is_verified, verification_code, verification_expires_at, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8, true, $9, $9)`,
		userID, email, passwordHash, input.FirstName, input.LastName,
		tenantID, code, expiresAt, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// === COMMIT TRANSACTION ===
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit signup transaction: %w", err)
	}

	// Send verification email (outside transaction — best effort)
	go func() {
		if err := s.emailSvc.SendVerification(email, input.FirstName, code); err != nil {
			log.Error().Err(err).Str("email", email).Msg("failed to send verification email")
		}
	}()

	tenant := &domain.Tenant{
		ID: tenantID, Name: input.OrgName, Slug: input.OrgSlug,
		Plan: "free", MaxSecrets: 100, MaxProjects: 5, RateLimitPerMin: 60,
		IsActive: true, Metadata: map[string]interface{}{}, CreatedAt: now, UpdatedAt: now,
	}

	user := &domain.User{
		ID: userID, Email: email, FirstName: input.FirstName, LastName: input.LastName,
		TenantID: &tenantID, IsVerified: false, IsActive: true, CreatedAt: now, UpdatedAt: now,
	}

	// Log the admin API key — shown only once in signup response
	log.Info().Str("tenant_id", tenantID.String()).Str("key_prefix", prefix).Msg("admin API key created during signup")

	return &SignupResult{User: user, Tenant: tenant, APIKey: plaintext}, nil
}

// Login authenticates a user and returns a JWT token.
func (s *UserService) Login(ctx context.Context, input *domain.LoginInput) (string, *domain.User, error) {
	email := strings.ToLower(input.Email)
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		log.Error().Err(err).Str("email", email).Msg("failed to fetch user during login")
		return "", nil, fmt.Errorf("authentication failed")
	}
	if user == nil {
		log.Warn().Str("email", email).Msg("login failed: user not found")
		return "", nil, fmt.Errorf("invalid email or password")
	}

	if !user.IsActive {
		log.Warn().Str("user_id", user.ID.String()).Str("email", email).Msg("login failed: inactive user")
		return "", nil, fmt.Errorf("account is deactivated")
	}

	if err := crypto.CheckPassword(input.Password, user.PasswordHash); err != nil {
		log.Warn().Str("user_id", user.ID.String()).Str("email", email).Msg("login failed: invalid password")
		return "", nil, fmt.Errorf("invalid email or password")
	}

	if !user.IsVerified {
		log.Warn().Str("user_id", user.ID.String()).Str("email", email).Msg("login failed: email not verified")
		return "", nil, fmt.Errorf("email not verified, please check your inbox")
	}

	if user.TenantID == nil {
		log.Error().Str("user_id", user.ID.String()).Str("email", email).Msg("login failed: user has no tenant")
		return "", nil, fmt.Errorf("no organization associated")
	}

	// Generate JWT
	token, err := crypto.GenerateToken(user.ID, *user.TenantID, user.Email, s.jwtSecret)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID.String()).Str("tenant_id", user.TenantID.String()).Str("email", email).Msg("failed to generate login token")
		return "", nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Update last login (fire and forget)
	go func() {
		if err := s.userRepo.UpdateLastLogin(context.Background(), user.ID); err != nil {
			log.Error().Err(err).Str("user_id", user.ID.String()).Str("email", email).Msg("failed to update last login")
		}
	}()

	log.Info().Str("user_id", user.ID.String()).Str("tenant_id", user.TenantID.String()).Str("email", email).Msg("user authenticated")
	return token, user, nil
}

// VerifyEmail validates the verification code and marks the user as verified.
func (s *UserService) VerifyEmail(ctx context.Context, input *domain.VerifyEmailInput) (*domain.User, error) {
	email := strings.ToLower(input.Email)
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if user.IsVerified {
		return user, nil // Already verified
	}

	// Brute-force protection: max 5 verification attempts per code
	const maxVerificationAttempts = 5
	if user.VerificationAttempts >= maxVerificationAttempts {
		return nil, fmt.Errorf("too many verification attempts, please request a new code")
	}

	// Increment attempt counter BEFORE checking the code (prevents timing-based bypass)
	_ = s.userRepo.IncrementVerificationAttempts(ctx, user.ID)

	if user.VerificationCode == nil || *user.VerificationCode != input.Code {
		return nil, fmt.Errorf("invalid verification code")
	}

	if user.VerificationExpiresAt != nil && user.VerificationExpiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("verification code has expired, please request a new one")
	}

	if err := s.userRepo.SetVerified(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("failed to verify email: %w", err)
	}

	user.IsVerified = true

	// Send welcome email (outside critical path — best effort)
	go func() {
		if err := s.emailSvc.SendWelcome(email, user.FirstName, "https://aegis.dev/dashboard"); err != nil {
			log.Error().Err(err).Str("email", email).Msg("failed to send welcome email")
		}
	}()

	return user, nil
}

// ResendVerification generates a new verification code and sends it.
func (s *UserService) ResendVerification(ctx context.Context, input *domain.ResendVerificationInput) error {
	email := strings.ToLower(input.Email)
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		// Don't reveal if email exists
		return nil
	}

	if user.IsVerified {
		return nil // Already verified, no-op
	}

	code, err := generateVerificationCode()
	if err != nil {
		return fmt.Errorf("failed to generate code: %w", err)
	}
	expiresAt := time.Now().UTC().Add(15 * time.Minute)

	if err := s.userRepo.UpdateVerificationCode(ctx, user.ID, code, expiresAt); err != nil {
		return fmt.Errorf("failed to update code: %w", err)
	}

	// Reset attempt counter when a new code is generated
	_ = s.userRepo.ResetVerificationAttempts(ctx, user.ID)

	go func() {
		if err := s.emailSvc.SendVerification(email, user.FirstName, code); err != nil {
			log.Error().Err(err).Str("email", email).Msg("failed to resend verification email")
		}
	}()

	return nil
}

// generateVerificationCode generates a cryptographically random 5-digit code.
func generateVerificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90000))
	if err != nil {
		return "", fmt.Errorf("failed to generate random number: %w", err)
	}
	code := fmt.Sprintf("%05d", n.Int64()+10000)
	return code, nil
}
