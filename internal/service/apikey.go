package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/crypto"
	"github.com/oluwasemilore/aegis/internal/domain"
)

// APIKeyService handles API key lifecycle.
type APIKeyService struct {
	repo       domain.APIKeyRepository
	tenantRepo domain.TenantRepository
}

// NewAPIKeyService creates a new API key service.
func NewAPIKeyService(repo domain.APIKeyRepository, tenantRepo domain.TenantRepository) *APIKeyService {
	return &APIKeyService{repo: repo, tenantRepo: tenantRepo}
}

// APIKeyCreateResult holds the result of key creation.
type APIKeyCreateResult struct {
	Key       *domain.APIKey `json:"key"`
	Plaintext string         `json:"plaintext_key"` // Shown only once
}

// Create creates a new API key.
func (s *APIKeyService) Create(ctx context.Context, tenantID uuid.UUID, input *domain.CreateAPIKeyInput) (*APIKeyCreateResult, error) {
	plaintext, hash, prefix, err := crypto.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	key := &domain.APIKey{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Name:       input.Name,
		KeyHash:    hash,
		KeyPrefix:  prefix,
		Scopes:     input.Scopes,
		ProjectIDs: input.ProjectIDs,
		IsActive:   true,
		ExpiresAt:  input.ExpiresAt,
		CreatedAt:  time.Now().UTC(),
	}

	if err := s.repo.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to create api key: %w", err)
	}

	return &APIKeyCreateResult{Key: key, Plaintext: plaintext}, nil
}

// ValidateKey validates an API key and returns the key record and tenant.
func (s *APIKeyService) ValidateKey(ctx context.Context, plaintextKey string) (*domain.APIKey, *domain.Tenant, error) {
	hash := crypto.HashAPIKey(plaintextKey)
	key, err := s.repo.GetByHash(ctx, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup api key: %w", err)
	}
	if key == nil {
		return nil, nil, fmt.Errorf("invalid api key")
	}

	if !key.IsActive {
		return nil, nil, fmt.Errorf("api key is revoked")
	}

	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now().UTC()) {
		return nil, nil, fmt.Errorf("api key has expired")
	}

	tenant, err := s.tenantRepo.GetByID(ctx, key.TenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tenant: %w", err)
	}
	if tenant == nil || !tenant.IsActive {
		return nil, nil, fmt.Errorf("tenant is inactive")
	}

	// Update last used (fire and forget)
	go func() {
		_ = s.repo.UpdateLastUsed(context.Background(), key.ID)
	}()

	return key, tenant, nil
}

// List lists API keys for a tenant.
func (s *APIKeyService) List(ctx context.Context, tenantID uuid.UUID) ([]*domain.APIKey, error) {
	return s.repo.List(ctx, tenantID)
}

// Revoke revokes an API key.
func (s *APIKeyService) Revoke(ctx context.Context, tenantID, keyID uuid.UUID) error {
	return s.repo.Revoke(ctx, tenantID, keyID)
}
