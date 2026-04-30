package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oluwasemilore/aegis/internal/crypto"
	"github.com/oluwasemilore/aegis/internal/domain"
)

// SecretService handles secret business logic with encryption.
type SecretService struct {
	secretRepo domain.SecretRepository
	tenantRepo domain.TenantRepository
	masterKey  []byte
}

// NewSecretService creates a new secret service.
func NewSecretService(secretRepo domain.SecretRepository, tenantRepo domain.TenantRepository, masterKey []byte) *SecretService {
	return &SecretService{secretRepo: secretRepo, tenantRepo: tenantRepo, masterKey: masterKey}
}

// DecryptedSecret is a secret with its plaintext value (for API responses).
type DecryptedSecret struct {
	ID        uuid.UUID              `json:"id"`
	Key       string                 `json:"key"`
	Value     string                 `json:"value"`
	Version   int                    `json:"version"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	Tags      map[string]interface{} `json:"tags,omitempty"`
	CreatedBy string                 `json:"created_by,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// Put creates or updates a secret (creates a new version).
func (s *SecretService) Put(ctx context.Context, tenantID, projectID uuid.UUID, input *domain.PutSecretInput, actor string) (*DecryptedSecret, error) {
	// Check tenant secret limit
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil || tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	count, err := s.secretRepo.CountByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to count secrets: %w", err)
	}

	// Check if this is a new key or update to existing
	existing, _ := s.secretRepo.GetLatest(ctx, tenantID, projectID, input.Key)
	if existing == nil && count >= tenant.MaxSecrets {
		return nil, fmt.Errorf("secret limit (%d) reached for plan '%s'", tenant.MaxSecrets, tenant.Plan)
	}

	// Derive tenant-specific KEK
	kek, err := crypto.DeriveKEK(s.masterKey, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}
	defer zeroBytes(kek)

	// Encrypt the secret value with envelope encryption
	payload, err := crypto.Encrypt([]byte(input.Value), kek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	secret := &domain.Secret{
		TenantID:       tenantID,
		ProjectID:      projectID,
		Key:            input.Key,
		EncryptedValue: payload.EncryptedValue,
		EncryptedDEK:   payload.EncryptedDEK,
		Nonce:          payload.Nonce,
		DEKNonce:       payload.DEKNonce,
		IsActive:       true,
		ExpiresAt:      input.ExpiresAt,
		Tags:           input.Tags,
		CreatedBy:      actor,
		UpdatedBy:      actor,
	}

	if err := s.secretRepo.Upsert(ctx, secret); err != nil {
		return nil, fmt.Errorf("failed to store secret: %w", err)
	}

	return &DecryptedSecret{
		ID: secret.ID, Key: secret.Key, Value: input.Value,
		Version: secret.Version, ExpiresAt: secret.ExpiresAt,
		Tags: secret.Tags, CreatedBy: secret.CreatedBy, CreatedAt: secret.CreatedAt,
	}, nil
}

// BulkPut creates or updates multiple secrets atomically.
func (s *SecretService) BulkPut(ctx context.Context, tenantID, projectID uuid.UUID, input *domain.BulkPutSecretsInput, actor string) ([]*DecryptedSecret, error) {
	// Check tenant secret limit
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil || tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	count, err := s.secretRepo.CountByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to count secrets: %w", err)
	}

	uniqueKeysMap := make(map[string]domain.PutSecretInput)
	for _, sec := range input.Secrets {
		uniqueKeysMap[sec.Key] = sec
	}

	keysToFetch := make([]string, 0, len(uniqueKeysMap))
	for k := range uniqueKeysMap {
		keysToFetch = append(keysToFetch, k)
	}

	existingSecrets, err := s.secretRepo.GetBulk(ctx, tenantID, projectID, keysToFetch)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing secrets: %w", err)
	}

	existingKeysMap := make(map[string]bool)
	for _, es := range existingSecrets {
		existingKeysMap[es.Key] = true
	}

	newKeysCount := 0
	for k := range uniqueKeysMap {
		if !existingKeysMap[k] {
			newKeysCount++
		}
	}

	if count+newKeysCount > tenant.MaxSecrets {
		return nil, fmt.Errorf("secret limit (%d) reached for plan '%s' (would exceed by %d)", tenant.MaxSecrets, tenant.Plan, count+newKeysCount-tenant.MaxSecrets)
	}

	// Derive tenant-specific KEK
	kek, err := crypto.DeriveKEK(s.masterKey, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}
	defer zeroBytes(kek)

	var secretsToInsert []*domain.Secret
	var result []*DecryptedSecret

	for _, secInput := range input.Secrets {
		payload, err := crypto.Encrypt([]byte(secInput.Value), kek)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt secret '%s': %w", secInput.Key, err)
		}

		secret := &domain.Secret{
			TenantID:       tenantID,
			ProjectID:      projectID,
			Key:            secInput.Key,
			EncryptedValue: payload.EncryptedValue,
			EncryptedDEK:   payload.EncryptedDEK,
			Nonce:          payload.Nonce,
			DEKNonce:       payload.DEKNonce,
			IsActive:       true,
			ExpiresAt:      secInput.ExpiresAt,
			Tags:           secInput.Tags,
			CreatedBy:      actor,
			UpdatedBy:      actor,
		}
		secretsToInsert = append(secretsToInsert, secret)
	}

	if err := s.secretRepo.BulkUpsert(ctx, secretsToInsert); err != nil {
		return nil, fmt.Errorf("failed to bulk store secrets: %w", err)
	}

	for i, secret := range secretsToInsert {
		result = append(result, &DecryptedSecret{
			ID: secret.ID, Key: secret.Key, Value: input.Secrets[i].Value,
			Version: secret.Version, ExpiresAt: secret.ExpiresAt,
			Tags: secret.Tags, CreatedBy: secret.CreatedBy, CreatedAt: secret.CreatedAt,
		})
	}

	return result, nil
}

// Get retrieves and decrypts the latest version of a secret.
func (s *SecretService) Get(ctx context.Context, tenantID, projectID uuid.UUID, key string) (*DecryptedSecret, error) {
	secret, err := s.secretRepo.GetLatest(ctx, tenantID, projectID, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	if secret == nil {
		return nil, nil
	}

	// Check expiry
	if secret.ExpiresAt != nil && secret.ExpiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("secret '%s' has expired", key)
	}

	return s.decryptSecret(secret, tenantID)
}

// GetVersion retrieves a specific version of a secret.
func (s *SecretService) GetVersion(ctx context.Context, tenantID, projectID uuid.UUID, key string, version int) (*DecryptedSecret, error) {
	secret, err := s.secretRepo.GetVersion(ctx, tenantID, projectID, key, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret version: %w", err)
	}
	if secret == nil {
		return nil, nil
	}
	return s.decryptSecret(secret, tenantID)
}

// ListVersions lists all versions of a secret (metadata only, no values).
func (s *SecretService) ListVersions(ctx context.Context, tenantID, projectID uuid.UUID, key string) ([]*domain.Secret, error) {
	return s.secretRepo.ListVersions(ctx, tenantID, projectID, key)
}

// ListKeys lists secret keys (no values).
func (s *SecretService) ListKeys(ctx context.Context, tenantID, projectID uuid.UUID, limit int, cursor *time.Time) ([]*domain.SecretKeyItem, error) {
	return s.secretRepo.ListKeys(ctx, tenantID, projectID, limit, cursor)
}

// BulkGet retrieves and decrypts multiple secrets.
func (s *SecretService) BulkGet(ctx context.Context, tenantID, projectID uuid.UUID, keys []string) (map[string]string, error) {
	secrets, err := s.secretRepo.GetBulk(ctx, tenantID, projectID, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk get secrets: %w", err)
	}

	kek, err := crypto.DeriveKEK(s.masterKey, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}
	defer zeroBytes(kek)

	result := make(map[string]string)
	for _, secret := range secrets {
		if secret.ExpiresAt != nil && secret.ExpiresAt.Before(time.Now().UTC()) {
			continue // Skip expired
		}
		payload := &crypto.EncryptedPayload{
			EncryptedValue: secret.EncryptedValue, Nonce: secret.Nonce,
			EncryptedDEK: secret.EncryptedDEK, DEKNonce: secret.DEKNonce,
		}
		plaintext, err := crypto.Decrypt(payload, kek)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret '%s': %w", secret.Key, err)
		}
		result[secret.Key] = string(plaintext)
	}

	return result, nil
}

// Delete soft-deletes all versions of a secret.
func (s *SecretService) Delete(ctx context.Context, tenantID, projectID uuid.UUID, key string) error {
	return s.secretRepo.SoftDelete(ctx, tenantID, projectID, key)
}

func (s *SecretService) decryptSecret(secret *domain.Secret, tenantID uuid.UUID) (*DecryptedSecret, error) {
	kek, err := crypto.DeriveKEK(s.masterKey, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}
	defer zeroBytes(kek)

	payload := &crypto.EncryptedPayload{
		EncryptedValue: secret.EncryptedValue, Nonce: secret.Nonce,
		EncryptedDEK: secret.EncryptedDEK, DEKNonce: secret.DEKNonce,
	}

	plaintext, err := crypto.Decrypt(payload, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return &DecryptedSecret{
		ID: secret.ID, Key: secret.Key, Value: string(plaintext),
		Version: secret.Version, ExpiresAt: secret.ExpiresAt,
		Tags: secret.Tags, CreatedBy: secret.CreatedBy, CreatedAt: secret.CreatedAt,
	}, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
