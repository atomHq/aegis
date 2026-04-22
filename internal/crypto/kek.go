package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKEK derives a tenant-specific Key Encryption Key from the master key.
//
// Uses HKDF-SHA256 with:
//   - Master key as input key material
//   - Tenant ID as salt (ensures per-tenant isolation)
//   - "aegis-kek" as info string
//
// Returns a 32-byte KEK suitable for AES-256-GCM.
func DeriveKEK(masterKey []byte, tenantID string) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}

	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID must not be empty")
	}

	salt := []byte(tenantID)
	info := []byte("aegis-kek")

	hkdfReader := hkdf.New(sha256.New, masterKey, salt, info)

	kek := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, kek); err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	return kek, nil
}
