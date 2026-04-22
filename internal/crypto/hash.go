package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	// APIKeyPrefix is the standard prefix for all Aegis API keys.
	APIKeyPrefix = "aegis_sk_live_"
	// APIKeyRandomBytes is the number of random bytes in an API key.
	APIKeyRandomBytes = 32
	// KeyPrefixLength is the number of characters stored as the key prefix for identification.
	KeyPrefixLength = 12
)

// GenerateAPIKey creates a new API key with the format: aegis_sk_live_<64 hex chars>
// Returns the plaintext key (shown once), its SHA-256 hash (stored), and a prefix (for identification).
func GenerateAPIKey() (plaintext, hash, prefix string, err error) {
	randomBytes, err := GenerateRandomBytes(APIKeyRandomBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate random bytes for API key: %w", err)
	}

	plaintext = APIKeyPrefix + hex.EncodeToString(randomBytes)
	hash = HashAPIKey(plaintext)
	prefix = plaintext[:KeyPrefixLength]

	return plaintext, hash, prefix, nil
}

// HashAPIKey computes the SHA-256 hash of an API key for storage.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// GenerateRandomBytes returns n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}
	return b, nil
}
