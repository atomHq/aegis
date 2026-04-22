package crypto

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	// bcryptCost is the work factor for bcrypt hashing.
	// Cost 12 is ~250ms on modern hardware — good balance of security vs latency.
	bcryptCost = 12
)

// HashPassword creates a bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 72 {
		// bcrypt silently truncates at 72 bytes — reject explicitly
		return "", fmt.Errorf("password must be at most 72 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword compares a plaintext password against a bcrypt hash.
// Returns nil on success, error on mismatch.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
