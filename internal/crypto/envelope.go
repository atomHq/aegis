package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptedPayload holds the result of envelope encryption.
type EncryptedPayload struct {
	EncryptedValue []byte // Secret value encrypted with DEK
	Nonce          []byte // GCM nonce for value encryption
	EncryptedDEK   []byte // DEK encrypted with KEK
	DEKNonce       []byte // GCM nonce for DEK encryption
}

// Encrypt performs envelope encryption on plaintext using the provided KEK.
//
// Flow:
//  1. Generate random 256-bit DEK
//  2. Encrypt plaintext with DEK using AES-256-GCM
//  3. Encrypt DEK with KEK using AES-256-GCM
//  4. Return all encrypted materials
func Encrypt(plaintext []byte, kek []byte) (*EncryptedPayload, error) {
	// Generate random Data Encryption Key (256-bit)
	dek, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt the plaintext with the DEK
	encryptedValue, nonce, err := encryptAESGCM(plaintext, dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt value with DEK: %w", err)
	}

	// Encrypt the DEK with the KEK
	encryptedDEK, dekNonce, err := encryptAESGCM(dek, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with KEK: %w", err)
	}

	// Zero out the plaintext DEK from memory
	for i := range dek {
		dek[i] = 0
	}

	return &EncryptedPayload{
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
		EncryptedDEK:   encryptedDEK,
		DEKNonce:       dekNonce,
	}, nil
}

// Decrypt performs envelope decryption to recover the original plaintext.
//
// Flow:
//  1. Decrypt the DEK using the KEK
//  2. Decrypt the value using the recovered DEK
//  3. Return plaintext
func Decrypt(payload *EncryptedPayload, kek []byte) ([]byte, error) {
	// Decrypt the DEK with the KEK
	dek, err := decryptAESGCM(payload.EncryptedDEK, payload.DEKNonce, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with KEK: %w", err)
	}

	// Decrypt the value with the recovered DEK
	plaintext, err := decryptAESGCM(payload.EncryptedValue, payload.Nonce, dek)
	if err != nil {
		// Zero out DEK before returning
		for i := range dek {
			dek[i] = 0
		}
		return nil, fmt.Errorf("failed to decrypt value with DEK: %w", err)
	}

	// Zero out the DEK from memory
	for i := range dek {
		dek[i] = 0
	}

	return plaintext, nil
}

// encryptAESGCM encrypts plaintext with key using AES-256-GCM.
// Returns the ciphertext and the randomly generated nonce.
func encryptAESGCM(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce = make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext = aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// decryptAESGCM decrypts ciphertext with key and nonce using AES-256-GCM.
func decryptAESGCM(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
