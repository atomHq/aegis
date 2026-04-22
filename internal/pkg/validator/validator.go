package validator

import (
	"fmt"
	"regexp"

	"github.com/go-playground/validator/v10"
)

var (
	validate   *validator.Validate
	slugRegex  = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	keyRegex   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func init() {
	validate = validator.New()
}

// ValidateStruct validates a struct using go-playground/validator tags.
func ValidateStruct(s interface{}) error {
	return validate.Struct(s)
}

// ValidateSecretKey checks that a secret key matches the allowed pattern.
func ValidateSecretKey(key string) error {
	if len(key) == 0 || len(key) > 255 {
		return fmt.Errorf("secret key must be 1-255 characters")
	}
	if !keyRegex.MatchString(key) {
		return fmt.Errorf("secret key must match pattern: ^[A-Za-z_][A-Za-z0-9_]*$")
	}
	return nil
}

// ValidateSecretValue checks that a secret value doesn't exceed max size.
func ValidateSecretValue(value string) error {
	if len(value) == 0 {
		return fmt.Errorf("secret value must not be empty")
	}
	if len(value) > 65536 { // 64KB
		return fmt.Errorf("secret value must not exceed 64KB")
	}
	return nil
}

// ValidateSlug checks that a slug matches the allowed pattern.
func ValidateSlug(slug string) error {
	if len(slug) < 2 || len(slug) > 100 {
		return fmt.Errorf("slug must be 2-100 characters")
	}
	if !slugRegex.MatchString(slug) {
		return fmt.Errorf("slug must contain only lowercase letters, numbers, and hyphens")
	}
	return nil
}
