package envparse

import (
	"fmt"
	"strings"
)

// Parse parses raw .env file content into key-value pairs.
// It handles comments (#), empty lines, quoted values, and inline comments.
func Parse(content string) (map[string]string, error) {
	result := make(map[string]string)
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Find the first '=' to split key and value
		idx := strings.Index(line, "=")
		if idx < 0 {
			return nil, fmt.Errorf("line %d: invalid format (missing '='): %s", i+1, line)
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", i+1)
		}

		// Remove surrounding quotes (single or double)
		value = unquote(value)

		result[key] = value
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no key-value pairs found in env content")
	}

	return result, nil
}

// unquote removes surrounding single or double quotes from a value,
// and strips inline comments for unquoted values.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}

	// For unquoted values, strip inline comments (space + #)
	if idx := strings.Index(s, " #"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}

	return s
}
