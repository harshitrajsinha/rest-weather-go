// Package models defines structures and functions that are used across the application
package models

import (
	"encoding/base64"
	"strings"
)

// ValidateJWTString validates if given string/token is of JWT form
func ValidateJWTString(token string) bool {

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	for _, p := range parts {
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			return false
		}
	}

	return true
}
