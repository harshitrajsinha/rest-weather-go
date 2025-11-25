// Package models defines structures used across the application
package models

// AuthToken defines the structure of access and refresh token
type AuthToken struct {
	AccessToken  string
	RefreshToken string
}

// TokenPayload defines structure of payload that will be returned for authenticated user
type TokenPayload struct {
	GoogleUserID string
	Email        string
}
