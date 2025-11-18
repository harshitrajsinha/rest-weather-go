// Package models defines structures and functions that are used across the application
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/harshitrajsinha/rest-weather-go/internal/database"
)

// AuthToken defines the structure of access and refresh token
type AuthToken struct {
	AccessToken  string
	RefreshToken string
}

// CustomClaims defines structure of JWT payload
type CustomClaims struct {
	GoogleUserID string `json:"google_user_id"`
	Email        string `json:"email"`
	jwt.RegisteredClaims
}

// CreateJWTAuthToken creates short-lived access token and long-lived refresh token
func CreateJWTAuthToken(googleUserID string, email string, secretAuthKey string, dbClient *database.DBClient) (AuthToken, error) {

	var authToken AuthToken
	now := time.Now().UTC()

	// access token
	accessTokenclaims := &CustomClaims{
		GoogleUserID: googleUserID,
		Email:        email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute).UTC()),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   googleUserID,
			Issuer:    "weather-go",
		},
	}

	atoken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenclaims)
	accessToken, err := atoken.SignedString([]byte(secretAuthKey))
	if err != nil {
		return authToken, fmt.Errorf("error generating access token, %w", err)
	}

	// refresh token
	refreshTokenclaims := &CustomClaims{
		GoogleUserID: googleUserID,
		Email:        email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour).UTC()),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   googleUserID,
			Issuer:    "weather-go",
		},
	}

	rToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenclaims)
	refreshToken, err := rToken.SignedString(([]byte(secretAuthKey)))
	if err != nil {
		return authToken, fmt.Errorf("error generating access token, %w", err)
	}

	// store refresh token in database (hashing for security)
	hashedRefreshToken := hashRefreshToken(refreshToken)
	err = dbClient.StoreRefreshToken(hashedRefreshToken, googleUserID, email)
	if err != nil {
		return authToken, err
	}

	authToken.AccessToken = accessToken
	authToken.RefreshToken = refreshToken

	return authToken, nil

}

// VerifyJWTAuthToken parse and verify the token from API request
func VerifyJWTAuthToken(token string, secretAuthKey string) error {

	var parsedClaims CustomClaims
	parsedToken, err := jwt.ParseWithClaims(token, &parsedClaims, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method, %v", token.Header["alg"])
		}
		return []byte(secretAuthKey), nil
	})

	if err != nil {
		return err
	}

	if !parsedToken.Valid {
		return errors.New("invalid token")
	}

	return nil
}

func hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
