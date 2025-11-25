// Package middleware adds additional functionality of log, authentication around request-response cycle
package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/harshitrajsinha/rest-weather-go/internal/auth"
	"github.com/harshitrajsinha/rest-weather-go/internal/database"
	"github.com/harshitrajsinha/rest-weather-go/internal/response"
)

type userContextKey string

const (
	// UserGoogleID is a context key variable
	UserGoogleID userContextKey = "usergoogleid"
	// UserEmailID is a context key variable
	UserEmailID userContextKey = "useremailid"
)

// AuthMiddleware adds authentication middleware to verify protected requests
func AuthMiddleware(next http.HandlerFunc, secretAuthKey string, dbClient *database.DBClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get token from authorization header
		authToken := strings.TrimSpace(r.Header.Get("Authorization"))
		if authToken == "" {
			log.Println("missing authorization header in request")
			errorDetails := map[string]string{
				"expected": "Bearer {jwt_token}",
				"received": "none",
			}
			response.SendErrorResponseToClient(w, response.StatusUnauthorizedCode, errorDetails)
			return
		}

		authToken = strings.TrimPrefix(authToken, "Bearer ")
		if authToken == "" {
			log.Println("invalid bearer token for authorization")
			errorDetails := map[string]string{
				"expected": "Bearer {JWT_token}",
				"received": "Bearer",
			}
			if err := response.SendErrorResponseToClient(w, response.StatusAuthTokenInvalidCode, errorDetails); err != nil {
				log.Println(err)
			}
			return
		}

		// validate JWT string
		isValidJWTStr := auth.ValidateJWTString(authToken)
		if !isValidJWTStr {
			log.Println("not a valid JWT string")
			errorDetails := map[string]string{
				"expected": "Bearer {JWT_token}",
				"received": "Invalid JWT string",
			}
			if err := response.SendErrorResponseToClient(w, response.StatusAuthTokenInvalidCode, errorDetails); err != nil {
				log.Println(err)
			}
			return
		}

		// verify token
		userData, err := auth.VerifyJWTAuthToken(authToken, secretAuthKey, dbClient)
		if err != nil {
			if strings.Contains(err.Error(), "token expired") {
				log.Println("authorization token has expired")
				errorDetails := map[string]string{
					"expected": "Valid Bearer token",
					"received": "expired",
				}
				if err := response.SendErrorResponseToClient(w, response.StatusAuthTokenInvalidCode, errorDetails); err != nil {
					log.Println(err)
				}
				return
			}

			log.Println("error while verifying auth token, ", err)
			errorDetails := map[string]string{}
			if err := response.SendErrorResponseToClient(w, response.StatusInternalServerErrorCode, errorDetails); err != nil {
				log.Println(err)
			}
			return
		}

		// store user data in request context
		ctx := context.WithValue(r.Context(), UserGoogleID, userData.GoogleUserID)
		ctx = context.WithValue(ctx, UserEmailID, userData.Email)
		r = r.WithContext(ctx)

		log.Println("successfully authenticated")
		next.ServeHTTP(w, r)

	}
}
