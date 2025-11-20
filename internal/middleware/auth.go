// Package middleware adds additional functionality of log, authentication around request-response cycle
package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/harshitrajsinha/rest-weather-go/internal/database"
	"github.com/harshitrajsinha/rest-weather-go/internal/models"
)

type userContextKey string

// UserGoogleID is context key for GoogleID value
var UserGoogleID userContextKey = "usergoogleid"

// UserEmailID is context key for EmailID value
var UserEmailID userContextKey = "useremailid"

// AuthMiddleware adds authentication middlware to verify protected requests
func AuthMiddleware(next http.HandlerFunc, secretAuthKey string, dbClient *database.DBClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get token from authorization header
		authToken := strings.TrimSpace(r.Header.Get("Authorization"))
		if authToken == "" {
			log.Println("missing authorization header in request")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("missing authorization token"))
			return
		}

		authToken = strings.TrimPrefix(authToken, "Bearer ")
		if authToken == "" {
			log.Println("invalid bearer token for authorization")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("invalid bearer token for authorization"))
			return
		}

		// validate JWT string
		isValidJWTStr := models.ValidateJWTString(authToken)
		if !isValidJWTStr {
			log.Println("not a valid JWT string")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("authorization token is invalid"))
			return
		}

		// verify token
		userData, err := models.VerifyJWTAuthToken(authToken, secretAuthKey, dbClient)
		if err != nil {
			if strings.Contains(err.Error(), "token expired") {
				log.Println("authorization token has expired")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("authorization token has expired"))
				return
			}

			log.Println("error while verifying auth token, ", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("something went wrong"))
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
