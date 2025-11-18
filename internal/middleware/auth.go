// Package middleware adds additional functionality of log, authentication around request-response cycle
package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/harshitrajsinha/rest-weather-go/internal/models"
)

// AuthMiddleware adds authentication middlware to verify protected requests
func AuthMiddleware(next http.Handler, secretAuthKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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

		// verify token
		if err := models.VerifyJWTAuthToken(authToken, secretAuthKey); err != nil {
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

		log.Println("successfully authenticated")
		next.ServeHTTP(w, r)

	})
}
