// Package handler implements the business logic for API routes
package handler

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/harshitrajsinha/rest-weather-go/internal/auth"
	"github.com/harshitrajsinha/rest-weather-go/internal/database"
	"github.com/harshitrajsinha/rest-weather-go/internal/middleware"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	userInfoURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
	redirectURL  = "http://localhost:8086/auth/google/callback"
	scopeEmail   = "https://www.googleapis.com/auth/userinfo.email"
	scopeProfile = "https://www.googleapis.com/auth/userinfo.profile"
)

var secureState string

// UserInfo struct to hold the data fetched from Google
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type user struct {
	userid    string
	name      string
	updatedAt string
	createdAt string
}

// UserHandler encapsulates all dependencies and configuration required
// for handling user login and logout
type UserHandler struct {
	dbClient          *database.DBClient
	secretAuthKey     string
	googleOauthConfig *oauth2.Config
}

// RefreshTokenPayload defines strucuture of payload that will be parsed on route call to /refresh
type RefreshTokenPayload struct {
	RefreshToken string `json:"refresh_token"`
}

// NewUserHandler is the constructor used for depenedency injection to login handler
func NewUserHandler(dbClient *database.DBClient, googleClientID string, googleClientSecret string, secretAuthKey string) *UserHandler {

	googleOauthConfig := &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		Scopes:       []string{scopeEmail, scopeProfile},
		Endpoint:     google.Endpoint,
	}

	return &UserHandler{
		dbClient:          dbClient,
		secretAuthKey:     secretAuthKey,
		googleOauthConfig: googleOauthConfig,
	}
}

// HandleGoogleLogin implements the business logic for Google Oauth
func (l UserHandler) HandleGoogleLogin(w http.ResponseWriter, _ *http.Request) {

	// Generate a random 'state' value to prevent CSRF attacks.
	var err error
	secureState, err = generateRandomState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		log.Printf("Error generating state: %v", err)
		return
	}

	url := l.googleOauthConfig.AuthCodeURL(secureState)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	//http.Redirect(w, r, url, http.StatusTemporaryRedirect) // for browser
	json.NewEncoder(w).Encode(map[string]string{
		"auth_url": url,
	})
}

// HandleGoogleCallback is called by Google Oauth to exchange code and user info
func (l UserHandler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {

	receivedState := r.FormValue("state")
	// stateCookie, err := r.Cookie("oauthstate")  // for browser client

	if secureState != receivedState {
		http.Error(w, "Invalid OAuth state or missing cookie. Possible CSRF attack.", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not received from Google", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	token, err := l.googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		log.Printf("Token exchange error: %v", err)
		return
	}

	userInfo, err := fetchUserInfo(token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
		log.Printf("User info fetch error: %v", err)
		return
	}

	// validate if signing in user is registered in database
	userData, err := getUserDetails(userInfo.ID, userInfo.Email, l.dbClient)
	if userData.userid == "" || err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "something went wrong",
		})
		return
	}

	// generate jwt auth token for authorization
	authTokenSet, err := auth.CreateJWTAuthToken(userInfo.ID, userInfo.Email, l.secretAuthKey, l.dbClient)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "something went wrong",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]string{
		"access-token":  authTokenSet.AccessToken,
		"refresh-token": authTokenSet.RefreshToken,
	})
}

// HandleUserLogout invokes refresh token from database
func (l UserHandler) HandleUserLogout(w http.ResponseWriter, r *http.Request) {

	userGoogleID := r.Context().Value(middleware.UserGoogleID).(string)
	userEmailID := r.Context().Value(middleware.UserEmailID).(string)

	// revoke refresh token
	err := l.dbClient.RevokeRefreshToken(userGoogleID, userEmailID)
	if err != nil {
		log.Println("could not revoke refresh token to logout user", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message": "could not log out"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "successfully logged out"}`))

}

// HandleRotateTokens rotates access and refresh token
func (l UserHandler) HandleRotateTokens(w http.ResponseWriter, r *http.Request) {

	// validate refresh token
	// if expire -> ask to re-login
	// else retrieve user data and generate new auth tokens

	var payload RefreshTokenPayload

	// get refresh token from payload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Println("error decoding payload to get refresh token", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message": "could not process now"}`))
		return
	}

	isValidJWTStr := auth.ValidateJWTString(payload.RefreshToken)
	if !isValidJWTStr {
		log.Println("not a valid JWT string")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Not a valid JWT string"}`))
		return
	}

	// verify refresh token
	userData, err := auth.VerifyJWTAuthToken(payload.RefreshToken, l.secretAuthKey, l.dbClient)
	if err != nil {
		if strings.Contains(err.Error(), "token expired") {
			log.Println("refresh token has expired")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("You need to re-login"))
			return
		}

		log.Println("error while verifying refresh token, ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("You need to re-login"))
		return
	}

	// check if user has entered its own refresh token
	hashedRefreshToken := auth.HashRefreshToken(payload.RefreshToken)

	// compare with refresh token stored in database
	var storedHashedToken string
	ctxWithTimeout, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	query := "SELECT refresh_token from users where google_id=$1 AND email=$2"
	if err := l.dbClient.QueryRowContext(ctxWithTimeout, query, userData.GoogleUserID, userData.Email).Scan(&storedHashedToken); err != nil {
		log.Println("error while verifying refresh token, ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("You need to re-login"))
		return
	}

	if hashedRefreshToken != storedHashedToken {
		log.Println("hashed refresh token and stored hashed token do not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("You need to re-login"))
		return
	}

	// generate new tokens
	authTokenSet, err := auth.CreateJWTAuthToken(userData.GoogleUserID, userData.Email, l.secretAuthKey, l.dbClient)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "something went wrong",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]string{
		"access-token":  authTokenSet.AccessToken,
		"refresh-token": authTokenSet.RefreshToken,
	})

}

func getUserDetails(googleUserID string, email string, dbClient *database.DBClient) (user, error) {
	var queryData user

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	err := dbClient.QueryRowContext(ctx, "SELECT user_id, name, updated_at, created_at FROM users WHERE google_id=$1 AND email=$2", googleUserID, email).Scan(
		&queryData.userid, &queryData.name, &queryData.updatedAt, &queryData.createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return queryData, errors.New("no data found based on request") // return empty model
		}
		return queryData, err // return empty model
	}

	return queryData, err
}

func generateRandomState() (string, error) {

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := base64.URLEncoding.EncodeToString(b)

	return state, nil
}

func fetchUserInfo(accessToken string) (UserInfo, error) {

	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to create user info request: %w", err)
	}

	// Set the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return UserInfo{}, fmt.Errorf("google user info API returned non-OK status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to read user info response body: %w", err)
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return UserInfo{}, fmt.Errorf("failed to unmarshal user info JSON: %w", err)
	}

	return userInfo, nil
}
