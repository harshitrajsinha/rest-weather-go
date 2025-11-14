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
	"time"

	"github.com/harshitrajsinha/rest-weather-go/internal/database"
	"github.com/harshitrajsinha/rest-weather-go/internal/models"
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

// LoginClient encapsulates all dependencies and configuration required
// for handling Google OAuth login and callback flows.
type LoginClient struct {
	dbClient           *database.DBClient
	googleClientID     string
	googleClientSecret string
	secretAuthKey      string
	googleOauthConfig  *oauth2.Config
}

// NewLoginHandler is the constructor used for depenedency injection to login handler
func NewLoginHandler(dbClient *database.DBClient, googleClientID string, googleClientSecret string, secretAuthKey string) *LoginClient {

	googleOauthConfig := &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		Scopes:       []string{scopeEmail, scopeProfile},
		Endpoint:     google.Endpoint,
	}

	return &LoginClient{
		dbClient:           dbClient,
		googleClientID:     googleClientID,
		googleClientSecret: googleClientSecret,
		secretAuthKey:      secretAuthKey,
		googleOauthConfig:  googleOauthConfig,
	}
}

// ///////////// for browser client
// func handleLogin(w http.ResponseWriter, _ *http.Request) {
// 	html := `
// 	<html>
// 	<head>
// 		<title>Google OAuth</title>
// 	</head>
// 	<body>
// 		<div style="display: flex;flex-direction: column;align-items: center;">
// 			<h1>Welcome to the REST Weather Go</h1>
// 			<a href="/auth/google/login" style="background-color: #008cff;color: white;padding: 10px;border-radius: 10px;text-decoration: none;">Sign in with Google</a>
// 		</div>
// 	</body>
// 	</html>
// 	`
// 	w.Header().Set("Content-Type", "text/html")
// 	w.WriteHeader(http.StatusOK)
// 	w.Write([]byte(html))
// }

// HandleGoogleLogin implements the business logic for Google Oauth
func (l LoginClient) HandleGoogleLogin(w http.ResponseWriter, _ *http.Request) {

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
func (l LoginClient) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {

	receivedState := r.FormValue("state")
	// stateCookie, err := r.Cookie("oauthstate")  // for browser client

	if secureState != receivedState {
		http.Error(w, "Invalid OAuth state or missing cookie. Possible CSRF attack.", http.StatusUnauthorized)
		return
	}

	///////////////////////////////////// for browser client
	// http.SetCookie(w, &http.Cookie{
	// 	Name:    "oauthstate",
	// 	Value:   "",
	// 	Expires: time.Now().Add(-time.Hour), // Expire immediately
	// 	Path:    "/",
	// })

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
		// displayError(w)   /////////// for browser client
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "something went wrong",
		})
		return
	}

	// generate jwt auth token for authorization
	authTokenSet, err := models.CreateJWTAuthToken(userInfo.ID, userInfo.Email, l.secretAuthKey, l.dbClient)
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

	// displaySuccess(w, authTokenSet)  /////////// for browser client
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

	////////////////////////////////////////for browser client
	// http.SetCookie(w, &http.Cookie{
	// 	Name:     "oauthstate",
	// 	Value:    state,
	// 	Expires:  time.Now().Add(10 * time.Minute),
	// 	HttpOnly: true,
	// 	Secure:   false, // true in production
	// 	Path:     "/",
	// 	SameSite: http.SameSiteLaxMode,
	// })

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

// ///////////// for browser client
// func displaySuccess(w http.ResponseWriter, authTokenSet models.AuthToken) {
// 	html := fmt.Sprintf(`
// 		<html>
// 		<head>
// 			<title>Login Successful</title>
// 		</head>
// 		<body style="background-color:#444444;">
// 			<div style="display: flex;flex-direction: column;align-items: center;">
// 				<h2 style="color:#007acc;">Login Successful!!</h2>
// 				<p style="color:#28a745;">You have successfully authenticated. You can now close this tab and make the authorized API requests</p>
// 				<div style="padding:4rem">
// 					<p style="word-break: break-all;white-space: normal;font-family: monospace; ">Access Token: %s</p>
// 					<p style="word-break: break-all;white-space: normal;font-family: monospace; ">Refresh Token: %s</p>
// 				</div>
// 			</div>
// 		</body>
// 		<script>
// 		</script>
// 		</html>
// 	`, authTokenSet.AccessToken, authTokenSet.RefreshToken)
// 	w.Header().Set("Content-Type", "text/html")
// 	w.WriteHeader(http.StatusOK)
// 	w.Write([]byte(html))
// }

// ///////////// for browser client
// func displayError(w http.ResponseWriter) {
// 	html := fmt.Sprintln(`
// 		<html>
// 		<head>
// 			<title>Login Failed</title>
// 		</head>
// 		<body style="background-color:#d4d4d4;">
// 			<div style="display: flex;flex-direction: column;align-items: center;">
// 				<h2 style="color:#007acc;">Login Failed!!</h2>
// 				<p style="color:#ff0023;">You are not allowed to make API requests</p>
// 			</div>
// 		</body>
// 		</html>
// 	`)
// 	w.Header().Set("Content-Type", "text/html")
// 	w.WriteHeader(http.StatusOK)
// 	w.Write([]byte(html))
// }
