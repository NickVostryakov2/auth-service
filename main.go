package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshToken struct {
	ID        int
	UserID    string
	TokenHash string
	UserAgent string
	ClientIP  string
	ExpiresAt int64
	Used      bool
}

type Config struct {
	DBConn     string
	Port       string
	JWTSecret  string
	WebhookURL string
}

func main() {
	// Load config from .env manually
	config := Config{
		DBConn:     "postgres://user:password@postgres:5432/authdb?sslmode=disable",
		Port:       "8080",
		JWTSecret:  "my-secret-key",
		WebhookURL: "http://example.com/webhook",
	}

	// Connect to database
	db, err := sql.Open("postgres", config.DBConn)
	if err != nil {
		log.Fatal("Cannot connect to DB:", err)
	}
	defer db.Close()

	// Set up router
	router := mux.NewRouter()
	router.HandleFunc("/auth/login", loginHandler(db, config)).Methods("POST")
	router.HandleFunc("/auth/refresh", refreshHandler(db, config)).Methods("POST")
	router.HandleFunc("/auth/user", getUserHandler(db, config)).Methods("GET")
	router.HandleFunc("/auth/logout", logoutHandler(db, config)).Methods("POST")

	// Start server
	log.Println("Starting server on :", config.Port)
	http.ListenAndServe(":"+config.Port, router)
}

func loginHandler(db *sql.DB, config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			http.Error(w, "Need user_id", 400)
			return
		}

		// Generate tokens
		accessToken, _ := generateAccessToken(userID, config.JWTSecret)
		refreshToken := generateRandomString(32)
		refreshTokenBase64 := base64.StdEncoding.EncodeToString([]byte(refreshToken))
		hash, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

		// Save refresh token to DB
		_, err := db.Exec(
			"INSERT INTO refresh_tokens (user_id, token_hash, user_agent, client_ip, expires_at) VALUES ($1, $2, $3, $4, $5)",
			userID, string(hash), r.UserAgent(), r.RemoteAddr, time.Now().Add(7*24*time.Hour).Unix(),
		)
		if err != nil {
			http.Error(w, "DB error", 500)
			return
		}

		// Send response
		response := TokenPair{AccessToken: accessToken, RefreshToken: refreshTokenBase64}
		json.NewEncoder(w).Encode(response)
	}
}

func refreshHandler(db *sql.DB, config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		// Parse access token
		token, err := jwt.Parse(input.AccessToken, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid access token", 401)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", 401)
			return
		}
		userID := claims["sub"].(string)

		// Decode refresh token
		refreshTokenBytes, err := base64.StdEncoding.DecodeString(input.RefreshToken)
		if err != nil {
			http.Error(w, "Invalid refresh token", 401)
			return
		}

		// Check refresh token in DB
		var tokenData RefreshToken
		err = db.QueryRow(
			"SELECT id, user_id, token_hash, user_agent, client_ip, expires_at, used FROM refresh_tokens WHERE user_id = $1",
			userID,
		).Scan(&tokenData.ID, &tokenData.UserID, &tokenData.TokenHash, &tokenData.UserAgent, &tokenData.ClientIP, &tokenData.ExpiresAt, &tokenData.Used)
		if err != nil || tokenData.Used || tokenData.ExpiresAt < time.Now().Unix() {
			http.Error(w, "Invalid or expired refresh token", 401)
			return
		}

		// Verify refresh token
		if err := bcrypt.CompareHashAndPassword([]byte(tokenData.TokenHash), refreshTokenBytes); err != nil {
			db.Exec("UPDATE refresh_tokens SET used = TRUE WHERE user_id = $1", userID)
			http.Error(w, "Invalid refresh token", 401)
			return
		}

		// Check User-Agent
		if tokenData.UserAgent != r.UserAgent() {
			db.Exec("UPDATE refresh_tokens SET used = TRUE WHERE user_id = $1", userID)
			http.Error(w, "User-Agent mismatch", 401)
			return
		}

		// Check IP and send webhook if changed
		if tokenData.ClientIP != r.RemoteAddr {
			go func() {
				payload := map[string]string{"user_id": userID, "client_ip": r.RemoteAddr}
				data, _ := json.Marshal(payload)
				http.Post(config.WebhookURL, "application/json", bytes.NewBuffer(data))
			}()
		}

		// Mark old token as used
		db.Exec("UPDATE refresh_tokens SET used = TRUE WHERE id = $1", tokenData.ID)

		// Generate new tokens
		newAccessToken, _ := generateAccessToken(userID, config.JWTSecret)
		newRefreshToken := generateRandomString(32)
		newRefreshTokenBase64 := base64.StdEncoding.EncodeToString([]byte(newRefreshToken))
		newHash, _ := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)

		// Save new refresh token
		db.Exec(
			"INSERT INTO refresh_tokens (user_id, token_hash, user_agent, client_ip, expires_at) VALUES ($1, $2, $3, $4, $5)",
			userID, string(newHash), r.UserAgent(), r.RemoteAddr, time.Now().Add(7*24*time.Hour).Unix(),
		)

		// Send response
		response := TokenPair{AccessToken: newAccessToken, RefreshToken: newRefreshTokenBase64}
		json.NewEncoder(w).Encode(response)
	}
}

func getUserHandler(db *sql.DB, config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "No token", 401)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", 401)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", 401)
			return
		}
		userID := claims["sub"].(string)

		// Check if user is authorized
		var count int
		db.QueryRow("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND used = FALSE AND expires_at > $2", userID, time.Now().Unix()).Scan(&count)
		if count == 0 {
			http.Error(w, "User not authorized", 401)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"user_id": userID})
	}
}

func logoutHandler(db *sql.DB, config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "No token", 401)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", 401)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", 401)
			return
		}
		userID := claims["sub"].(string)

		// Mark all tokens as used
		db.Exec("UPDATE refresh_tokens SET used = TRUE WHERE user_id = $1", userID)
		w.WriteHeader(200)
	}
}

func generateAccessToken(userID, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}
