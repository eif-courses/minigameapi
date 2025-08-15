package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/eif-courses/minigameapi/internal/auth"
	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"
	"go.uber.org/zap"
)

type AuthHandler struct {
	authService  *auth.AuthService
	sessionStore sessions.Store
	log          *zap.SugaredLogger
}

func NewAuthHandler(authService *auth.AuthService, sessionStore sessions.Store, log *zap.SugaredLogger) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		sessionStore: sessionStore,
		log:          log,
	}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// Local authentication endpoints
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	deviceInfo := r.UserAgent()
	ipAddress := getClientIP(r)

	authResponse, err := h.authService.LoginWithPassword(r.Context(), req.Email, req.Password, deviceInfo, ipAddress)
	if err != nil {
		h.log.Errorw("Login failed", "error", err, "email", req.Email)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session cookie
	h.setSessionCookie(w, authResponse.SessionToken)

	// Return response with JWT token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":         authResponse.User,
		"access_token": authResponse.AccessToken,
		"message":      "Login successful",
	})
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.authService.RegisterUser(r.Context(), req.Email, req.Password, req.FirstName, req.LastName, "user")
	if err != nil {
		h.log.Errorw("Registration failed", "error", err, "email", req.Email)
		http.Error(w, "Registration failed", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":    user,
		"message": "Registration successful",
	})
}

// OAuth endpoints
func (h *AuthHandler) BeginOAuth(w http.ResponseWriter, r *http.Request) {
	h.log.Infow("Starting OAuth flow", "provider", r.URL.Query().Get("provider"), "url", r.URL.String())

	// Add some debugging
	session, err := h.sessionStore.Get(r, gothic.SessionName)
	if err != nil {
		h.log.Errorw("Failed to get session for OAuth", "error", err)
	} else {
		h.log.Infow("Session info", "session_id", session.ID, "is_new", session.IsNew)
	}

	gothic.BeginAuthHandler(w, r)
}

func (h *AuthHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	h.log.Infow("OAuth callback received", "url", r.URL.String(), "state", r.URL.Query().Get("state"))

	// Debug session information
	session, err := h.sessionStore.Get(r, gothic.SessionName)
	if err != nil {
		h.log.Errorw("Failed to get session in callback", "error", err)
	} else {
		h.log.Infow("Callback session info", "session_id", session.ID, "is_new", session.IsNew, "values", len(session.Values))
	}

	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		h.log.Errorw("OAuth callback failed", "error", err, "url", r.URL.String())

		// Try to provide more helpful error message
		if strings.Contains(err.Error(), "could not find a matching session") {
			http.Error(w, "OAuth session expired or invalid. Please try again.", http.StatusBadRequest)
			return
		}

		http.Error(w, "OAuth authentication failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.log.Infow("OAuth user authenticated", "provider", gothUser.Provider, "user_id", gothUser.UserID, "email", gothUser.Email)

	deviceInfo := r.UserAgent()
	ipAddress := getClientIP(r)

	authResponse, err := h.authService.HandleOAuthCallback(r.Context(), gothUser, deviceInfo, ipAddress)
	if err != nil {
		h.log.Errorw("OAuth user creation failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	h.setSessionCookie(w, authResponse.SessionToken)

	// Check if request wants JSON response (API) or redirect (web)
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":         authResponse.User,
			"access_token": authResponse.AccessToken,
			"message":      "OAuth login successful",
		})
	} else {
		// For web browser, return success page or redirect
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":         authResponse.User,
			"access_token": authResponse.AccessToken,
			"message":      "OAuth login successful! You can close this window.",
		})
	}
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionToken := h.getSessionToken(r)
	if sessionToken != "" {
		h.authService.Logout(r.Context(), sessionToken)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Logout successful",
	})
}

func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": user,
	})
}

// Helper methods
func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, sessionToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *AuthHandler) getSessionToken(r *http.Request) string {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return ip
}
