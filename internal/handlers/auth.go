package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
		h.log.Errorw("Invalid login request body", "error", err)
		h.sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		h.sendErrorResponse(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	deviceInfo := r.UserAgent()
	ipAddress := getClientIP(r)

	h.log.Infow("Login attempt", "email", req.Email, "ip", ipAddress)

	authResponse, err := h.authService.LoginWithPassword(r.Context(), req.Email, req.Password, deviceInfo, ipAddress)
	if err != nil {
		h.log.Errorw("Login failed", "error", err, "email", req.Email, "ip", ipAddress)
		h.sendErrorResponse(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session cookie (primary auth for browsers)
	h.setSessionCookie(w, authResponse.SessionToken)

	h.log.Infow("Login successful", "user_id", authResponse.User.ID, "email", req.Email)

	// Determine response based on client type
	if h.isAPIClient(r) {
		// API client - include JWT token
		h.sendSuccessResponse(w, map[string]interface{}{
			"user":         h.sanitizeUser(authResponse.User),
			"access_token": authResponse.AccessToken,
			"message":      "Login successful",
			"auth_method":  "jwt",
		})
	} else {
		// Browser client - cookie-based auth
		h.sendSuccessResponse(w, map[string]interface{}{
			"user":        h.sanitizeUser(authResponse.User),
			"message":     "Login successful",
			"auth_method": "cookie",
		})
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.log.Errorw("Invalid registration request body", "error", err)
		h.sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		h.sendErrorResponse(w, "All fields are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		h.sendErrorResponse(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	h.log.Infow("Registration attempt", "email", req.Email)

	user, err := h.authService.RegisterUser(r.Context(), req.Email, req.Password, req.FirstName, req.LastName, "user")
	if err != nil {
		h.log.Errorw("Registration failed", "error", err, "email", req.Email)

		// Check for duplicate email error
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "already exists") {
			h.sendErrorResponse(w, "Email already registered", http.StatusConflict)
		} else {
			h.sendErrorResponse(w, "Registration failed", http.StatusBadRequest)
		}
		return
	}

	h.log.Infow("Registration successful", "user_id", user.ID, "email", req.Email)

	h.sendSuccessResponse(w, map[string]interface{}{
		"user":    h.sanitizeUser(user),
		"message": "Registration successful. Please login.",
	})
}

// OAuth endpoints
func (h *AuthHandler) BeginOAuth(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		// Extract provider from URL path if not in query
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) >= 2 {
			provider = pathParts[len(pathParts)-1]
		}
	}

	h.log.Infow("Starting OAuth flow",
		"provider", provider,
		"url", r.URL.String(),
		"referer", r.Header.Get("Referer"))

	// Add session debugging
	session, err := h.sessionStore.Get(r, gothic.SessionName)
	if err != nil {
		h.log.Errorw("Failed to get session for OAuth", "error", err)
	} else {
		h.log.Infow("OAuth session info",
			"session_id", session.ID,
			"is_new", session.IsNew,
			"values_count", len(session.Values))
	}

	gothic.BeginAuthHandler(w, r)
}

func (h *AuthHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	h.log.Infow("OAuth callback received",
		"url", r.URL.String(),
		"state", r.URL.Query().Get("state"),
		"code_present", r.URL.Query().Get("code") != "")

	// Debug session information
	session, err := h.sessionStore.Get(r, gothic.SessionName)
	if err != nil {
		h.log.Errorw("Failed to get session in callback", "error", err)
	} else {
		h.log.Infow("Callback session info",
			"session_id", session.ID,
			"is_new", session.IsNew,
			"values_count", len(session.Values))
	}

	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		h.log.Errorw("OAuth callback failed", "error", err, "url", r.URL.String())

		// Provide more helpful error messages
		if strings.Contains(err.Error(), "could not find a matching session") {
			h.sendErrorResponse(w, "OAuth session expired. Please try again.", http.StatusBadRequest)
			return
		}

		if strings.Contains(err.Error(), "access_denied") {
			h.sendErrorResponse(w, "OAuth access denied by user.", http.StatusBadRequest)
			return
		}

		h.sendErrorResponse(w, "OAuth authentication failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.log.Infow("OAuth user authenticated",
		"provider", gothUser.Provider,
		"user_id", gothUser.UserID,
		"email", gothUser.Email,
		"nickname", gothUser.NickName)

	deviceInfo := r.UserAgent()
	ipAddress := getClientIP(r)

	authResponse, err := h.authService.HandleOAuthCallback(r.Context(), gothUser, deviceInfo, ipAddress)
	if err != nil {
		h.log.Errorw("OAuth user creation failed", "error", err)
		h.sendErrorResponse(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	h.setSessionCookie(w, authResponse.SessionToken)

	h.log.Infow("OAuth login successful", "user_id", authResponse.User.ID, "provider", gothUser.Provider)

	// Determine response based on client type
	if h.isAPIClient(r) {
		// API client response
		h.sendSuccessResponse(w, map[string]interface{}{
			"user":         h.sanitizeUser(authResponse.User),
			"access_token": authResponse.AccessToken,
			"message":      "OAuth login successful",
			"provider":     gothUser.Provider,
			"auth_method":  "jwt",
		})
	} else {
		// Browser client - redirect to success page
		redirectURL := "http://localhost:3000/auth-success"

		// You can also include user info in URL params if needed
		params := url.Values{}
		params.Add("success", "true")
		params.Add("provider", gothUser.Provider)

		finalURL := fmt.Sprintf("%s?%s", redirectURL, params.Encode())

		h.log.Infow("Redirecting to frontend", "url", finalURL)
		http.Redirect(w, r, finalURL, http.StatusTemporaryRedirect)
	}
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionToken := h.getSessionToken(r)
	userID := "unknown"

	// Get user info for logging if possible
	if user := h.getUserFromContext(r); user != nil {
		userID = user.ID.String()
	}

	h.log.Infow("Logout attempt", "user_id", userID, "has_session_token", sessionToken != "")

	// Logout from backend (invalidate session)
	if sessionToken != "" {
		if err := h.authService.Logout(r.Context(), sessionToken); err != nil {
			h.log.Errorw("Failed to logout from backend", "error", err, "user_id", userID)
		}
	}

	// Clear session cookie
	h.clearSessionCookie(w)

	// Clear Gothic session for OAuth
	if err := gothic.Logout(w, r); err != nil {
		h.log.Warnw("Failed to clear Gothic session", "error", err)
	}

	h.log.Infow("Logout successful", "user_id", userID)

	h.sendSuccessResponse(w, map[string]interface{}{
		"message": "Logout successful",
	})
}

func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	if user == nil {
		h.sendErrorResponse(w, "User not found in context", http.StatusInternalServerError)
		return
	}

	h.log.Infow("Profile request", "user_id", user.ID)

	h.sendSuccessResponse(w, map[string]interface{}{
		"user": h.sanitizeUser(user),
	})
}

// Helper methods
func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, sessionToken string) {
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()), // 24 hours
		HttpOnly: true,                            // XSS protection
		Secure:   false,                           // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,            // CSRF protection, Lax for OAuth redirects
	}

	http.SetCookie(w, cookie)

	h.log.Debugw("Session cookie set",
		"name", cookie.Name,
		"max_age", cookie.MaxAge,
		"http_only", cookie.HttpOnly,
		"same_site", cookie.SameSite)
}

func (h *AuthHandler) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)

	h.log.Debugw("Session cookie cleared")
}

func (h *AuthHandler) getSessionToken(r *http.Request) string {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *AuthHandler) getUserFromContext(r *http.Request) *repository.User {
	if user := r.Context().Value("user"); user != nil {
		if u, ok := user.(*repository.User); ok {
			return u
		}
	}
	return nil
}

func (h *AuthHandler) isAPIClient(r *http.Request) bool {
	// Check if request explicitly asks for JSON
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}

	// Check for API-specific headers
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}

	// Check User-Agent for API clients, mobile apps, etc.
	userAgent := r.Header.Get("User-Agent")
	apiIndicators := []string{
		"curl", "wget", "HTTPie", "Postman", "Insomnia",
		"axios", "fetch", "okhttp", "Mobile", "Android", "iOS",
	}

	for _, indicator := range apiIndicators {
		if strings.Contains(userAgent, indicator) {
			return true
		}
	}

	return false
}

func (h *AuthHandler) sanitizeUser(user *repository.User) map[string]interface{} {
	role := "user"
	if user.Role.Valid {
		role = user.Role.String
	}

	return map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"role":       role,
		"is_active":  user.IsActive.Bool,
		"created_at": user.CreatedAt.Time,
	}
}

func (h *AuthHandler) sendSuccessResponse(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.log.Errorw("Failed to encode success response", "error", err)
	}
}

func (h *AuthHandler) sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":   true,
		"message": message,
		"status":  statusCode,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Errorw("Failed to encode error response", "error", err)
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (proxy/load balancer)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		ip := strings.TrimSpace(ips[0])
		if ip != "" {
			return ip
		}
	}

	// Check X-Real-IP header (proxy)
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Check CF-Connecting-IP header (Cloudflare)
	cfIP := r.Header.Get("CF-Connecting-IP")
	if cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Remove brackets from IPv6 addresses
	ip = strings.Trim(ip, "[]")

	return ip
}
