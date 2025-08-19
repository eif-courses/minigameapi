package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/eif-courses/minigameapi/internal/auth"
	"github.com/eif-courses/minigameapi/internal/config"
	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/eif-courses/minigameapi/internal/handlers"
	"github.com/eif-courses/minigameapi/internal/middleware"
	"github.com/eif-courses/minigameapi/internal/services"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/battlenet"
	"go.uber.org/zap"
)

func NewRouter(queries *repository.Queries, log *zap.SugaredLogger) http.Handler {
	r := chi.NewRouter()

	// Load config first
	cfg := config.Load()

	// CORS configuration for cookie-based auth with frontend
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",            // Nuxt dev server
			"http://127.0.0.1:3000",            // Alternative localhost
			"http://localhost:3001",            // Alternative port
			"https://your-frontend-domain.com", // Production frontend
			cfg.BaseURL,                        // Current domain
		},
		AllowedMethods: []string{
			"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH",
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"X-Requested-With",
			"Accept-Encoding",
			"Accept-Language",
			"Cache-Control",
		},
		ExposedHeaders: []string{
			"Link",
			"X-Total-Count",
			"X-Page-Count",
		},
		AllowCredentials: true, // CRITICAL: This allows cookies to be sent cross-origin
		MaxAge:           300,  // Maximum value not ignored by any major browsers
	}))

	// Security and logging middleware
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Timeout(60 * time.Second)) // Request timeout
	r.Use(chimiddleware.Compress(5))               // Gzip compression
	r.Use(chimiddleware.Heartbeat("/health"))

	// Custom security headers middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Don't cache sensitive endpoints
			if isAuthEndpoint(r.URL.Path) {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
			}

			next.ServeHTTP(w, r)
		})
	})

	// Session store setup with proper cookie configuration
	sessionKey := cfg.JWTSecret
	if len(sessionKey) < 32 {
		sessionKey = "your-secret-key-here-change-in-production-make-it-longer-than-32-chars"
		log.Warnw("Using default session key - change this in production!")
	}

	sessionStore := sessions.NewCookieStore([]byte(sessionKey))
	sessionStore.MaxAge(86400 * 30) // 30 days
	sessionStore.Options.Path = "/"
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = cfg.CookieSecure
	sessionStore.Options.SameSite = http.SameSiteLaxMode // Lax for OAuth compatibility

	// Set Gothic session store
	gothic.Store = sessionStore

	// Setup OAuth providers
	setupOAuth(cfg, log)

	// Initialize services
	jwtService := auth.NewJWTService(cfg.JWTSecret, "minigameapi")
	authService := auth.NewAuthService(queries, jwtService)
	d3Service := services.NewDiablo3Service(queries, log, cfg.BattleNetRegion)

	// Initialize middleware and handlers
	authMiddleware := middleware.NewAuthMiddleware(authService, log)
	authHandler := handlers.NewAuthHandler(authService, sessionStore, log)
	d3Handler := handlers.NewDiablo3Handler(d3Service, log)

	// Add this route to handle the mobile callback
	r.Get("/oauth/mobile", func(w http.ResponseWriter, r *http.Request) {
		log.Infow("Mobile OAuth callback received", "url", r.URL.String())

		code := r.URL.Query().Get("code")
		error := r.URL.Query().Get("error")

		if error != "" {
			log.Warnw("OAuth error received", "error", error)
			// Redirect to Android app with error
			redirectURL := fmt.Sprintf("minigameapp://oauth/callback?error=%s", url.QueryEscape(error))
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}

		if code == "" {
			log.Warnw("No authorization code received")
			redirectURL := "minigameapp://oauth/callback?error=no_code"
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}

		log.Infow("Redirecting to Android app", "code_length", len(code))
		// Redirect to Android app with authorization code
		redirectURL := fmt.Sprintf("minigameapp://oauth/callback?code=%s", url.QueryEscape(code))
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	})

	// API Routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public authentication routes
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", authHandler.Login)
			r.Post("/register", authHandler.Register)

			// OAuth routes
			r.Get("/{provider}", authHandler.BeginOAuth)
			r.Get("/{provider}/callback", authHandler.OAuthCallback)

			// Protected auth routes
			r.Group(func(r chi.Router) {
				r.Use(authMiddleware.RequireAuth)
				r.Get("/profile", authHandler.Profile)
				r.Post("/logout", authHandler.Logout)
			})
		})
		// NEW: API-only OAuth endpoint for mobile apps (Retrofit)
		r.Post("/auth/battlenet/token", authHandler.APILoginWithBattleNet)

		// Protected application routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.RequireAuth)

			// Basic protected endpoints
			r.Get("/profile", authHandler.Profile)
			r.Get("/hello", handleHelloWorld)

			// Diablo 3 Community API endpoints
			r.Route("/d3", func(r chi.Router) {
				// Test endpoint
				r.Get("/test-token", d3Handler.TestToken)

				// Profile endpoints
				r.Get("/profile", d3Handler.GetMyProfile)           // Current user's D3 profile
				r.Get("/profile/{battleTag}", d3Handler.GetProfile) // Profile by BattleTag

				// Game data endpoints
				r.Get("/acts", d3Handler.GetActs)                 // All acts
				r.Get("/act/{actId}", d3Handler.GetAct)           // Specific act
				r.Get("/item/{itemSlugAndId}", d3Handler.GetItem) // Item information
			})
		})

		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.RequireRole("admin"))

			r.Route("/admin", func(r chi.Router) {
				r.Get("/users", handleAdminUsers)
				r.Get("/stats", handleAdminStats)
				r.Delete("/sessions", handleAdminClearSessions)
			})
		})
	})

	// Static file serving and web routes (if needed)
	r.Route("/", func(r chi.Router) {
		// Health check endpoints
		r.Get("/health", handleHealthCheck)
		r.Get("/status", handleStatusCheck)

		// API documentation
		r.Get("/docs", handleAPIDocs)

		// Serve static files if they exist
		workDir, _ := os.Getwd()
		filesDir := http.Dir(workDir + "/static/")
		r.Handle("/static/*", http.StripPrefix("/static", http.FileServer(filesDir)))
	})

	// Global error handling
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "endpoint not found", "status": 404}`))
	})

	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error": "method not allowed", "status": 405}`))
	})

	return r
}

// OAuth setup with comprehensive error handling
func setupOAuth(cfg *config.Config, log *zap.SugaredLogger) {
	if cfg.BattleNetClientID == "" || cfg.BattleNetSecret == "" {
		log.Warnw("⚠️  Battle.net OAuth not configured",
			"client_id_set", cfg.BattleNetClientID != "",
			"secret_set", cfg.BattleNetSecret != "")
		log.Infow("💡 To enable OAuth: set BATTLE_NET_CLIENT_ID and BATTLE_NET_SECRET")
		return
	}

	// Validate region
	validRegions := []string{"us", "eu", "kr", "tw", "cn"}
	region := cfg.BattleNetRegion
	if region == "" {
		region = "us"
		log.Warnw("No Battle.net region specified, defaulting to 'us'")
	}

	isValidRegion := false
	for _, validRegion := range validRegions {
		if region == validRegion {
			isValidRegion = true
			break
		}
	}

	if !isValidRegion {
		log.Warnw("Invalid Battle.net region, falling back to 'us'",
			"provided_region", region,
			"valid_regions", validRegions)
		region = "us"
	}

	// Use BaseURL from config for the callback URL
	callbackURL := cfg.BaseURL + "/api/v1/auth/battlenet/callback"

	// Setup Battle.net provider
	battlenetProvider := battlenet.New(
		cfg.BattleNetClientID,
		cfg.BattleNetSecret,
		callbackURL,
		region,
	)

	// Add any additional providers here
	providers := []goth.Provider{
		battlenetProvider,
		// google.New("google-key", "google-secret", "callback-url"),
		// github.New("github-key", "github-secret", "callback-url"),
	}

	goth.UseProviders(providers...)

	log.Infow("🔐 OAuth providers configured",
		"battle_net_region", region,
		"callback_url", callbackURL,
		"environment", cfg.Environment,
		"base_url", cfg.BaseURL,
		"provider_count", len(providers))
}

// Handler functions
func handleHelloWorld(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)
	firstName := user.FirstName
	if firstName == "" {
		firstName = "User"
	}

	response := map[string]interface{}{
		"message":       fmt.Sprintf("Hello %s!", firstName),
		"authenticated": true,
		"user_id":       user.ID,
		"timestamp":     time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	// In a real app, you'd fetch actual user data
	response := map[string]interface{}{
		"message": "Admin access granted - User management endpoint",
		"users":   []string{"admin@example.com", "user@example.com"},
		"total":   2,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message":         "Admin statistics",
		"total_users":     42,
		"active_sessions": 15,
		"api_calls_today": 1337,
		"uptime":          "2 days, 3 hours",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleAdminClearSessions(w http.ResponseWriter, r *http.Request) {
	// In a real app, you'd clear expired sessions from database
	response := map[string]interface{}{
		"message":          "Expired sessions cleared",
		"sessions_cleared": 5,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"services": map[string]string{
			"database": "connected",
			"oauth":    "configured",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleStatusCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"api":          "online",
		"database":     "connected",
		"oauth":        "available",
		"uptime":       "running",
		"last_updated": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	docs := `
<!DOCTYPE html>
<html>
<head>
    <title>Diablo III API Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #f0f0f0; }
        h1 { color: #ff8000; }
        h2 { color: #ff8000; border-bottom: 1px solid #444; }
        .endpoint { background: #2d2d2d; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .method { display: inline-block; padding: 2px 8px; border-radius: 3px; font-weight: bold; }
        .get { background: #28a745; }
        .post { background: #007bff; }
        .delete { background: #dc3545; }
        code { background: #333; padding: 2px 4px; border-radius: 3px; }
        .warning { background: #ffc107; color: #000; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🎮 Diablo III API Documentation</h1>
    
    <div class="warning">
        <strong>⚠️ Important:</strong> This API requires Battle.net OAuth authentication for Diablo 3 endpoints.
    </div>
    
    <h2>Authentication Endpoints</h2>
    <div class="endpoint">
        <span class="method post">POST</span> <code>/api/v1/auth/login</code><br>
        Login with email and password
    </div>
    <div class="endpoint">
        <span class="method post">POST</span> <code>/api/v1/auth/register</code><br>
        Register a new user account
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/auth/battlenet</code><br>
        Start Battle.net OAuth flow
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/profile</code><br>
        Get user profile (requires authentication)
    </div>
    
    <h2>Diablo 3 API Endpoints</h2>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/d3/profile</code><br>
        Get your Diablo 3 profile (requires Battle.net OAuth)
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/d3/profile/{battleTag}</code><br>
        Get profile by BattleTag (requires Battle.net OAuth)
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/d3/acts</code><br>
        Get all Diablo 3 acts (requires Battle.net OAuth)
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/d3/act/{actId}</code><br>
        Get specific act information (requires Battle.net OAuth)
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/d3/item/{itemSlugAndId}</code><br>
        Get item information (requires Battle.net OAuth)
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/d3/test-token</code><br>
        Test Battle.net access token validity
    </div>
    
    <h2>Admin Endpoints</h2>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/admin/users</code><br>
        Manage users (admin only)
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/api/v1/admin/stats</code><br>
        View system statistics (admin only)
    </div>
    <div class="endpoint">
        <span class="method delete">DELETE</span> <code>/api/v1/admin/sessions</code><br>
        Clear expired sessions (admin only)
    </div>
    
    <h2>Utility Endpoints</h2>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/health</code><br>
        Health check endpoint
    </div>
    <div class="endpoint">
        <span class="method get">GET</span> <code>/status</code><br>
        Detailed status information
    </div>
    
    <p><strong>Authentication:</strong> Use session cookies (browser) or Authorization header with JWT token (API)</p>
    <p><strong>Example:</strong> <code>Authorization: Bearer your-jwt-token</code></p>
    <p><strong>OAuth Flow:</strong> Visit <code>/api/v1/auth/battlenet</code> to start Battle.net authentication</p>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(docs))
}

// Utility functions
func isAuthEndpoint(path string) bool {
	authPaths := []string{"/api/v1/auth/", "/api/v1/profile"}
	for _, authPath := range authPaths {
		if strings.Contains(path, authPath) {
			return true
		}
	}
	return false
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
