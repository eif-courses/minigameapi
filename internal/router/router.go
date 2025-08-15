package router

import (
	"net/http"
	"os"

	"github.com/eif-courses/minigameapi/internal/auth"
	"github.com/eif-courses/minigameapi/internal/config"
	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/eif-courses/minigameapi/internal/handlers"
	"github.com/eif-courses/minigameapi/internal/middleware"
	"github.com/eif-courses/minigameapi/internal/services"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
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

	// Session store setup (same as before)
	sessionKey := cfg.JWTSecret
	if len(sessionKey) < 32 {
		sessionKey = "your-secret-key-here-change-in-production-make-it-longer-than-32-chars"
	}

	sessionStore := sessions.NewCookieStore([]byte(sessionKey))
	sessionStore.MaxAge(86400 * 30)
	sessionStore.Options.Path = "/"
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = cfg.CookieSecure
	sessionStore.Options.SameSite = http.SameSiteDefaultMode

	gothic.Store = sessionStore
	setupOAuth(cfg, log)

	// Middleware setup
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Heartbeat("/health"))

	// Services setup
	jwtService := auth.NewJWTService(cfg.JWTSecret, "minigameapi")
	authService := auth.NewAuthService(queries, jwtService)
	d3Service := services.NewDiablo3Service(queries, log, cfg.BattleNetRegion)

	// Middleware and handlers
	authMiddleware := middleware.NewAuthMiddleware(authService, log)
	authHandler := handlers.NewAuthHandler(authService, sessionStore, log)
	d3Handler := handlers.NewDiablo3Handler(d3Service, log)

	// Routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/register", authHandler.Register)
		r.Get("/auth/{provider}", authHandler.BeginOAuth)
		r.Get("/auth/{provider}/callback", authHandler.OAuthCallback)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.RequireAuth)

			// Auth endpoints
			r.Get("/profile", authHandler.Profile)
			r.Post("/auth/logout", authHandler.Logout)

			// Basic protected endpoint
			r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
				user := r.Context().Value("user").(*repository.User)
				firstName := user.FirstName
				if firstName == "" {
					firstName = "User"
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"message": "Hello ` + firstName + `!", "authenticated": true}`))
			})

			// Diablo 3 API endpoints
			r.Route("/d3", func(r chi.Router) {
				// Profile endpoints
				r.Get("/profile", d3Handler.GetMyProfile)           // Get current user's profile
				r.Get("/profile/{battleTag}", d3Handler.GetProfile) // Get profile by BattleTag

				// Game data endpoints
				r.Get("/acts", d3Handler.GetActs)                 // Get all acts
				r.Get("/act/{actId}", d3Handler.GetAct)           // Get specific act
				r.Get("/item/{itemSlugAndId}", d3Handler.GetItem) // Get item info
			})
		})

		// Admin only routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.RequireRole("admin"))

			r.Get("/admin/users", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"message": "Admin access granted"}`))
			})
		})
	})

	return r
}

// Rest of the file remains the same...
func setupOAuth(cfg *config.Config, log *zap.SugaredLogger) {
	if cfg.BattleNetClientID == "" || cfg.BattleNetSecret == "" {
		log.Warnw("Battle.net OAuth not configured - skipping OAuth setup")
		return
	}

	battlenetProvider := battlenet.New(
		cfg.BattleNetClientID,
		cfg.BattleNetSecret,
		"http://localhost:8080/api/v1/auth/battlenet/callback",
		cfg.BattleNetRegion,
	)

	goth.UseProviders(battlenetProvider)

	log.Infow("Battle.net OAuth configured", "region", cfg.BattleNetRegion)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
