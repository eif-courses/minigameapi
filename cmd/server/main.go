package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/eif-courses/minigameapi/internal/config"
	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/eif-courses/minigameapi/internal/logger"
	mainrouter "github.com/eif-courses/minigameapi/internal/router"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func main() {
	log := logger.NewLogger()
	defer log.Sync()

	// ASCII art banner
	printBanner(log)

	cfg := config.Load()

	// Database connection
	log.Infow("🔌 Connecting to database...", "url", maskDatabaseURL(cfg.DatabaseURL))

	dbpool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatalw("❌ Failed to create connection pool", "error", err)
	}
	defer dbpool.Close()

	if err := dbpool.Ping(context.Background()); err != nil {
		log.Fatalw("❌ Failed to ping database", "error", err)
	}

	log.Infow("✅ Database connected successfully")

	// Battle.net OAuth status
	printOAuthStatus(cfg, log)

	// Create router
	queries := repository.New(dbpool)
	router := mainrouter.NewRouter(queries, log)

	// Server startup info
	addr := fmt.Sprintf(":%d", cfg.Port)
	baseURL := fmt.Sprintf("http://localhost:%d", cfg.Port)

	printServerInfo(cfg, baseURL, log)
	printAvailableEndpoints(baseURL, log)
	printQuickStart(baseURL, log)

	log.Infow("🚀 Starting HTTP server...",
		"port", cfg.Port,
		"environment", cfg.Environment,
		"base_url", baseURL)

	// Start server
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Infow("🌟 Server is running! Press Ctrl+C to stop.")

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalw("❌ Server failed", "error", err)
	}
}

func printBanner(log *zap.SugaredLogger) {
	banner := []string{
		"",
		"╔══════════════════════════════════════════════════════╗",
		"║                                                      ║",
		"║    🎮 DIABLO III MINIGAME API                        ║",
		"║    Battle.net OAuth + Community API Integration      ║",
		"║                                                      ║",
		"╚══════════════════════════════════════════════════════╝",
		"",
	}

	for _, line := range banner {
		log.Info(line)
	}
}

func printOAuthStatus(cfg *config.Config, log *zap.SugaredLogger) {
	if cfg.BattleNetClientID != "" && cfg.BattleNetSecret != "" {
		log.Infow("🔐 Battle.net OAuth configured",
			"client_id", maskClientID(cfg.BattleNetClientID),
			"region", cfg.BattleNetRegion)
	} else {
		log.Warnw("⚠️  Battle.net OAuth not configured - some features will be unavailable")
		log.Infow("💡 To enable OAuth, set BATTLE_NET_CLIENT_ID and BATTLE_NET_SECRET in .env")
	}
}

func printServerInfo(cfg *config.Config, baseURL string, log *zap.SugaredLogger) {
	log.Infow("📊 Server Configuration",
		"environment", cfg.Environment,
		"port", cfg.Port,
		"log_level", cfg.LogLevel,
		"cookie_secure", cfg.CookieSecure,
		"jwt_configured", cfg.JWTSecret != "",
		"base_url", baseURL)
}

func printAvailableEndpoints(baseURL string, log *zap.SugaredLogger) {
	log.Info("")
	log.Info("🔗 Available API Endpoints:")
	log.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Health & Status
	log.Infow("📊 Health Check", "endpoint", baseURL+"/health")

	// Authentication endpoints
	log.Info("")
	log.Info("🔐 Authentication Endpoints:")
	log.Infow("   • Register",
		"method", "POST",
		"endpoint", baseURL+"/api/v1/auth/register")
	log.Infow("   • Login",
		"method", "POST",
		"endpoint", baseURL+"/api/v1/auth/login")
	log.Infow("   • Battle.net OAuth",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/auth/battlenet")
	log.Infow("   • Profile",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/profile")
	log.Infow("   • Logout",
		"method", "POST",
		"endpoint", baseURL+"/api/v1/auth/logout")

	// Protected endpoints
	log.Info("")
	log.Info("🎮 Protected Endpoints:")
	log.Infow("   • Hello World",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/hello",
		"auth", "required")
	log.Infow("   • Test D3 Token",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/d3/test-token",
		"auth", "required")

	// Diablo 3 API endpoints
	log.Info("")
	log.Info("⚔️  Diablo 3 Community API:")
	log.Infow("   • My Profile",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/d3/profile",
		"auth", "battlenet_required")
	log.Infow("   • User Profile",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/d3/profile/{battleTag}",
		"auth", "battlenet_required")
	log.Infow("   • Acts",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/d3/acts",
		"auth", "battlenet_required")
	log.Infow("   • Specific Act",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/d3/act/{actId}",
		"auth", "battlenet_required")
	log.Infow("   • Item Info",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/d3/item/{itemSlugAndId}",
		"auth", "battlenet_required")

	// Admin endpoints
	log.Info("")
	log.Info("👑 Admin Endpoints:")
	log.Infow("   • User Management",
		"method", "GET",
		"endpoint", baseURL+"/api/v1/admin/users",
		"auth", "admin_required")

	log.Info("")
}

func printQuickStart(baseURL string, log *zap.SugaredLogger) {
	log.Info("🚀 Quick Start Guide:")
	log.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	log.Info("")
	log.Info("1️⃣  Test the API:")
	log.Infow("Health check", "curl", fmt.Sprintf("curl %s/health", baseURL))

	log.Info("")
	log.Info("2️⃣  Register a user:")
	registerCmd := fmt.Sprintf(`curl -X POST %s/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","first_name":"John","last_name":"Doe"}'`, baseURL)
	log.Infow("Register command", "curl", registerCmd)

	log.Info("")
	log.Info("3️⃣  Login:")
	loginCmd := fmt.Sprintf(`curl -X POST %s/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  -c cookies.txt`, baseURL)
	log.Infow("Login command", "curl", loginCmd)

	log.Info("")
	log.Info("4️⃣  Test protected endpoint:")
	log.Infow("Protected endpoint", "curl", fmt.Sprintf("curl %s/api/v1/hello -b cookies.txt", baseURL))

	log.Info("")
	log.Info("5️⃣  Battle.net OAuth (open in browser):")
	log.Infow("OAuth URL", "url", baseURL+"/api/v1/auth/battlenet")

	log.Info("")
	log.Info("6️⃣  Test Diablo 3 API (after OAuth):")
	d3Cmd := fmt.Sprintf(`curl %s/api/v1/d3/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"`, baseURL)
	log.Infow("D3 API command", "curl", d3Cmd)

	log.Info("")
	log.Info("📁 HTTP Test Files:")
	log.Infow("Testing tips",
		"auth_tests", "Create api-tests/auth.http for authentication testing",
		"d3_tests", "Create api-tests/diablo3.http for D3 API testing",
		"tool", "Use VS Code REST Client extension or similar")

	log.Info("")
	log.Info("🔧 Development Info:")
	log.Infow("Development details",
		"logs", "Check console output for detailed logging",
		"database", maskDatabaseURL(os.Getenv("DATABASE_URL")),
		"environment", os.Getenv("ENVIRONMENT"),
		"config_file", ".env")

	log.Info("")
	log.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Info("")
}

// Helper functions to mask sensitive information
func maskDatabaseURL(url string) string {
	if url == "" {
		return "not configured"
	}

	// Hide password in database URL
	if strings.Contains(url, "@") {
		parts := strings.Split(url, "@")
		if len(parts) == 2 {
			beforeAt := parts[0]
			afterAt := parts[1]

			// Find the password part
			if strings.Contains(beforeAt, ":") {
				userPass := strings.Split(beforeAt, ":")
				if len(userPass) >= 3 {
					// postgres://user:password@host -> postgres://user:***@host
					masked := strings.Join(userPass[:len(userPass)-1], ":") + ":***"
					return masked + "@" + afterAt
				}
			}
		}
	}

	return url
}

func maskClientID(clientID string) string {
	if len(clientID) <= 8 {
		return "***"
	}
	return clientID[:4] + "***" + clientID[len(clientID)-4:]
}
