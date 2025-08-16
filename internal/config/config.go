package config

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL       string
	Port              int
	JWTSecret         string
	Environment       string
	CookieSecure      bool
	LogLevel          string
	BattleNetClientID string
	BattleNetSecret   string
	BattleNetRegion   string
	BaseURL           string // Added for OAuth callback URLs
}

func Load() *Config {
	// Load .env only in development (not on Railway)
	if os.Getenv("RAILWAY_ENVIRONMENT") == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("No .env file found, using environment variables or defaults")
		}
	}

	port, _ := strconv.Atoi(getEnv("PORT", "8080"))

	// Determine base URL based on environment
	var baseURL string
	if getEnv("ENVIRONMENT", "development") == "production" || os.Getenv("RAILWAY_ENVIRONMENT") != "" {
		// Production: Use Railway domain
		railwayDomain := os.Getenv("RAILWAY_PUBLIC_DOMAIN")
		if railwayDomain != "" {
			baseURL = "https://" + railwayDomain
		} else {
			// Fallback if RAILWAY_PUBLIC_DOMAIN is not available
			baseURL = getEnv("BASE_URL", "https://minigameapi-production.up.railway.app")
		}
	} else {
		// Development: Use localhost
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	return &Config{
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://postgres:password@localhost:5432/databasename?sslmode=disable"),
		Port:              port,
		JWTSecret:         getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
		Environment:       getEnv("ENVIRONMENT", "development"),
		CookieSecure:      getEnv("ENVIRONMENT", "development") == "production",
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		BattleNetClientID: getEnv("BATTLE_NET_CLIENT_ID", ""),
		BattleNetSecret:   getEnv("BATTLE_NET_SECRET", ""),
		BattleNetRegion:   getEnv("BATTLE_NET_REGION", "us"),
		BaseURL:           baseURL, // Added BaseURL field
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
