package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL  string
	Port         int
	JWTSecret    string
	Environment  string
	CookieSecure bool // For HTTPS in production
	LogLevel     string
}

func Load() *Config {
	port, _ := strconv.Atoi(getEnv("PORT", "8080"))

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables or defaults")
	}

	return &Config{
		DatabaseURL:  getEnv("DATABASE_URL", "postgres://postgres:password@localhost:5432/civilregistry?sslmode=disable"),
		Port:         port,
		JWTSecret:    getEnv("JWT_SECRET", ""),
		Environment:  getEnv("ENVIRONMENT", "development"),
		CookieSecure: getEnv("ENVIRONMENT", "development") == "production",
		LogLevel:     getEnv("LOG_LEVEL", "info"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
