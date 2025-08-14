package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/eif-courses/minigameapi/internal/config"
	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/eif-courses/minigameapi/internal/logger"
	mainrouter "github.com/eif-courses/minigameapi/internal/router"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	log := logger.NewLogger()
	defer log.Sync()

	cfg := config.Load()

	dbpool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatalw("Failed to create connection pool", "error", err)
	}
	defer dbpool.Close()

	if err := dbpool.Ping(context.Background()); err != nil {
		log.Fatalw("Failed to ping database", "error", err)
	}

	queries := repository.New(dbpool)
	router := mainrouter.NewRouter(queries, log)

	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Infow("Starting server",
		"port", cfg.Port,
		"database", "connected",
	)

	err = http.ListenAndServe(addr, router)
	if err != nil {
		log.Fatalw("Server failed", "error", err)
	}
}
