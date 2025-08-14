package router

import (
	"net/http"

	"github.com/eif-courses/minigameapi/internal/generated/repository"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

func NewRouter(queries *repository.Queries, log *zap.SugaredLogger) http.Handler {
	r := chi.NewRouter()

	// Add middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	return r
}
