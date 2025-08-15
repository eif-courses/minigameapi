package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/eif-courses/minigameapi/internal/services"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type Diablo3Handler struct {
	d3Service *services.Diablo3Service
	log       *zap.SugaredLogger
}

func NewDiablo3Handler(d3Service *services.Diablo3Service, log *zap.SugaredLogger) *Diablo3Handler {
	return &Diablo3Handler{
		d3Service: d3Service,
		log:       log,
	}
}

// Add a test endpoint to check access token
func (h *Diablo3Handler) TestToken(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)

	err := h.d3Service.TestAccessToken(r.Context(), user.ID.String())
	if err != nil {
		h.log.Errorw("Access token test failed", "error", err, "user_id", user.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   err.Error(),
			"message": "Battle.net access token test failed",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Battle.net access token is valid",
		"status":  "success",
	})
}

// Get current user's D3 profile
func (h *Diablo3Handler) GetMyProfile(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)

	// Extract BattleTag from user's first name (where we stored it)
	battleTag := user.FirstName
	if battleTag == "" {
		http.Error(w, "No BattleTag found for user", http.StatusBadRequest)
		return
	}

	profile, err := h.d3Service.GetProfile(r.Context(), user.ID.String(), battleTag)
	if err != nil {
		h.log.Errorw("Failed to get D3 profile", "error", err, "user_id", user.ID)
		http.Error(w, "Failed to get Diablo 3 profile", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"profile": profile,
		"message": "Diablo 3 profile retrieved successfully",
	})
}

// Get specific user's D3 profile by BattleTag
func (h *Diablo3Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)
	battleTag := chi.URLParam(r, "battleTag")

	if battleTag == "" {
		http.Error(w, "BattleTag is required", http.StatusBadRequest)
		return
	}

	profile, err := h.d3Service.GetProfile(r.Context(), user.ID.String(), battleTag)
	if err != nil {
		h.log.Errorw("Failed to get D3 profile", "error", err, "battletag", battleTag)
		http.Error(w, "Failed to get Diablo 3 profile", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"profile":   profile,
		"battleTag": battleTag,
		"message":   "Diablo 3 profile retrieved successfully",
	})
}

// Get D3 acts
func (h *Diablo3Handler) GetActs(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)

	acts, err := h.d3Service.GetActIndex(r.Context(), user.ID.String())
	if err != nil {
		h.log.Errorw("Failed to get D3 acts", "error", err)
		http.Error(w, "Failed to get Diablo 3 acts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"acts":    acts,
		"message": "Diablo 3 acts retrieved successfully",
	})
}

// Get specific act
func (h *Diablo3Handler) GetAct(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)
	actIDStr := chi.URLParam(r, "actId")

	actID, err := strconv.Atoi(actIDStr)
	if err != nil {
		http.Error(w, "Invalid act ID", http.StatusBadRequest)
		return
	}

	act, err := h.d3Service.GetAct(r.Context(), user.ID.String(), actID)
	if err != nil {
		h.log.Errorw("Failed to get D3 act", "error", err, "act_id", actID)
		http.Error(w, "Failed to get Diablo 3 act", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"act":     act,
		"message": "Diablo 3 act retrieved successfully",
	})
}

// Updated GetItem method to use D3ItemResponse
func (h *Diablo3Handler) GetItem(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*repository.User)
	itemSlugAndID := chi.URLParam(r, "itemSlugAndId")

	h.log.Infow("Getting D3 item",
		"user_id", user.ID,
		"item", itemSlugAndID)

	if itemSlugAndID == "" {
		http.Error(w, "Item slug and ID is required", http.StatusBadRequest)
		return
	}

	// This now returns *D3ItemResponse instead of *D3Item
	itemResponse, err := h.d3Service.GetItem(r.Context(), user.ID.String(), itemSlugAndID)
	if err != nil {
		h.log.Errorw("Failed to get D3 item",
			"error", err,
			"item", itemSlugAndID,
			"user_id", user.ID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   err.Error(),
			"message": "Failed to get Diablo 3 item",
			"item":    itemSlugAndID,
		})
		return
	}

	// Return the complete D3ItemResponse which already includes iconURL, parsedStats, etc.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(itemResponse)
}
