package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Updated D3Item struct to match actual API response
type D3Item struct {
	ID                     string          `json:"id"`
	Slug                   string          `json:"slug"`
	Name                   string          `json:"name"`
	Icon                   string          `json:"icon"`
	TooltipParams          string          `json:"tooltipParams"`
	RequiredLevel          int             `json:"requiredLevel"`
	StackSizeMax           int             `json:"stackSizeMax"`
	AccountBound           bool            `json:"accountBound"`
	FlavorText             string          `json:"flavorText"`
	FlavorTextHtml         string          `json:"flavorTextHtml"`
	TypeName               string          `json:"typeName"`
	Type                   D3ItemType      `json:"type"`
	Damage                 string          `json:"damage"` // String, not map!
	DPS                    string          `json:"dps"`    // String, not map!
	DamageHtml             string          `json:"damageHtml"`
	Color                  string          `json:"color"`
	IsSeasonRequiredToDrop bool            `json:"isSeasonRequiredToDrop"`
	SeasonRequiredToDrop   int             `json:"seasonRequiredToDrop"`
	Slots                  []string        `json:"slots"`
	Attributes             D3Attributes    `json:"attributes"`
	RandomAffixes          []D3RandomAffix `json:"randomAffixes"`
	SetItems               []interface{}   `json:"setItems"`

	// Optional fields that may appear on some items
	Armor           string        `json:"armor,omitempty"`
	ArmorHtml       string        `json:"armorHtml,omitempty"`
	ItemLevel       int           `json:"itemLevel,omitempty"`
	BonusAffixes    int           `json:"bonusAffixes,omitempty"`
	BonusAffixesMax int           `json:"bonusAffixesMax,omitempty"`
	OpenSockets     int           `json:"openSockets,omitempty"`
	Gems            []interface{} `json:"gems,omitempty"`
}

type D3ItemType struct {
	TwoHanded bool   `json:"twoHanded"`
	ID        string `json:"id"`
}

type D3Attributes struct {
	Primary   []D3Attribute `json:"primary"`
	Secondary []D3Attribute `json:"secondary"`
	Other     []D3Attribute `json:"other"`
}

type D3Attribute struct {
	Text     string `json:"text"`
	TextHtml string `json:"textHtml"`
}

type D3RandomAffix struct {
	OneOf []D3Attribute `json:"oneOf"`
}

// Enhanced response structure
type D3ItemResponse struct {
	Item        *D3Item           `json:"item"`
	IconURL     string            `json:"iconURL,omitempty"`
	IconURLs    map[string]string `json:"iconURLs,omitempty"`
	ParsedStats D3ParsedStats     `json:"parsedStats,omitempty"`
	Message     string            `json:"message"`
}

type D3ParsedStats struct {
	DamageRange    string   `json:"damageRange,omitempty"`
	AttackSpeed    string   `json:"attackSpeed,omitempty"`
	DPS            string   `json:"dps,omitempty"`
	WeaponType     string   `json:"weaponType,omitempty"`
	IsTwoHanded    bool     `json:"isTwoHanded"`
	PrimaryStats   []string `json:"primaryStats,omitempty"`
	SecondaryStats []string `json:"secondaryStats,omitempty"`
}

// Keep existing structs for other endpoints...
type D3Profile struct {
	BattleTag      string   `json:"battleTag"`
	ParagonLevel   int      `json:"paragonLevel"`
	ParagonLevelH  int      `json:"paragonLevelHardcore"`
	GuildName      string   `json:"guildName"`
	Heroes         []D3Hero `json:"heroes"`
	LastHeroPlayed int64    `json:"lastHeroPlayed"`
	LastUpdated    int64    `json:"lastUpdated"`
}

type D3Hero struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Class        string `json:"class"`
	Gender       int    `json:"gender"`
	Level        int    `json:"level"`
	ParagonLevel int    `json:"paragonLevel"`
	Hardcore     bool   `json:"hardcore"`
	Seasonal     bool   `json:"seasonal"`
	Dead         bool   `json:"dead"`
	LastUpdated  int64  `json:"lastUpdated"`
}

type D3Act struct {
	Slug   string `json:"slug"`
	Number int    `json:"number"`
	Name   string `json:"name"`
}

type D3ActIndex struct {
	Acts []D3Act `json:"acts"`
}

type Diablo3Service struct {
	queries    *repository.Queries
	httpClient *http.Client
	log        *zap.SugaredLogger
	baseURL    string
}

func NewDiablo3Service(queries *repository.Queries, log *zap.SugaredLogger, region string) *Diablo3Service {
	if region == "" {
		region = "us"
	}

	baseURL := fmt.Sprintf("https://%s.api.blizzard.com", region)
	if region == "cn" {
		baseURL = "https://gateway.battlenet.com.cn"
	}

	return &Diablo3Service{
		queries: queries,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		log:     log,
		baseURL: baseURL,
	}
}

// Helper function to parse damage string
func parseDamageString(damage string) (damageRange, attackSpeed string) {
	lines := strings.Split(damage, "\n")
	if len(lines) >= 1 {
		damageRange = strings.TrimSpace(lines[0])
	}
	if len(lines) >= 2 {
		attackSpeed = strings.TrimSpace(lines[1])
	}
	return
}

// Enhanced item response parser
func (d *Diablo3Service) parseItemResponse(item *D3Item) *D3ItemResponse {
	response := &D3ItemResponse{
		Item:    item,
		Message: "Diablo 3 item retrieved successfully",
	}

	// Generate icon URLs in different sizes
	if item.Icon != "" {
		response.IconURL = d.GetIconURL("items", "large", item.Icon)
		response.IconURLs = map[string]string{
			"small": d.GetIconURL("items", "small", item.Icon),
			"large": d.GetIconURL("items", "large", item.Icon),
		}
	}

	// Parse stats
	damageRange, attackSpeed := parseDamageString(item.Damage)

	// Extract primary and secondary stats as text
	var primaryStats, secondaryStats []string
	for _, attr := range item.Attributes.Primary {
		primaryStats = append(primaryStats, attr.Text)
	}
	for _, attr := range item.Attributes.Secondary {
		secondaryStats = append(secondaryStats, attr.Text)
	}

	response.ParsedStats = D3ParsedStats{
		DamageRange:    damageRange,
		AttackSpeed:    attackSpeed,
		DPS:            item.DPS,
		WeaponType:     item.TypeName,
		IsTwoHanded:    item.Type.TwoHanded,
		PrimaryStats:   primaryStats,
		SecondaryStats: secondaryStats,
	}

	return response
}

// Updated GetItem method
func (d *Diablo3Service) GetItem(ctx context.Context, userID, itemSlugAndID string) (*D3ItemResponse, error) {
	accessToken, err := d.getUserAccessToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/d3/data/item/%s", d.baseURL, itemSlugAndID)

	var item D3Item
	err = d.makeAuthenticatedRequest(ctx, "GET", endpoint, accessToken, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to get D3 item: %w", err)
	}

	return d.parseItemResponse(&item), nil
}

// Get user's Battle.net access token from database
func (d *Diablo3Service) getUserAccessToken(ctx context.Context, userID string) (string, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return "", fmt.Errorf("invalid user ID format: %w", err)
	}

	providers, err := d.queries.GetUserOAuthProviders(ctx, uid)
	if err != nil {
		d.log.Errorw("Failed to get OAuth providers", "error", err, "user_id", userID)
		return "", fmt.Errorf("failed to get OAuth providers: %w", err)
	}

	d.log.Infow("Found OAuth providers", "count", len(providers), "user_id", userID)

	for _, provider := range providers {
		d.log.Infow("Checking provider",
			"provider", provider.Provider,
			"has_token", provider.AccessToken != nil)

		if provider.Provider == "battlenet" && provider.AccessToken != nil {
			d.log.Infow("Found Battle.net access token", "user_id", userID)
			return *provider.AccessToken, nil
		}
	}

	return "", fmt.Errorf("no Battle.net access token found for user %s", userID)
}

// Keep all other existing methods (GetProfile, GetActIndex, etc.)...
func (d *Diablo3Service) GetProfile(ctx context.Context, userID, battleTag string) (*D3Profile, error) {
	accessToken, err := d.getUserAccessToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	encodedBattleTag := strings.ReplaceAll(battleTag, "#", "-")
	endpoint := fmt.Sprintf("%s/d3/profile/%s/", d.baseURL, encodedBattleTag)

	var profile D3Profile
	err = d.makeAuthenticatedRequest(ctx, "GET", endpoint, accessToken, &profile)
	if err != nil {
		return nil, fmt.Errorf("failed to get D3 profile: %w", err)
	}

	return &profile, nil
}

func (d *Diablo3Service) GetActIndex(ctx context.Context, userID string) (*D3ActIndex, error) {
	accessToken, err := d.getUserAccessToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/d3/data/act", d.baseURL)

	var actIndex D3ActIndex
	err = d.makeAuthenticatedRequest(ctx, "GET", endpoint, accessToken, &actIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get D3 act index: %w", err)
	}

	return &actIndex, nil
}

func (d *Diablo3Service) GetAct(ctx context.Context, userID string, actID int) (*D3Act, error) {
	accessToken, err := d.getUserAccessToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/d3/data/act/%d", d.baseURL, actID)

	var act D3Act
	err = d.makeAuthenticatedRequest(ctx, "GET", endpoint, accessToken, &act)
	if err != nil {
		return nil, fmt.Errorf("failed to get D3 act: %w", err)
	}

	return &act, nil
}

func (d *Diablo3Service) makeAuthenticatedRequest(ctx context.Context, method, endpoint, accessToken string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("locale", "en_US")
	req.URL.RawQuery = q.Encode()

	d.log.Infow("Making Diablo 3 API request",
		"endpoint", endpoint,
		"method", method,
		"full_url", req.URL.String())

	resp, err := d.httpClient.Do(req)
	if err != nil {
		d.log.Errorw("HTTP request failed", "error", err, "endpoint", endpoint)
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		d.log.Errorw("Failed to read response body", "error", err)
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		d.log.Errorw("Diablo 3 API error",
			"status", resp.StatusCode,
			"body", string(body),
			"endpoint", endpoint)

		var errorResp map[string]interface{}
		if json.Unmarshal(body, &errorResp) == nil {
			return fmt.Errorf("API request failed with status %d: %v", resp.StatusCode, errorResp)
		}

		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, result); err != nil {
		d.log.Errorw("Failed to unmarshal response",
			"error", err,
			"body", string(body))
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return nil
}

func (d *Diablo3Service) GetIconURL(iconType, size, icon string) string {
	return fmt.Sprintf("http://media.blizzard.com/d3/icons/%s/%s/%s.png", iconType, size, icon)
}

func (d *Diablo3Service) TestAccessToken(ctx context.Context, userID string) error {
	accessToken, err := d.getUserAccessToken(ctx, userID)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/d3/data/act", d.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	q := req.URL.Query()
	q.Add("locale", "en_US")
	req.URL.RawQuery = q.Encode()

	d.log.Infow("Testing access token", "endpoint", endpoint)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("test request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	d.log.Infow("Access token test result",
		"status", resp.StatusCode,
		"body", string(body))

	if resp.StatusCode == 401 {
		return fmt.Errorf("access token is invalid or expired")
	}

	return nil
}
