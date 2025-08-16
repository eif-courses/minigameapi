package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/eif-courses/minigameapi/internal/generated/repository"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/markbates/goth"
)

type AuthService struct {
	queries    *repository.Queries
	jwtService *JWTService
}

type AuthResponse struct {
	User         *repository.User `json:"user"`
	AccessToken  string           `json:"access_token,omitempty"`
	SessionToken string           `json:"session_token,omitempty"`
}

// NEW: API-specific auth response for mobile/API clients
type APIAuthResponse struct {
	Success     bool             `json:"success"`
	User        *repository.User `json:"user"`
	AccessToken string           `json:"access_token"`
	TokenType   string           `json:"token_type"`
	ExpiresIn   int              `json:"expires_in"`
	Provider    string           `json:"provider,omitempty"`
}

func NewAuthService(queries *repository.Queries, jwtService *JWTService) *AuthService {
	return &AuthService{
		queries:    queries,
		jwtService: jwtService,
	}
}

// NEW: Handle API OAuth callback (for Retrofit)
func (a *AuthService) HandleAPIAuthCallback(ctx context.Context, gothUser goth.User, deviceInfo, ipAddress string) (*APIAuthResponse, error) {
	// Use the same OAuth logic but return API-specific response
	authResponse, err := a.HandleOAuthCallback(ctx, gothUser, deviceInfo, ipAddress)
	if err != nil {
		return nil, err
	}

	return &APIAuthResponse{
		Success:     true,
		User:        authResponse.User,
		AccessToken: authResponse.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   86400, // 24 hours in seconds
		Provider:    gothUser.Provider,
	}, nil
}

// Local authentication
func (a *AuthService) LoginWithPassword(ctx context.Context, email, password, deviceInfo, ipAddress string) (*AuthResponse, error) {
	user, err := a.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	if !CheckPassword(password, user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return a.createUserSession(ctx, &user, deviceInfo, ipAddress)
}

func (a *AuthService) RegisterUser(ctx context.Context, email, password, firstName, lastName, role string) (*repository.User, error) {
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	params := repository.CreateUserParams{
		Email:        email,
		PasswordHash: hashedPassword,
		FirstName:    firstName,
		LastName:     lastName,
		Role:         StringToPgText(role),
	}

	user, err := a.queries.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// OAuth authentication
func (a *AuthService) HandleOAuthCallback(ctx context.Context, gothUser goth.User, deviceInfo, ipAddress string) (*AuthResponse, error) {
	// Check if OAuth provider already exists
	oauthProvider, err := a.queries.GetOAuthProvider(ctx, repository.GetOAuthProviderParams{
		Provider:       gothUser.Provider,
		ProviderUserID: gothUser.UserID,
	})

	var user *repository.User

	if err == nil {
		// OAuth provider exists, get the user
		existingUser, err := a.queries.GetUserByID(ctx, oauthProvider.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		user = &existingUser

		// Update OAuth tokens
		var accessToken, refreshToken *string
		if gothUser.AccessToken != "" {
			accessToken = &gothUser.AccessToken
		}
		if gothUser.RefreshToken != "" {
			refreshToken = &gothUser.RefreshToken
		}

		err = a.queries.UpdateOAuthTokens(ctx, repository.UpdateOAuthTokensParams{
			Provider:       gothUser.Provider,
			ProviderUserID: gothUser.UserID,
			AccessToken:    accessToken,
			RefreshToken:   refreshToken,
			TokenExpiresAt: TimeToPgTimestamptz(gothUser.ExpiresAt),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to update OAuth tokens: %w", err)
		}
	} else {
		// New OAuth user, create user account
		email := gothUser.Email
		if email == "" {
			email = fmt.Sprintf("%s@%s.oauth", gothUser.UserID, gothUser.Provider)
		}

		firstName := gothUser.FirstName
		if firstName == "" {
			firstName = gothUser.NickName
		}
		if firstName == "" {
			firstName = "User"
		}

		lastName := gothUser.LastName
		if lastName == "" {
			lastName = ""
		}

		newUser, err := a.RegisterUser(ctx, email, "", firstName, lastName, "user")
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
		user = newUser

		// Create OAuth provider link
		var accessToken, refreshToken *string
		if gothUser.AccessToken != "" {
			accessToken = &gothUser.AccessToken
		}
		if gothUser.RefreshToken != "" {
			refreshToken = &gothUser.RefreshToken
		}

		_, err = a.queries.CreateOAuthProvider(ctx, repository.CreateOAuthProviderParams{
			UserID:           user.ID,
			Provider:         gothUser.Provider,
			ProviderUserID:   gothUser.UserID,
			ProviderUsername: StringToPgText(gothUser.NickName),
			ProviderEmail:    StringToPgText(gothUser.Email),
			AccessToken:      accessToken,
			RefreshToken:     refreshToken,
			TokenExpiresAt:   TimeToPgTimestamptz(gothUser.ExpiresAt),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth provider: %w", err)
		}
	}

	// Update last login
	err = a.queries.UpdateUserLastLogin(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update last login: %w", err)
	}

	return a.createUserSession(ctx, user, deviceInfo, ipAddress)
}

// Session management
func (a *AuthService) createUserSession(ctx context.Context, user *repository.User, deviceInfo, ipAddress string) (*AuthResponse, error) {
	// Generate session token for cookies
	sessionToken, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}

	// Generate JWT token
	role := "user"
	if user.Role.Valid {
		role = user.Role.String
	}

	jwtToken, jti, err := a.jwtService.GenerateToken(user.ID, user.Email, role)
	if err != nil {
		return nil, err
	}

	// Parse IP address
	var ip net.IP
	if ipAddress != "" {
		ip = net.ParseIP(ipAddress)
	}

	// Convert device info to pointer
	var deviceInfoPtr *string
	if deviceInfo != "" {
		deviceInfoPtr = &deviceInfo
	}

	// Create session in database
	_, err = a.queries.CreateSession(ctx, repository.CreateSessionParams{
		UserID:       user.ID,
		SessionToken: sessionToken,
		JwtTokenID:   StringToPgText(jti),
		DeviceInfo:   deviceInfoPtr,
		IpAddress:    ip,
		ExpiresAt:    time.Now().Add(24 * time.Hour), // This is now time.Time, not pgtype.Timestamptz
	})
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  jwtToken,
		SessionToken: sessionToken,
	}, nil
}

func (a *AuthService) ValidateSession(ctx context.Context, sessionToken string) (*repository.User, error) {
	sessionData, err := a.queries.GetSessionByToken(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("invalid session")
	}

	// Update last used
	err = a.queries.UpdateSessionLastUsed(ctx, sessionData.ID)
	if err != nil {
		// Log error but don't fail authentication
	}

	user := &repository.User{
		ID:        sessionData.UserID,
		Email:     sessionData.Email,
		FirstName: sessionData.FirstName,
		LastName:  sessionData.LastName,
		Role:      sessionData.Role,
		IsActive:  sessionData.IsActive,
	}

	return user, nil
}

func (a *AuthService) ValidateJWT(ctx context.Context, tokenString string) (*repository.User, error) {
	claims, err := a.jwtService.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify session exists in database (optional - you can skip this for stateless JWT)
	if claims.JTI != "" {
		sessionData, err := a.queries.GetSessionByJWT(ctx, StringToPgText(claims.JTI))
		if err != nil {
			return nil, fmt.Errorf("session not found")
		}

		user := &repository.User{
			ID:        claims.UserID,
			Email:     claims.Email,
			FirstName: sessionData.FirstName,
			LastName:  sessionData.LastName,
			Role:      sessionData.Role,
			IsActive:  sessionData.IsActive,
		}

		return user, nil
	}

	// Fallback: create user from JWT claims only (stateless)
	user := &repository.User{
		ID:       claims.UserID,
		Email:    claims.Email,
		Role:     StringToPgText(claims.Role),
		IsActive: pgtype.Bool{Bool: true, Valid: true},
	}

	return user, nil
}

func (a *AuthService) Logout(ctx context.Context, sessionToken string) error {
	return a.queries.DeleteSession(ctx, sessionToken)
}

func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
