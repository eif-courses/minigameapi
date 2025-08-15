-- name: CreateUser :one
INSERT INTO users (email, password_hash, first_name, last_name, role)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 AND is_active = true;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1 AND is_active = true;

-- name: UpdateUserLastLogin :exec
UPDATE users
SET last_login_at = NOW()
WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $1, updated_at = NOW()
WHERE id = $2;

-- name: DeactivateUser :exec
UPDATE users
SET is_active = false, updated_at = NOW()
WHERE id = $1;

-- name: GetUsersByRole :many
SELECT * FROM users
WHERE role = $1 AND is_active = true
ORDER BY created_at DESC;

-- name: GetAllUsers :many
SELECT * FROM users
WHERE is_active = true
ORDER BY created_at DESC;

-- OAuth provider queries
-- name: CreateOAuthProvider :one
INSERT INTO oauth_providers (user_id, provider, provider_user_id, provider_username, provider_email, access_token, refresh_token, token_expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetOAuthProvider :one
SELECT * FROM oauth_providers
WHERE provider = $1 AND provider_user_id = $2;

-- name: GetUserOAuthProviders :many
SELECT * FROM oauth_providers
WHERE user_id = $1;

-- name: UpdateOAuthTokens :exec
UPDATE oauth_providers
SET access_token = $3, refresh_token = $4, token_expires_at = $5, updated_at = NOW()
WHERE provider = $1 AND provider_user_id = $2;

-- name: DeleteOAuthProvider :exec
DELETE FROM oauth_providers
WHERE user_id = $1 AND provider = $2;

-- Session management queries (simplified)
-- name: CreateSession :one
INSERT INTO user_sessions (user_id, session_token, jwt_token_id, device_info, ip_address, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSessionByToken :one
SELECT
    us.id,
    us.user_id,
    us.session_token,
    us.jwt_token_id,
    us.device_info,
    us.ip_address,
    us.expires_at,
    us.created_at,
    us.last_used_at,
    u.email,
    u.first_name,
    u.last_name,
    u.role,
    u.is_active
FROM user_sessions us
         JOIN users u ON us.user_id = u.id
WHERE us.session_token = $1 AND us.expires_at > NOW() AND u.is_active = true;

-- name: GetSessionByJWT :one
SELECT
    us.id,
    us.user_id,
    us.session_token,
    us.jwt_token_id,
    us.device_info,
    us.ip_address,
    us.expires_at,
    us.created_at,
    us.last_used_at,
    u.email,
    u.first_name,
    u.last_name,
    u.role,
    u.is_active
FROM user_sessions us
         JOIN users u ON us.user_id = u.id
WHERE us.jwt_token_id = $1 AND us.expires_at > NOW() AND u.is_active = true;

-- name: UpdateSessionLastUsed :exec
UPDATE user_sessions
SET last_used_at = NOW()
WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM user_sessions
WHERE session_token = $1;

-- name: DeleteUserSessions :exec
DELETE FROM user_sessions
WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM user_sessions
WHERE expires_at < NOW();