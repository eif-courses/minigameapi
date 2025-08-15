-- +goose Up
-- +goose StatementBegin

-- OAuth providers table to link external accounts
CREATE TABLE oauth_providers (
                                 id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                 provider VARCHAR(50) NOT NULL, -- 'battlenet', 'google', etc.
                                 provider_user_id VARCHAR(255) NOT NULL, -- ID from the OAuth provider
                                 provider_username VARCHAR(255), -- Username/handle from provider
                                 provider_email VARCHAR(255), -- Email from provider (might differ from main email)
                                 access_token TEXT, -- OAuth access token (encrypted in production)
                                 refresh_token TEXT, -- OAuth refresh token (encrypted in production)
                                 token_expires_at TIMESTAMPTZ, -- When the access token expires
                                 created_at TIMESTAMPTZ DEFAULT NOW(),
                                 updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Ensure one account per provider per user
                                 UNIQUE(user_id, provider),
    -- Ensure one provider account can't link to multiple users
                                 UNIQUE(provider, provider_user_id)
);

-- Sessions table for managing user sessions
CREATE TABLE user_sessions (
                               id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                               user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                               session_token VARCHAR(255) UNIQUE NOT NULL, -- For cookie-based sessions
                               jwt_token_id VARCHAR(255), -- JTI claim for JWT tokens
                               device_info TEXT, -- User agent, device info
                               ip_address INET, -- IP address
                               expires_at TIMESTAMPTZ NOT NULL,
                               created_at TIMESTAMPTZ DEFAULT NOW(),
                               last_used_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_oauth_providers_user_id ON oauth_providers(user_id);
CREATE INDEX idx_oauth_providers_provider ON oauth_providers(provider, provider_user_id);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_user_sessions_jwt_id ON user_sessions(jwt_token_id);
CREATE INDEX idx_user_sessions_expires ON user_sessions(expires_at);

-- Add trigger for oauth_providers updated_at
CREATE TRIGGER update_oauth_providers_updated_at
    BEFORE UPDATE ON oauth_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS update_oauth_providers_updated_at ON oauth_providers;
DROP INDEX IF EXISTS idx_oauth_providers_user_id;
DROP INDEX IF EXISTS idx_oauth_providers_provider;
DROP INDEX IF EXISTS idx_user_sessions_user_id;
DROP INDEX IF EXISTS idx_user_sessions_token;
DROP INDEX IF EXISTS idx_user_sessions_jwt_id;
DROP INDEX IF EXISTS idx_user_sessions_expires;

DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS oauth_providers CASCADE;

-- +goose StatementEnd