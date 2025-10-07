-- 🗄️ SoulLift Enterprise Database Schema
-- Production-ready PostgreSQL schema with proper indexing

-- Users table with subscription management
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    subscription_tier VARCHAR(50) DEFAULT 'free' CHECK (subscription_tier IN ('free', 'standard', 'pro')),
    subscription_status VARCHAR(50) DEFAULT 'inactive' CHECK (subscription_status IN ('inactive', 'active', 'past_due', 'canceled', 'unpaid')),
    stripe_customer_id VARCHAR(255) UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Subscriptions tracking table
CREATE TABLE user_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_subscription_id VARCHAR(255) UNIQUE,
    stripe_customer_id VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    tier VARCHAR(50) NOT NULL,
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User favorites for quotes
CREATE TABLE user_favorites (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    quote_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_user_quote UNIQUE(user_id, quote_id)
);

-- Audio generation logs for analytics
CREATE TABLE audio_generations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    quote_id INTEGER,
    voice_id VARCHAR(100) NOT NULL,
    text_length INTEGER NOT NULL,
    duration_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User sessions for JWT management
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit logs for security and compliance
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- System metrics for monitoring
CREATE TABLE system_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,4) NOT NULL,
    tags JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;
CREATE INDEX idx_users_subscription_tier ON users(subscription_tier);
CREATE INDEX idx_users_created_at ON users(created_at);

CREATE INDEX idx_subscriptions_user_id ON user_subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe_sub ON user_subscriptions(stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL;
CREATE INDEX idx_subscriptions_status ON user_subscriptions(status);
CREATE INDEX idx_subscriptions_period_end ON user_subscriptions(current_period_end);

CREATE INDEX idx_favorites_user_id ON user_favorites(user_id);
CREATE INDEX idx_favorites_quote_id ON user_favorites(quote_id);
CREATE INDEX idx_favorites_created_at ON user_favorites(created_at);

CREATE INDEX idx_audio_user_id ON audio_generations(user_id);
CREATE INDEX idx_audio_voice_id ON audio_generations(voice_id);
CREATE INDEX idx_audio_created_at ON audio_generations(created_at);

CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_sessions_active ON user_sessions(is_active) WHERE is_active = TRUE;

CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_request_id ON audit_logs(request_id) WHERE request_id IS NOT NULL;

CREATE INDEX idx_metrics_name ON system_metrics(metric_name);
CREATE INDEX idx_metrics_timestamp ON system_metrics(timestamp);

-- Automated updated_at triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON user_subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Data retention policies (run periodically)
-- Clean old audit logs (keep 1 year)
-- DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '1 year';

-- Clean old metrics (keep 90 days)
-- DELETE FROM system_metrics WHERE timestamp < NOW() - INTERVAL '90 days';

-- Clean expired sessions
-- DELETE FROM user_sessions WHERE expires_at < NOW() OR (is_active = FALSE AND last_used_at < NOW() - INTERVAL '30 days');

-- Views for common queries
CREATE VIEW active_subscriptions AS
SELECT 
    u.id as user_id,
    u.email,
    u.subscription_tier,
    u.subscription_status,
    s.stripe_subscription_id,
    s.current_period_end,
    s.cancel_at_period_end
FROM users u
LEFT JOIN user_subscriptions s ON u.id = s.user_id
WHERE u.subscription_status = 'active';

CREATE VIEW user_stats AS
SELECT 
    u.id as user_id,
    u.email,
    u.subscription_tier,
    u.created_at as registered_at,
    COUNT(DISTINCT f.id) as total_favorites,
    COUNT(DISTINCT a.id) as total_audio_generated,
    MAX(a.created_at) as last_audio_generated
FROM users u
LEFT JOIN user_favorites f ON u.id = f.user_id
LEFT JOIN audio_generations a ON u.id = a.user_id
GROUP BY u.id, u.email, u.subscription_tier, u.created_at;

-- Grant permissions (adjust for your setup)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO soulift_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO soulift_app;
