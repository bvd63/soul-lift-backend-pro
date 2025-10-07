-- migrate.sql — SoulLift DB schema (compatibil cu index.js)
-- Rulează o singură dată pe baza de date.

-- ========== USERS ==========
create table if not exists users (
  email                text primary key,
  password_hash        text,
  created_at           timestamptz default now(),
  badges               jsonb        default '[]',   -- ["Streak 3", "Streak 7", ...]
  streak               int          default 0,
  last_login           date,
  subscription_status  text         default 'inactive', -- inactive | active | past_due | canceled
  subscription_tier    text         default 'free',     -- free | pro
  stripe_customer_id   text,
  stripe_sub_id        text,
  current_period_end   bigint       -- ms epoch (Stripe)
);

create index if not exists idx_users_sub_status on users (subscription_status);
create index if not exists idx_users_last_login on users (last_login);

-- ========== FAVORITES ==========
create table if not exists favorites (
  email       text references users(email) on delete cascade,
  quote_id    text,
  created_at  timestamptz default now(),
  primary key (email, quote_id)
);

create index if not exists idx_favorites_email on favorites (email);

-- ========== PUSH TOKENS (FCM v1) ==========
create table if not exists push_tokens (
  id         bigserial primary key,
  email      text references users(email) on delete cascade,
  token      text not null unique,
  created_at timestamptz default now()
);

create index if not exists idx_push_tokens_email on push_tokens (email);

-- ========== QUOTES (BASIC) ==========
create table if not exists quotes (
  id         bigserial primary key,
  quote      text not null,
  author     text,
  category   text,
  language   text default 'EN',
  created_at timestamptz default now()
);

create index if not exists idx_quotes_category on quotes (category);
create index if not exists idx_quotes_language on quotes (language);
create index if not exists idx_quotes_created_at on quotes (created_at desc);
-- GIN index pentru full-text search în quotes
CREATE INDEX IF NOT EXISTS quotes_fts_idx ON quotes USING GIN (to_tsvector('english', quote || ' ' || coalesce(author, '')));

-- ========== AI QUOTES ==========
create table if not exists ai_quotes (
  id         bigserial primary key,
  text       text  not null,
  tags       jsonb default '[]',   -- ["stoicism","focus",...]
  score      int   default 0,      -- 1..100 (calitate/impact)
  embedding  jsonb,                -- vector (OpenAI embedding)
  created_at timestamptz default now()
);

create index if not exists idx_ai_quotes_score_desc on ai_quotes (score desc);
create index if not exists idx_ai_quotes_created_at on ai_quotes (created_at desc);

-- ========== FULL-TEXT SEARCH INDEXES ==========
-- GIN index pentru full-text search performant
CREATE INDEX IF NOT EXISTS ai_quotes_fts_idx ON ai_quotes USING GIN (to_tsvector('english', text));
-- GIN index pentru căutare în tags (JSONB)
CREATE INDEX IF NOT EXISTS ai_quotes_tags_gin ON ai_quotes USING GIN ((tags));

-- ========== AUDIT LOG ==========
create table if not exists audit_log (
  id    bigserial primary key,
  ts    timestamptz default now(),
  type  text,    -- ex: 'login', 'checkout:create', 'stripe:subscription.update'
  email text,
  meta  jsonb
);

create index if not exists idx_audit_ts_desc on audit_log (ts desc);
create index if not exists idx_audit_type on audit_log (type);

-- ========== AUTH: REFRESH TOKENS ==========
create table if not exists refresh_tokens (
  id          bigserial primary key,
  email       text references users(email) on delete cascade,
  token       text not null unique,
  issued_at   timestamptz default now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);
create index if not exists idx_refresh_email on refresh_tokens (email);
create index if not exists idx_refresh_expires on refresh_tokens (expires_at);

-- ========== STRIPE EVENTS IDEMPOTENCY ==========
create table if not exists consumed_events (
  id          bigserial primary key,
  event_id    text not null,
  event_type  text not null,
  processed_at timestamptz default now(),
  metadata    jsonb,
  unique (event_id, event_type)
);

create index if not exists idx_consumed_events_processed_at on consumed_events (processed_at desc);
create index if not exists idx_consumed_events_type on consumed_events (event_type);

-- ========== EXTRA INDEXES ==========
create index if not exists idx_favorites_created_at on favorites (created_at desc);

-- ========== SOCIAL FEATURES TABLES ==========

-- Quote collections for user-created playlists
CREATE TABLE IF NOT EXISTS quote_collections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) REFERENCES users(email) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  is_public BOOLEAN DEFAULT FALSE,
  tags JSONB DEFAULT '[]',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Bridge table for quotes in collections
CREATE TABLE IF NOT EXISTS collection_quotes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  collection_id UUID REFERENCES quote_collections(id) ON DELETE CASCADE,
  quote_id VARCHAR(255) NOT NULL,
  added_at TIMESTAMP DEFAULT NOW(),
  added_by VARCHAR(255) REFERENCES users(email) ON DELETE CASCADE,
  UNIQUE(collection_id, quote_id)
);

-- Quote sharing with enhanced metadata
CREATE TABLE IF NOT EXISTS quote_shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  quote_id VARCHAR(255) NOT NULL,
  email VARCHAR(255) REFERENCES users(email) ON DELETE CASCADE,
  platform VARCHAR(50) NOT NULL,
  share_url TEXT NOT NULL UNIQUE,
  custom_message TEXT,
  image_style VARCHAR(50) DEFAULT 'minimal',
  include_attribution BOOLEAN DEFAULT TRUE,
  click_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Quote likes/reactions
CREATE TABLE IF NOT EXISTS quote_likes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  quote_id VARCHAR(255) NOT NULL,
  email VARCHAR(255) REFERENCES users(email) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(quote_id, email)
);

-- Social features indexes for performance
CREATE INDEX IF NOT EXISTS idx_quote_collections_email ON quote_collections(email);
CREATE INDEX IF NOT EXISTS idx_quote_collections_public ON quote_collections(is_public) WHERE is_public = true;
CREATE INDEX IF NOT EXISTS idx_collection_quotes_collection ON collection_quotes(collection_id);
CREATE INDEX IF NOT EXISTS idx_quote_shares_email ON quote_shares(email);
CREATE INDEX IF NOT EXISTS idx_quote_shares_quote ON quote_shares(quote_id);
CREATE INDEX IF NOT EXISTS idx_quote_likes_quote ON quote_likes(quote_id);
CREATE INDEX IF NOT EXISTS idx_quote_likes_email ON quote_likes(email);

-- ========== CONTENT CURATION ENHANCEMENTS ==========

-- Add premium tier and enhanced categorization to ai_quotes
ALTER TABLE ai_quotes ADD COLUMN IF NOT EXISTS premium_tier VARCHAR(20) DEFAULT NULL;
ALTER TABLE ai_quotes ADD COLUMN IF NOT EXISTS categorization JSONB DEFAULT '{}';
ALTER TABLE ai_quotes ADD COLUMN IF NOT EXISTS quality_factors JSONB DEFAULT '{}';
ALTER TABLE ai_quotes ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();

-- Content performance tracking
CREATE TABLE IF NOT EXISTS quote_analytics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  quote_id VARCHAR(255) NOT NULL,
  metric_type VARCHAR(50) NOT NULL, -- 'view', 'audio_request', 'share_click', 'time_spent'
  metric_value NUMERIC DEFAULT 1,
  user_email VARCHAR(255),
  session_id VARCHAR(255),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Audio cache metadata
CREATE TABLE IF NOT EXISTS audio_cache (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  quote_id VARCHAR(255) NOT NULL,
  voice VARCHAR(20) NOT NULL,
  speed NUMERIC NOT NULL,
  format VARCHAR(10) NOT NULL,
  file_url TEXT,
  file_size INTEGER,
  duration_seconds INTEGER,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  UNIQUE(quote_id, voice, speed, format)
);

-- Content curation indexes
CREATE INDEX IF NOT EXISTS idx_ai_quotes_premium_tier ON ai_quotes(premium_tier) WHERE premium_tier IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_quotes_categorization ON ai_quotes USING GIN (categorization);
CREATE INDEX IF NOT EXISTS idx_ai_quotes_updated_at ON ai_quotes(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_quote_analytics_quote ON quote_analytics(quote_id);
CREATE INDEX IF NOT EXISTS idx_quote_analytics_type ON quote_analytics(metric_type);
CREATE INDEX IF NOT EXISTS idx_quote_analytics_created ON quote_analytics(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audio_cache_quote ON audio_cache(quote_id);
CREATE INDEX IF NOT EXISTS idx_audio_cache_expires ON audio_cache(expires_at);

-- ========== ADVANCED ANALYTICS TABLES ==========

-- Mood tracking for personalization
CREATE TABLE IF NOT EXISTS mood_tracking (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) REFERENCES users(email) ON DELETE CASCADE,
  mood VARCHAR(50) NOT NULL,
  energy_level INTEGER CHECK (energy_level >= 1 AND energy_level <= 10),
  context TEXT,
  triggers JSONB DEFAULT '[]',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Analytics indexes
CREATE INDEX IF NOT EXISTS idx_mood_tracking_email ON mood_tracking(email);
CREATE INDEX IF NOT EXISTS idx_mood_tracking_created ON mood_tracking(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mood_tracking_mood ON mood_tracking(mood);

-- ========== OPTIONAL: VIEW-uri simple pentru raportări ==========
-- select * from audit_log where ts > now() - interval '24 hours' order by ts desc;
-- select count(*) from ai_quotes where created_at > now() - interval '24 hours';
