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

-- ========== OPTIONAL: VIEW-uri simple pentru raportări ==========
-- select * from audit_log where ts > now() - interval '24 hours' order by ts desc;
-- select count(*) from ai_quotes where created_at > now() - interval '24 hours';
