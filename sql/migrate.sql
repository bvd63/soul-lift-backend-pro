create table if not exists users (
  email text primary key,
  password_hash text,
  created_at timestamptz default now(),
  badges jsonb default '[]',
  streak int default 0,
  last_login date,
  subscription_status text default 'inactive',
  subscription_tier text default 'free',
  stripe_customer_id text,
  stripe_sub_id text,
  current_period_end bigint
);

create table if not exists favorites (
  email text references users(email) on delete cascade,
  quote_id text,
  created_at timestamptz default now(),
  primary key(email, quote_id)
);

create table if not exists push_tokens (
  id bigserial primary key,
  email text references users(email) on delete cascade,
  token text not null unique,
  created_at timestamptz default now()
);

create table if not exists ai_quotes (
  id bigserial primary key,
  text text not null,
  tags jsonb default '[]',
  score int default 0,
  embedding jsonb,
  created_at timestamptz default now()
);

create table if not exists audit_log (
  id bigserial primary key,
  ts timestamptz default now(),
  type text,
  email text,
  meta jsonb
);
