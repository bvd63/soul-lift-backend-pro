# 🚀 SoulLift Enterprise - Deployment & Infrastructure

## Quick Start

Replace your existing `index.js` with `index-enterprise.js` for production deployment:

```bash
# Backup current version
cp index.js index-backup.js

# Use enterprise version
cp index-enterprise.js index.js

# Deploy to Render
git add .
git commit -m "Deploy enterprise version"
git push
```

## 🏗️ Enterprise Features Implemented

### ✅ 1. Securitate & Auth serios
- **Strict CORS** with origin validation
- **Helmet CSP** with secure content policies  
- **Rate limiting** (100 req/min with IP-based keys)
- **JWT rotation** with refresh tokens (15min + 7day)
- **Brute-force protection** (5 attempts per 15min window)
- **Request correlation** with unique IDs

### ✅ 2. Observabilitate, erori și sănătate  
- **Health endpoints**: `/health`, `/healthz`, `/readyz`
- **Prometheus metrics** at `/api/metrics`
- **Global error handler** with correlation IDs
- **Request/response logging** with duration tracking
- **Admin endpoints** for error logs and performance

### ✅ 3. Stripe battle-tested
- **Idempotent webhooks** with Redis deduplication
- **Subscription state sync** in database
- **Enhanced checkout** with retry logic
- **Webhook handlers** for all subscription events
- **Payment failure handling** with status updates

### ✅ 4. Performanță, cache & joburi
- **Redis caching** for quotes, checkout sessions, metrics
- **Optimized queries** with proper error handling  
- **Background metrics** collection and storage
- **Memory monitoring** and leak detection
- **Service health checks** for all dependencies

### ✅ 5. Deploy, date și DR
- **Multi-environment** configuration
- **Graceful shutdown** with cleanup
- **Database migration** ready structure
- **Backup-ready** audit logging
- **Production hardening** with security headers

## 🎵 Audio System (20 Voices)

### Femei (10 voci):
- `sophia_calm` - Calm & nurturing (Standard)
- `emma_wise` - Wise & grounded (Standard) 
- `luna_gentle` - Gentle & soothing (Standard)
- `aria_inspiring` - Inspiring & uplifting (Pro)
- `zoe_energetic` - Energetic & motivating (Pro)
- `maya_peaceful` - Peaceful & meditative (Pro)
- `iris_thoughtful` - Thoughtful & reflective (Pro)
- `nova_confident` - Confident & empowering (Pro)
- `serena_compassionate` - Compassionate & warm (Pro)
- `grace_elegant` - Elegant & sophisticated (Pro)

### Bărbați (10 voci):
- `alex_strong` - Strong & confident (Standard)
- `david_warm` - Warm & reassuring (Standard)
- `marcus_wise` - Wise & experienced (Standard)
- `leo_inspiring` - Inspiring & bold (Pro)
- `noah_gentle` - Gentle & kind (Pro)
- `sage_philosophical` - Philosophical & deep (Pro)
- `atlas_powerful` - Powerful & commanding (Pro)
- `river_calm` - Calm & flowing (Pro)
- `phoenix_transformative` - Transformative & renewal (Pro)
- `zen_mindful` - Mindful & centered (Pro)

## 💰 Pricing Structure

- **Free**: Basic quotes, 50 favorites, no audio
- **Standard**: $6.49/month, 6 voices, unlimited favorites
- **Pro**: $9.49/month, 20 voices, premium features

## 🔧 Environment Variables

```bash
# Required
NODE_ENV=production
PORT=3000
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-refresh-secret-key
FRONTEND_URL=https://your-domain.com
CORS_ORIGIN=https://your-domain.com

# Optional (enables features)
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
OPENAI_API_KEY=sk-...
STRIPE_SECRET_KEY=sk_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID_STANDARD_MONTHLY=price_...
STRIPE_PRICE_ID_PRO_MONTHLY=price_...
ADMIN_KEY=your-admin-secret
```

## 📊 Monitoring Endpoints

- `GET /health` - Basic health check
- `GET /healthz` - Kubernetes-style health  
- `GET /readyz` - Readiness check with dependencies
- `GET /api/health` - Service status overview
- `GET /api/metrics` - Prometheus metrics
- `GET /api/admin/errors` - Error logs (admin only)
- `GET /api/admin/performance` - Performance metrics (admin only)

## 🗄️ Database Schema

The app works with or without a database. If `DATABASE_URL` is provided, it expects these tables:

```sql
-- Users table
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  subscription_tier VARCHAR(50) DEFAULT 'free',
  subscription_status VARCHAR(50) DEFAULT 'inactive',
  stripe_customer_id VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Subscriptions table  
CREATE TABLE user_subscriptions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  stripe_subscription_id VARCHAR(255) UNIQUE,
  stripe_customer_id VARCHAR(255),
  status VARCHAR(50),
  tier VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Favorites table
CREATE TABLE user_favorites (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  quote_id INTEGER,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, quote_id)
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id);
CREATE INDEX idx_subscriptions_user ON user_subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe ON user_subscriptions(stripe_subscription_id);
CREATE INDEX idx_favorites_user ON user_favorites(user_id);
```

## 🔄 Deployment Process

1. **Push to Render**: App auto-deploys from Git
2. **Health check**: Render monitors `/healthz`
3. **Environment**: All secrets configured via dashboard
4. **Scaling**: Standard plan handles production traffic
5. **Monitoring**: Built-in metrics and error tracking

## 🚨 Production Checklist

- [ ] All environment variables configured
- [ ] Database tables created
- [ ] Stripe webhooks configured to `/api/webhooks/stripe`
- [ ] CORS origins match your frontend domains
- [ ] Admin key secured for monitoring endpoints
- [ ] Redis configured for optimal caching
- [ ] SSL/HTTPS enabled (automatic with Render)

## 🎯 API Endpoints Summary

### Auth
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login  
- `POST /api/auth/refresh` - Token refresh

### Quotes & Audio
- `GET /api/quotes` - Get filtered quotes
- `POST /api/audio/generate` - Generate audio (requires subscription)
- `GET /api/voices` - Available voices (requires subscription)

### Billing  
- `GET /api/pricing` - Pricing plans
- `POST /api/billing/checkout` - Create checkout session
- `POST /api/webhooks/stripe` - Stripe webhooks

### User Features
- `POST /api/favorites` - Add favorite quote
- `GET /api/favorites` - Get user favorites
- `GET /api/analytics/dashboard` - User analytics (requires subscription)

### System
- `GET /health` - Health check
- `GET /api/metrics` - Prometheus metrics
- `GET /docs` - API documentation (Swagger)

Enterprise version is ready for production! 🚀