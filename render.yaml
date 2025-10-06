# render.yaml — SoulLift backend (Fastify + Stripe + OpenAI/DeepL + FCM v1 + Sentry)
# Compatibil cu index.js (health: /health, cron intern, Stripe raw-body)
envVarGroups:
  - name: soullift-common
    envVars:
      - key: NODE_ENV
        value: production
      - key: CORS_ORIGINS
        value: "http://localhost:5173"
      - key: USE_OPENAI
        value: "true"
      - key: DEEPL_ENDPOINT
        value: "https://api-free.deepl.com"
      - key: SENTRY_DSN
        sync: false
      - key: DATABASE_URL
        sync: false
      - key: DATABASE_SSL
        value: false

services:
  - type: web
    name: soullift-backend
    env: node
    plan: starter              # poți pune "free" pentru test, dar "starter" e mai stabil
    region: frankfurt          # sau oregon/singapore, după publicul tău
    branch: main
    autoDeploy: true
    pullRequestPreviewsEnabled: false

    envVarGroups:
      - soullift-common

    buildCommand: "npm ci"
    startCommand: "node index.js"

    # Se potrivește cu rutele din index.js (există și /healthz ca alias)
    healthCheckPath: /api/health
    healthCheckTimeout: 100

    envVars:
      # Runtime
      - key: NODE_VERSION
        value: 20
      - key: NODE_ENV
        value: production
      - key: PORT
        value: 3000
      - key: APP_BASE_URL
        value: "https://soullift-backend.onrender.com"   # ajustează după ce ai domeniu
      - key: FRONTEND_URL
        value: "http://localhost:5173"                    # ajustează la frontend-ul tău

      # --- Secrets necesare (setează valorile în Dashboard; aici le lăsăm ne-sincronizate) ---
      # Auth / JWT
      - key: JWT_SECRET
        sync: false

      # OpenAI / DeepL
      - key: OPENAI_API_KEY
        sync: false
      - key: DEEPL_API_KEY
        sync: false
      - key: DEEPL_ENDPOINT
        value: "https://api-free.deepl.com"

      # Stripe
      - key: STRIPE_SECRET_KEY
        sync: false
      - key: STRIPE_WEBHOOK_SECRET
        sync: false
      - key: STRIPE_PRICE_ID_MONTHLY
        sync: false
      - key: STRIPE_PRICE_ID_YEARLY
        sync: false

      # FCM v1 (Service Account) — înlocuiește FCM_SERVER_KEY (legacy)
      - key: FIREBASE_PROJECT_ID
        sync: false
      - key: FIREBASE_CLIENT_EMAIL
        sync: false
      - key: FIREBASE_PRIVATE_KEY       # păstrează \n în valoare
        sync: false

      # Sentry (opțional)
      - key: SENTRY_DSN
        sync: false

      # Daily Digest Telegram (opțional)
      - key: TELEGRAM_BOT_TOKEN
        sync: false
      - key: TELEGRAM_CHAT_ID
        sync: false

      # Redis Enterprise Cloud (Managed)
      - key: REDIS_URL
        sync: false
      - key: REDIS_USERNAME
        value: default
      - key: REDIS_PASSWORD
        sync: false
      - key: REDIS_TLS
        value: true

      # Upstash Redis REST (alternativ, nu seta REDIS_URL dacă folosești asta)
      - key: UPSTASH_REDIS_REST_URL
        sync: false
      - key: UPSTASH_REDIS_REST_TOKEN
        sync: false
