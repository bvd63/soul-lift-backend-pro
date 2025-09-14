# SoulLift Backend PRO (Fastify + TypeScript)

Production-grade backend for AI-powered quotes with categories & languages.

## Features
- Fastify + TypeScript + Zod validation
- Security: Helmet, CORS (configurable), rate limiting
- Caching (LRU) with per-key TTL
- Retry with backoff on OpenAI API
- Health & readiness endpoints
- Structured error responses
- SSE streaming endpoint (optional in future)
- Dockerfile + GitHub Actions (Render-friendly)

## Env
Copy `.env.example` to `.env` and set values:
- `OPENAI_API_KEY` (required)
- `PORT` (default 3000)
- `ORIGIN` allowed CORS origin(s), `*` for any

## Dev
```bash
npm i
npm run dev
```

## Build & Run
```bash
npm run build
npm start
```

## Endpoints
- `GET /health` → `{ ok, hasKey }`
- `GET /v1/quote?lang=en&category=motivation` → `{ lang, category, text, cached }`

## Deploy (Render)
- Build Command: `npm i && npm run build`
- Start Command: `npm start`
- Add env var: `OPENAI_API_KEY`
