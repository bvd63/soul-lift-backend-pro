# SoulLift Backend PRO (Render-ready)

Fastify + TypeScript backend pentru citate AI multilingve.

## Endpoints
- `GET /health` → `{ ok, hasKey }`
- `GET /v1/quote?lang=en&category=motivation` → `{ lang, category, text }`

## Deploy pe Render
- Language: **Node**
- Build Command: `npm i && npm run build`
- Start Command: `npm start`
- Env:
  - `OPENAI_API_KEY` = `sk-...`
  - `ORIGIN` = `*` (sau domeniul tău)

