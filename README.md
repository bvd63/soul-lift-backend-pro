# Soul Lift Backend

## Overview
Soul Lift Backend is a production-ready backend designed to handle AI-driven functionalities, including personalized recommendations and quotes. It leverages modern technologies like Fastify, PostgreSQL, Redis, and Stripe for scalability and performance.

## Features
- 🤖 AI personalization and recommendations (OpenAI + DeepL fallback)
- 🔐 Secure JWT authentication with blacklist support
- 💳 Stripe payment integration with webhook verification
- 📊 Advanced caching with Redis/Upstash and fallback to memory cache
- 🚀 Health monitoring and metrics
- 📝 Comprehensive API documentation with Swagger
- 🔍 Logging and monitoring with Sentry
- 🧪 Full test coverage including integration tests

## Quick Start

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/soul-lift-backend.git
   ```
2. Navigate to the project directory:
   ```bash
   cd soul-lift-backend
   ```
3. Install dependencies:
   ```bash
   npm install
   ```

### Environment Setup
Create a `.env` file in the root directory. See [INTEGRATION_TESTING.md](./INTEGRATION_TESTING.md) for complete environment variable documentation.

**Essential variables:**
```env
NODE_ENV=development
JWT_SECRET=your-secret-key-here
DATABASE_URL=postgresql://user:pass@host:port/db
```

### Database Setup
```bash
# Run database migrations
npm run migrate
```

### Running the Server
```bash
# Development mode
npm run dev

# Production mode
npm run start:prod
```

## Testing

### Basic Tests (No External Dependencies)
```bash
npm test                    # Core functionality tests
npm run test:logout         # JWT authentication flow tests  
npm run test:migration      # Database migration validation
npm run test:all           # All basic tests
```

### Integration Tests (Requires Real API Keys)
```bash
npm run test:integration    # E2E tests with Stripe, OpenAI, etc.
```

See [INTEGRATION_TESTING.md](./INTEGRATION_TESTING.md) for detailed testing documentation.

## API Documentation

- **Swagger UI**: `/docs` (when server is running)
- **Health Check**: `/health` 
- **Metrics**: `/metrics` (Prometheus format)

## Architecture

### Core Components
- **Fastify**: Web framework with plugin architecture
- **PostgreSQL**: Primary database with connection pooling
- **Redis/Upstash**: Distributed caching and session storage
- **Stripe**: Payment processing and webhook handling
- **OpenAI**: AI personalization with retry logic
- **DeepL**: Translation fallback service

### Key Features
- **JWT Blacklisting**: Secure logout with token invalidation
- **Request-scoped Logging**: Structured logs with request IDs
- **Circuit Breaker**: Resilient external API calls
- **Graceful Degradation**: Fallbacks when external services are unavailable
- **Rate Limiting**: Protection against abuse
- **CORS Configuration**: Secure cross-origin requests
