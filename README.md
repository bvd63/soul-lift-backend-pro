# Soul Lift Backend

## Overview
Soul Lift Backend is a minimal yet powerful backend designed to handle AI-driven functionalities, including personalized recommendations and quotes. It leverages modern technologies like Fastify, Redis, and Stripe for scalability and performance.

## Features
- AI personalization and recommendations
- Advanced caching with Redis
- Secure API with JWT authentication
- Integration with Stripe for payments
- Logging and monitoring with Sentry

## Installation
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

## Environment Variables
Create a `.env` file in the root directory and configure the following variables:
```env
OPENAI_API_KEY=your_openai_api_key
ORIGIN=your_origin_url
JWT_SECRET=your_jwt_secret
REDIS_URL=your_redis_url
STRIPE_SECRET_KEY=your_stripe_secret_key
```

Refer to `.env.example` for more details.
