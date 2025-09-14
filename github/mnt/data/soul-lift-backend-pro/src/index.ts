import "dotenv/config";
import Fastify from "fastify";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import pino from "pino";
import quoteRoutes from "./routes/quote.js";

const app = Fastify({
  logger: pino({ level: "info" })
});

await app.register(helmet);
await app.register(cors, { origin: process.env.ORIGIN || "*" });
await app.register(rateLimit, { max: 60, timeWindow: "1 minute" });

app.get("/health", async () => ({
  ok: true,
  hasKey: !!process.env.OPENAI_API_KEY
}));

await app.register(quoteRoutes);

const port = Number(process.env.PORT || 3000);
app.listen({ port, host: "0.0.0.0" })
  .then(() => app.log.info(`🚀 API ready on :${port}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
