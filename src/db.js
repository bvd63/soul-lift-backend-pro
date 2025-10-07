// Database connection and utilities for SoulLift
import pkg from 'pg';
const { Pool } = pkg;

const url = process.env.DATABASE_URL;

if (!url) {
  throw new Error('Missing DATABASE_URL');
}

// Detect if we need SSL (Render.com external connections)
const needsSSL = /render\.com/i.test(url) && !url.includes('.internal');

export const pool = new Pool({
  connectionString: url,
  ssl: needsSSL ? { rejectUnauthorized: false } : false,
  max: 10,
  connectionTimeoutMillis: 5000,
});

// Test database connection
export async function assertDbConnection() {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT 1 as ok');
    return result.rows[0];
  } finally {
    client.release();
  }
}

// Graceful shutdown
export async function closeDb() {
  await pool.end();
}