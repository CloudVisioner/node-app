// config/env.js
import dotenv from "dotenv";
dotenv.config();

function need(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`❌ Missing required env: ${name}`);
    process.exit(1);
  }
  return v;
}

export const config = {
  NODE_ENV: process.env.NODE_ENV || "development",
  PORT: Number(process.env.PORT || 3000),
  MONGODB_URI: need("MONGODB_URI"),
  JWT_SECRET: need("JWT_SECRET"),
  CORS_ORIGINS: (process.env.CORS_ORIGIN || "*")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean),
};