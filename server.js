// server.js — Mongo + Items CRUD + JWT Auth + Ownership + Prod hardening (ESM)

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { config } from "./config/env.js"; // MONGODB_URI, JWT_SECRET, PORT, CORS_ORIGINS, NODE_ENV

/* -------------------- App & Middleware -------------------- */
const app = express();

// security + logging
app.use(helmet());
app.use(morgan(config.NODE_ENV === "production" ? "combined" : "dev"));

// CORS (allow list from .env)
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // curl/postman
      if (config.CORS_ORIGINS.includes("*") || config.CORS_ORIGINS.includes(origin)) return cb(null, true);
      cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

// rate limit (100 req / 15 min per IP)
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// JSON body
app.use(express.json());

/* -------------------- Database -------------------- */
await mongoose.connect(config.MONGODB_URI);
console.log("✅ Mongo connected");

/* -------------------- Models -------------------- */
const itemSchema = new mongoose.Schema(
  {
    name:  { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true }
);
const Item = mongoose.model("Item", itemSchema);

const userSchema = new mongoose.Schema(
  {
    email:        { type: String, required: true, trim: true, lowercase: true, unique: true },
    passwordHash: { type: String, required: true },
    role:         { type: String, enum: ["user", "admin"], default: "user" },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

/* -------------------- Auth helpers -------------------- */
function signToken(user) {
  return jwt.sign({ sub: user._id, email: user.email, role: user.role }, config.JWT_SECRET, { expiresIn: "7d" });
}
function authRequired(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    req.user = jwt.verify(token, config.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) return res.status(403).json({ error: "forbidden" });
    next();
  };
}
async function requireOwner(req, res, next) {
  try {
    const item = await Item.findById(req.params.id).select("owner");
    if (!item) return res.status(404).json({ error: "not_found" });
    if (String(item.owner) !== String(req.user.sub) && req.user.role !== "admin") {
      return res.status(403).json({ error: "forbidden", message: "not your item" });
    }
    next();
  } catch (e) { next(e); }
}

/* -------------------- Routes -------------------- */
// Health
app.get("/health", (_req, res) => res.json({ status: "ok" }));

// Auth
app.post("/auth/register", async (req, res, next) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    if (!email) return res.status(400).json({ error: "email is required" });
    if (password.length < 6) return res.status(400).json({ error: "password min 6 chars" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: "email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });

    const token = signToken(user);
    res.status(201).json({ token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (e) { next(e); }
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "invalid_credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });

    const token = signToken(user);
    res.json({ token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (e) { next(e); }
});

// Items (public reads)
app.get("/items", async (_req, res, next) => {
  try {
    const items = await Item.find().sort({ createdAt: -1 });
    res.json(items);
  } catch (e) { next(e); }
});
app.get("/items/:id", async (req, res, next) => {
  try {
    const item = await Item.findById(req.params.id);
    if (!item) return res.status(404).json({ error: "not_found" });
    res.json(item);
  } catch (e) { next(e); }
});

// My items (auth)
app.get("/my/items", authRequired, async (req, res, next) => {
  try {
    const items = await Item.find({ owner: req.user.sub }).sort({ createdAt: -1 });
    res.json(items);
  } catch (e) { next(e); }
});

// Items (writes: auth + ownership)
app.post("/items", authRequired, async (req, res, next) => {
  try {
    const name = String(req.body?.name || "").trim();
    const price = Number(req.body?.price);
    if (!name) return res.status(400).json({ error: "name is required" });
    if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: "price must be a non-negative number" });

    const created = await Item.create({ name, price, owner: req.user.sub });
    res.status(201).json(created);
  } catch (e) { next(e); }
});

app.put("/items/:id", authRequired, requireOwner, async (req, res, next) => {
  try {
    const patch = {};
    if (req.body.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name) return res.status(400).json({ error: "name cannot be empty" });
      patch.name = name;
    }
    if (req.body.price !== undefined) {
      const price = Number(req.body.price);
      if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: "price must be a non-negative number" });
      patch.price = price;
    }
    const updated = await Item.findByIdAndUpdate(req.params.id, patch, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ error: "not_found" });
    res.json(updated);
  } catch (e) { next(e); }
});

app.delete("/items/:id", authRequired, requireOwner, async (req, res, next) => {
  try {
    const del = await Item.findByIdAndDelete(req.params.id);
    if (!del) return res.status(404).json({ error: "not_found" });
    res.status(204).end();
  } catch (e) { next(e); }
});

/* -------------------- Errors -------------------- */
app.use((_req, _res, next) => { const err = new Error("Not found"); err.status = 404; next(err); });
app.use((err, _req, res, _next) => {
  if (err?.name === "CastError") return res.status(400).json({ error: "bad_id", message: "invalid id format" });
  if (err?.code === 11000) return res.status(409).json({ error: "conflict", message: "duplicate key" });
  const status = err.status || 500;
  res.status(status).json({ error: status === 404 ? "not_found" : "server_error", message: err.message || "Unknown error" });
});

/* -------------------- Start -------------------- */
app.listen(config.PORT, () =>
  console.log(`🚀 API on http://localhost:${config.PORT} (env: ${config.NODE_ENV})`)
);