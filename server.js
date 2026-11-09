"use strict";
require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = path.join(__dirname, "public");
// Dashboard sebaiknya di luar folder public (private/dashboard.html) agar tidak bisa
// dilayani CDN/hosting statis (Vercel, Netlify, dll) tanpa melewati middleware.
const PRIVATE_DASH = path.join(__dirname, "private", "dashboard.html");
const DASH_FILE = fs.existsSync(PRIVATE_DASH) ? PRIVATE_DASH : path.join(ROOT, "dashboard.html");
if (DASH_FILE !== PRIVATE_DASH)
  console.warn("PERINGATAN: pindahkan public/dashboard.html ke private/dashboard.html agar benar-benar terproteksi.");
const IS_PROD = process.env.NODE_ENV === "production";

// ---- Konfigurasi wajib ----
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "hiro-friends";
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32 || !process.env.DATABASE_URL) {
  console.error("Isi SESSION_SECRET (>=32 karakter) dan DATABASE_URL di .env");
  process.exit(1);
}
const COOKIE = "nk_session";
const SESSION_DAYS = 5;
// Opsional: batasi akun tertentu, contoh ALLOWED_EMAILS=a@gmail.com,b@gmail.com
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  connectionTimeoutMillis: 10000,
});
pool.on("error", (e) => console.error("Postgres error:", e.message));

app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}
function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  throw e;
}

// ---- Header keamanan & proteksi origin (tanpa CORS terbuka) ----
app.use((req, res, next) => {
  res.set({
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  });
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const origin = req.get("origin");
  if (origin) {
    try {
      if (new URL(origin).host !== req.get("host"))
        return res.status(403).json({ error: "Origin tidak diizinkan." });
    } catch {
      return res.status(403).json({ error: "Origin tidak valid." });
    }
  }
  next();
});

// ---- Verifikasi Firebase ID Token (tanpa firebase-admin) ----
const CERT_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
let certCache = { certs: null, exp: 0 };

async function getCerts(force = false) {
  if (!force && certCache.certs && Date.now() < certCache.exp) return certCache.certs;
  const r = await fetch(CERT_URL);
  if (!r.ok) httpError(503, "Gagal mengambil sertifikat verifikasi Google.");
  const m = /max-age=(\d+)/.exec(r.headers.get("cache-control") || "");
  certCache = {
    certs: await r.json(),
    exp: Date.now() + (m ? Number(m[1]) : 3600) * 1000,
  };
  return certCache.certs;
}

async function verifyFirebaseIdToken(idToken) {
  const decoded = jwt.decode(idToken, { complete: true });
  const kid = decoded?.header?.kid;
  if (!kid || decoded.header.alg !== "RS256") httpError(401, "Token tidak valid.");
  let certs = await getCerts();
  if (!certs[kid]) certs = await getCerts(true); // kunci Google bisa dirotasi
  if (!certs[kid]) httpError(401, "Token tidak valid.");
  let payload;
  try {
    payload = jwt.verify(idToken, certs[kid], {
      algorithms: ["RS256"],
      audience: PROJECT_ID,
      issuer: `https://securetoken.google.com/${PROJECT_ID}`,
    });
  } catch {
    httpError(401, "Token tidak valid atau kedaluwarsa.");
  }
  if (!payload.sub || payload.sub.length > 128) httpError(401, "Token tidak valid.");
  return payload;
}

// ---- Middleware autentikasi ----
function readSession(req) {
  try {
    const s = jwt.verify(req.cookies[COOKIE] || "", SESSION_SECRET, { algorithms: ["HS256"] });
    return s.uid ? s : null;
  } catch {
    return null;
  }
}
function requireAuth(req, res, next) {
  const session = readSession(req);
  if (session) {
    req.user = session;
    return next();
  }
  if (req.path.startsWith("/api/") || req.originalUrl.startsWith("/api/"))
    return res.status(401).json({ error: "Belum login. Silakan masuk dengan Google." });
  return res.redirect("/");
}

const cookieOpts = {
  httpOnly: true,
  sameSite: "lax",
  secure: IS_PROD,
  path: "/",
};

app.post(
  "/api/auth/session",
  asyncRoute(async (req, res) => {
    const idToken = req.body?.idToken;
    if (typeof idToken !== "string" || idToken.length < 100 || idToken.length > 5000)
      httpError(400, "idToken wajib diisi.");
    const p = await verifyFirebaseIdToken(idToken);
    if (p.firebase?.sign_in_provider !== "google.com")
      httpError(403, "Hanya login dengan Google yang diizinkan.");
    if (!p.email || p.email_verified !== true)
      httpError(403, "Email Google belum terverifikasi.");
    if (ALLOWED_EMAILS.length && !ALLOWED_EMAILS.includes(p.email.toLowerCase()))
      httpError(403, "Akun ini tidak memiliki akses.");

    const token = jwt.sign({ uid: p.sub, email: p.email }, SESSION_SECRET, {
      algorithm: "HS256",
      expiresIn: `${SESSION_DAYS}d`,
    });
    res.cookie(COOKIE, token, { ...cookieOpts, maxAge: SESSION_DAYS * 86400000 });
    res.json({ ok: true });
  }),
);
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie(COOKIE, cookieOpts);
  res.json({ ok: true });
});
app.get("/api/auth/me", requireAuth, (req, res) =>
  res.json({ authenticated: true, uid: req.user.uid, email: req.user.email }),
);

// ---- Halaman (dashboard dilindungi; WAJIB sebelum express.static) ----
app.get("/", (req, res) => res.sendFile(path.join(ROOT, "index.html")));
app.get(["/login", "/login.html"], (req, res) =>
  res.sendFile(path.join(ROOT, "login.html")),
);
app.get(["/dashboard", "/dashboard.html"], requireAuth, (req, res) =>
  res.sendFile(DASH_FILE),
);

// ---- API Kotoba (hanya READ, wajib login) ----
app.get(
  "/api/decks",
  requireAuth,
  asyncRoute(async (req, res) => {
    const r = await pool.query(`
      SELECT d.id, d.name, d.description, d.color, d.icon,
      (SELECT COUNT(*)::int FROM flashcards f WHERE f.deck_id=d.id AND f.archived=false) AS card_count
      FROM decks d WHERE d.archived=false ORDER BY d.id DESC
    `);
    res.json({ data: r.rows });
  }),
);

app.get(
  "/api/flashcards",
  requireAuth,
  asyncRoute(async (req, res) => {
    const deckId = Number(req.query.deckId);
    if (!Number.isSafeInteger(deckId) || deckId < 1)
      httpError(400, "deckId tidak valid.");
    const r = await pool.query(
      `SELECT id, kanji, furigana, arti, example_sentence, sentence_translation, notes, source_url, audio_url
       FROM flashcards WHERE deck_id=$1 AND archived=false ORDER BY id`,
      [deckId],
    );
    res.json({ data: r.rows });
  }),
);

// Endpoint /api/* lain yang tidak ada → 404 JSON (bukan jatuh ke static)
app.use("/api", (req, res) => res.status(404).json({ error: "Endpoint tidak ditemukan." }));

// File statis publik (css/js/gambar, login.html, dll). index dimatikan agar tidak bocor.
app.use(express.static(ROOT, { index: false }));

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  let status = err.status || 500;
  let message = status === 500 ? "Terjadi kesalahan server." : err.message;
  if (err instanceof SyntaxError && "body" in err) {
    status = 400;
    message = "Format JSON tidak valid.";
  }
  if (status === 500) console.error("Request failed:", err.message);
  res.status(status).json({ error: message });
});

app.listen(PORT, () => console.log(`API Server aktif: http://localhost:${PORT}`));