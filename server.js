'use strict';
/**
 * MAC'LAY Workspace — server
 * Zero npm dependencies. Needs Node 22.13+ (uses the built-in node:sqlite).
 *
 *   npm start                                  run the site on http://localhost:3000
 *   node server.js --make-owner you@mail.com  give an existing account owner access
 *   node server.js --reset-password you@mail.com NewPassword123
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

/* ───────────────────────── config ───────────────────────── */
function loadDotEnv() {
  const f = path.join(__dirname, '.env');
  if (!fs.existsSync(f)) return;
  for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i.exec(line);
    if (!m || line.trim().startsWith('#')) continue;
    if (process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}
loadDotEnv();

const CFG = {
  port: Number(process.env.PORT) || 3000,
  host: process.env.HOST || '0.0.0.0',
  production: process.env.PRODUCTION === '1',
  trustProxy: process.env.TRUST_PROXY === '1',
  ownerEmail: (process.env.OWNER_EMAIL || '').trim().toLowerCase(),
  dataDir: process.env.DATA_DIR || path.join(__dirname, 'data'),
  anthropicKey: process.env.ANTHROPIC_API_KEY || '',
  aiDailyLimit: Number(process.env.AI_DAILY_LIMIT) || 40,
  aiModels: (process.env.AI_MODELS || 'claude-sonnet-5-5,claude-opus-5-5,claude-haiku-5-5').split(',').map(s => s.trim()).filter(Boolean),
  judge0Url: (process.env.JUDGE0_URL || '').replace(/\/$/, ''),
  judge0Key: process.env.JUDGE0_API_KEY || '',
  judge0Host: process.env.JUDGE0_API_HOST || '',
  maxBody: 256 * 1024,
  sessionDays: 14,
  quotaBytes: 2 * 1024 * 1024,   // storage per user
  maxSnippets: 200,
  maxSnippetBytes: 100 * 1024
};
const PUBLIC_DIR = path.join(__dirname, 'public');
const LANGS = ['javascript', 'python', 'html', 'c', 'cpp', 'java', 'php', 'sql', 'bash'];
const SECTIONS = ['home', 'editor', 'ai', 'files', 'deploy', 'contact', 'account'];

/* ───────────────────────── database ───────────────────────── */
fs.mkdirSync(CFG.dataDir, { recursive: true });
const db = new DatabaseSync(path.join(CFG.dataDir, 'maclay.db'));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  bio TEXT NOT NULL DEFAULT '',
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','owner')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','banned')),
  created_at INTEGER NOT NULL,
  last_login INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS snippets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  lang TEXT NOT NULL,
  code TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snippets_user ON snippets(user_id);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  day TEXT NOT NULL,
  type TEXT NOT NULL,
  visitor TEXT,
  user_id INTEGER,
  device TEXT,
  page TEXT,
  lang TEXT,
  info TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_day ON events(day, type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  msg TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'info',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

const q = {
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  insertUser: db.prepare('INSERT INTO users (email,name,pass_hash,role,created_at) VALUES (?,?,?,?,?)'),
  ownerCount: db.prepare("SELECT COUNT(*) c FROM users WHERE role='owner' AND status='active'"),
  session: db.prepare('SELECT s.id sid, s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?'),
  insertSession: db.prepare('INSERT INTO sessions (id,user_id,created_at,expires_at) VALUES (?,?,?,?)'),
  extendSession: db.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?'),
  delSession: db.prepare('DELETE FROM sessions WHERE id = ?'),
  delUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  delOtherSessions: db.prepare('DELETE FROM sessions WHERE user_id = ? AND id <> ?'),
  purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
  snippetsOf: db.prepare('SELECT id,name,lang,code,bytes,created_at,updated_at FROM snippets WHERE user_id = ? ORDER BY updated_at DESC'),
  snippetOne: db.prepare('SELECT * FROM snippets WHERE id = ? AND user_id = ?'),
  insertSnippet: db.prepare('INSERT INTO snippets (user_id,name,lang,code,bytes,created_at,updated_at) VALUES (?,?,?,?,?,?,?)'),
  updateSnippet: db.prepare('UPDATE snippets SET name=?, lang=?, code=?, bytes=?, updated_at=? WHERE id=? AND user_id=?'),
  deleteSnippet: db.prepare('DELETE FROM snippets WHERE id = ? AND user_id = ?'),
  usage: db.prepare('SELECT COUNT(*) n, COALESCE(SUM(bytes),0) b FROM snippets WHERE user_id = ?'),
  usageByLang: db.prepare('SELECT lang, COUNT(*) n, COALESCE(SUM(bytes),0) b FROM snippets WHERE user_id = ? GROUP BY lang'),
  insertEvent: db.prepare('INSERT INTO events (ts,day,type,visitor,user_id,device,page,lang,info) VALUES (?,?,?,?,?,?,?,?,?)'),
  getSetting: db.prepare('SELECT value FROM settings WHERE key = ?'),
  putSetting: db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
  announcements: db.prepare('SELECT id,msg,type,created_at FROM announcements ORDER BY id DESC LIMIT 20'),
  insertAnn: db.prepare('INSERT INTO announcements (msg,type,created_at) VALUES (?,?,?)'),
  delAnn: db.prepare('DELETE FROM announcements WHERE id = ?')
};

function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; }
}

/* ───────────────────────── helpers ───────────────────────── */
const now = () => Date.now();
const dayOf = (ts = now()) => new Date(ts).toISOString().slice(0, 10);
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const getSetting = (k, d = null) => { const r = q.getSetting.get(k); return r ? r.value : d; };

let SERVER_SECRET = getSetting('server_secret');
if (!SERVER_SECRET) { SERVER_SECRET = crypto.randomBytes(32).toString('hex'); q.putSetting.run('server_secret', SERVER_SECRET); }

const scrypt = (pw, salt, len, opts) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, len, opts, (e, k) => (e ? rej(e) : res(k))));
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw.normalize('NFKC'), salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  const [alg, N, r, p, salt, key] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(key, 'base64');
  const got = await scrypt(pw.normalize('NFKC'), Buffer.from(salt, 'base64'), expected.length,
    { N: +N, r: +r, p: +p, maxmem: 64 * 1024 * 1024 });
  return got.length === expected.length && crypto.timingSafeEqual(got, expected);
}
let DUMMY_HASH = null; // makes "unknown email" take as long as "wrong password"
hashPassword('dummy-password-for-timing').then(h => { DUMMY_HASH = h; });

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = (m, s = 400) => { throw new HttpError(s, m); };

function clientIp(req) {
  if (CFG.trustProxy) {
    const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xf) return xf;
  }
  return req.socket.remoteAddress || '0.0.0.0';
}
function deviceOf(ua = '') {
  if (/ipad|tablet|kindle/i.test(ua)) return 'tablet';
  if (/mobi|android|iphone|ipod/i.test(ua)) return 'mobile';
  return 'desktop';
}
const visitorId = req => sha256(`${SERVER_SECRET}|${dayOf()}|${clientIp(req)}|${req.headers['user-agent'] || ''}`).slice(0, 12);

function logEvent(req, type, extra = {}) {
  try {
    const ts = now();
    q.insertEvent.run(ts, dayOf(ts), type, req ? visitorId(req) : null, extra.userId ?? null,
      req ? deviceOf(req.headers['user-agent']) : null, extra.page ?? null, extra.lang ?? null, extra.info ?? null);
  } catch (e) { console.error('event log failed:', e.message); }
}

/* ───────────────────────── rate limiting ───────────────────────── */
const buckets = new Map();
function hit(key, limit, windowMs) {
  const t = now();
  let b = buckets.get(key);
  if (!b || b.reset < t) { b = { n: 0, reset: t + windowMs }; buckets.set(key, b); }
  b.n++;
  return { ok: b.n <= limit, retry: Math.ceil((b.reset - t) / 1000) };
}
function limit(key, max, windowMs, msg = 'Too many requests. Please slow down.') {
  const r = hit(key, max, windowMs);
  if (!r.ok) { const e = new HttpError(429, msg); e.retry = r.retry; throw e; }
}
setInterval(() => { const t = now(); for (const [k, b] of buckets) if (b.reset < t) buckets.delete(k); q.purgeSessions.run(t); }, 60_000).unref();

const failures = new Map(); // email -> {n, until}
function checkLock(email) {
  const f = failures.get(email);
  if (f && f.until > now()) { const e = new HttpError(429, 'Too many failed attempts. Try again in a few minutes.'); e.retry = Math.ceil((f.until - now()) / 1000); throw e; }
}
function noteFailure(email) {
  const f = failures.get(email) || { n: 0, until: 0 };
  f.n++;
  if (f.n >= 5) { f.until = now() + 15 * 60_000; f.n = 0; }
  failures.set(email, f);
}

/* ───────────────────────── sessions ───────────────────────── */
const COOKIE = 'maclay_sid';
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function setCookie(res, value, maxAgeSec) {
  const parts = [`${COOKIE}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSec}`];
  if (CFG.production) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const t = now();
  q.insertSession.run(sha256(token), userId, t, t + CFG.sessionDays * 864e5);
  setCookie(res, token, CFG.sessionDays * 86400);
}
function currentUser(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token || token.length > 100) return null;
  const sid = sha256(token);
  const row = q.session.get(sid);
  if (!row) return null;
  const t = now();
  if (row.expires_at < t || row.status !== 'active') { q.delSession.run(sid); return null; }
  if (row.expires_at - t < (CFG.sessionDays / 2) * 864e5) q.extendSession.run(t + CFG.sessionDays * 864e5, sid);
  row.sid = sid;
  return row;
}
const publicUser = u => ({
  id: u.id, email: u.email, name: u.name, bio: u.bio, role: u.role,
  created_at: u.created_at, last_login: u.last_login
});

/* ───────────────────────── validation ───────────────────────── */
const EMAIL_RE = /^[^\s@<>()"',;:\\]+@[^\s@<>()"',;:\\]+\.[A-Za-z]{2,}$/;
const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);
const COMMON = new Set(['password', 'password1', '12345678', '123456789', 'qwertyui', 'iloveyou', '11111111', 'abc12345', 'letmein1', 'welcome1']);
function checkPassword(pw, email) {
  if (typeof pw !== 'string' || pw.length < 8) bad('Password must be at least 8 characters.');
  if (pw.length > 128) bad('Password is too long (max 128).');
  if (COMMON.has(pw.toLowerCase()) || pw.toLowerCase() === String(email).toLowerCase()) bad('That password is too easy to guess. Pick a different one.');
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) bad('Use at least one letter and one number in your password.');
}
function checkSnippet(body, partial = false) {
  const name = clean(body.name, 80);
  const lang = String(body.lang || '');
  const code = typeof body.code === 'string' ? body.code : '';
  if (!name) bad('Give the snippet a name.');
  if (!LANGS.includes(lang)) bad('Unknown language.');
  if (!code.trim()) bad('The snippet is empty.');
  const bytes = Buffer.byteLength(code);
  if (bytes > CFG.maxSnippetBytes) bad(`Snippet is too large (max ${CFG.maxSnippetBytes / 1024} KB).`, 413);
  return { name, lang, code, bytes };
}
function usageOf(userId) {
  const u = q.usage.get(userId);
  const byLang = {};
  for (const r of q.usageByLang.all(userId)) byLang[r.lang] = { count: r.n, bytes: r.b };
  return { count: u.n, bytes: u.b, quota: CFG.quotaBytes, maxCount: CFG.maxSnippets, byLang };
}

/* ───────────────────────── site settings ───────────────────────── */
const DEFAULT_SITE = {
  siteName: "MAC'LAY Workspace", tagline: '', subtitle: '', badge: '', footer: '', accent: '',
  maintenance: false, features: { ai: true, editor: true, files: true }
};
function getSite() {
  try { return { ...DEFAULT_SITE, ...JSON.parse(getSetting('site', '{}')) }; } catch (_) { return { ...DEFAULT_SITE }; }
}

/* ───────────────────────── request plumbing ───────────────────────── */
function readJson(req) {
  return new Promise((resolve, reject) => {
    if (req.method === 'GET' || req.method === 'HEAD') return resolve({});
    const ct = String(req.headers['content-type'] || '');
    if (!ct.startsWith('application/json')) return reject(new HttpError(415, 'Expected JSON.'));
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > CFG.maxBody) { reject(new HttpError(413, 'Request too large.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!size) return resolve({});
      try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(v && typeof v === 'object' ? v : {}); }
      catch (_) { reject(new HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', reject);
  });
}
function send(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}
function securityHeaders(res) {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https:",
    "font-src 'self' data: https:",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' https://cdn.jsdelivr.net",
    "worker-src 'self' blob:",
    "frame-src 'self' blob: data:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'"
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (CFG.production) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.webp': 'image/webp', '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2' };
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
  let rel;
  try { rel = decodeURIComponent(pathname); } catch (_) { return send(res, 400, { error: 'Bad path' }); }
  if (rel === '/' || rel === '') rel = '/index.html';
  if (rel.includes('\0')) return send(res, 400, { error: 'Bad path' });
  const full = path.resolve(PUBLIC_DIR, '.' + rel);
  if (full !== PUBLIC_DIR && !full.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, { error: 'Forbidden' });
  fs.stat(full, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, { error: 'Not found' });
    const type = MIME[path.extname(full).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size,
      'Cache-Control': type.startsWith('text/html') ? 'no-cache' : 'public, max-age=3600' });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(full).pipe(res);
  });
}

/* ───────────────────────── routes ───────────────────────── */
const routes = [];
const route = (method, pattern, opts, fn) => {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, opts, fn });
};

/* — public — */
route('GET', '/api/health', {}, async () => ({ ok: true }));

route('GET', '/api/site', {}, async () => {
  const site = getSite();
  return { site: { ...site, aiEnabled: !!CFG.anthropicKey, execEnabled: !!CFG.judge0Url && !!CFG.judge0Key }, announcements: q.announcements.all() };
});

route('GET', '/api/me', {}, async ({ user }) => ({ user: user ? publicUser(user) : null }));

route('POST', '/api/track', { limit: ['track', 90, 60_000] }, async ({ req, body, user }) => {
  const type = String(body.type || '');
  const page = SECTIONS.includes(body.page) ? body.page : 'home';
  const lang = LANGS.includes(body.lang) ? body.lang : null;
  if (type === 'ping') { online.set(visitorId(req), now()); return { ok: true }; }
  if (!['visit', 'section', 'run', 'download'].includes(type)) bad('Unknown event.');
  online.set(visitorId(req), now());
  logEvent(req, type, { userId: user?.id, page: type === 'visit' ? 'home' : page, lang });
  return { ok: true };
});
const online = new Map(); // visitor -> last ping

/* — auth — */
route('POST', '/api/auth/register', { limit: ['register', 8, 3600_000] }, async ({ req, res, body }) => {
  if (getSite().maintenance) bad('The site is in maintenance mode. Registration is paused.', 503);
  const email = clean(body.email, 254).toLowerCase();
  const name = clean(body.name, 60);
  if (!EMAIL_RE.test(email)) bad('Enter a valid email address.');
  if (name.length < 2) bad('Enter your name (at least 2 characters).');
  checkPassword(body.password, email);
  if (q.userByEmail.get(email)) bad('That email is already registered. Try signing in.', 409);
  const pass_hash = await hashPassword(body.password);
  // First sign-up with OWNER_EMAIL becomes owner while no owner exists (delete OWNER_EMAIL afterwards).
  const role = CFG.ownerEmail && email === CFG.ownerEmail && q.ownerCount.get().c === 0 ? 'owner' : 'user';
  let id;
  try { id = Number(q.insertUser.run(email, name, pass_hash, role, now()).lastInsertRowid); }
  catch (_) { bad('That email is already registered. Try signing in.', 409); }
  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now(), id);
  startSession(res, id);
  logEvent(req, 'signup', { userId: id });
  return { user: publicUser(q.userById.get(id)) };
});

route('POST', '/api/auth/login', { limit: ['login', 20, 15 * 60_000] }, async ({ req, res, body }) => {
  const email = clean(body.email, 254).toLowerCase();
  const password = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
  if (!email || !password) bad('Enter your email and password.');
  checkLock(email);
  const row = q.userByEmail.get(email);
  const ok = await verifyPassword(password, row ? row.pass_hash : (DUMMY_HASH || 'scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAA'));
  if (!row || !ok) { noteFailure(email); bad('Wrong email or password.', 401); }
  if (row.status !== 'active') bad('This account has been suspended. Contact the site owner.', 403);
  if (getSite().maintenance && row.role !== 'owner') bad('The site is in maintenance mode. Please try again later.', 503);
  failures.delete(email);
  // Claim ownership at sign-in too (password already verified): covers an account created before OWNER_EMAIL was set.
  if (CFG.ownerEmail && email === CFG.ownerEmail && row.role !== 'owner' && q.ownerCount.get().c === 0) {
    db.prepare("UPDATE users SET role = 'owner' WHERE id = ?").run(row.id);
  }
  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now(), row.id);
  startSession(res, row.id);
  logEvent(req, 'login', { userId: row.id });
  return { user: publicUser(q.userById.get(row.id)) };
});

route('POST', '/api/auth/logout', {}, async ({ res, user }) => {
  if (user) q.delSession.run(user.sid);
  setCookie(res, '', 0);
  return { ok: true };
});

route('POST', '/api/auth/logout-all', { auth: true }, async ({ res, user }) => {
  q.delUserSessions.run(user.id);
  setCookie(res, '', 0);
  return { ok: true };
});

/* — profile — */
route('POST', '/api/me/profile', { auth: true, limit: ['profile', 30, 3600_000] }, async ({ user, body }) => {
  const name = clean(body.name, 60);
  const bio = clean(body.bio, 280);
  if (name.length < 2) bad('Enter your name (at least 2 characters).');
  db.prepare('UPDATE users SET name = ?, bio = ? WHERE id = ?').run(name, bio, user.id);
  return { user: publicUser(q.userById.get(user.id)) };
});

route('POST', '/api/me/password', { auth: true, limit: ['pw', 10, 3600_000] }, async ({ user, body }) => {
  if (!(await verifyPassword(String(body.current || '').slice(0, 200), user.pass_hash))) bad('Your current password is wrong.', 403);
  checkPassword(body.next, user.email);
  db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(await hashPassword(body.next), user.id);
  q.delOtherSessions.run(user.id, user.sid);
  return { ok: true };
});

route('POST', '/api/me/delete', { auth: true, limit: ['del', 5, 3600_000] }, async ({ res, user, body }) => {
  if (!(await verifyPassword(String(body.password || '').slice(0, 200), user.pass_hash))) bad('Wrong password.', 403);
  if (user.role === 'owner' && q.ownerCount.get().c <= 1) bad('You are the only owner. Make someone else an owner first.', 409);
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id); // cascades to sessions + snippets
  setCookie(res, '', 0);
  return { ok: true };
});

/* — snippets — */
route('GET', '/api/snippets', { auth: true }, async ({ user }) => ({
  snippets: q.snippetsOf.all(user.id), usage: usageOf(user.id)
}));

route('POST', '/api/snippets', { auth: true, limit: ['snip', 120, 3600_000] }, async ({ user, body }) => {
  const s = checkSnippet(body);
  const use = usageOf(user.id);
  if (use.count >= CFG.maxSnippets) bad(`You have reached the limit of ${CFG.maxSnippets} snippets. Delete some first.`, 409);
  if (use.bytes + s.bytes > CFG.quotaBytes) bad('Not enough storage left. Delete some snippets first.', 413);
  const t = now();
  const id = Number(q.insertSnippet.run(user.id, s.name, s.lang, s.code, s.bytes, t, t).lastInsertRowid);
  return { snippet: q.snippetOne.get(id, user.id), usage: usageOf(user.id) };
});

route('POST', '/api/snippets/import', { auth: true, limit: ['import', 5, 3600_000] }, async ({ user, body }) => {
  const items = Array.isArray(body.items) ? body.items.slice(0, 50) : [];
  let added = 0;
  tx(() => {
    for (const it of items) {
      try {
        const s = checkSnippet(it || {});
        const use = usageOf(user.id);
        if (use.count >= CFG.maxSnippets || use.bytes + s.bytes > CFG.quotaBytes) break;
        const t = now();
        q.insertSnippet.run(user.id, s.name, s.lang, s.code, s.bytes, t, t);
        added++;
      } catch (_) { /* skip invalid */ }
    }
  });
  return { added, usage: usageOf(user.id) };
});

route('PUT', '/api/snippets/:id', { auth: true, limit: ['snip', 120, 3600_000] }, async ({ user, body, params }) => {
  const id = Number(params.id);
  const cur = q.snippetOne.get(id, user.id);
  if (!cur) bad('Snippet not found.', 404);
  const s = checkSnippet({ name: body.name ?? cur.name, lang: body.lang ?? cur.lang, code: body.code ?? cur.code });
  const use = usageOf(user.id);
  if (use.bytes - cur.bytes + s.bytes > CFG.quotaBytes) bad('Not enough storage left for this change.', 413);
  q.updateSnippet.run(s.name, s.lang, s.code, s.bytes, now(), id, user.id);
  return { snippet: q.snippetOne.get(id, user.id), usage: usageOf(user.id) };
});

route('DELETE', '/api/snippets/:id', { auth: true }, async ({ user, params }) => {
  q.deleteSnippet.run(Number(params.id), user.id);
  return { ok: true, usage: usageOf(user.id) };
});

/* — AI and code execution (optional, need keys in .env) — */
const AI_SYSTEM = `You are MAC AI — the intelligent coding assistant built into MAC'LAY Workspace.
Help users write code, debug errors, optimize performance, build bots (Telegram, Discord, WhatsApp), explain programming concepts and generate snippets.
Format: use markdown code blocks with language names. Be concise but thorough. Always practical.`;

route('POST', '/api/chat', { auth: true, limit: ['chat', 30, 60_000] }, async ({ req, user, body }) => {
  const site = getSite();
  if (site.maintenance && user.role !== 'owner') bad('The site is in maintenance mode.', 503);
  if (site.features.ai === false) bad('MAC AI is switched off by the site owner.', 403);
  if (!CFG.anthropicKey) bad('MAC AI is not configured on this server. The owner needs to set ANTHROPIC_API_KEY.', 501);
  const today = db.prepare("SELECT COUNT(*) c FROM events WHERE type='ai' AND user_id = ? AND day = ?").get(user.id, dayOf()).c;
  if (user.role !== 'owner' && today >= CFG.aiDailyLimit) bad(`Daily AI limit reached (${CFG.aiDailyLimit} messages). Try again tomorrow.`, 429);

  const msgs = Array.isArray(body.messages) ? body.messages.slice(-20) : [];
  const messages = msgs
    .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
    .map(m => ({ role: m.role, content: m.content.slice(0, 8000) }));
  while (messages.length && messages[0].role !== 'user') messages.shift();
  if (!messages.length || messages[messages.length - 1].role !== 'user') bad('Send a message first.');
  const model = CFG.aiModels.includes(body.model) ? body.model : CFG.aiModels[0];

  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': CFG.anthropicKey, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model, max_tokens: 1024, system: AI_SYSTEM, messages }),
    signal: AbortSignal.timeout(60_000)
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    console.error('Anthropic error', r.status, JSON.stringify(data).slice(0, 300));
    bad(r.status === 401 ? 'The server’s Anthropic API key was rejected.' : 'The AI service returned an error. Try again shortly.', 502);
  }
  logEvent(req, 'ai', { userId: user.id, info: model });
  return { content: (data.content || []).filter(b => b.type === 'text').map(b => ({ type: 'text', text: b.text })) };
});

const J0 = { python: 71, c: 50, cpp: 54, java: 62, php: 68, bash: 46, sql: 82 };
route('POST', '/api/execute', { auth: true, limit: ['exec', 20, 60_000] }, async ({ req, user, body }) => {
  const lang = String(body.language || '');
  if (!J0[lang]) bad('That language cannot run on the server.');
  if (!CFG.judge0Url || !CFG.judge0Key) bad('Server-side execution is not configured. The owner needs to set JUDGE0_URL and JUDGE0_API_KEY.', 501);
  const code = typeof body.code === 'string' ? body.code : '';
  if (!code.trim() || Buffer.byteLength(code) > CFG.maxSnippetBytes) bad('Code is empty or too large.');
  const headers = { 'content-type': 'application/json' };
  if (CFG.judge0Host) { headers['X-RapidAPI-Key'] = CFG.judge0Key; headers['X-RapidAPI-Host'] = CFG.judge0Host; }
  else headers['X-Auth-Token'] = CFG.judge0Key;
  const r = await fetch(`${CFG.judge0Url}/submissions?base64_encoded=false&wait=true`, {
    method: 'POST', headers,
    body: JSON.stringify({ language_id: J0[lang], source_code: code, stdin: String(body.stdin || '').slice(0, 10_000), cpu_time_limit: 5, memory_limit: 128000 }),
    signal: AbortSignal.timeout(25_000)
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { console.error('Judge0 error', r.status, JSON.stringify(d).slice(0, 300)); bad('The code runner returned an error.', 502); }
  return { stdout: d.stdout || '', stderr: d.stderr || d.compile_output || d.message || '', status: d.status?.description || '' };
});

/* — owner dashboard — */
const OWNER = { auth: true, owner: true };

route('GET', '/api/admin/overview', OWNER, async () => {
  const since = dayOf(now() - 29 * 864e5);
  const days = [];
  for (let i = 29; i >= 0; i--) days.push(dayOf(now() - i * 864e5));
  const grid = rows => { const m = Object.fromEntries(rows.map(r => [r.day, r])); return days.map(d => m[d] || { day: d }); };
  const views = grid(db.prepare("SELECT day, COUNT(*) n, COUNT(DISTINCT visitor) u FROM events WHERE type='visit' AND day >= ? GROUP BY day").all(since));
  const runs = grid(db.prepare("SELECT day, COUNT(*) n FROM events WHERE type='run' AND day >= ? GROUP BY day").all(since));
  const ai = grid(db.prepare("SELECT day, COUNT(*) n FROM events WHERE type='ai' AND day >= ? GROUP BY day").all(since));
  const signups = grid(db.prepare("SELECT day, COUNT(*) n FROM events WHERE type='signup' AND day >= ? GROUP BY day").all(since));
  const sum = a => a.reduce((s, r) => s + (r.n || 0), 0);
  const t = now();
  let onlineNow = 0;
  for (const [k, ts] of online) { if (t - ts < 150_000) onlineNow++; else if (t - ts > 3600_000) online.delete(k); }
  return {
    generated: t,
    totals: {
      views: sum(views), visitors: views.reduce((s, r) => s + (r.u || 0), 0), online: onlineNow,
      users: db.prepare('SELECT COUNT(*) c FROM users').get().c,
      newUsers7d: db.prepare('SELECT COUNT(*) c FROM users WHERE created_at > ?').get(t - 7 * 864e5).c,
      snippets: db.prepare('SELECT COUNT(*) c FROM snippets').get().c,
      storageBytes: db.prepare('SELECT COALESCE(SUM(bytes),0) c FROM snippets').get().c,
      runs: sum(runs), ai: sum(ai), downloads: db.prepare("SELECT COUNT(*) c FROM events WHERE type='download' AND day >= ?").get(since).c
    },
    days,
    series: { views: views.map(r => r.n || 0), visitors: views.map(r => r.u || 0), runs: runs.map(r => r.n || 0), ai: ai.map(r => r.n || 0), signups: signups.map(r => r.n || 0) },
    sections: db.prepare("SELECT page label, COUNT(*) n FROM events WHERE type='section' AND day >= ? GROUP BY page ORDER BY n DESC").all(since),
    devices: db.prepare("SELECT COALESCE(device,'desktop') label, COUNT(*) n FROM events WHERE type='visit' AND day >= ? GROUP BY device ORDER BY n DESC").all(since),
    languages: db.prepare("SELECT lang label, COUNT(*) n FROM events WHERE type='run' AND lang IS NOT NULL AND day >= ? GROUP BY lang ORDER BY n DESC").all(since),
    members: db.prepare("SELECT SUM(user_id IS NOT NULL) m, SUM(user_id IS NULL) g FROM events WHERE type='visit' AND day >= ?").get(since)
  };
});

route('GET', '/api/admin/activity', OWNER, async () => ({
  events: db.prepare(`SELECT e.id, e.ts, e.type, e.lang, e.info, e.page, u.name, u.email
    FROM events e LEFT JOIN users u ON u.id = e.user_id
    WHERE e.type IN ('signup','login','run','ai','admin','download') ORDER BY e.id DESC LIMIT 40`).all()
}));

route('GET', '/api/admin/users', OWNER, async ({ url }) => {
  const term = clean(url.searchParams.get('q') || '', 80);
  const like = `%${term.replace(/[\\%_]/g, c => '\\' + c)}%`;
  const rows = db.prepare(`SELECT u.id, u.email, u.name, u.role, u.status, u.created_at, u.last_login,
      (SELECT COUNT(*) FROM snippets s WHERE s.user_id = u.id) snippets,
      (SELECT COALESCE(SUM(bytes),0) FROM snippets s WHERE s.user_id = u.id) bytes
    FROM users u WHERE (? = '' OR u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\')
    ORDER BY u.created_at DESC LIMIT 200`).all(term, like, like);
  return { users: rows };
});

function adminTarget(params, user) {
  const target = q.userById.get(Number(params.id));
  if (!target) bad('User not found.', 404);
  if (target.id === user.id) bad('You cannot do that to your own account here.', 409);
  return target;
}
route('POST', '/api/admin/users/:id/role', OWNER, async ({ req, user, params, body }) => {
  const target = adminTarget(params, user);
  const role = body.role === 'owner' ? 'owner' : 'user';
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, target.id);
  logEvent(req, 'admin', { userId: user.id, info: `${role === 'owner' ? 'promoted' : 'demoted'} ${target.email}` });
  return { ok: true };
});
route('POST', '/api/admin/users/:id/status', OWNER, async ({ req, user, params, body }) => {
  const target = adminTarget(params, user);
  if (target.role === 'owner') bad('Remove their owner role before suspending them.', 409);
  const status = body.status === 'banned' ? 'banned' : 'active';
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, target.id);
  if (status === 'banned') q.delUserSessions.run(target.id);
  logEvent(req, 'admin', { userId: user.id, info: `${status === 'banned' ? 'suspended' : 'reinstated'} ${target.email}` });
  return { ok: true };
});
route('POST', '/api/admin/users/:id/delete', OWNER, async ({ req, user, params, body }) => {
  const target = adminTarget(params, user);
  if (!(await verifyPassword(String(body.password || '').slice(0, 200), user.pass_hash))) bad('Wrong password.', 403);
  if (target.role === 'owner') bad('Remove their owner role before deleting them.', 409);
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  logEvent(req, 'admin', { userId: user.id, info: `deleted ${target.email}` });
  return { ok: true };
});

route('POST', '/api/admin/announcements', OWNER, async ({ req, user, body }) => {
  const msg = clean(body.msg, 240);
  const type = ['info', 'warn', 'success'].includes(body.type) ? body.type : 'info';
  if (!msg) bad('Write a message first.');
  q.insertAnn.run(msg, type, now());
  logEvent(req, 'admin', { userId: user.id, info: 'posted an announcement' });
  return { announcements: q.announcements.all() };
});
route('POST', '/api/admin/announcements/:id/delete', OWNER, async ({ params }) => {
  q.delAnn.run(Number(params.id));
  return { announcements: q.announcements.all() };
});

route('POST', '/api/admin/settings', OWNER, async ({ req, user, body }) => {
  const cur = getSite();
  const accent = clean(body.accent ?? cur.accent, 9);
  if (accent && !/^#[0-9a-fA-F]{3,8}$/.test(accent)) bad('Accent must be a hex colour like #00d4cc.');
  const next = {
    siteName: clean(body.siteName ?? cur.siteName, 60) || DEFAULT_SITE.siteName,
    tagline: clean(body.tagline ?? cur.tagline, 80),
    subtitle: clean(body.subtitle ?? cur.subtitle, 200),
    badge: clean(body.badge ?? cur.badge, 80),
    footer: clean(body.footer ?? cur.footer, 120),
    accent,
    maintenance: typeof body.maintenance === 'boolean' ? body.maintenance : cur.maintenance,
    features: {
      ai: body.features?.ai !== undefined ? !!body.features.ai : cur.features.ai,
      editor: body.features?.editor !== undefined ? !!body.features.editor : cur.features.editor,
      files: body.features?.files !== undefined ? !!body.features.files : cur.features.files
    }
  };
  q.putSetting.run('site', JSON.stringify(next));
  logEvent(req, 'admin', { userId: user.id, info: 'changed site settings' });
  return { site: next };
});

route('POST', '/api/admin/reset-analytics', OWNER, async ({ user, body }) => {
  if (!(await verifyPassword(String(body.password || '').slice(0, 200), user.pass_hash))) bad('Wrong password.', 403);
  db.prepare("DELETE FROM events WHERE type <> 'signup'").run();
  online.clear();
  return { ok: true };
});

/* ───────────────────────── dispatcher ───────────────────────── */
async function handle(req, res) {
  securityHeaders(res);
  const url = new URL(req.url, 'http://x');
  if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);

  try {
    const ip = clientIp(req);
    limit(`api:${ip}`, 600, 60_000);

    const match = routes.map(r => ({ r, m: r.re.exec(url.pathname) })).find(x => x.m && x.r.method === req.method);
    if (!match) {
      if (routes.some(r => r.re.test(url.pathname))) bad('Method not allowed.', 405);
      bad('Not found.', 404);
    }
    const { r, m } = match;

    if (req.method !== 'GET') {
      // CSRF defence in depth (cookies are also SameSite=Strict): custom header + same-origin Origin.
      if (req.headers['x-requested-with'] !== 'maclay') bad('Blocked: missing request header.', 403);
      const origin = req.headers.origin;
      if (origin) {
        let ok = false;
        try { ok = new URL(origin).host === req.headers.host; } catch (_) {}
        if (!ok) bad('Blocked: cross-site request.', 403);
      }
    }
    if (r.opts.limit) { const [k, max, win] = r.opts.limit; limit(`${k}:${ip}`, max, win); }

    const user = currentUser(req);
    if (r.opts.auth && !user) bad('Please sign in first.', 401);
    if (r.opts.owner && user.role !== 'owner') bad('Not found.', 404); // do not reveal that admin routes exist
    const body = await readJson(req);
    const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));

    const out = await r.fn({ req, res, url, user, body, params });
    if (!res.headersSent) send(res, 200, out);
  } catch (err) {
    const status = err instanceof HttpError ? err.status : 500;
    if (!(err instanceof HttpError)) console.error(err);
    if (!res.headersSent) {
      send(res, status, { error: err instanceof HttpError ? err.message : 'Something went wrong on the server.' },
        err.retry ? { 'Retry-After': String(err.retry) } : {});
    }
  }
}

/* ───────────────────────── CLI ───────────────────────── */
async function cli() {
  const a = process.argv.slice(2);
  if (a[0] === '--make-owner') {
    const email = String(a[1] || '').toLowerCase();
    const u = q.userByEmail.get(email);
    if (!u) { console.error(`No account with email "${email}". Sign up on the site first, then run this again.`); process.exit(1); }
    db.prepare("UPDATE users SET role = 'owner', status = 'active' WHERE id = ?").run(u.id);
    console.log(`✓ ${u.email} is now an owner.`); process.exit(0);
  }
  if (a[0] === '--reset-password') {
    const email = String(a[1] || '').toLowerCase(); const pw = a[2] || '';
    const u = q.userByEmail.get(email);
    if (!u) { console.error('No such account.'); process.exit(1); }
    try { checkPassword(pw, email); } catch (e) { console.error(e.message); process.exit(1); }
    db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(await hashPassword(pw), u.id);
    q.delUserSessions.run(u.id);
    console.log(`✓ Password reset for ${u.email}. All their sessions were signed out.`); process.exit(0);
  }
}

if (require.main === module) {
  cli().then(() => {
    const server = http.createServer((req, res) => { handle(req, res); });
    server.requestTimeout = 60_000;
    server.headersTimeout = 20_000;
    server.listen(CFG.port, CFG.host, () => {
      console.log(`MAC'LAY is running at http://localhost:${CFG.port}`);
      if (!q.ownerCount.get().c) {
        console.log('No owner account yet: sign up on the site, then run:  node server.js --make-owner your@email');
        if (CFG.ownerEmail) console.log(`(Signing up as ${CFG.ownerEmail} will make it the owner while no owner exists. Remove OWNER_EMAIL afterwards.)`);
      }
      if (!CFG.production) console.log('Running in development mode. Set PRODUCTION=1 when serving over HTTPS.');
    });
    const stop = () => { server.close(() => { try { db.close(); } catch (_) {} process.exit(0); }); setTimeout(() => process.exit(0), 3000).unref(); };
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
  });
}
module.exports = { handle, CFG, db };
