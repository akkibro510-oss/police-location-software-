'use strict';
require('dotenv').config();

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');

const requiredEnv = ['DATABASE_URL', 'JWT_SECRET', 'BOOTSTRAP_ADMIN_USERNAME', 'BOOTSTRAP_ADMIN_PASSWORD'];
for (const key of requiredEnv) {
  if (!process.env[key] || process.env[key].startsWith('REPLACE_WITH')) {
    console.error(`Missing or placeholder environment variable: ${key}`);
    process.exit(1);
  }
}
if (Buffer.byteLength(process.env.JWT_SECRET, 'utf8') < 32) {
  console.error('JWT_SECRET must be at least 32 bytes.');
  process.exit(1);
}

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});
const PORT = Number(process.env.PORT || 3000);
const COOKIE_NAME = 'police_session';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://unpkg.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
      imgSrc: ["'self'", 'data:', 'https://*.tile.openstreetmap.org'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '32kb' }));
app.use(cookieParser());

// This application uses same-site, HTTP-only cookies and JSON requests.
// In production set APP_ORIGIN to the exact HTTPS origin and deploy behind HTTPS.
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    const expected = process.env.APP_ORIGIN;
    if (origin && expected && origin !== expected) {
      return res.status(403).json({ error: 'Origin not allowed' });
    }
    if (!origin && process.env.NODE_ENV === 'production') {
      return res.status(403).json({ error: 'Origin header required' });
    }
  }
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' }
});

function cleanString(value, max = 200) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}
function validPhone(value) {
  return value === '' || /^[0-9]{10}$/.test(value);
}
function validCoords(lat, lon) {
  return Number.isFinite(lat) && Number.isFinite(lon) &&
    lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}
async function audit(req, action, entityType, entityId = null, details = {}) {
  // Do not log passwords, tokens, raw request bodies, or unnecessary personal data.
  await pool.query(
    `INSERT INTO audit_logs(actor_user_id, action, entity_type, entity_id, request_id, details)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [req.user ? req.user.id : null, action, entityType, entityId == null ? null : String(entityId),
      req.requestId, JSON.stringify(details)]
  );
}
function auth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Please log in.' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { issuer: 'police-location-system' });
    req.user = { id: Number(payload.sub), username: payload.username, role: payload.role };
    next();
  } catch {
    res.clearCookie(COOKIE_NAME, cookieOptions());
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}
function roles(...allowed) {
  return (req, res, next) => allowed.includes(req.user.role)
    ? next()
    : res.status(403).json({ error: 'You do not have permission for this action.' });
}
function cookieOptions() {
  return { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: '/', maxAge: 8 * 60 * 60 * 1000 };
}
function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

app.get('/api/health', asyncRoute(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true });
}));

app.post('/api/auth/login', loginLimiter, asyncRoute(async (req, res) => {
  const username = cleanString(req.body?.username, 80);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!username || !password || password.length > 200) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  const result = await pool.query(
    'SELECT id, username, password_hash, role, active FROM app_users WHERE username=$1',
    [username]
  );
  const user = result.rows[0];
  if (!user || !user.active || !(await bcrypt.compare(password, user.password_hash))) {
    await audit(req, 'auth.login_failed', 'user', null, { username });
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  const token = jwt.sign(
    { sub: String(user.id), username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h', issuer: 'police-location-system', jwtid: crypto.randomUUID() }
  );
  res.cookie(COOKIE_NAME, token, cookieOptions());
  req.user = { id: Number(user.id), username: user.username, role: user.role };
  await audit(req, 'auth.login_success', 'user', user.id);
  res.json({ user: req.user });
}));

app.post('/api/auth/logout', auth, asyncRoute(async (req, res) => {
  await audit(req, 'auth.logout', 'user', req.user.id);
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: '/' });
  res.json({ ok: true });
}));

app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

// Admin can create named accounts. The initial admin is bootstrapped from .env.
app.post('/api/users', auth, roles('admin'), asyncRoute(async (req, res) => {
  const username = cleanString(req.body?.username, 80);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const role = cleanString(req.body?.role, 20);
  if (!/^[A-Za-z0-9._-]{3,80}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-80 characters: letters, numbers, dot, underscore, hyphen.' });
  }
  if (password.length < 12 || password.length > 200) {
    return res.status(400).json({ error: 'Password must be at least 12 characters.' });
  }
  if (!['admin', 'investigator', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role.' });
  }
  const hash = await bcrypt.hash(password, 12);
  try {
    const result = await pool.query(
      'INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,$3) RETURNING id,username,role,active,created_at',
      [username, hash, role]
    );
    await audit(req, 'user.created', 'user', result.rows[0].id, { role });
    res.status(201).json({ user: result.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username already exists.' });
    throw e;
  }
}));

app.get('/api/cases', auth, asyncRoute(async (req, res) => {
  const q = cleanString(req.query.q, 100);
  const result = await pool.query(
    `SELECT id, case_number, title, phone_number, status, notes, created_at, updated_at
     FROM cases
     WHERE ($1 = '' OR case_number ILIKE '%' || $1 || '%' OR title ILIKE '%' || $1 || '%'
       OR COALESCE(phone_number,'') ILIKE '%' || $1 || '%')
     ORDER BY created_at DESC LIMIT 200`,
    [q]
  );
  res.json({ cases: result.rows });
}));

app.post('/api/cases', auth, roles('admin', 'investigator'), asyncRoute(async (req, res) => {
  const caseNumber = cleanString(req.body?.caseNumber, 80);
  const title = cleanString(req.body?.title, 200);
  const phone = cleanString(req.body?.phoneNumber, 10);
  const notes = cleanString(req.body?.notes, 5000);
  const status = cleanString(req.body?.status || 'open', 30);
  if (!caseNumber || !title) return res.status(400).json({ error: 'Case number and title are required.' });
  if (!validPhone(phone)) return res.status(400).json({ error: 'Phone number must be 10 digits or blank.' });
  if (!['open', 'under_investigation', 'closed'].includes(status)) return res.status(400).json({ error: 'Invalid case status.' });
  try {
    const result = await pool.query(
      `INSERT INTO cases(case_number,title,phone_number,status,notes,created_by)
       VALUES($1,$2,$3,$4,$5,$6)
       RETURNING id,case_number,title,phone_number,status,notes,created_at,updated_at`,
      [caseNumber, title, phone || null, status, notes, req.user.id]
    );
    await audit(req, 'case.created', 'case', result.rows[0].id, { caseNumber });
    res.status(201).json({ case: result.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Case number already exists.' });
    throw e;
  }
}));

app.patch('/api/cases/:id', auth, roles('admin', 'investigator'), asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid case ID.' });
  const caseNumber = cleanString(req.body?.caseNumber, 80);
  const title = cleanString(req.body?.title, 200);
  const phone = cleanString(req.body?.phoneNumber, 10);
  const notes = cleanString(req.body?.notes, 5000);
  const status = cleanString(req.body?.status, 30);
  if (!caseNumber || !title || !validPhone(phone) ||
      !['open', 'under_investigation', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'Check case number, title, phone number, and status.' });
  }
  const result = await pool.query(
    `UPDATE cases SET case_number=$1,title=$2,phone_number=$3,status=$4,notes=$5,updated_at=NOW()
     WHERE id=$6 RETURNING id,case_number,title,phone_number,status,notes,created_at,updated_at`,
    [caseNumber, title, phone || null, status, notes, id]
  );
  if (!result.rowCount) return res.status(404).json({ error: 'Case not found.' });
  await audit(req, 'case.updated', 'case', id, { caseNumber, status });
  res.json({ case: result.rows[0] });
}));

app.get('/api/cases/:id/locations', auth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid case ID.' });
  const result = await pool.query(
    `SELECT id,case_id,source_type,latitude,longitude,captured_at,authority_reference,details,created_at
     FROM location_reports WHERE case_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [id]
  );
  res.json({ reports: result.rows });
}));

app.post('/api/cases/:id/locations', auth, roles('admin', 'investigator'), asyncRoute(async (req, res) => {
  const caseId = Number(req.params.id);
  const sourceType = cleanString(req.body?.sourceType, 30);
  const latitude = Number(req.body?.latitude);
  const longitude = Number(req.body?.longitude);
  const authorityReference = cleanString(req.body?.authorityReference, 200);
  const details = cleanString(req.body?.details, 3000);
  const capturedAt = req.body?.capturedAt ? new Date(req.body.capturedAt) : null;
  const authorized = req.body?.authorized === true;

  if (!Number.isSafeInteger(caseId) || caseId <= 0) return res.status(400).json({ error: 'Invalid case ID.' });
  if (!['authorized_gps', 'official_report'].includes(sourceType)) return res.status(400).json({ error: 'Select an accepted report source.' });
  if (!validCoords(latitude, longitude)) return res.status(400).json({ error: 'Valid latitude and longitude are required.' });
  if (!authorityReference) return res.status(400).json({ error: 'Authorization / report reference is required.' });
  if (!authorized) return res.status(400).json({ error: 'Confirm that this report was obtained through an authorized source.' });
  if (capturedAt && Number.isNaN(capturedAt.getTime())) return res.status(400).json({ error: 'Invalid capture date.' });

  const exists = await pool.query('SELECT id FROM cases WHERE id=$1', [caseId]);
  if (!exists.rowCount) return res.status(404).json({ error: 'Case not found.' });

  const result = await pool.query(
    `INSERT INTO location_reports(case_id,source_type,latitude,longitude,captured_at,authority_reference,details,created_by)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id,case_id,source_type,latitude,longitude,captured_at,authority_reference,details,created_at`,
    [caseId, sourceType, latitude, longitude, capturedAt, authorityReference, details, req.user.id]
  );
  await audit(req, 'location_report.created', 'location_report', result.rows[0].id,
    { caseId, sourceType, authorityReference });
  res.status(201).json({ report: result.rows[0] });
}));

app.get('/api/audit', auth, roles('admin'), asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,actor_user_id,action,entity_type,entity_id,request_id,details,created_at
     FROM audit_logs ORDER BY created_at DESC LIMIT 200`
  );
  res.json({ logs: result.rows });
}));

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: '1h' }));
app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((err, req, res, next) => {
  console.error(`[${req.requestId}]`, err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error.', requestId: req.requestId });
});

async function start() {
  await pool.query('SELECT 1');
  const username = process.env.BOOTSTRAP_ADMIN_USERNAME;
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  const found = await pool.query('SELECT id FROM app_users WHERE username=$1', [username]);
  if (!found.rowCount) {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,'admin')",
      [username, hash]
    );
    console.log(`Bootstrap admin created: ${username}. Change credentials through your deployment process.`);
  } else {
    console.log('Bootstrap admin already exists; environment password will not reset it.');
  }
  app.listen(PORT, () => console.log(`Police Location System listening on port ${PORT}`));
}
start().catch(err => {
  console.error('Startup failed:', err.message);
  process.exit(1);
});
process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });
