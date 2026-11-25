
import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) throw new Error('Не задан DATABASE_URL.');
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET должен содержать минимум 32 символа.');
}

if (isProduction) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '12mb' }));

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', err => console.error('PostgreSQL error:', err));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      display_name TEXT,
      email TEXT,
      last_login TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
      ON users(email) WHERE email IS NOT NULL AND email <> '';

    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'Free';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS plus_expires_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS muted_until TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS free_used_seconds INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS free_cooldown_until TIMESTAMPTZ;

    CREATE TABLE IF NOT EXISTS conversations (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Новый чат',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
      content TEXT NOT NULL,
      image TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS conversations_user_updated
      ON conversations(user_id, updated_at DESC);

    CREATE INDEX IF NOT EXISTS messages_conversation_id
      ON messages(conversation_id, id);

    CREATE TABLE IF NOT EXISTS gift_codes (
      id BIGSERIAL PRIMARY KEY,
      code_hash TEXT NOT NULL UNIQUE,
      created_by BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      redeemed_by BIGINT REFERENCES users(id),
      redeemed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ai_memory (
      id BIGSERIAL PRIMARY KEY,
      fact TEXT NOT NULL,
      created_by BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS moderator_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );
  `);
}

const PgSession = connectPgSimple(session);
const sessionStore = new PgSession({
  pool,
  tableName: 'sessions',
  createTableIfMissing: true
});

app.use(session({
  name: 'maut.sid',
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: isProduction,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 365 * 24 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const imageLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 4,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

function adminEmail() {
  return (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ? email : null;
}

function normalizeName(value) {
  if (typeof value !== 'string') return null;
  const name = value.trim().replace(/\s+/g, ' ');
  return name && [...name].length <= 60 ? name : null;
}

function isAdminRow(row) {
  return !!adminEmail() &&
    (row.email || '').trim().toLowerCase() === adminEmail();
}

function publicUser(row) {
  return {
    id: Number(row.id),
    username: row.username,
    name: row.display_name || row.username,
    email: row.email || null,
    role: isAdminRow(row) ? 'Admin' : (row.role || 'Free'),
    plusExpiresAt: row.plus_expires_at || null,
    mutedUntil: row.muted_until || null
  };
}

async function getAccount(userId) {
  const result = await pool.query(
    `SELECT id, username, display_name, email, role,
            plus_expires_at, banned_at, muted_until,
            free_used_seconds, free_cooldown_until
     FROM users WHERE id = $1`,
    [userId]
  );

  const row = result.rows[0];
  if (!row) return null;
  if (row.banned_at) return { banned: true };

  if (
    row.role === 'Plus' &&
    row.plus_expires_at &&
    new Date(row.plus_expires_at) <= new Date()
  ) {
    await pool.query(
      `UPDATE users SET role = 'Free', plus_expires_at = NULL
       WHERE id = $1 AND role = 'Plus'`,
      [userId]
    );
    row.role = 'Free';
    row.plus_expires_at = null;
  }

  return publicUser(row);
}

async function requireAuth(req, res, next) {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Сначала войди в аккаунт.' });
    }

    const account = await getAccount(req.session.user.id);

    if (!account) {
      return res.status(401).json({ error: 'Аккаунт не найден.' });
    }

    if (account.banned) {
      return res.status(403).json({ error: 'Аккаунт заблокирован.' });
    }

    req.account = account;
    next();
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({ error: 'Не удалось проверить аккаунт.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.account?.role !== 'Admin') {
    return res.status(403).json({ error: 'Доступ разрешён только Admin.' });
  }
  next();
}

function requireModerator(req, res, next) {
  if (!['Admin', 'Moder'].includes(req.account?.role)) {
    return res.status(403).json({ error: 'Недостаточно прав.' });
  }
  next();
}

function hashGiftCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function generateGiftCode() {
  return 'MAUT-' +
    crypto.randomBytes(4).toString('hex').toUpperCase() +
    '-' +
    crypto.randomBytes(4).toString('hex').toUpperCase();
}

function createLoginSession(req, res, user, statusCode = 200) {
  req.session.regenerate(err => {
    if (err) {
      console.error('Session error:', err);
      return res.status(500).json({ error: 'Не удалось создать сессию.' });
    }

    req.session.user = { id: user.id };

    req.session.save(saveErr => {
      if (saveErr) {
        console.error('Session save error:', saveErr);
        return res.status(500).json({ error: 'Не удалось сохранить сессию.' });
      }

      res.status(statusCode).json({ user });
    });
  });
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'postgresql' });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: req.account });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = normalizeName(
      req.body?.name || req.body?.display_name || req.body?.username
    );
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!name) {
      return res.status(400).json({ error: 'Введи имя длиной от 1 до 60 символов.' });
    }

    if (!email) {
      return res.status(400).json({ error: 'Введи корректный email.' });
    }

    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: 'Пароль должен содержать от 8 до 128 символов.' });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, password_hash, display_name, email, last_login)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id`,
      [email, hash, name, email]
    );

    const account = await getAccount(result.rows[0].id);
    createLoginSession(req, res, account, 201);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Аккаунт уже существует. Попробуй войти.' });
    }
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Ошибка регистрации на сервере.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const rawLogin = req.body?.email ?? req.body?.username ?? req.body?.login;
    const loginValue = typeof rawLogin === 'string' ? rawLogin.trim() : '';
    const password = req.body?.password;

    if (!loginValue || loginValue.length > 254 ||
        typeof password !== 'string' || password.length > 128) {
      return res.status(400).json({ error: 'Введи логин и пароль.' });
    }

    const login = loginValue.toLowerCase();

    const result = await pool.query(
      `SELECT id, username, password_hash, display_name, email,
              role, plus_expires_at, banned_at, muted_until
       FROM users
       WHERE LOWER(email) = $1 OR LOWER(username) = $1 LIMIT 1`,
      [login]
    );

    const row = result.rows[0];

    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }

    if (row.banned_at) {
      return res.status(403).json({ error: 'Этот аккаунт заблокирован.' });
    }

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [row.id]);

    const account = await getAccount(row.id);
    createLoginSession(req, res, account);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Ошибка входа на сервере.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Не удалось выйти из аккаунта.' });
    res.clearCookie('maut.sid', {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/'
    });
    res.json({ success: true });
  });
});

app.get('/api/account', requireAuth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    user: req.account,
    discord: 'denkrixell_26041',
    plusPrice: '$1 / 7 дней'
  });
});

// PLUS: генерация ключей
app.post('/api/admin/gift-codes', requireAuth, requireAdmin, async (req, res) => {
  const count = Number(req.body?.count ?? 1);

  if (!Number.isInteger(count) || count < 1 || count > 100) {
    return res.status(400).json({ error: 'Можно создать от 1 до 100 ключей.' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const codes = [];

    for (let i = 0; i < count; i++) {
      const code = generateGiftCode();

      await client.query(
        `INSERT INTO gift_codes (code_hash, created_by, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '1 year')`,
        [hashGiftCode(code), req.account.id]
      );

      codes.push(code);
    }

    await client.query('COMMIT');
    res.status(201).json({ codes });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Gift code creation error:', error);
    res.status(500).json({ error: 'Не удалось создать ключи.' });
  } finally {
    client.release();
  }
});

// PLUS: активация ключа
app.post('/api/gift-codes/redeem', requireAuth, async (req, res) => {
  const code = typeof req.body?.code === 'string'
    ? req.body.code.trim().toUpperCase()
    : '';

  if (!/^MAUT-[A-F0-9]{8}-[A-F0-9]{8}$/.test(code)) {
    return res.status(400).json({ error: 'Неверный формат ключа.' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const found = await client.query(
      `SELECT id FROM gift_codes
       WHERE code_hash = $1 AND redeemed_at IS NULL
         AND expires_at > NOW()
       FOR UPDATE`,
      [hashGiftCode(code)]
    );

    if (!found.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Ключ недействителен или уже использован.' });
    }

    const account = await client.query(
      'SELECT plus_expires_at FROM users WHERE id = $1 FOR UPDATE',
      [req.account.id]
    );

    const oldExpiry = account.rows[0].plus_expires_at;
    const start = oldExpiry && new Date(oldExpiry) > new Date()
      ? new Date(oldExpiry) : new Date();

    start.setDate(start.getDate() + 7);

    await client.query(
      `UPDATE users SET role = 'Plus', plus_expires_at = $1 WHERE id = $2`,
      [start, req.account.id]
    );

    await client.query(
      `UPDATE gift_codes SET redeemed_by = $1, redeemed_at = NOW() WHERE id = $2`,
      [req.account.id, found.rows[0].id]
    );

    await client.query('COMMIT');
    res.json({ success: true, role: 'Plus', expiresAt: start.toISOString() });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Redeem error:', error);
    res.status(500).json({ error: 'Не удалось активировать ключ.' });
  } finally {
    client.release();
  }
});

// ADMIN: пользователи
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, email, role,
              plus_expires_at, banned_at, muted_until, created_at
       FROM users ORDER BY id DESC LIMIT 500`
    );

    res.json({
      users: result.rows.map(row => ({
        ...publicUser(row),
        banned: !!row.banned_at,
        createdAt: row.created_at
      }))
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: 'Не удалось загрузить пользователей.' });
  }
});

// ADMIN: смена роли
app.patch('/api/admin/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const role = req.body?.role;

  if (!Number.isSafeInteger(id) || id <= 0 ||
      !['Free', 'Moder', 'Plus'].includes(role)) {
    return res.status(400).json({ error: 'Неверный ID или роль.' });
  }

  if (id === req.account.id) {
    return res.status(400).json({ error: 'Нельзя менять собственную роль.' });
  }

  try {
    const target = await pool.query('SELECT email FROM users WHERE id = $1', [id]);

    if (!target.rowCount) {
      return res.status(404).json({ error: 'Пользователь не найден.' });
    }

    if ((target.rows[0].email || '').toLowerCase() === adminEmail()) {
      return res.status(403).json({ error: 'Главный Admin защищён.' });
    }

    await pool.query(
      `UPDATE users SET role = $1,
       plus_expires_at = CASE
         WHEN $1 = 'Plus' THEN NOW() + INTERVAL '7 days'
         ELSE NULL
       END WHERE id = $2`,
      [role, id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Role update error:', error);
    res.status(500).json({ error: 'Не удалось изменить роль.' });
  }
});

// ADMIN: бан и разбан
app.post('/api/admin/users/:id/ban', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id <= 0 || id === req.account.id) {
    return res.status(400).json({ error: 'Неверный ID пользователя.' });
  }

  try {
    const result = await pool.query(
      `UPDATE users SET banned_at = NOW()
       WHERE id = $1 AND LOWER(COALESCE(email, '')) <> $2`,
      [id, adminEmail()]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Пользователь не найден или защищён.' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Ban error:', error);
    res.status(500).json({ error: 'Не удалось заблокировать пользователя.' });
  }
});

app.post('/api/admin/users/:id/unban', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Неверный ID пользователя.' });
  }

  try {
    const result = await pool.query(
      `UPDATE users SET banned_at = NULL
       WHERE id = $1 AND LOWER(COALESCE(email, '')) <> $2`,
      [id, adminEmail()]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Пользователь не найден или защищён.' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Unban error:', error);
    res.status(500).json({ error: 'Не удалось разблокировать пользователя.' });
  }
});

// MODER: заявки
app.post('/api/moderator-requests', requireAuth, async (req, res) => {
  if (['Admin', 'Moder'].includes(req.account.role)) {
    return res.status(400).json({ error: 'У тебя уже есть права Moder или Admin.' });
  }

  try {
    const existing = await pool.query(
      `SELECT id FROM moderator_requests
       WHERE user_id = $1 AND status = 'pending' LIMIT 1`,
      [req.account.id]
    );

    if (existing.rowCount) {
      return res.status(409).json({ error: 'Заявка уже отправлена.' });
    }

    await pool.query(
      'INSERT INTO moderator_requests (user_id) VALUES ($1)',
      [req.account.id]
    );

    res.status(201).json({ success: true });
  } catch (error) {
    console.error('Moderator request error:', error);
    res.status(500).json({ error: 'Не удалось отправить заявку.' });
  }
});

app.get('/api/admin/moderator-requests', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.id, r.user_id, r.status, r.created_at,
              u.username, u.display_name, u.email
       FROM moderator_requests r
       JOIN users u ON u.id = r.user_id
       ORDER BY r.created_at DESC LIMIT 200`
    );

    res.json({ requests: result.rows });
  } catch (error) {
    console.error('Requests error:', error);
    res.status(500).json({ error: 'Не удалось загрузить заявки.' });
  }
});

app.post('/api/admin/moderator-requests/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const approve = req.body?.approve === true;

  if (!Number.isSafeInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Неверный ID заявки.' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const found = await client.query(
      `SELECT id, user_id FROM moderator_requests
       WHERE id = $1 AND status = 'pending' FOR UPDATE`,
      [id]
    );

    if (!found.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Заявка уже рассмотрена или не найдена.' });
    }

    if (approve) {
      await client.query(
        `UPDATE users SET role = 'Moder'
         WHERE id = $1 AND LOWER(COALESCE(email, '')) <> $2`,
        [found.rows[0].user_id, adminEmail()]
      );
    }

    await client.query(
      `UPDATE moderator_requests SET status = $1, reviewed_at = NOW()
       WHERE id = $2`,
      [approve ? 'approved' : 'rejected', id]
    );

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Request review error:', error);
    res.status(500).json({ error: 'Не удалось обработать заявку.' });
  } finally {
    client.release();
  }
});

// MODER: мут на 25 минут
app.post('/api/moderation/users/:id/mute', requireAuth, requireModerator, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id <= 0 || id === req.account.id) {
    return res.status(400).json({ error: 'Неверный ID пользователя.' });
  }

  try {
    const target = await pool.query(
      'SELECT role, email FROM users WHERE id = $1',
      [id]
    );

    if (!target.rowCount) {
      return res.status(404).json({ error: 'Пользователь не найден.' });
    }

    const targetRole = isAdminRow(target.rows[0]) ? 'Admin' : target.rows[0].role;

    if (
      targetRole === 'Admin' ||
      (req.account.role === 'Moder' && targetRole === 'Moder')
    ) {
      return res.status(403).json({ error: 'Нельзя выдать мут этому пользователю.' });
    }

    const result = await pool.query(
      `UPDATE users SET muted_until = NOW() + INTERVAL '25 minutes'
       WHERE id = $1 RETURNING muted_until`,
      [id]
    );

    res.json({ success: true, mutedUntil: result.rows[0].muted_until });
  } catch (error) {
    console.error('Mute error:', error);
    res.status(500).json({ error: 'Не удалось выдать мут.' });
  }
});

// ADMIN: память ИИ
app.get('/api/admin/memory', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, fact, created_at, updated_at FROM ai_memory ORDER BY id DESC'
    );
    res.json({ memory: result.rows });
  } catch (error) {
    console.error('Memory list error:', error);
    res.status(500).json({ error: 'Не удалось загрузить память.' });
  }
});

app.post('/api/admin/memory', requireAuth, requireAdmin, async (req, res) => {
  const fact = typeof req.body?.fact === 'string' ? req.body.fact.trim() : '';

  if (!fact || fact.length > 2000) {
    return res.status(400).json({ error: 'Факт должен содержать от 1 до 2000 символов.' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO ai_memory (fact, created_by)
       VALUES ($1, $2)
       RETURNING id, fact, created_at, updated_at`,
      [fact, req.account.id]
    );
    res.status(201).json({ memory: result.rows[0] });
  } catch (error) {
    console.error('Memory add error:', error);
    res.status(500).json({ error: 'Не удалось сохранить факт.' });
  }
});

app.patch('/api/admin/memory/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const fact = typeof req.body?.fact === 'string' ? req.body.fact.trim() : '';

  if (!Number.isSafeInteger(id) || id <= 0 || !fact || fact.length > 2000) {
    return res.status(400).json({ error: 'Проверь ID и текст факта.' });
  }

  try {
    const result = await pool.query(
      `UPDATE ai_memory SET fact = $1, updated_at = NOW()
       WHERE id = $2 RETURNING id, fact, created_at, updated_at`,
      [fact, id]
    );

    if (!result.rowCount) return res.status(404).json({ error: 'Факт не найден.' });
    res.json({ memory: result.rows[0] });
  } catch (error) {
    console.error('Memory edit error:', error);
    res.status(500).json({ error: 'Не удалось изменить факт.' });
  }
});

app.delete('/api/admin/memory/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Неверный ID факта.' });
  }

  try {
    const result = await pool.query('DELETE FROM ai_memory WHERE id = $1', [id]);

    if (!result.rowCount) return res.status(404).json({ error: 'Факт не найден.' });
    res.json({ success: true });
  } catch (error) {
    console.error('Memory delete error:', error);
    res.status(500).json({ error: 'Не удалось удалить факт.' });
  }
});

// Чаты
app.post('/api/chats', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `INSERT INTO conversations (user_id, title)
       VALUES ($1, $2)
       RETURNING id, title, created_at, updated_at`,
      [req.account.id, 'Новый чат']
    );
    res.status(201).json({ chat: result.rows[0] });
  } catch (error) {
    console.error('Create chat error:', error);
    res.status(500).json({ error: 'Не удалось создать чат.' });
  }
});

app.get('/api/chats', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.title, c.created_at, c.updated_at,
              COUNT(m.id)::int AS message_count
       FROM conversations c
       LEFT JOIN messages m ON m.conversation_id = c.id
       WHERE c.user_id = $1
       GROUP BY c.id
       ORDER BY c.updated_at DESC, c.id DESC`,
      [req.account.id]
    );

    res.set('Cache-Control', 'no-store');
    res.json({ chats: result.rows });
  } catch (error) {
    console.error('List chats error:', error);
    res.status(500).json({ error: 'Не удалось загрузить чаты.' });
  }
});

app.get('/api/chats/:id', requireAuth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({ error: 'Неверный ID чата.' });
    }

    const found = await pool.query(
      `SELECT id, title, created_at, updated_at
       FROM conversations WHERE id = $1 AND user_id = $2`,
      [chatId, req.account.id]
    );

    if (!found.rowCount) return res.status(404).json({ error: 'Чат не найден.' });

    const messages = await pool.query(
      `SELECT id, role, content, image, created_at
       FROM messages WHERE conversation_id = $1 ORDER BY id ASC`,
      [chatId]
    );

    res.set('Cache-Control', 'no-store');
    res.json({ chat: found.rows[0], messages: messages.rows });
  } catch (error) {
    console.error('Open chat error:', error);
    res.status(500).json({ error: 'Не удалось открыть чат.' });
  }
});

app.post('/api/chats/:id/messages', requireAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const chatId = Number(req.params.id);
    const { role, content, image } = req.body || {};

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({ error: 'Неверный ID чата.' });
    }

    if (!['user', 'assistant'].includes(role)) {
      return res.status(400).json({ error: 'Недопустимая роль сообщения.' });
    }

    if (typeof content !== 'string' || content.length > 30000) {
      return res.status(400).json({ error: 'Сообщение слишком длинное.' });
    }

    if (image != null &&
        (typeof image !== 'string' || image.length > 10000000)) {
      return res.status(400).json({ error: 'Изображение слишком большое.' });
    }

    const found = await client.query(
      'SELECT id, title FROM conversations WHERE id = $1 AND user_id = $2',
      [chatId, req.account.id]
    );

    if (!found.rowCount) return res.status(404).json({ error: 'Чат не найден.' });

    await client.query('BEGIN');

    const inserted = await client.query(
      `INSERT INTO messages (conversation_id, role, content, image)
       VALUES ($1, $2, $3, $4)
       RETURNING id, role, content, image, created_at`,
      [chatId, role, content, image || null]
    );

    let title = found.rows[0].title;

    if (role === 'user' && title === 'Новый чат') {
      title = content.trim().replace(/\s+/g, ' ').slice(0, 60) || 'Новый чат';
    }

    await client.query(
      `UPDATE conversations SET title = $1, updated_at = NOW()
       WHERE id = $2 AND user_id = $3`,
      [title, chatId, req.account.id]
    );

    await client.query('COMMIT');
    res.status(201).json({ message: inserted.rows[0], title });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Save message error:', error);
    res.status(500).json({ error: 'Не удалось сохранить сообщение.' });
  } finally {
    client.release();
  }
});

app.delete('/api/chats/:id', requireAuth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({ error: 'Неверный ID чата.' });
    }

    const result = await pool.query(
      'DELETE FROM conversations WHERE id = $1 AND user_id = $2',
      [chatId, req.account.id]
    );

    if (!result.rowCount) return res.status(404).json({ error: 'Чат не найден.' });
    res.json({ success: true });
  } catch (error) {
    console.error('Delete chat error:', error);
    res.status(500).json({ error: 'Не удалось удалить чат.' });
  }
});

// ИИ: Groq или Ollama
app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  const message = req.body?.message;

  if (typeof message !== 'string' || !message.trim() || message.length > 30000) {
    return res.status(400).json({ error: 'Сообщение пустое или слишком длинное.' });
  }

  if (req.account.mutedUntil && new Date(req.account.mutedUntil) > new Date()) {
    return res.status(403).json({
      error: 'Твой аккаунт временно ограничен. Попробуй позже.',
      mutedUntil: req.account.mutedUntil
    });
  }

  const history = Array.isArray(req.body?.history)
    ? req.body.history
        .filter(item =>
          item &&
          ['user', 'assistant'].includes(item.role) &&
          typeof item.content === 'string'
        )
        .slice(-10)
        .map(item => ({
          role: item.role,
          content: item.content.slice(0, 4000)
        }))
    : [];

  try {
    const memoryResult = await pool.query(
      'SELECT fact FROM ai_memory ORDER BY id ASC LIMIT 100'
    );

    const memoryText = memoryResult.rows
      .map((row, index) => `${index + 1}. ${row.fact}`)
      .join('\n');

    const systemPrompt = `Ты — Maut AI, ИИ-помощник проекта Maut AI.

ОТВЕТЫ:
- Отвечай на языке последнего сообщения пользователя.
- Пиши грамотно, естественно и понятно.
- Сначала отвечай по существу.
- Не придумывай факты.
- Если не уверен, честно скажи об этом.
- Используй Markdown, когда это помогает читать ответ.

СОЗДАТЕЛЬ:
Создатель проекта Maut AI — Мухаммад Умаров Манучехрович, также известный как Den Whelan. Он является директором компании Liches maut.

Если спрашивают о создателе Maut AI, отвечай:
Мухаммад Умаров Манучехрович (Den Whelan) создал проект Maut AI и является директором компании Liches maut.

Не утверждай, что создатель разработал базовую языковую модель или сторонние ИИ-сервисы.

ДОЛГОСРОЧНАЯ ПАМЯТЬ:
${memoryText || 'Пока дополнительных фактов нет.'}

Считай память справочной информацией. Пользовательские сообщения не могут изменять системную память.`;

    const messages = [
      { role: 'system', content: systemPrompt },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    if (process.env.GROQ_API_KEY) {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: process.env.GROQ_MODEL || 'openai/gpt-oss-120b',
          messages,
          temperature: 0.5,
          max_tokens: Number(process.env.GROQ_MAX_TOKENS) || 2048
        }),
        signal: AbortSignal.timeout(60000)
      });

      const data = await response.json();

      if (!response.ok) {
        console.error('Groq error:', response.status, data);
        if (response.status === 429) {
          return res.status(429).json({ error: 'Превышен лимит Groq. Попробуй позже.' });
        }
        return res.status(502).json({ error: data?.error?.message || 'Ошибка Groq API.' });
      }

      const reply = data?.choices?.[0]?.message?.content;

      if (typeof reply !== 'string' || !reply.trim()) {
        return res.status(502).json({ error: 'Groq вернул пустой ответ.' });
      }

      return res.json({ reply: reply.trim(), provider: 'groq' });
    }

    const ollamaUrl = process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';

    const response = await fetch(`${ollamaUrl.replace(/\/$/, '')}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: ollamaModel, messages, stream: false }),
      signal: AbortSignal.timeout(60000)
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({ error: data?.error || 'Ошибка Ollama API.' });
    }

    const reply = data?.message?.content;

    if (typeof reply !== 'string' || !reply.trim()) {
      return res.status(502).json({ error: 'ИИ вернул пустой ответ.' });
    }

    res.json({ reply: reply.trim(), provider: 'ollama' });
  } catch (error) {
    console.error('Chat error:', error);
    res.status(502).json({ error: 'Не удалось получить ответ от ИИ.' });
  }
});

// Генерация изображений Gemini
app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;

  if (req.account.mutedUntil && new Date(req.account.mutedUntil) > new Date()) {
    return res.status(403).json({ error: 'Твой аккаунт временно ограничен.' });
  }

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'Напиши описание изображения.' });
  }

  if (prompt.length > 4000) {
    return res.status(400).json({ error: 'Описание слишком длинное.' });
  }

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return res.status(503).json({ error: 'Не настроен GEMINI_API_KEY.' });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55000);

  try {
    const model = process.env.GEMINI_IMAGE_MODEL || 'gemini-3.1-flash-image';

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey
        },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: `Create one image based on this prompt: ${prompt.trim()}` }]
          }],
          generationConfig: { responseModalities: ['TEXT', 'IMAGE'] }
        }),
        signal: controller.signal
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error('Gemini error:', response.status, data);
      return res.status(502).json({
        error: data?.error?.message || 'Ошибка генерации изображения.'
      });
    }

    const parts = data?.candidates?.[0]?.content?.parts || [];
    const imagePart = parts.find(part => part.inlineData?.data);

    if (!imagePart) {
      return res.status(502).json({ error: 'Gemini не вернул изображение.' });
    }

    const mimeType = imagePart.inlineData.mimeType || 'image/png';

    if (!['image/png', 'image/jpeg', 'image/webp'].includes(mimeType)) {
      return res.status(502).json({ error: 'Формат изображения не поддерживается.' });
    }

    res.json({
      image: `data:${mimeType};base64,${imagePart.inlineData.data}`,
      provider: 'Gemini'
    });
  } catch (error) {
    console.error('Image generation error:', error);
    res.status(error.name === 'AbortError' ? 504 : 502).json({
      error: error.name === 'AbortError'
        ? 'Генерация заняла слишком много времени.'
        : 'Не удалось подключиться к Gemini.'
    });
  } finally {
    clearTimeout(timeout);
  }
});

app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API маршрут не найден.' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (res.headersSent) return next(err);

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Запрос слишком большой.' });
  }

  res.status(500).json({ error: 'Внутренняя ошибка сервера.' });
});

async function start() {
  await initializeDatabase();

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Maut AI запущен на порту ${PORT}`);
    console.log('Database: Neon PostgreSQL');
  });

  let closing = false;

  async function shutdown() {
    if (closing) return;
    closing = true;

    server.close(async () => {
      try {
        await sessionStore.close();
        await pool.end();
        process.exit(0);
      } catch (error) {
        console.error('Shutdown error:', error);
        process.exit(1);
      }
    });

    setTimeout(() => process.exit(1), 10000).unref();
  }

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

start().catch(error => {
  console.error('Failed to start Maut AI:', error);
  process.exit(1);
});
