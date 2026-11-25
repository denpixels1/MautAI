
import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const PROD = process.env.NODE_ENV === 'production';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();

if (PROD) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '20mb' }));

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'maut.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  email TEXT UNIQUE,
  role TEXT NOT NULL DEFAULT 'Free',
  plus_expires_at TEXT,
  muted_until TEXT,
  banned_until TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS conversations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL DEFAULT 'Новый чат',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('user','assistant')),
  content TEXT NOT NULL,
  image TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS gift_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  days INTEGER NOT NULL,
  used_by INTEGER,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(used_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ai_memory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS moderator_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS conversations_user_updated
ON conversations(user_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS messages_conversation_id
ON messages(conversation_id, id);
`);

// Миграции для уже существующей базы
function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some(c => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}
ensureColumn('users', 'display_name', 'TEXT');
ensureColumn('users', 'email', 'TEXT');
ensureColumn('users', 'role', "TEXT NOT NULL DEFAULT 'Free'");
ensureColumn('users', 'plus_expires_at', 'TEXT');
ensureColumn('users', 'muted_until', 'TEXT');
ensureColumn('users', 'banned_until', 'TEXT');

const SQLiteStore = SQLiteStoreFactory(session);
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: DATA_DIR,
  table: 'sessions'
});

const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET должен содержать минимум 32 символа.');
}

app.use(session({
  name: 'maut.sid',
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: PROD,
  cookie: {
    httpOnly: true,
    secure: PROD,
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

const getUser = db.prepare('SELECT * FROM users WHERE id = ?');

function isAdmin(user) {
  return Boolean(user && (
    user.role === 'Admin' ||
    (ADMIN_EMAIL && user.email?.toLowerCase() === ADMIN_EMAIL)
  ));
}

function isModerator(user) {
  return user?.role === 'Moder';
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    name: user.display_name || user.username,
    email: user.email || null,
    role: isAdmin(user) ? 'Admin' : user.role,
    plusExpiresAt: user.plus_expires_at || null,
    mutedUntil: user.muted_until || null,
    bannedUntil: user.banned_until || null
  };
}

function refreshSessionUser(req) {
  if (!req.session.user?.id) return null;
  const row = getUser.get(req.session.user.id);
  if (!row) return null;
  req.session.user = publicUser(row);
  return row;
}

function requireAuth(req, res, next) {
  const row = refreshSessionUser(req);
  if (!row) {
    return res.status(401).json({ error: 'Войди в аккаунт.' });
  }

  if (row.banned_until && new Date(row.banned_until) > new Date()) {
    return res.status(403).json({
      error: 'Твой аккаунт временно заблокирован.',
      bannedUntil: row.banned_until
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  const row = refreshSessionUser(req);
  if (!row || !isAdmin(row)) {
    return res.status(403).json({ error: 'Доступ только для Admin.' });
  }
  next();
}

function requireModerator(req, res, next) {
  const row = refreshSessionUser(req);
  if (!row || (!isAdmin(row) && !isModerator(row))) {
    return res.status(403).json({ error: 'Недостаточно прав.' });
  }
  next();
}

function cleanName(value) {
  if (typeof value !== 'string') return null;
  const v = value.trim().replace(/\s+/g, ' ');
  return v && [...v].length <= 60 ? v : null;
}

function cleanEmail(value) {
  if (typeof value !== 'string') return null;
  const v = value.trim().toLowerCase();
  return v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)
    ? v : null;
}

function loginSession(req, res, row, status = 200) {
  req.session.regenerate(err => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Ошибка создания сессии.' });
    }
    req.session.user = publicUser(row);
    req.session.save(saveErr => {
      if (saveErr) {
        console.error(saveErr);
        return res.status(500).json({ error: 'Ошибка сохранения сессии.' });
      }
      res.status(status).json({ user: req.session.user });
    });
  });
}

// AUTH
app.get('/api/auth/me', (req, res) => {
  const row = refreshSessionUser(req);
  res.set('Cache-Control', 'no-store');
  res.json({ user: publicUser(row) });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = cleanName(req.body?.name || req.body?.username);
    const email = cleanEmail(req.body?.email);
    const password = req.body?.password;

    if (!name || !email || typeof password !== 'string' ||
        password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: 'Проверь имя, email и пароль (не менее 8 символов).'
      });
    }

    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
      return res.status(409).json({ error: 'Этот email уже зарегистрирован.' });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(`
      INSERT INTO users(username,password_hash,display_name,email)
      VALUES(?,?,?,?)
    `).run(email, hash, name, email);

    loginSession(req, res, getUser.get(Number(result.lastInsertRowid)), 201);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка регистрации.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const login = String(req.body?.email || req.body?.username || '')
      .trim().toLowerCase();
    const password = req.body?.password;

    const row = db.prepare(`
      SELECT * FROM users WHERE email = ? OR username = ? LIMIT 1
    `).get(login, login);

    if (!row || typeof password !== 'string' ||
        !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }

    if (row.banned_until && new Date(row.banned_until) > new Date()) {
      return res.status(403).json({
        error: 'Аккаунт заблокирован до ' + row.banned_until
      });
    }

    loginSession(req, res, row);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка входа.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Не удалось выйти.' });
    res.clearCookie('maut.sid', {
      httpOnly: true, secure: PROD, sameSite: 'lax', path: '/'
    });
    res.json({ success: true });
  });
});

// ACCOUNT
app.get('/api/account', requireAuth, (req, res) => {
  const row = getUser.get(req.session.user.id);
  res.json({ user: publicUser(row) });
});

// CHATS
app.post('/api/chats', requireAuth, (req, res) => {
  const result = db.prepare(`
    INSERT INTO conversations(user_id,title) VALUES(?,?)
  `).run(req.session.user.id, 'Новый чат');

  const chat = db.prepare(`
    SELECT id,title,created_at,updated_at FROM conversations WHERE id=?
  `).get(result.lastInsertRowid);

  res.status(201).json({ chat });
});

app.get('/api/chats', requireAuth, (req, res) => {
  const chats = db.prepare(`
    SELECT c.id,c.title,c.created_at,c.updated_at,COUNT(m.id) AS message_count
    FROM conversations c
    LEFT JOIN messages m ON m.conversation_id=c.id
    WHERE c.user_id=?
    GROUP BY c.id ORDER BY c.updated_at DESC
  `).all(req.session.user.id);
  res.set('Cache-Control', 'no-store');
  res.json({ chats });
});

app.get('/api/chats/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const chat = db.prepare(`
    SELECT id,title,created_at,updated_at
    FROM conversations WHERE id=? AND user_id=?
  `).get(id, req.session.user.id);

  if (!chat) return res.status(404).json({ error: 'Чат не найден.' });

  const messages = db.prepare(`
    SELECT id,role,content,image,created_at
    FROM messages WHERE conversation_id=? ORDER BY id
  `).all(id);

  res.json({ chat, messages });
});

app.post('/api/chats/:id/messages', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const { role, content, image } = req.body || {};

  if (!['user', 'assistant'].includes(role) ||
      typeof content !== 'string' || content.length > 30000) {
    return res.status(400).json({ error: 'Некорректное сообщение.' });
  }

  const chat = db.prepare(`
    SELECT id,title FROM conversations WHERE id=? AND user_id=?
  `).get(id, req.session.user.id);

  if (!chat) return res.status(404).json({ error: 'Чат не найден.' });

  const result = db.prepare(`
    INSERT INTO messages(conversation_id,role,content,image)
    VALUES(?,?,?,?)
  `).run(id, role, content, typeof image === 'string' ? image : null);

  let title = chat.title;
  if (role === 'user' && title === 'Новый чат') {
    title = content.trim().replace(/\s+/g, ' ').slice(0, 60) || 'Новый чат';
  }

  db.prepare(`
    UPDATE conversations SET title=?,updated_at=CURRENT_TIMESTAMP
    WHERE id=? AND user_id=?
  `).run(title, id, req.session.user.id);

  res.status(201).json({
    message: {
      id: Number(result.lastInsertRowid),
      role, content, image: image || null
    },
    title
  });
});

app.delete('/api/chats/:id', requireAuth, (req, res) => {
  const result = db.prepare(`
    DELETE FROM conversations WHERE id=? AND user_id=?
  `).run(Number(req.params.id), req.session.user.id);

  if (!result.changes) return res.status(404).json({ error: 'Чат не найден.' });
  res.json({ success: true });
});

// AI CHAT
app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    const message = req.body?.message;
    if (typeof message !== 'string' || !message.trim() ||
        message.length > 30000) {
      return res.status(400).json({ error: 'Некорректное сообщение.' });
    }

    const userRow = getUser.get(req.session.user.id);
    if (userRow.muted_until && new Date(userRow.muted_until) > new Date()) {
      return res.status(403).json({
        error: 'Ты временно не можешь отправлять сообщения.',
        mutedUntil: userRow.muted_until
      });
    }

    const memory = db.prepare('SELECT title,content FROM ai_memory ORDER BY id DESC LIMIT 30').all();
    const memoryText = memory.map(m => `${m.title}: ${m.content}`).join('\n');

    const history = Array.isArray(req.body.history)
      ? req.body.history.slice(-10)
          .filter(x => x && ['user','assistant'].includes(x.role) &&
            typeof x.content === 'string')
          .map(x => ({ role: x.role, content: x.content.slice(0, 4000) }))
      : [];

    const messages = [
      {
        role: 'system',
        content: `Ты — Maut AI. Отвечай на языке пользователя, ясно и дружелюбно.
Создатель Maut AI — Den Whelan, директор компании Liches maut.
Не утверждай, что создатель проекта создал базовые сторонние модели.
Память проекта:\n${memoryText}`
      },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    if (process.env.GROQ_API_KEY) {
      const response = await fetch(
        'https://api.groq.com/openai/v1/chat/completions',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: process.env.GROQ_MODEL || 'openai/gpt-oss-120b',
            messages,
            temperature: 0.5,
            max_tokens: 4096
          }),
          signal: AbortSignal.timeout(60000)
        }
      );

      const data = await response.json();
      if (!response.ok) {
        return res.status(response.status === 429 ? 429 : 502).json({
          error: data?.error?.message || 'Ошибка Groq API.'
        });
      }

      const reply = data?.choices?.[0]?.message?.content;
      if (!reply) return res.status(502).json({ error: 'Пустой ответ Groq.' });
      return res.json({ reply, provider: 'groq' });
    }

    const base = (process.env.OLLAMA_URL || 'http://127.0.0.1:11434')
      .replace(/\/$/, '');
    const response = await fetch(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: process.env.OLLAMA_MODEL || 'llama3.2',
        messages,
        stream: false
      }),
      signal: AbortSignal.timeout(60000)
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(502).json({ error: data?.error || 'Ошибка Ollama.' });
    }

    const reply = data?.message?.content;
    if (!reply) return res.status(502).json({ error: 'ИИ вернул пустой ответ.' });
    res.json({ reply, provider: 'ollama' });
  } catch (e) {
    console.error('Chat error:', e);
    res.status(502).json({ error: 'Не удалось подключиться к ИИ.' });
  }
});

// IMAGE GENERATION
app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  try {
    const prompt = req.body?.prompt;
    if (typeof prompt !== 'string' || !prompt.trim() || prompt.length > 4000) {
      return res.status(400).json({ error: 'Напиши описание изображения.' });
    }

    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({ error: 'Не задан GEMINI_API_KEY.' });
    }

    const model = process.env.GEMINI_IMAGE_MODEL || 'gemini-3.1-flash-image';
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': process.env.GEMINI_API_KEY
        },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt.trim() }] }],
          generationConfig: { responseModalities: ['TEXT', 'IMAGE'] }
        }),
        signal: AbortSignal.timeout(55000)
      }
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(502).json({
        error: data?.error?.message || 'Ошибка Gemini.'
      });
    }

    const part = data?.candidates?.[0]?.content?.parts
      ?.find(p => p.inlineData?.data);

    if (!part) return res.status(502).json({ error: 'Gemini не вернула изображение.' });

    const mime = part.inlineData.mimeType || 'image/png';
    if (!['image/png','image/jpeg','image/webp'].includes(mime)) {
      return res.status(502).json({ error: 'Неподдерживаемый формат изображения.' });
    }

    res.json({
      image: `data:${mime};base64,${part.inlineData.data}`,
      provider: 'Gemini'
    });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: 'Не удалось создать изображение.' });
  }
});

// PLUS GIFT CODES
app.post('/api/gift-codes/redeem', requireAuth, (req, res) => {
  const code = String(req.body?.code || '').trim().toUpperCase();
  if (!code) return res.status(400).json({ error: 'Введи ключ.' });

  const redeem = db.transaction(() => {
    const gift = db.prepare(`
      SELECT * FROM gift_codes WHERE code=? AND used_by IS NULL
    `).get(code);

    if (!gift) return null;

    const user = getUser.get(req.session.user.id);
    const current = user.plus_expires_at &&
      new Date(user.plus_expires_at) > new Date()
      ? new Date(user.plus_expires_at)
      : new Date();

    current.setDate(current.getDate() + gift.days);

    db.prepare(`
      UPDATE users SET role='Plus',plus_expires_at=? WHERE id=?
    `).run(current.toISOString(), user.id);

    db.prepare(`
      UPDATE gift_codes SET used_by=?,used_at=CURRENT_TIMESTAMP WHERE id=?
    `).run(user.id, gift.id);

    return getUser.get(user.id);
  });

  const updated = redeem();
  if (!updated) return res.status(400).json({ error: 'Ключ неверный или уже использован.' });

  req.session.user = publicUser(updated);
  res.json({ success: true, user: req.session.user });
});

// MODERATOR REQUESTS
app.post('/api/moderator-requests', requireAuth, (req, res) => {
  const user = getUser.get(req.session.user.id);
  if (isAdmin(user) || isModerator(user)) {
    return res.status(400).json({ error: 'У тебя уже есть права персонала.' });
  }

  const message = typeof req.body?.message === 'string'
    ? req.body.message.slice(0, 1000)
    : '';

  const pending = db.prepare(`
    SELECT id FROM moderator_requests WHERE user_id=? AND status='pending'
  `).get(user.id);

  if (pending) return res.status(409).json({ error: 'Заявка уже отправлена.' });

  const result = db.prepare(`
    INSERT INTO moderator_requests(user_id,message) VALUES(?,?)
  `).run(user.id, message);

  res.status(201).json({ success: true, id: result.lastInsertRowid });
});

// ADMIN: USERS
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id,username,display_name,email,role,plus_expires_at,
      muted_until,banned_until,created_at
    FROM users ORDER BY id DESC
  `).all().map(u => ({
    ...u,
    name: u.display_name || u.username,
    plusExpiresAt: u.plus_expires_at,
    mutedUntil: u.muted_until,
    bannedUntil: u.banned_until
  }));

  res.json({ users });
});

app.patch('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const role = req.body?.role;
  if (!['Free','Plus','Moder','Admin'].includes(role)) {
    return res.status(400).json({ error: 'Недопустимая роль.' });
  }

  const target = getUser.get(id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден.' });

  // Нельзя случайно снять или изменить права текущего Admin через этот маршрут.
  if (isAdmin(target) && id !== req.session.user.id) {
    return res.status(403).json({ error: 'Нельзя изменить другого Admin.' });
  }

  db.prepare('UPDATE users SET role=? WHERE id=?').run(role, id);
  res.json({ success: true, user: publicUser(getUser.get(id)) });
});

app.post('/api/admin/users/:id/ban', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = getUser.get(id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден.' });
  if (isAdmin(target)) return res.status(403).json({ error: 'Нельзя заблокировать Admin.' });

  const until = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE users SET banned_until=? WHERE id=?').run(until, id);
  res.json({ success: true, bannedUntil: until });
});

app.post('/api/admin/users/:id/unban', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = getUser.get(id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден.' });

  db.prepare('UPDATE users SET banned_until=NULL WHERE id=?').run(id);
  res.json({ success: true });
});

app.post('/api/admin/users/:id/unban', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = getUser.get(id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден.' });
  db.prepare('UPDATE users SET banned_until=NULL WHERE id=?').run(id);
  res.json({ success: true });
});

// ADMIN: GIFT KEYS
app.post('/api/admin/gift-codes', requireAdmin, (req, res) => {
  const days = Number(req.body?.days);
  const amount = Math.min(20, Math.max(1, Number(req.body?.amount) || 1));

  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ error: 'Количество дней должно быть от 1 до 3650.' });
  }

  const codes = [];
  const insert = db.prepare('INSERT INTO gift_codes(code,days) VALUES(?,?)');

  const create = db.transaction(() => {
    for (let i = 0; i < amount; i++) {
      const code = crypto.randomBytes(8).toString('hex').toUpperCase();
      insert.run(code, days);
      codes.push(code);
    }
  });

  create();
  res.status(201).json({ success: true, codes, days });
});

app.get('/api/admin/gift-codes', requireAdmin, (req, res) => {
  const codes = db.prepare(`
    SELECT g.id,g.code,g.days,g.used_at,g.created_at,
      u.email AS used_by_email
    FROM gift_codes g LEFT JOIN users u ON u.id=g.used_by
    ORDER BY g.id DESC
  `).all();
  res.json({ codes });
});

// ADMIN: MEMORY
app.get('/api/admin/memory', requireAdmin, (req, res) => {
  const memory = db.prepare('SELECT * FROM ai_memory ORDER BY id DESC').all();
  res.json({ memory });
});

app.post('/api/admin/memory', requireAdmin, (req, res) => {
  const title = cleanName(req.body?.title);
  const content = typeof req.body?.content === 'string'
    ? req.body.content.trim()
    : '';

  if (!title || !content || content.length > 10000) {
    return res.status(400).json({ error: 'Проверь заголовок и текст памяти.' });
  }

  const result = db.prepare(`
    INSERT INTO ai_memory(title,content) VALUES(?,?)
  `).run(title, content);

  res.status(201).json({
    success: true,
    memory: db.prepare('SELECT * FROM ai_memory WHERE id=?').get(result.lastInsertRowid)
  });
});

app.patch('/api/admin/memory/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const title = cleanName(req.body?.title);
  const content = typeof req.body?.content === 'string'
    ? req.body.content.trim()
    : '';

  if (!title || !content || content.length > 10000) {
    return res.status(400).json({ error: 'Некорректная память.' });
  }

  const result = db.prepare(`
    UPDATE ai_memory SET title=?,content=? WHERE id=?
  `).run(title, content, id);

  if (!result.changes) return res.status(404).json({ error: 'Запись не найдена.' });
  res.json({ success: true });
});

app.delete('/api/admin/memory/:id', requireAdmin, (req, res) => {
  const result = db.prepare('DELETE FROM ai_memory WHERE id=?').run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Запись не найдена.' });
  res.json({ success: true });
});

// ADMIN: MODERATOR REQUESTS
app.get('/api/admin/moderator-requests', requireAdmin, (req, res) => {
  const requests = db.prepare(`
    SELECT r.*,u.username,u.display_name,u.email
    FROM moderator_requests r
    JOIN users u ON u.id=r.user_id
    ORDER BY r.id DESC
  `).all();
  res.json({ requests });
});

app.post('/api/admin/moderator-requests/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const action = req.body?.action;
  if (!['approve','reject'].includes(action)) {
    return res.status(400).json({ error: 'Неизвестное действие.' });
  }

  const request = db.prepare(`
    SELECT * FROM moderator_requests WHERE id=?
  `).get(id);
  if (!request) return res.status(404).json({ error: 'Заявка не найдена.' });

  const update = db.transaction(() => {
    db.prepare('UPDATE moderator_requests SET status=? WHERE id=?')
      .run(action === 'approve' ? 'approved' : 'rejected', id);

    if (action === 'approve') {
      db.prepare('UPDATE users SET role=? WHERE id=?')
        .run('Moder', request.user_id);
    }
  });

  update();
  res.json({ success: true });
});

// MODERATOR: LIST USERS
app.get('/api/moderation/users', requireModerator, (req, res) => {
  const users = db.prepare(`
    SELECT id,username,display_name,email,role,muted_until,banned_until
    FROM users WHERE role IN ('Free','Plus')
    ORDER BY id DESC
  `).all().map(u => ({
    ...u,
    name: u.display_name || u.username,
    mutedUntil: u.muted_until,
    bannedUntil: u.banned_until
  }));
  res.json({ users });
});

function getModerationTarget(req, res) {
  const id = Number(req.params.id);
  const target = getUser.get(id);
  if (!target) {
    res.status(404).json({ error: 'Пользователь не найден.' });
    return null;
  }

  const actor = getUser.get(req.session.user.id);

  if (!isAdmin(actor) && !['Free','Plus'].includes(target.role)) {
    res.status(403).json({ error: 'Moder может управлять только обычными аккаунтами.' });
    return null;
  }

  if (isAdmin(target) || isModerator(target)) {
    res.status(403).json({ error: 'Нельзя применять наказания к Admin или Moder.' });
    return null;
  }

  return target;
}

// Мут на 25 минут
app.post('/api/moderation/users/:id/mute', requireModerator, (req, res) => {
  const target = getModerationTarget(req, res);
  if (!target) return;

  const until = new Date(Date.now() + 25 * 60 * 1000).toISOString();
  db.prepare('UPDATE users SET muted_until=? WHERE id=?').run(until, target.id);
  res.json({ success: true, mutedUntil: until });
});

// Бан на 7 дней
app.post('/api/moderation/users/:id/ban', requireModerator, (req, res) => {
  const target = getModerationTarget(req, res);
  if (!target) return;

  const until = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE users SET banned_until=? WHERE id=?').run(until, target.id);
  res.json({ success: true, bannedUntil: until });
});

// Досрочный разбан
app.post('/api/moderation/users/:id/unban', requireModerator, (req, res) => {
  const target = getModerationTarget(req, res);
  if (!target) return;

  db.prepare('UPDATE users SET banned_until=NULL WHERE id=?').run(target.id);
  res.json({ success: true });
});

// Снять мут
app.post('/api/moderation/users/:id/unmute', requireModerator, (req, res) => {
  const target = getModerationTarget(req, res);
  if (!target) return;

  db.prepare('UPDATE users SET muted_until=NULL WHERE id=?').run(target.id);
  res.json({ success: true });
});

// STATIC FILES
app.use(express.static(__dirname));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API маршрут не найден.' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  if (res.headersSent) return next(err);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Запрос слишком большой.' });
  }
  res.status(500).json({ error: 'Внутренняя ошибка сервера.' });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Maut AI запущен на порту ${PORT}`);
});

function shutdown() {
  server.close(() => {
    sessionStore.close?.();
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
