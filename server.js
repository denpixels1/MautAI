// Maut AI — server.js
// Полный объединённый сервер

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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

const MAX_MESSAGE_LENGTH = 30000;
const MAX_HISTORY_MESSAGES = 10;
const MAX_HISTORY_TOTAL_LENGTH = 12000;

if (isProduction) app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT || '12mb' }));

// База данных
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
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const userColumns = db.prepare('PRAGMA table_info(users)')
  .all()
  .map(column => column.name);

if (!userColumns.includes('display_name')) {
  db.exec('ALTER TABLE users ADD COLUMN display_name TEXT');
}

if (!userColumns.includes('email')) {
  db.exec('ALTER TABLE users ADD COLUMN email TEXT');
}

if (!userColumns.includes('last_login')) {
  db.exec('ALTER TABLE users ADD COLUMN last_login TEXT');
}

// Для существующих аккаунтов сохраняем доступ и начинаем отсчёт с текущих данных.
db.exec(`
  UPDATE users
  SET last_login = COALESCE(last_login, created_at, CURRENT_TIMESTAMP)
  WHERE last_login IS NULL
`);

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
  ON users(email)
  WHERE email IS NOT NULL AND email != ''
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT 'Новый чат',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    image TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id)
      REFERENCES conversations(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS conversations_user_updated
  ON conversations(user_id, updated_at DESC);

  CREATE INDEX IF NOT EXISTS messages_conversation_id
  ON messages(conversation_id, id);
`);

// Сессии
const SQLiteStore = SQLiteStoreFactory(session);

const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: DATA_DIR,
  table: 'sessions'
});

const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    'Установи SESSION_SECRET длиной минимум 32 символа в переменных окружения.'
  );
}

app.use(session({
  name: 'maut.sid',
  secret: SESSION_SECRET,
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

// Ограничение частоты запросов
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
  legacyHeaders: false,
  message: {
    error: 'Слишком много генераций. Подожди минуту.'
  }
});

// Защита одного экземпляра сервера от слишком большого числа одновременных AI-запросов.
// Для нескольких экземпляров приложения понадобится общая очередь Redis/BullMQ.
const MAX_PARALLEL_AI_REQUESTS = Math.max(1, Number(process.env.MAX_PARALLEL_AI_REQUESTS) || 4);
const MAX_QUEUED_AI_REQUESTS = Math.max(0, Number(process.env.MAX_QUEUED_AI_REQUESTS) || 20);
let activeAIRequests = 0;
let queuedAIRequests = 0;

function aiCapacity(req, res, next) {
  if (activeAIRequests < MAX_PARALLEL_AI_REQUESTS) {
    activeAIRequests++;
    let released = false;
    const release = () => { if (!released) { released = true; activeAIRequests = Math.max(0, activeAIRequests - 1); } };
    res.once('finish', release);
    res.once('close', release);
    return next();
  }
  if (queuedAIRequests >= MAX_QUEUED_AI_REQUESTS) {
    return res.status(503).json({ error: 'Сейчас Maut AI занят. Подожди немного и попробуй снова.' });
  }
  queuedAIRequests++;
  const started = Date.now();
  const poll = setInterval(() => {
    if (res.destroyed || res.writableEnded) {
      clearInterval(poll);
      queuedAIRequests = Math.max(0, queuedAIRequests - 1);
      return;
    }
    if (activeAIRequests < MAX_PARALLEL_AI_REQUESTS) {
      clearInterval(poll);
      queuedAIRequests = Math.max(0, queuedAIRequests - 1);
      activeAIRequests++;
      let released = false;
      const release = () => { if (!released) { released = true; activeAIRequests = Math.max(0, activeAIRequests - 1); } };
      res.once('finish', release);
      res.once('close', release);
      return next();
    }
    if (Date.now() - started >= 15000) {
      clearInterval(poll);
      queuedAIRequests = Math.max(0, queuedAIRequests - 1);
      if (!res.headersSent) res.status(503).json({ error: 'Очередь Maut AI переполнена. Попробуй ещё раз через минуту.' });
    }
  }, 200);
}

// Вспомогательные функции
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Сначала войди в аккаунт.'
    });
  }

  next();
}

function normalizeDisplayName(value) {
  if (typeof value !== 'string') return null;

  const name = value.trim().replace(/\s+/g, ' ');

  if (!name || [...name].length > 60) return null;

  return name;
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;

  const email = value.trim().toLowerCase();

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return null;
  }

  return email;
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    name: row.display_name || row.username,
    email: row.email || null
  };
}

function createLoginSession(req, res, user, statusCode = 200) {
  req.session.regenerate(err => {
    if (err) {
      console.error('Session regenerate error:', err);

      return res.status(500).json({
        error: 'Не удалось создать сессию.'
      });
    }

    req.session.user = user;

    req.session.save(saveErr => {
      if (saveErr) {
        console.error('Session save error:', saveErr);

        return res.status(500).json({
          error: 'Не удалось сохранить вход.'
        });
      }

      res.status(statusCode).json({ user });
    });
  });
}

// Авторизация: текущий пользователь
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: req.session.user || null });
});

// Регистрация
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = normalizeDisplayName(
      req.body?.name || req.body?.username
    );

    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!name) {
      return res.status(400).json({
        error: 'Введи имя длиной от 1 до 60 символов.'
      });
    }

    if (!email) {
      return res.status(400).json({
        error: 'Введи корректный email.'
      });
    }

    if (
      typeof password !== 'string' ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: 'Пароль должен содержать от 8 до 128 символов.'
      });
    }

    const existing = db.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).get(email);

    if (existing) {
      return res.status(409).json({
        error: 'Аккаунт с таким email уже существует. Войди в него.'
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users
        (username, password_hash, display_name, email, last_login)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(email, hash, name, email);

    const user = {
      id: Number(result.lastInsertRowid),
      username: email,
      name,
      email
    };

    createLoginSession(req, res, user, 201);
  } catch (err) {
    console.error('Registration error:', err);

    res.status(500).json({
      error: 'Ошибка регистрации на сервере.'
    });
  }
});

// Вход
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const loginValue = typeof req.body?.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : (
          typeof req.body?.username === 'string'
            ? req.body.username.trim()
            : ''
        );

    const password = req.body?.password;

    if (
      !loginValue ||
      loginValue.length > 254 ||
      typeof password !== 'string' ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: 'Введи email и пароль.'
      });
    }

    const row = db.prepare(`
      SELECT id, username, password_hash, display_name, email, last_login
      FROM users
      WHERE email = ? OR username = ?
      LIMIT 1
    `).get(loginValue, loginValue);

    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({
        error: 'Неверный email или пароль.'
      });
    }

    // После 30 дней без входа удаляем только чаты и сообщения.
    // Аккаунт, email и хеш пароля остаются: пользователь сможет войти снова.
    const cleanupInactiveUser = db.transaction(userId => {
      const inactive = db.prepare(`
        SELECT 1 FROM users
        WHERE id = ?
          AND datetime(COALESCE(last_login, created_at)) <= datetime('now', '-30 days')
      `).get(userId);

      if (inactive) {
        db.prepare('DELETE FROM conversations WHERE user_id = ?').run(userId);
      }

      db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?')
        .run(userId);
    });
    cleanupInactiveUser(row.id);

    createLoginSession(req, res, publicUser(row));
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Ошибка входа на сервере.'
    });
  }
});

// Выход
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Не удалось выйти из аккаунта.'
      });
    }

    res.clearCookie('maut.sid', {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/'
    });

    res.json({ success: true });
  });
});

// Создать новый чат
app.post('/api/chats', requireAuth, (req, res) => {
  try {
    const result = db.prepare(`
      INSERT INTO conversations (user_id, title)
      VALUES (?, ?)
    `).run(req.session.user.id, 'Новый чат');

    const chat = db.prepare(`
      SELECT id, title, created_at, updated_at
      FROM conversations
      WHERE id = ? AND user_id = ?
    `).get(result.lastInsertRowid, req.session.user.id);

    res.status(201).json({ chat });
  } catch (err) {
    console.error('Create chat error:', err);

    res.status(500).json({
      error: 'Не удалось создать чат.'
    });
  }
});

// Получить список чатов
app.get('/api/chats', requireAuth, (req, res) => {
  try {
    const chats = db.prepare(`
      SELECT
        c.id,
        c.title,
        c.created_at,
        c.updated_at,
        COUNT(m.id) AS message_count
      FROM conversations c
      LEFT JOIN messages m ON m.conversation_id = c.id
      WHERE c.user_id = ?
      GROUP BY c.id
      ORDER BY c.updated_at DESC, c.id DESC
    `).all(req.session.user.id);

    res.set('Cache-Control', 'no-store');
    res.json({ chats });
  } catch (err) {
    console.error('List chats error:', err);

    res.status(500).json({
      error: 'Не удалось загрузить список чатов.'
    });
  }
});

// Открыть чат
app.get('/api/chats/:id', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({
        error: 'Неверный ID чата.'
      });
    }

    const chat = db.prepare(`
      SELECT id, title, created_at, updated_at
      FROM conversations
      WHERE id = ? AND user_id = ?
    `).get(chatId, req.session.user.id);

    if (!chat) {
      return res.status(404).json({
        error: 'Чат не найден.'
      });
    }

    const messages = db.prepare(`
      SELECT id, role, content, image, created_at
      FROM messages
      WHERE conversation_id = ?
      ORDER BY id ASC
    `).all(chatId);

    res.set('Cache-Control', 'no-store');
    res.json({ chat, messages });
  } catch (err) {
    console.error('Open chat error:', err);

    res.status(500).json({
      error: 'Не удалось открыть чат.'
    });
  }
});

// Сохранить сообщение в чате
app.post('/api/chats/:id/messages', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const { role, content, image } = req.body || {};

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({
        error: 'Неверный ID чата.'
      });
    }

    if (!['user', 'assistant'].includes(role)) {
      return res.status(400).json({
        error: 'Недопустимая роль сообщения.'
      });
    }

    if (
      typeof content !== 'string' ||
      content.length > MAX_MESSAGE_LENGTH
    ) {
      return res.status(400).json({
        error: `Сообщение должно содержать не более ${MAX_MESSAGE_LENGTH} символов.`
      });
    }

    if (
      image != null &&
      (typeof image !== 'string' || image.length > 10000000)
    ) {
      return res.status(400).json({
        error: 'Изображение слишком большое.'
      });
    }

    const chat = db.prepare(`
      SELECT id, title
      FROM conversations
      WHERE id = ? AND user_id = ?
    `).get(chatId, req.session.user.id);

    if (!chat) {
      return res.status(404).json({
        error: 'Чат не найден.'
      });
    }

    const insert = db.prepare(`
      INSERT INTO messages
        (conversation_id, role, content, image)
      VALUES (?, ?, ?, ?)
    `).run(chatId, role, content, image || null);

    let title = chat.title;

    if (role === 'user' && title === 'Новый чат') {
      title = content.trim().replace(/\s+/g, ' ').slice(0, 60)
        || 'Новый чат';

      db.prepare(`
        UPDATE conversations
        SET title = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
      `).run(title, chatId, req.session.user.id);
    } else {
      db.prepare(`
        UPDATE conversations
        SET updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
      `).run(chatId, req.session.user.id);
    }

    res.status(201).json({
      message: {
        id: Number(insert.lastInsertRowid),
        role,
        content,
        image: image || null
      },
      title
    });
  } catch (err) {
    console.error('Save message error:', err);

    res.status(500).json({
      error: 'Не удалось сохранить сообщение.'
    });
  }
});

// Удалить чат
app.delete('/api/chats/:id', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({
        error: 'Неверный ID чата.'
      });
    }

    const result = db.prepare(`
      DELETE FROM conversations
      WHERE id = ? AND user_id = ?
    `).run(chatId, req.session.user.id);

    if (!result.changes) {
      return res.status(404).json({
        error: 'Чат не найден.'
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Delete chat error:', err);

    res.status(500).json({
      error: 'Не удалось удалить чат.'
    });
  }
});
