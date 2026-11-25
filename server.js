import 'dotenv/config';
import crypto from 'node:crypto';
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

if (!userColumns.includes('rank')) {
  db.exec("ALTER TABLE users ADD COLUMN rank TEXT NOT NULL DEFAULT 'FREE'");
}

db.exec(`
  CREATE TABLE IF NOT EXISTS rank_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    rank TEXT NOT NULL CHECK (rank IN ('PLUS', 'MODER')),
    created_by INTEGER,
    used_by INTEGER,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const ADMIN_EMAIL = 'denpixels1@gmail.com';
const VALID_RANKS = ['FREE', 'PLUS', 'MODER', 'ADMIN'];

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

const SQLiteStore = SQLiteStoreFactory(session);

const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: DATA_DIR,
  table: 'sessions'
});

const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    'Установи SESSION_SECRET длиной минимум 32 символа в Render.'
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
    email: row.email || null,
    rank: VALID_RANKS.includes(row.rank) ? row.rank : 'FREE'
  };
}

function getUserRank(userId) {
  const row = db.prepare(
    'SELECT rank FROM users WHERE id = ?'
  ).get(userId);

  return VALID_RANKS.includes(row?.rank) ? row.rank : 'FREE';
}

function requireRank(...allowedRanks) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Сначала войди в аккаунт.' });
    }

    const rank = getUserRank(req.session.user.id);

    if (!allowedRanks.includes(rank)) {
      return res.status(403).json({ error: 'Недостаточно прав.' });
    }

    req.session.user.rank = rank;
    next();
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

// Проверка аккаунта
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');

  if (!req.session.user) {
    return res.json({ user: null });
  }

  const row = db.prepare(`
    SELECT id, username, display_name, email, rank
    FROM users
    WHERE id = ?
  `).get(req.session.user.id);

  if (!row) {
    return res.json({ user: null });
  }

  const user = publicUser(row);
  req.session.user = user;

  res.json({ user });
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
        (username, password_hash, display_name, email, rank)
      VALUES (?, ?, ?, ?, 'FREE')
    `).run(email, hash, name, email);

    const user = {
      id: Number(result.lastInsertRowid),
      username: email,
      name,
      email,
      rank: 'FREE'
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
      SELECT id, username, password_hash, display_name, email, rank
      FROM users
      WHERE email = ? OR username = ?
      LIMIT 1
    `).get(loginValue, loginValue);

    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({
        error: 'Неверный email или пароль.'
      });
    }

    // ADMIN назначается только указанному аккаунту после проверки пароля.
    if (row.email?.toLowerCase() === ADMIN_EMAIL) {
      db.prepare(
        "UPDATE users SET rank = 'ADMIN' WHERE id = ?"
      ).run(row.id);

      row.rank = 'ADMIN';
    }

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
});// Создать новый чат
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
    res.status(500).json({ error: 'Не удалось создать чат.' });
  }
});

// История чатов
app.get('/api/chats', requireAuth, (req, res) => {
  try {
    const chats = db.prepare(`
      SELECT c.id, c.title, c.created_at, c.updated_at,
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
    console.error(err);
    res.status(500).json({ error: 'Не удалось загрузить историю.' });
  }
});

// Открыть чат
app.get('/api/chats/:id', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({ error: 'Неверный ID чата.' });
    }

    const chat = db.prepare(`
      SELECT id, title, created_at, updated_at
      FROM conversations
      WHERE id = ? AND user_id = ?
    `).get(chatId, req.session.user.id);

    if (!chat) {
      return res.status(404).json({ error: 'Чат не найден.' });
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
    console.error(err);
    res.status(500).json({ error: 'Не удалось открыть чат.' });
  }
});

// Сохранить сообщение
app.post('/api/chats/:id/messages', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const { role, content, image } = req.body || {};

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({ error: 'Неверный ID чата.' });
    }

    if (!['user', 'assistant'].includes(role)) {
      return res.status(400).json({ error: 'Недопустимая роль.' });
    }

    if (typeof content !== 'string' || content.length > MAX_MESSAGE_LENGTH) {
      return res.status(400).json({
        error: `Максимум ${MAX_MESSAGE_LENGTH} символов.`
      });
    }

    if (image != null && (
      typeof image !== 'string' || image.length > 10000000
    )) {
      return res.status(400).json({ error: 'Изображение слишком большое.' });
    }

    const chat = db.prepare(`
      SELECT id, title
      FROM conversations
      WHERE id = ? AND user_id = ?
    `).get(chatId, req.session.user.id);

    if (!chat) {
      return res.status(404).json({ error: 'Чат не найден.' });
    }

    const insert = db.prepare(`
      INSERT INTO messages (conversation_id, role, content, image)
      VALUES (?, ?, ?, ?)
    `).run(chatId, role, content, image || null);

    let title = chat.title;

    if (role === 'user' && title === 'Новый чат') {
      title = content.trim().replace(/\s+/g, ' ').slice(0, 60) || 'Новый чат';

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
    console.error(err);
    res.status(500).json({ error: 'Не удалось сохранить сообщение.' });
  }
});

// Удалить чат
app.delete('/api/chats/:id', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({ error: 'Неверный ID чата.' });
    }

    const result = db.prepare(`
      DELETE FROM conversations
      WHERE id = ? AND user_id = ?
    `).run(chatId, req.session.user.id);

    if (!result.changes) {
      return res.status(404).json({ error: 'Чат не найден.' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Не удалось удалить чат.' });
  }
});

// Maut AI — общение с ИИ
app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    const message = req.body?.message;

    if (
      typeof message !== 'string' ||
      !message.trim() ||
      message.length > MAX_MESSAGE_LENGTH
    ) {
      return res.status(400).json({
        error: `Сообщение пустое или превышает лимит ${MAX_MESSAGE_LENGTH} символов.`
      });
    }

    const rawHistory = Array.isArray(req.body?.history)
      ? req.body.history.filter(item =>
          item &&
          ['user', 'assistant'].includes(item.role) &&
          typeof item.content === 'string'
        ).slice(-MAX_HISTORY_MESSAGES)
      : [];

    const history = [];
    let historyLength = 0;

    for (let i = rawHistory.length - 1; i >= 0; i--) {
      const item = rawHistory[i];
      const remaining = MAX_HISTORY_TOTAL_LENGTH - historyLength;
      if (remaining <= 0) break;

      const content = item.content.slice(0, remaining);
      if (!content) continue;

      history.unshift({ role: item.role, content });
      historyLength += content.length;
    }

    const messages = [
      {
        role: 'system',
        content: `Ты — Maut AI, полезный, внимательный и дружелюбный ИИ-помощник.
Отвечай на языке пользователя.

Пиши грамотно, понятно и последовательно.
Для длинных ответов используй Markdown-заголовки и списки.
Код оформляй в блоках с указанием языка.
Не выдумывай факты и не повторяй одну мысль без необходимости.

Создатель проекта Maut AI — Den Whelan,
директор компании Liches maut.
Если спрашивают о создателе, отвечай именно так.
Не утверждай, что он создал сторонние модели ИИ.`
      },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    // Groq API
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
            max_tokens: Number(process.env.GROQ_MAX_TOKENS) || 4096
          }),
          signal: AbortSignal.timeout(60000)
        }
      );

      const data = await response.json();

      if (!response.ok) {
        console.error('Groq error:', response.status, data);

        return res.status(response.status === 429 ? 429 : 502).json({
          error: data?.error?.message || 'Ошибка Groq API.'
        });
      }

      const reply = data?.choices?.[0]?.message?.content;

      if (typeof reply !== 'string' || !reply.trim()) {
        return res.status(502).json({ error: 'ИИ вернул пустой ответ.' });
      }

      return res.json({ reply: reply.trim(), provider: 'groq' });
    }

    // Ollama — если Groq не настроен
    const ollamaUrl =
      process.env.OLLAMA_URL || 'http://127.0.0.1:11434';

    const ollamaModel =
      process.env.OLLAMA_MODEL || 'llama3.2';

    const response = await fetch(
      `${ollamaUrl.replace(/\/$/, '')}/api/chat`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: ollamaModel,
          messages,
          stream: false
        }),
        signal: AbortSignal.timeout(60000)
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({
        error: data?.error || `Ошибка Ollama: ${response.status}`
      });
    }

    const reply = data?.message?.content;

    if (typeof reply !== 'string' || !reply.trim()) {
      return res.status(502).json({ error: 'ИИ вернул пустой ответ.' });
    }

    return res.json({ reply: reply.trim(), provider: 'ollama' });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(502).json({
      error: 'Не удалось получить ответ от ИИ. Проверь настройки модели.'
    });
  }
});// Генерация изображений через Gemini
app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'Напиши описание изображения.' });
  }

  if (prompt.length > 4000) {
    return res.status(400).json({
      error: 'Описание изображения слишком длинное.'
    });
  }

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return res.status(503).json({
      error: 'Добавь GEMINI_API_KEY в переменные окружения.'
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55000);

  try {
    const model =
      process.env.GEMINI_IMAGE_MODEL || 'gemini-3.1-flash-image';

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
            parts: [{
              text: `Create one image based on this prompt: ${prompt.trim()}`
            }]
          }],
          generationConfig: {
            responseModalities: ['TEXT', 'IMAGE']
          }
        }),
        signal: controller.signal
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({
        error: data?.error?.message || 'Ошибка Gemini API.'
      });
    }

    const parts = data?.candidates?.[0]?.content?.parts || [];
    const imagePart = parts.find(part => part.inlineData?.data);

    if (!imagePart) {
      return res.status(502).json({
        error: 'Модель не вернула изображение.'
      });
    }

    const mimeType = imagePart.inlineData.mimeType || 'image/png';

    if (!['image/png', 'image/jpeg', 'image/webp'].includes(mimeType)) {
      return res.status(502).json({ error: 'Формат изображения не поддерживается.' });
    }

    res.json({
      image: `data:${mimeType};base64,${imagePart.inlineData.data}`,
      provider: 'Gemini'
    });
  } catch (err) {
    console.error('Image generation error:', err);

    res.status(err.name === 'AbortError' ? 504 : 502).json({
      error: err.name === 'AbortError'
        ? 'Генерация заняла слишком много времени.'
        : 'Не удалось подключиться к Gemini API.'
    });
  } finally {
    clearTimeout(timeout);
  }
});

// Получить свой ранг
app.get('/api/ranks/me', requireAuth, (req, res) => {
  const rank = getUserRank(req.session.user.id);
  req.session.user.rank = rank;

  res.set('Cache-Control', 'no-store');
  res.json({ rank });
});

// Активировать код
app.post('/api/ranks/redeem', requireAuth, (req, res) => {
  const code = String(req.body?.code || '').trim().toUpperCase();

  if (!code || code.length > 80) {
    return res.status(400).json({ error: 'Введи корректный код.' });
  }

  try {
    const redeem = db.transaction(() => {
      const item = db.prepare(`
        SELECT id, rank
        FROM rank_codes
        WHERE code = ? AND used_by IS NULL
      `).get(code);

      if (!item) return null;

      const result = db.prepare(`
        UPDATE rank_codes
        SET used_by = ?, used_at = CURRENT_TIMESTAMP
        WHERE id = ? AND used_by IS NULL
      `).run(req.session.user.id, item.id);

      if (!result.changes) return null;

      db.prepare(`
        UPDATE users SET rank = ?
        WHERE id = ?
      `).run(item.rank, req.session.user.id);

      return item.rank;
    });

    const rank = redeem();

    if (!rank) {
      return res.status(400).json({
        error: 'Код не найден или уже использован.'
      });
    }

    req.session.user.rank = rank;
    res.json({ success: true, rank });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Не удалось активировать код.' });
  }
});

// Список пользователей для администратора
app.get('/api/admin/users', requireAuth, requireRank('ADMIN'), (req, res) => {
  const users = db.prepare(`
    SELECT id, username, email, display_name, rank, created_at
    FROM users
    ORDER BY id DESC
  `).all();

  res.json({ users });
});

// Изменить ранг пользователя
app.post('/api/admin/users/:id/rank', requireAuth, requireRank('ADMIN'), (req, res) => {
  const id = Number(req.params.id);
  const rank = String(req.body?.rank || '').toUpperCase();

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Неверный ID пользователя.' });
  }

  if (!VALID_RANKS.includes(rank)) {
    return res.status(400).json({ error: 'Неизвестный ранг.' });
  }

  const target = db.prepare(
    'SELECT id, email FROM users WHERE id = ?'
  ).get(id);

  if (!target) {
    return res.status(404).json({ error: 'Пользователь не найден.' });
  }

  if (
    String(target.email || '').toLowerCase() === ADMIN_EMAIL &&
    rank !== 'ADMIN'
  ) {
    return res.status(403).json({
      error: 'Нельзя изменить ранг владельца.'
    });
  }

  // Нельзя назначить другого ADMIN через эту панель.
  if (rank === 'ADMIN' && id !== req.session.user.id) {
    return res.status(403).json({
      error: 'Нельзя назначить дополнительного администратора.'
    });
  }

  db.prepare('UPDATE users SET rank = ? WHERE id = ?').run(rank, id);
  res.json({ success: true, rank });
});

// Создать коды PLUS или MODER
app.post('/api/admin/codes', requireAuth, requireRank('ADMIN'), (req, res) => {
  const rank = String(req.body?.rank || '').toUpperCase();
  const amount = Math.min(20, Math.max(1, Number(req.body?.amount) || 1));

  if (!['PLUS', 'MODER'].includes(rank)) {
    return res.status(400).json({
      error: 'Коды доступны для PLUS и MODER.'
    });
  }

  const create = db.transaction(() => {
    const codes = [];

    for (let i = 0; i < amount; i++) {
      const code = `MAUT-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;

      db.prepare(`
        INSERT INTO rank_codes (code, rank, created_by)
        VALUES (?, ?, ?)
      `).run(code, rank, req.session.user.id);

      codes.push(code);
    }

    return codes;
  });

  res.status(201).json({
    success: true,
    rank,
    codes: create()
  });
});

// Список созданных кодов
app.get('/api/admin/codes', requireAuth, requireRank('ADMIN'), (req, res) => {
  const codes = db.prepare(`
    SELECT code, rank, created_at, used_at, used_by
    FROM rank_codes
    ORDER BY id DESC
    LIMIT 100
  `).all();

  res.json({ codes });
});

// Статические файлы сайта
const PUBLIC_CANDIDATES = [
  path.join(__dirname, 'public', 'public'),
  path.join(__dirname, 'public'),
  __dirname
];

const PUBLIC_DIR = PUBLIC_CANDIDATES.find(dir =>
  fs.existsSync(path.join(dir, 'index.html'))
);

if (!PUBLIC_DIR) {
  throw new Error(
    'Не найден index.html. Проверь папки public/public, public и корень проекта.'
  );
}

app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  maxAge: isProduction ? '1h' : 0
}));

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Maut AI запущен на порту ${PORT}`);
});

function shutdown() {
  console.log('Остановка Maut AI...');

  server.close(() => {
    try {
      sessionStore.close?.();
      db.close();
    } catch (err) {
      console.error(err);
    }

    process.exit(0);
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
