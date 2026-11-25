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
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ADMIN_EMAIL = 'denpixels1@gmail.com';

const MAX_MESSAGE_LENGTH = 30000;
const MAX_HISTORY_MESSAGES = 12;
const MAX_HISTORY_LENGTH = 16000;
const VALID_RANKS = ['FREE', 'PLUS', 'MODER', 'ADMIN'];

if (IS_PRODUCTION) {
  app.set('trust proxy', 1);
}

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
  );
`);

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some(item => item.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

ensureColumn('users', 'display_name', 'TEXT');
ensureColumn('users', 'email', 'TEXT');
ensureColumn('users', 'rank', "TEXT NOT NULL DEFAULT 'FREE'");
ensureColumn('users', 'banned', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('users', 'ban_reason', 'TEXT');
ensureColumn('users', 'last_login', 'TEXT');

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
  ON users(email)
  WHERE email IS NOT NULL AND email != '';

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
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    image TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(conversation_id)
      REFERENCES conversations(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS conversations_user_updated
  ON conversations(user_id, updated_at DESC);

  CREATE INDEX IF NOT EXISTS messages_conversation_id
  ON messages(conversation_id, id);

  CREATE TABLE IF NOT EXISTS rank_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    requested_rank TEXT NOT NULL
      CHECK(requested_rank IN ('PLUS', 'MODER', 'ADMIN')),
    message TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'PENDING'
      CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS rank_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    rank TEXT NOT NULL CHECK(rank IN ('PLUS', 'MODER')),
    created_by INTEGER,
    used_by INTEGER,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    'SESSION_SECRET должен быть задан и содержать минимум 32 символа.'
  );
}

const SQLiteStore = SQLiteStoreFactory(session);

const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: DATA_DIR,
  table: 'sessions'
});

app.use(session({
  name: 'maut.sid',
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: IS_PRODUCTION,
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
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

function normalizeUsername(value) {
  if (typeof value !== 'string') return null;

  const username = value.trim().toLowerCase();

  if (!/^[a-z0-9_.-]{3,30}$/.test(username)) {
    return null;
  }

  return username;
}

function normalizeDisplayName(value) {
  if (typeof value !== 'string') return null;

  const name = value.trim().replace(/\s+/g, ' ');

  if (!name || [...name].length > 60) return null;

  return name;
}

function getUserById(id) {
  return db.prepare(`
    SELECT id, username, display_name, email, rank, banned, ban_reason,
           created_at, password_hash
    FROM users
    WHERE id = ?
  `).get(id);
}

function getRank(userId) {
  const user = db.prepare(`
    SELECT email, rank
    FROM users
    WHERE id = ?
  `).get(userId);

  if (!user) return 'FREE';

  if (String(user.email || '').toLowerCase() === ADMIN_EMAIL) {
    if (user.rank !== 'ADMIN') {
      db.prepare('UPDATE users SET rank = ? WHERE id = ?')
        .run('ADMIN', userId);
    }

    return 'ADMIN';
  }

  return VALID_RANKS.includes(user.rank) ? user.rank : 'FREE';
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    name: user.display_name || user.username,
    email: user.email,
    rank: getRank(user.id)
  };
}

function requireAuth(req, res, next) {
  const sessionUser = req.session?.user;

  if (!sessionUser?.id) {
    return res.status(401).json({
      error: 'Сначала войди в аккаунт.'
    });
  }

  const user = getUserById(sessionUser.id);

  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({
      error: 'Аккаунт не найден. Войди снова.'
    });
  }

  if (user.banned) {
    req.session.destroy(() => {});
    return res.status(403).json({
      error: user.ban_reason
        ? `Аккаунт заблокирован: ${user.ban_reason}`
        : 'Аккаунт заблокирован администратором.'
    });
  }

  req.user = user;
  next();
}

function requireRank(...allowedRanks) {
  return (req, res, next) => {
    if (!req.session?.user?.id) {
      return res.status(401).json({
        error: 'Сначала войди в аккаунт.'
      });
    }

    const rank = getRank(req.session.user.id);

    if (!allowedRanks.includes(rank)) {
      return res.status(403).json({
        error: 'Недостаточно прав.'
      });
    }

    next();
  };
}

function createSession(req, user, res) {
  req.session.regenerate(err => {
    if (err) {
      console.error('Session error:', err);
      return res.status(500).json({
        error: 'Не удалось создать сессию.'
      });
    }

    req.session.user = {
      id: user.id
    };

    req.session.save(saveError => {
      if (saveError) {
        console.error('Session save error:', saveError);
        return res.status(500).json({
          error: 'Не удалось сохранить сессию.'
        });
      }

      const freshUser = getUserById(user.id);
      res.json({
        success: true,
        user: publicUser(freshUser)
      });
    });
  });
}

function makeRankCode() {
  return `MAUT-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

function getOwnedChat(chatId, userId) {
  return db.prepare(`
    SELECT id, user_id, title, created_at, updated_at
    FROM conversations
    WHERE id = ? AND user_id = ?
  `).get(chatId, userId);
}

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'Maut AI',
    time: new Date().toISOString()
  });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};

    const email = normalizeEmail(body.email);
    const password = body.password;
    const displayName = normalizeDisplayName(
      body.name || body.displayName || body.username
    );

    let username = normalizeUsername(body.username);

    if (!username && email) {
      username = normalizeUsername(email.split('@')[0]);
    }

    if (!email) {
      return res.status(400).json({
        error: 'Введи корректный адрес электронной почты.'
      });
    }

    if (!username) {
      return res.status(400).json({
        error: 'Имя пользователя должно содержать 3–30 символов: латинские буквы, цифры, точку, дефис или _.'
      });
    }

    if (!displayName) {
      return res.status(400).json({
        error: 'Введи имя длиной не более 60 символов.'
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

    const existing = db.prepare(`
      SELECT id
      FROM users
      WHERE email = ? OR username = ?
    `).get(email, username);

    if (existing) {
      return res.status(409).json({
        error: 'Аккаунт с таким email или именем пользователя уже существует.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users
        (username, password_hash, display_name, email, rank)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      username,
      passwordHash,
      displayName,
      email,
      email === ADMIN_EMAIL ? 'ADMIN' : 'FREE'
    );

    const user = getUserById(Number(result.lastInsertRowid));

    db.prepare(`
      UPDATE users
      SET last_login = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(user.id);

    createSession(req, user, res);
  } catch (err) {
    console.error('Registration error:', err);

    if (String(err.code || '').includes('CONSTRAINT')) {
      return res.status(409).json({
        error: 'Такой аккаунт уже существует.'
      });
    }

    res.status(500).json({
      error: 'Не удалось создать аккаунт.'
    });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const login = String(
      body.login || body.email || body.username || ''
    ).trim().toLowerCase();

    const password = body.password;

    if (!login || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Введи логин и пароль.'
      });
    }

    const user = db.prepare(`
      SELECT *
      FROM users
      WHERE lower(email) = ? OR lower(username) = ?
    `).get(login, login);

    if (!user) {
      return res.status(401).json({
        error: 'Неверный логин или пароль.'
      });
    }

    if (user.banned) {
      return res.status(403).json({
        error: user.ban_reason
          ? `Аккаунт заблокирован: ${user.ban_reason}`
          : 'Аккаунт заблокирован администратором.'
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: 'Неверный логин или пароль.'
      });
    }

    db.prepare(`
      UPDATE users
      SET last_login = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(user.id);

    createSession(req, user, res);
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Не удалось выполнить вход.'
    });
  }
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session?.user?.id) {
    return res.json({ user: null });
  }

  const user = getUserById(req.session.user.id);

  if (!user || user.banned) {
    req.session.destroy(() => {});
    return res.json({ user: null });
  }

  res.set('Cache-Control', 'no-store');
  res.json({
    user: publicUser(user)
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Не удалось выйти из аккаунта.'
      });
    }

    res.clearCookie('maut.sid', {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: 'lax',
      path: '/'
    });

    res.json({ success: true });
  });
});

app.post('/api/chats', requireAuth, (req, res) => {
  try {
    const result = db.prepare(`
      INSERT INTO conversations (user_id, title)
      VALUES (?, 'Новый чат')
    `).run(req.user.id);

    const chat = getOwnedChat(
      Number(result.lastInsertRowid),
      req.user.id
    );

    res.status(201).json({ chat });
  } catch (err) {
    console.error('Create chat error:', err);
    res.status(500).json({
      error: 'Не удалось создать чат.'
    });
  }
});

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
    `).all(req.user.id);

    res.set('Cache-Control', 'no-store');
    res.json({ chats });
  } catch (err) {
    console.error('Get chats error:', err);
    res.status(500).json({
      error: 'Не удалось загрузить чаты.'
    });
  }
});

app.get('/api/chats/:id', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({
        error: 'Неверный ID чата.'
      });
    }

    const chat = getOwnedChat(chatId, req.user.id);

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
        error: `Сообщение не должно превышать ${MAX_MESSAGE_LENGTH} символов.`
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

    const chat = getOwnedChat(chatId, req.user.id);

    if (!chat) {
      return res.status(404).json({
        error: 'Чат не найден.'
      });
    }

    const result = db.prepare(`
      INSERT INTO messages (conversation_id, role, content, image)
      VALUES (?, ?, ?, ?)
    `).run(chatId, role, content, image || null);

    let title = chat.title;

    if (role === 'user' && title === 'Новый чат') {
      title = content.trim().replace(/\s+/g, ' ').slice(0, 60)
        || 'Новый чат';
    }

    db.prepare(`
      UPDATE conversations
      SET title = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ?
    `).run(title, chatId, req.user.id);

    res.status(201).json({
      message: {
        id: Number(result.lastInsertRowid),
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
    `).run(chatId, req.user.id);

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

const SYSTEM_PROMPT = `Ты — Maut AI, полезный, внимательный и дружелюбный ИИ-помощник. Отвечай на языке пользователя, если он не попросил другой язык.

Пиши естественно, грамотно и понятно. Сначала отвечай по существу. Не выдумывай факты. Если не знаешь ответа, честно скажи об этом. Используй Markdown, когда он помогает сделать ответ понятнее. Код оформляй в блоках с указанием языка.

Создатель проекта Maut AI — Мухаммад Умаров Манучехрович, также известный как Den Whelan, директор компании Liches maut. Если спрашивают о создателе Maut AI, сообщай именно это. Не утверждай, что он создал базовые языковые модели или сторонние ИИ-сервисы.`;

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
      ? req.body.history
          .filter(item =>
            item &&
            ['user', 'assistant'].includes(item.role) &&
            typeof item.content === 'string'
          )
          .slice(-MAX_HISTORY_MESSAGES)
      : [];

    const history = [];
    let totalLength = 0;

    for (let i = rawHistory.length - 1; i >= 0; i--) {
      const item = rawHistory[i];
      const remaining = MAX_HISTORY_LENGTH - totalLength;

      if (remaining <= 0) break;

      const content = item.content.slice(0, remaining);

      if (!content) continue;

      history.unshift({
        role: item.role,
        content
      });

      totalLength += content.length;
    }

    const messages = [
      { role: 'system', content: SYSTEM_PROMPT },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    if (process.env.GROQ_API_KEY) {
      let response;

      try {
        response = await fetch(
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
      } catch (err) {
        console.error('Groq connection error:', err);
        return res.status(502).json({
          error: 'Не удалось подключиться к Groq API.'
        });
      }

      let data;

      try {
        data = await response.json();
      } catch {
        return res.status(502).json({
          error: 'Groq вернул ответ в неизвестном формате.'
        });
      }

      if (!response.ok) {
        console.error('Groq API error:', response.status, data);

        if (response.status === 429) {
          return res.status(429).json({
            error: 'Превышен лимит запросов Groq. Попробуй позже.'
          });
        }

        if ([401, 403].includes(response.status)) {
          return res.status(502).json({
            error: 'Groq отклонил API-ключ. Проверь GROQ_API_KEY.'
          });
        }

        return res.status(502).json({
          error: data?.error?.message || 'Ошибка Groq API.'
        });
      }

      const reply = data?.choices?.[0]?.message?.content;

      if (typeof reply !== 'string' || !reply.trim()) {
        return res.status(502).json({
          error: 'Groq вернул пустой ответ.'
        });
      }

      return res.json({
        reply: reply.trim(),
        provider: 'groq'
      });
    }

    const ollamaUrl = (
      process.env.OLLAMA_URL || 'http://127.0.0.1:11434'
    ).replace(/\/$/, '');

    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';

    let response;

    try {
      response = await fetch(`${ollamaUrl}/api/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: ollamaModel,
          messages,
          stream: false
        }),
        signal: AbortSignal.timeout(60000)
      });
    } catch (err) {
      console.error('Ollama connection error:', err);
      return res.status(502).json({
        error: 'Не удалось подключиться к Ollama. Настрой GROQ_API_KEY или проверь OLLAMA_URL.'
      });
    }

    let data;

    try {
      data = await response.json();
    } catch {
      return res.status(502).json({
        error: 'Ollama вернула ответ в неизвестном формате.'
      });
    }

    if (!response.ok) {
      return res.status(502).json({
        error: data?.error || `Ошибка Ollama: ${response.status}.`
      });
    }

    const reply = data?.message?.content;

    if (typeof reply !== 'string' || !reply.trim()) {
      return res.status(502).json({
        error: 'ИИ вернул пустой ответ.'
      });
    }

    res.json({
      reply: reply.trim(),
      provider: 'ollama'
    });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).json({
      error: 'Не удалось обработать сообщение.'
    });
  }
});

app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({
      error: 'Напиши описание изображения.'
    });
  }

  if (prompt.length > 4000) {
    return res.status(400).json({
      error: 'Описание изображения слишком длинное. Максимум 4000 символов.'
    });
  }

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return res.status(503).json({
      error: 'Для генерации изображений добавь GEMINI_API_KEY в переменные окружения.'
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55000);

  try {
    const model = process.env.GEMINI_IMAGE_MODEL
      || 'gemini-2.0-flash-preview-image-generation';

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
      console.error('Gemini API error:', data);
      return res.status(502).json({
        error: data?.error?.message || 'Не удалось создать изображение через Gemini.'
      });
    }

    const parts = data?.candidates?.[0]?.content?.parts || [];
    const imagePart = parts.find(part => part.inlineData?.data);

    if (!imagePart) {
      return res.status(502).json({
        error: 'Модель не вернула изображение. Попробуй изменить описание.'
      });
    }

    const mimeType = imagePart.inlineData.mimeType || 'image/png';

    if (!['image/png', 'image/jpeg', 'image/webp'].includes(mimeType)) {
      return res.status(502).json({
        error: 'Формат изображения не поддерживается.'
      });
    }

    res.json({
      image: `data:${mimeType};base64,${imagePart.inlineData.data}`,
      provider: 'Gemini'
    });
  } catch (err) {
    console.error('Image generation error:', err);

    res.status(err.name === 'AbortError' ? 504 : 502).json({
      error: err.name === 'AbortError'
        ? 'Генерация заняла слишком много времени. Попробуй ещё раз.'
        : 'Не удалось подключиться к Gemini.'
    });
  } finally {
    clearTimeout(timeout);
  }
});

app.get('/api/ranks/me', requireAuth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    rank: getRank(req.user.id)
  });
});

app.post('/api/ranks/redeem', requireAuth, (req, res) => {
  const code = String(req.body?.code || '').trim().toUpperCase();

  if (!code || code.length > 80) {
    return res.status(400).json({
      error: 'Введи корректный код.'
    });
  }

  try {
    const redeem = db.transaction(() => {
      const item = db.prepare(`
        SELECT id, rank
        FROM rank_codes
        WHERE code = ? AND used_by IS NULL
      `).get(code);

      if (!item) return null;

      const update = db.prepare(`
        UPDATE rank_codes
        SET used_by = ?, used_at = CURRENT_TIMESTAMP
        WHERE id = ? AND used_by IS NULL
      `).run(req.user.id, item.id);

      if (!update.changes) return null;

      db.prepare(`
        UPDATE users
        SET rank = ?
        WHERE id = ?
      `).run(item.rank, req.user.id);

      return item.rank;
    });

    const rank = redeem();

    if (!rank) {
      return res.status(400).json({
        error: 'Код не найден или уже использован.'
      });
    }

    res.json({
      success: true,
      rank
    });
  } catch (err) {
    console.error('Redeem code error:', err);
    res.status(500).json({
      error: 'Не удалось активировать код.'
    });
  }
});

app.post('/api/ranks/request', requireAuth, (req, res) => {
  const rank = String(req.body?.rank || '').toUpperCase();
  const message = String(req.body?.message || '').trim().slice(0, 500);
  const current = getRank(req.user.id);

  if (!['PLUS', 'MODER', 'ADMIN'].includes(rank)) {
    return res.status(400).json({
      error: 'Неверный ранг.'
    });
  }

  if (
    current === 'ADMIN' ||
    (current === 'MODER' && rank !== 'ADMIN') ||
    (current === 'PLUS' && rank === 'PLUS')
  ) {
    return res.status(400).json({
      error: 'У тебя уже есть этот или более высокий ранг.'
    });
  }

  const pending = db.prepare(`
    SELECT id
    FROM rank_requests
    WHERE user_id = ? AND status = 'PENDING'
  `).get(req.user.id);

  if (pending) {
    return res.status(409).json({
      error: 'У тебя уже есть ожидающая заявка.'
    });
  }

  const result = db.prepare(`
    INSERT INTO rank_requests (user_id, requested_rank, message)
    VALUES (?, ?, ?)
  `).run(req.user.id, rank, message);

  res.status(201).json({
    success: true,
    id: Number(result.lastInsertRowid)
  });
});

app.get(
  '/api/admin/requests',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const requests = db.prepare(`
      SELECT
        r.id,
        r.requested_rank,
        r.message,
        r.created_at,
        u.id AS user_id,
        u.display_name,
        u.username,
        u.email,
        u.rank AS current_rank
      FROM rank_requests r
      JOIN users u ON u.id = r.user_id
      WHERE r.status = 'PENDING'
      ORDER BY r.id DESC
    `).all();

    res.set('Cache-Control', 'no-store');
    res.json({ requests });
  }
);

app.post(
  '/api/admin/requests/:id/review',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const id = Number(req.params.id);
    const decision = String(req.body?.decision || '').toUpperCase();

    if (
      !Number.isSafeInteger(id) ||
      id < 1 ||
      !['APPROVE', 'REJECT'].includes(decision)
    ) {
      return res.status(400).json({
        error: 'Некорректный запрос.'
      });
    }

    const review = db.transaction(() => {
      const item = db.prepare(`
        SELECT id, user_id, requested_rank
        FROM rank_requests
        WHERE id = ? AND status = 'PENDING'
      `).get(id);

      if (!item) return null;

      if (decision === 'APPROVE') {
        db.prepare(`
          UPDATE users
          SET rank = ?
          WHERE id = ?
        `).run(item.requested_rank, item.user_id);
      }

      db.prepare(`
        UPDATE rank_requests
        SET status = ?,
            reviewed_at = CURRENT_TIMESTAMP,
            reviewed_by = ?
        WHERE id = ?
      `).run(
        decision === 'APPROVE' ? 'APPROVED' : 'REJECTED',
        req.user.id,
        id
      );

      return item;
    });

    const result = review();

    if (!result) {
      return res.status(404).json({
        error: 'Заявка уже обработана или не найдена.'
      });
    }

    res.json({ success: true });
  }
);

app.get(
  '/api/admin/users',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const users = db.prepare(`
      SELECT
        id,
        username,
        email,
        display_name,
        rank,
        banned,
        ban_reason,
        created_at,
        last_login
      FROM users
      ORDER BY id DESC
    `).all();

    res.set('Cache-Control', 'no-store');
    res.json({ users });
  }
);

app.post(
  '/api/admin/users/:id/rank',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const id = Number(req.params.id);
    const rank = String(req.body?.rank || '').toUpperCase();

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        error: 'Неверный ID пользователя.'
      });
    }

    if (!VALID_RANKS.includes(rank)) {
      return res.status(400).json({
        error: 'Неизвестный ранг.'
      });
    }

    const target = db.prepare(`
      SELECT id, email
      FROM users
      WHERE id = ?
    `).get(id);

    if (!target) {
      return res.status(404).json({
        error: 'Пользователь не найден.'
      });
    }

    if (
      String(target.email || '').toLowerCase() === ADMIN_EMAIL &&
      rank !== 'ADMIN'
    ) {
      return res.status(403).json({
        error: 'Нельзя изменить ранг владельца.'
      });
    }

    db.prepare(`
      UPDATE users
      SET rank = ?
      WHERE id = ?
    `).run(rank, id);

    res.json({
      success: true,
      rank
    });
  }
);

app.post(
  '/api/admin/users/:id/ban',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const id = Number(req.params.id);
    const reason = String(
      req.body?.reason || 'Нарушение правил'
    ).trim().slice(0, 300);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        error: 'Неверный ID пользователя.'
      });
    }

    const target = db.prepare(`
      SELECT id, email
      FROM users
      WHERE id = ?
    `).get(id);

    if (!target) {
      return res.status(404).json({
        error: 'Пользователь не найден.'
      });
    }

    if (
      id === req.user.id ||
      String(target.email || '').toLowerCase() === ADMIN_EMAIL
    ) {
      return res.status(403).json({
        error: 'Нельзя заблокировать владельца.'
      });
    }

    db.prepare(`
      UPDATE users
      SET banned = 1, ban_reason = ?
      WHERE id = ?
    `).run(reason, id);

    res.json({ success: true });
  }
);

app.post(
  '/api/admin/users/:id/unban',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        error: 'Неверный ID пользователя.'
      });
    }

    const result = db.prepare(`
      UPDATE users
      SET banned = 0, ban_reason = NULL
      WHERE id = ?
    `).run(id);

    if (!result.changes) {
      return res.status(404).json({
        error: 'Пользователь не найден.'
      });
    }

    res.json({ success: true });
  }
);

app.post(
  '/api/admin/codes',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const rank = String(req.body?.rank || '').toUpperCase();
    const amount = Math.min(
      20,
      Math.max(1, Math.floor(Number(req.body?.amount) || 1))
    );

    if (!['PLUS', 'MODER'].includes(rank)) {
      return res.status(400).json({
        error: 'Коды доступны только для PLUS и MODER.'
      });
    }

    try {
      const createCodes = db.transaction(() => {
        const codes = [];

        for (let i = 0; i < amount; i++) {
          const code = makeRankCode();

          db.prepare(`
            INSERT INTO rank_codes (code, rank, created_by)
            VALUES (?, ?, ?)
          `).run(code, rank, req.user.id);

          codes.push(code);
        }

        return codes;
      });

      res.status(201).json({
        success: true,
        rank,
        codes: createCodes()
      });
    } catch (err) {
      console.error('Create codes error:', err);
      res.status(500).json({
        error: 'Не удалось создать коды.'
      });
    }
  }
);

app.get(
  '/api/admin/codes',
  requireAuth,
  requireRank('ADMIN'),
  (req, res) => {
    const codes = db.prepare(`
      SELECT
        id,
        code,
        rank,
        used_by,
        used_at,
        created_at
      FROM rank_codes
      ORDER BY id DESC
      LIMIT 500
    `).all();

    res.json({ codes });
  }
);

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      error: 'API-маршрут не найден.'
    });
  }

  next();
});

const publicDirectories = [
  path.join(__dirname, 'public'),
  path.join(__dirname, 'public', 'public'),
  __dirname
];

let frontendDirectory = publicDirectories.find(directory =>
  fs.existsSync(path.join(directory, 'index.html'))
);

if (frontendDirectory) {
  app.use(express.static(frontendDirectory));

  app.get('*', (req, res) => {
    res.sendFile(path.join(frontendDirectory, 'index.html'));
  });
} else {
  app.get('/', (req, res) => {
    res.status(200).send(
      'Maut AI server is running. Put index.html in the public folder.'
    );
  });
}

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: 'Внутренняя ошибка сервера.'
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Maut AI запущен на порту ${PORT}`);
  console.log(`Режим: ${IS_PRODUCTION ? 'production' : 'development'}`);
  console.log(`База данных: ${path.join(DATA_DIR, 'maut.db')}`);
});

function shutdown() {
  console.log('Остановка Maut AI...');

  server.close(() => {
    try {
      sessionStore.close?.();
      db.close();
    } catch (err) {
      console.error('Shutdown error:', err);
    }

    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
