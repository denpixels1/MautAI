
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

if (isProduction) app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(express.json({ limit: '12mb' }));

// ========================================
// DATABASE
// ========================================

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'maut.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

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

// ========================================
// SESSION
// ========================================

const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET должен содержать минимум 32 символа.');
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
  proxy: isProduction,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 365 * 24 * 60 * 60 * 1000
  }
}));

// ========================================
// LIMITERS
// ========================================

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

// ========================================
// HELPERS
// ========================================

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

function normalizeName(value) {
  if (typeof value !== 'string') return null;

  const name = value.trim().replace(/\s+/g, ' ');

  if (!name || [...name].length > 60) return null;

  return name;
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    name: row.display_name || row.username,
    email: row.email || null
  };
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Сначала войди в аккаунт.'
    });
  }

  next();
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
          error: 'Не удалось сохранить сессию.'
        });
      }

      res.status(statusCode).json({ user });
    });
  });
}

// ========================================
// AUTH
// ========================================

app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: req.session.user || null });
});

// REGISTER

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = normalizeName(
      req.body?.name || req.body?.display_name || req.body?.username
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

    const existing = db.prepare(`
      SELECT id FROM users
      WHERE email = ? OR username = ?
      LIMIT 1
    `).get(email, email);

    if (existing) {
      return res.status(409).json({
        error: 'Аккаунт уже существует. Попробуй войти.'
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

    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({
        error: 'Аккаунт с такими данными уже существует.'
      });
    }

    res.status(500).json({
      error: 'Ошибка регистрации на сервере.'
    });
  }
});

// LOGIN

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const rawLogin =
      req.body?.email ??
      req.body?.username ??
      req.body?.login;

    const loginValue = typeof rawLogin === 'string'
      ? rawLogin.trim()
      : '';

    const password = req.body?.password;

    if (
      !loginValue ||
      loginValue.length > 254 ||
      typeof password !== 'string' ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: 'Введи логин и пароль.'
      });
    }

    const normalizedLogin = loginValue.toLowerCase();

    const row = db.prepare(`
      SELECT id, username, password_hash, display_name, email
      FROM users
      WHERE LOWER(email) = ?
         OR LOWER(username) = ?
      LIMIT 1
    `).get(normalizedLogin, normalizedLogin);

    if (!row) {
      return res.status(401).json({
        error: 'Неверный email или пароль.'
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      row.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: 'Неверный email или пароль.'
      });
    }

    db.prepare(`
      UPDATE users
      SET last_login = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(row.id);

    createLoginSession(req, res, publicUser(row));

  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Ошибка входа на сервере.'
    });
  }
});

// LOGOUT

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

// ========================================
// CHATS
// ========================================

// CREATE CHAT

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

// LIST CHATS

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
      error: 'Не удалось загрузить чаты.'
    });
  }
});

// OPEN CHAT

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

// SAVE MESSAGE

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

    if (typeof content !== 'string' || content.length > 30000) {
      return res.status(400).json({
        error: 'Сообщение слишком длинное.'
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
    `).run(title, chatId, req.session.user.id);

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

// DELETE CHAT

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

// ========================================
// AI CHAT
// ========================================

app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    const message = req.body?.message;

    if (
      typeof message !== 'string' ||
      !message.trim() ||
      message.length > 30000
    ) {
      return res.status(400).json({
        error: 'Сообщение пустое или слишком длинное.'
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

Если спрашивают о создателе Maut AI, отвечай на языке пользователя:
Мухаммад Умаров Манучехрович (Den Whelan) создал проект Maut AI и является директором компании Liches maut.

Не утверждай, что создатель проекта разработал базовую языковую модель или сторонние ИИ-сервисы.`;

    const messages = [
      { role: 'system', content: systemPrompt },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    // GROQ

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
            max_tokens: Number(process.env.GROQ_MAX_TOKENS) || 2048
          }),
          signal: AbortSignal.timeout(60000)
        }
      );

      const data = await response.json();

      if (!response.ok) {
        console.error('Groq error:', response.status, data);

        if (response.status === 429) {
          return res.status(429).json({
            error: 'Превышен лимит Groq. Попробуй позже.'
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

    // OLLAMA FALLBACK

    const ollamaUrl =
      process.env.OLLAMA_URL || 'http://127.0.0.1:11434';

    const ollamaModel =
      process.env.OLLAMA_MODEL || 'llama3.2';

    const response = await fetch(
      `${ollamaUrl.replace(/\/$/, '')}/api/chat`,
      {
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
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({
        error: data?.error || 'Ошибка Ollama API.'
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

    res.status(502).json({
      error: 'Не удалось получить ответ от ИИ.'
    });
  }
});

// ========================================
// IMAGE GENERATION — GEMINI
// ========================================

app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({
      error: 'Напиши описание изображения.'
    });
  }

  if (prompt.length > 4000) {
    return res.status(400).json({
      error: 'Описание слишком длинное.'
    });
  }

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return res.status(503).json({
      error: 'Не настроен GEMINI_API_KEY.'
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
      console.error('Gemini error:', response.status, data);

      return res.status(502).json({
        error: data?.error?.message || 'Ошибка генерации изображения.'
      });
    }

    const parts = data?.candidates?.[0]?.content?.parts || [];
    const imagePart = parts.find(part => part.inlineData?.data);

    if (!imagePart) {
      return res.status(502).json({
        error: 'Gemini не вернул изображение.'
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
        ? 'Генерация заняла слишком много времени.'
        : 'Не удалось подключиться к Gemini.'
    });

  } finally {
    clearTimeout(timeout);
  }
});

// ========================================
// STATIC FILES
// ========================================

app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API маршрут не найден.'
  });
});

// ========================================
// ERROR HANDLER
// ========================================

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (res.headersSent) return next(err);

  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Запрос слишком большой.'
    });
  }

  res.status(500).json({
    error: 'Внутренняя ошибка сервера.'
  });
});

// ========================================
// START SERVER
// ========================================

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Maut AI запущен на порту ${PORT}`);
  console.log(`Database location: ${path.join(DATA_DIR, 'maut.db')}`);
});

// ========================================
// SHUTDOWN
// ========================================

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
