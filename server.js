
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
app.use(express.json({ limit: '1mb' }));

// Persistent database storage
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

// Add new columns without deleting existing users.
const userColumns = db
  .prepare('PRAGMA table_info(users)')
  .all()
  .map(column => column.name);

if (!userColumns.includes('display_name')) {
  db.exec('ALTER TABLE users ADD COLUMN display_name TEXT');
}

if (!userColumns.includes('email')) {
  db.exec('ALTER TABLE users ADD COLUMN email TEXT');
}

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
  ON users(email)
  WHERE email IS NOT NULL AND email != ''
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

// Accept Cyrillic, Latin characters, spaces, punctuation and emoji.
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

// Check current account
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');

  res.json({
    user: req.session.user || null
  });
});

// Register a new account
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

    // Keep username populated for compatibility with older databases.
    const result = db.prepare(`
      INSERT INTO users (
        username,
        password_hash,
        display_name,
        email
      )
      VALUES (?, ?, ?, ?)
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

    if (String(err.message).includes('UNIQUE constraint failed')) {
      return res.status(409).json({
        error: 'Этот email уже зарегистрирован. Попробуй войти.'
      });
    }

    res.status(500).json({
      error: 'Ошибка регистрации на сервере.'
    });
  }
});

// Login with email and password
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
      SELECT
        id,
        username,
        password_hash,
        display_name,
        email
      FROM users
      WHERE email = ? OR username = ?
      LIMIT 1
    `).get(loginValue, loginValue);

    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({
        error: 'Неверный email или пароль.'
      });
    }

    createLoginSession(req, res, publicUser(row));
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Ошибка входа на сервере.'
    });
  }
});

// Logout
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

// Chat endpoint
app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    const message = req.body?.message;

    const history = Array.isArray(req.body?.history)
      ? req.body.history
          .filter(item =>
            item &&
            ['user', 'assistant'].includes(item.role) &&
            typeof item.content === 'string'
          )
          .slice(-12)
          .map(item => ({
            role: item.role,
            content: item.content.slice(0, 12000)
          }))
      : [];

    if (
      typeof message !== 'string' ||
      !message.trim() ||
      message.length > 12000
    ) {
      return res.status(400).json({
        error: 'Пустое или слишком длинное сообщение.'
      });
    }

    const messages = [
      {
        role: 'system',
        content:
          'Ты Maut AI — полезный и дружелюбный ИИ-помощник. Отвечай на языке пользователя.'
      },
      ...history,
      {
        role: 'user',
        content: message.trim()
      }
    ];

    // Groq chat
    if (process.env.GROQ_API_KEY) {
      try {
        const response = await fetch(
          'https://api.groq.com/openai/v1/chat/completions',
          {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              model:
                process.env.GROQ_MODEL ||
                'openai/gpt-oss-120b',
              messages,
              temperature: 0.7,
              max_tokens: 2048
            }),
            signal: AbortSignal.timeout(45000)
          }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(
            data?.error?.message || 'Ошибка Groq API'
          );
        }

        const reply = data?.choices?.[0]?.message?.content;

        if (typeof reply === 'string' && reply.trim()) {
          return res.json({
            reply: reply.trim(),
            provider: 'groq'
          });
        }

        throw new Error('Groq вернул пустой ответ.');
      } catch (err) {
        console.error('Groq error:', err.message);
      }
    }

    // Optional Ollama fallback
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
        signal: AbortSignal.timeout(45000)
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({
        error: 'ИИ-сервис недоступен. Проверь настройки Groq или Ollama.'
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

// Image generation through Pollinations
app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({
      error: 'Напиши описание изображения.'
    });
  }

  if (prompt.length > 4000) {
    return res.status(400).json({
      error: 'Описание изображения слишком длинное (максимум 4000 символов).'
    });
  }

  const apiKey = process.env.POLLINATIONS_API_KEY;

  if (!apiKey) {
    return res.status(503).json({
      error: 'Добавь POLLINATIONS_API_KEY в переменные окружения Render.'
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55000);

  try {
    // Pollinations API may change. Confirm the supported model and endpoint
    // in the current Pollinations API documentation for your account.
    const model = process.env.POLLINATIONS_IMAGE_MODEL || 'flux';

    const imageUrl =
      `https://gen.pollinations.ai/image/${encodeURIComponent(prompt.trim())}` +
      `?model=${encodeURIComponent(model)}`;

    const response = await fetch(imageUrl, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${apiKey}`
      },
      signal: controller.signal
    });

    if (!response.ok) {
      const errorText = await response.text();

      console.error(
        'Pollinations API error:',
        response.status,
        errorText.slice(0, 1000)
      );

      return res.status(502).json({
        error:
          `Pollinations не смог создать изображение (HTTP ${response.status}). ` +
          'Проверь API-ключ, доступ к модели и баланс аккаунта.'
      });
    }

    const contentType =
      response.headers.get('content-type') || 'image/png';

    if (!contentType.startsWith('image/')) {
      const responseText = await response.text();

      console.error(
        'Pollinations returned non-image response:',
        responseText.slice(0, 500)
      );

      return res.status(502).json({
        error: 'Сервис не вернул изображение. Проверь настройки Pollinations.'
      });
    }

    const imageBuffer = Buffer.from(await response.arrayBuffer());

    if (!imageBuffer.length || imageBuffer.length > 15 * 1024 * 1024) {
      return res.status(502).json({
        error: 'Изображение пустое или слишком большое.'
      });
    }

    const safeMimeType = [
      'image/png',
      'image/jpeg',
      'image/webp'
    ].includes(contentType.split(';')[0])
      ? contentType.split(';')[0]
      : 'image/png';

    res.json({
      image: `data:${safeMimeType};base64,${imageBuffer.toString('base64')}`,
      provider: 'Pollinations'
    });
  } catch (err) {
    console.error('Image generation error:', err);

    res.status(err.name === 'AbortError' ? 504 : 502).json({
      error: err.name === 'AbortError'
        ? 'Генерация заняла слишком много времени. Попробуй ещё раз.'
        : 'Не удалось подключиться к Pollinations.'
    });
  } finally {
    clearTimeout(timeout);
  }
});

// Static website
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API маршрут не найден.'
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (res.headersSent) return next(err);

  res.status(500).json({
    error: 'Внутренняя ошибка сервера.'
  });
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
