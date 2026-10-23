
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

// Persistent storage
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'maut.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const SQLiteStore = SQLiteStoreFactory(session);
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: DATA_DIR,
  table: 'sessions'
});

const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('Установи SESSION_SECRET длиной минимум 32 символа в Render.');
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
  message: { error: 'Слишком много генераций. Подожди минуту.' }
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Сначала войди в аккаунт.' });
  }
  next();
}

function normalizeUsername(value) {
  if (typeof value !== 'string') return null;
  const username = value.trim();

  if (!/^[a-zA-Z0-9_-]{3,24}$/.test(username)) return null;
  return username;
}

function getUsername(body = {}) {
  return normalizeUsername(body.username || body.name || body.email);
}

function publicUser(row) {
  return { id: row.id, username: row.username, name: row.username };
}

function createLoginSession(req, res, user, statusCode = 200) {
  req.session.regenerate(err => {
    if (err) {
      console.error('Session regenerate error:', err);
      return res.status(500).json({ error: 'Не удалось создать сессию.' });
    }

    req.session.user = user;
    req.session.save(saveErr => {
      if (saveErr) {
        console.error('Session save error:', saveErr);
        return res.status(500).json({ error: 'Не удалось сохранить вход.' });
      }
      res.status(statusCode).json({ user });
    });
  });
}

// Check current session
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: req.session.user || null });
});

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const username = getUsername(req.body);
    const password = req.body?.password;

    if (!username) {
      return res.status(400).json({
        error: 'Имя: 3–24 латинских символа, цифры, _ или -.'
      });
    }

    if (typeof password !== 'string' ||
        password.length < 8 ||
        password.length > 128) {
      return res.status(400).json({
        error: 'Пароль должен содержать от 8 до 128 символов.'
      });
    }

    const exists = db.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).get(username);

    if (exists) {
      return res.status(409).json({ error: 'Это имя уже занято.' });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    ).run(username, hash);

    const user = {
      id: Number(result.lastInsertRowid),
      username,
      name: username
    };

    createLoginSession(req, res, user, 201);
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Ошибка регистрации на сервере.' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const username = getUsername(req.body);
    const password = req.body?.password;

    if (!username || typeof password !== 'string' || password.length > 128) {
      return res.status(400).json({
        error: 'Проверь имя пользователя и пароль.'
      });
    }

    const row = db.prepare(
      'SELECT id, username, password_hash FROM users WHERE username = ?'
    ).get(username);

    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({
        error: 'Неверное имя пользователя или пароль.'
      });
    }

    createLoginSession(req, res, publicUser(row));
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Ошибка входа на сервере.' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Не удалось выйти из аккаунта.' });
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

// Chat
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

    if (typeof message !== 'string' ||
        !message.trim() ||
        message.length > 12000) {
      return res.status(400).json({ error: 'Пустое или слишком длинное сообщение.' });
    }

    const messages = [
      {
        role: 'system',
        content: 'Ты Maut AI — полезный и дружелюбный ИИ-помощник. Отвечай на языке пользователя.'
      },
      ...history,
      { role: 'user', content: message.trim() }
    ];

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
              model: process.env.GROQ_MODEL || 'openai/gpt-oss-120b',
              messages,
              temperature: 0.7,
              max_tokens: 2048
            }),
            signal: AbortSignal.timeout(45000)
          }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data?.error?.message || 'Ошибка Groq API');
        }

        const reply = data?.choices?.[0]?.message?.content;
        if (typeof reply === 'string' && reply.trim()) {
          return res.json({ reply: reply.trim(), provider: 'groq' });
        }

        throw new Error('Groq вернул пустой ответ.');
      } catch (err) {
        console.error('Groq error:', err.message);
      }
    }

    const ollamaUrl = process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';

    const response = await fetch(
      `${ollamaUrl.replace(/\/$/, '')}/api/chat`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: ollamaModel, messages, stream: false }),
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
      return res.status(502).json({ error: 'ИИ вернул пустой ответ.' });
    }

    res.json({ reply: reply.trim(), provider: 'ollama' });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(502).json({ error: 'Не удалось получить ответ от ИИ.' });
  }
});

// Nano Banana 2 image generation through Gemini API
app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'Напиши описание изображения.' });
  }

  if (prompt.length > 4000) {
    return res.status(400).json({
      error: 'Описание изображения слишком длинное (максимум 4000 символов).'
    });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return res.status(503).json({
      error: 'Добавь GEMINI_API_KEY в переменные окружения Render.'
    });
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
        error: data?.error?.message || 'Nano Banana 2 не смог создать изображение.'
      });
    }

    const parts = data?.candidates?.[0]?.content?.parts || [];
    const imagePart = parts.find(part => part.inlineData?.data);

    if (!imagePart) {
      return res.status(502).json({
        error: 'Модель не вернула картинку. Попробуй изменить описание.'
      });
    }

    const mimeType = imagePart.inlineData.mimeType || 'image/png';
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(mimeType)) {
      return res.status(502).json({ error: 'Формат картинки не поддерживается.' });
    }

    res.json({
      image: `data:${mimeType};base64,${imagePart.inlineData.data}`,
      provider: 'Nano Banana 2'
    });
  } catch (err) {
    console.error('Image generation error:', err);
    res.status(err.name === 'AbortError' ? 504 : 502).json({
      error: err.name === 'AbortError'
        ? 'Генерация заняла слишком много времени. Попробуй ещё раз.'
        : 'Не удалось подключиться к Gemini API.'
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
  res.status(404).json({ error: 'API маршрут не найден.' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
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
