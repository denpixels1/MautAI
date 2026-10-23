
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

// Постоянное хранилище
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
  throw new Error(
    'Добавь SESSION_SECRET длиной минимум 32 символа в Render.'
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

// Имя может содержать буквы разных языков, пробелы и символы.
// Ограничение длины защищает от чрезмерно длинных имён.
function normalizeUsername(value) {
  if (typeof value !== 'string') return null;

  const username = value.trim();

  if (
    username.length < 1 ||
    username.length > 60 ||
    /[\u0000-\u001F\u007F]/u.test(username)
  ) {
    return null;
  }

  return username;
}

function getUsername(body = {}) {
  return normalizeUsername(body.username || body.name || body.email);
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    name: row.username
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

// Проверка текущего пользователя
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: req.session.user || null });
});

// Регистрация
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const username = getUsername(req.body);
    const password = req.body?.password;

    if (!username) {
      return res.status(400).json({
        error: 'Введи имя длиной от 1 до 60 символов.'
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

    const exists = db.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).get(username);

    if (exists) {
      return res.status(409).json({
        error: 'Это имя уже занято. Попробуй другое.'
      });
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
    if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({
        error: 'Это имя уже занято. Попробуй другое.'
      });
    }

    console.error('Registration error:', err);
    res.status(500).json({
      error: 'Ошибка регистрации на сервере.'
    });
  }
});

// Вход
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const username = getUsername(req.body);
    const password = req.body?.password;

    if (
      !username ||
      typeof password !== 'string' ||
      password.length > 128
    ) {
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
    res.status(500).json({
      error: 'Ошибка входа на сервере.'
    });
  }
});

// Выход
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
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

// Чат
app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    // Поддерживаем и новый формат { message, history },
    // и формат фронтенда { messages }.
    let message = req.body?.message;
    let history = req.body?.history;

    if (Array.isArray(req.body?.messages)) {
      const validMessages = req.body.messages.filter(item =>
        item &&
        ['user', 'assistant'].includes(item.role) &&
        typeof (item.content ?? item.text) === 'string'
      );

      const lastUserMessage = [...validMessages]
        .reverse()
        .find(item => item.role === 'user');

      if (!message && lastUserMessage) {
        message = lastUserMessage.content ?? lastUserMessage.text;
      }

      if (!Array.isArray(history)) {
        history = validMessages
          .filter(item => item !== lastUserMessage)
          .slice(-12)
          .map(item => ({
            role: item.role,
            content: item.content ?? item.text
          }));
      }
    }

    if (
      typeof message !== 'string' ||
      !message.trim() ||
      message.length > 12000
    ) {
      return res.status(400).json({
        error: 'Пустое или слишком длинное сообщение.'
      });
    }

    const safeHistory = Array.isArray(history)
      ? history
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

    const messages = [
      {
        role: 'system',
        content: 'Ты Maut AI — полезный и дружелюбный ИИ-помощник. Отвечай на языке пользователя.'
      },
      ...safeHistory,
      { role: 'user', content: message.trim() }
    ];

    const groqKey = process.env.GROQ_API_KEY;

    if (groqKey) {
      try {
        const response = await fetch(
          'https://api.groq.com/openai/v1/chat/completions',
          {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${groqKey}`,
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
          return res.json({
            reply: reply.trim(),
            text: reply.trim(),
            provider: 'groq'
          });
        }

        throw new Error('Groq вернул пустой ответ.');
      } catch (err) {
        console.error('Groq error:', err.message);
      }
    }

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
      text: reply.trim(),
      provider: 'ollama'
    });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(502).json({
      error: 'Не удалось получить ответ от ИИ. Проверь настройки API.'
    });
  }
});

// Генерация изображений через Pollinations
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

  const apiKey = process.env.POLLINATIONS_API_KEY?.trim();

  if (!apiKey) {
    return res.status(503).json({
      error: 'В Render добавь секрет POLLINATIONS_API_KEY.'
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55000);

  try {
    const model = process.env.POLLINATIONS_IMAGE_MODEL || 'flux';
    const imageUrl =
      `https://gen.pollinations.ai/image/${encodeURIComponent(prompt.trim())}` +
      `?model=${encodeURIComponent(model)}`;

    const response = await fetch(imageUrl, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'image/*'
      },
      signal: controller.signal
    });

    if (!response.ok) {
      const details = await response.text().catch(() => '');
      console.error('Pollinations API error:', {
        status: response.status,
        details: details.slice(0, 1000)
      });

      let message;

      if (response.status === 401) {
        message = 'Pollinations отклонил API-ключ. Проверь POLLINATIONS_API_KEY: нужен секретный ключ для сервера.';
      } else if (response.status === 402) {
        message = 'На аккаунте Pollinations недостаточно средств или Pollen для генерации.';
      } else if (response.status === 403) {
        message = 'У API-ключа Pollinations нет разрешения на эту операцию.';
      } else if (response.status === 429) {
        message = 'Pollinations временно ограничил запросы. Подожди и попробуй снова.';
      } else {
        message = `Pollinations вернул ошибку HTTP ${response.status}. Попробуй позже или проверь настройки ключа и модели.`;
      }

      return res.status(502).json({ error: message });
    }

    const contentType = (
      response.headers.get('content-type') || ''
    ).split(';')[0].trim().toLowerCase();

    if (!['image/png', 'image/jpeg', 'image/webp'].includes(contentType)) {
      const details = await response.text().catch(() => '');
      console.error('Pollinations returned non-image response:', {
        contentType,
        details: details.slice(0, 500)
      });

      return res.status(502).json({
        error: 'Pollinations ответил, но не вернул картинку. Проверь название модели.'
      });
    }

    const imageBuffer = Buffer.from(await response.arrayBuffer());

    if (!imageBuffer.length) {
      return res.status(502).json({
        error: 'Pollinations вернул пустое изображение.'
      });
    }

    if (imageBuffer.length > 15 * 1024 * 1024) {
      return res.status(502).json({
        error: 'Изображение слишком большое. Попробуй более короткое описание.'
      });
    }

    return res.json({
      image: `data:${contentType};base64,${imageBuffer.toString('base64')}`,
      provider: 'Pollinations'
    });
  } catch (err) {
    const timedOut =
      err.name === 'AbortError' ||
      err.name === 'TimeoutError';

    console.error('Pollinations connection error:', {
      name: err.name,
      message: err.message,
      cause: err.cause?.message
    });

    return res.status(timedOut ? 504 : 502).json({
      error: timedOut
        ? 'Pollinations не ответил за 55 секунд. Попробуй ещё раз.'
        : `Ошибка подключения к Pollinations: ${err.cause?.message || err.message || 'неизвестная ошибка сети'}`
    });
  } finally {
    clearTimeout(timeout);
  }
});

// Статические файлы
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
