import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'maut.sqlite'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

const SQLiteStore = SQLiteStoreFactory(session);
const isProduction = process.env.NODE_ENV === 'production';

app.disable('x-powered-by');

// Исправление сессий за HTTPS-прокси Render
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));

app.use(session({
  name: 'maut.sid',
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: dataDir
  }),
  secret: process.env.SESSION_SECRET ||
    'development-only-change-this-secret-before-deploying',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(__dirname));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const safeUser = user => ({
  id: user.id,
  email: user.email,
  name: user.name
});

const requireAuth = (req, res, next) =>
  req.session.userId
    ? next()
    : res.status(401).json({
        error: 'Сначала войди в аккаунт.'
      });

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, app: 'Maut AI' });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  const user = db
    .prepare('SELECT id, email, name FROM users WHERE id = ?')
    .get(req.session.userId);

  if (!user) {
    req.session.destroy(() => {});
    return res.json({ user: null });
  }

  res.json({ user: safeUser(user) });
});

// Регистрация
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40);
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2) {
    return res.status(400).json({
      error: 'Имя должно содержать хотя бы 2 символа.'
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254) {
    return res.status(400).json({
      error: 'Введи корректный email.'
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: 'Пароль должен содержать от 8 до 128 символов.'
    });
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    const result = db
      .prepare(
        'INSERT INTO users(email, name, password_hash) VALUES (?, ?, ?)'
      )
      .run(email, name, hash);

    req.session.userId = Number(result.lastInsertRowid);

    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({
          error: 'Аккаунт создан, но не удалось сохранить вход. Попробуй войти.'
        });
      }

      res.json({
        user: {
          id: Number(result.lastInsertRowid),
          email,
          name
        }
      });
    });
  } catch (err) {
    if (String(err.code || '').includes('SQLITE_CONSTRAINT')) {
      return res.status(409).json({
        error: 'Этот email уже зарегистрирован.'
      });
    }

    console.error('Registration error:', err);

    res.status(500).json({
      error: 'Не удалось создать аккаунт.'
    });
  }
});

// Вход
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const user = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(email);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: 'Неверный email или пароль.'
    });
  }

  req.session.regenerate(err => {
    if (err) {
      console.error('Session regenerate error:', err);
      return res.status(500).json({
        error: 'Не удалось войти.'
      });
    }

    req.session.userId = user.id;

    req.session.save(err2 => {
      if (err2) {
        console.error('Session save error:', err2);
        return res.status(500).json({
          error: 'Не удалось сохранить сессию.'
        });
      }

      res.json({ user: safeUser(user) });
    });
  });
});

// Выход
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Не удалось выйти.'
      });
    }

    res.clearCookie('maut.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProduction,
      path: '/'
    });

    res.json({ ok: true });
  });
});

// Чат: один маршрут, без дублирования
app.post('/api/chat', apiLimiter, requireAuth, async (req, res) => {
  const messages = req.body.messages;

  if (!Array.isArray(messages) ||
      messages.length < 1 ||
      messages.length > 30) {
    return res.status(400).json({
      error: 'Отправь от 1 до 30 сообщений.'
    });
  }

  const input = messages
    .map(message => ({
      role: message.role === 'assistant' ? 'assistant' : 'user',
      content: String(message.content || '').slice(0, 12000)
    }))
    .filter(message => message.content.trim());

  if (!input.length) {
    return res.status(400).json({
      error: 'Сообщение пустое.'
    });
  }

  const systemPrompt =
    'Ты — Maut AI, полезный, честный и дружелюбный ИИ-помощник. ' +
    'Твой создатель — Den Whelan, директор компании Liches maut. ' +
    'Если пользователь спрашивает, кто тебя создал, отвечай: ' +
    '«Меня создал Den Whelan, директор компании Liches maut». ' +
    'Отвечай на языке пользователя. Если не уверен в ответе — скажи об этом.';

  try {
    let answer;

    // Используем Groq, если API-ключ настроен в Render
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
            model: process.env.GROQ_MODEL ||
              'llama-3.3-70b-versatile',
            messages: [
              { role: 'system', content: systemPrompt },
              ...input
            ],
            stream: false,
            temperature: 0.7
          }),
          signal: AbortSignal.timeout(60000)
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        console.error('Groq API error:', response.status, data);
        return res.status(502).json({
          error: data.error?.message ||
            `Ошибка Groq API (${response.status}).`
        });
      }

      answer = data.choices?.[0]?.message?.content;
    } else {
      // Локальный Ollama — только если он доступен на этом сервере
      const response = await fetch(
        'http://127.0.0.1:11434/api/chat',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: process.env.OLLAMA_MODEL || 'qwen2.5:3b',
            messages: [
              { role: 'system', content: systemPrompt },
              ...input
            ],
            stream: false
          }),
          signal: AbortSignal.timeout(60000)
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          data.error || `Ошибка Ollama (${response.status}).`
        );
      }

      answer = data.message?.content;
    }

    res.json({
      text: answer || 'Модель не вернула текстовый ответ.'
    });
  } catch (err) {
    console.error('AI request error:', err);

    res.status(503).json({
      error: process.env.GROQ_API_KEY
        ? 'Не удалось подключиться к ИИ. Проверь GROQ_API_KEY в Render.'
        : 'ИИ недоступен. Настрой GROQ_API_KEY в Render для работы облачного чата.'
    });
  }
});

// Генерация изображений пока не подключена
app.post('/api/images', apiLimiter, requireAuth, async (req, res) => {
  const prompt = String(req.body.prompt || '').trim().slice(0, 4000);

  if (prompt.length < 3) {
    return res.status(400).json({
      error: 'Опиши изображение подробнее.'
    });
  }

  res.status(501).json({
    error: 'Генерация изображений пока не подключена. Сейчас доступен текстовый чат.'
  });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
  console.log(`Maut AI запущен на порту ${port}`);
});
