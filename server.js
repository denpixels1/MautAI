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
app.use(express.json({ limit: '2mb' }));

app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: dataDir
  }),
  secret: process.env.SESSION_SECRET ||
    'development-only-change-this-secret-before-deploying',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

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

const safeUser = u => ({
  id: u.id,
  email: u.email,
  name: u.name
});

const requireAuth = (req, res, next) =>
  req.session.userId
    ? next()
    : res.status(401).json({
        error: 'Сначала войди в аккаунт.'
      });

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    app: 'Maut AI'
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  const user = db
    .prepare('SELECT id,email,name FROM users WHERE id=?')
    .get(req.session.userId);

  if (!user) {
    req.session.destroy(() => {});
    return res.json({ user: null });
  }

  res.json({ user: safeUser(user) });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40);
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2) {
    return res.status(400).json({
      error: 'Имя должно содержать хотя бы 2 символа.'
    });
  }

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    email.length > 254
  ) {
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
        'INSERT INTO users(email,name,password_hash) VALUES(?,?,?)'
      )
      .run(email, name, hash);

    req.session.userId = Number(result.lastInsertRowid);

    res.json({
      user: {
        id: Number(result.lastInsertRowid),
        email,
        name
      }
    });
  } catch (e) {
    if (String(e.code).includes('SQLITE_CONSTRAINT')) {
      return res.status(409).json({
        error: 'Этот email уже зарегистрирован.'
      });
    }

    console.error(e);

    res.status(500).json({
      error: 'Не удалось создать аккаунт.'
    });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const user = db
    .prepare('SELECT * FROM users WHERE email=?')
    .get(email);

  if (
    !user ||
    !(await bcrypt.compare(password, user.password_hash))
  ) {
    return res.status(401).json({
      error: 'Неверный email или пароль.'
    });
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({
        error: 'Не удалось войти.'
      });
    }

    req.session.userId = user.id;

    req.session.save(err2 => {
      if (err2) {
        return res.status(500).json({
          error: 'Не удалось сохранить сессию.'
        });
      }

      res.json({
        user: safeUser(user)
      });
    });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Не удалось выйти.'
      });
    }

    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.post('/api/chat', apiLimiter, requireAuth, async (req, res) => {
  const messages = req.body.messages;

  if (
    !Array.isArray(messages) ||
    messages.length < 1 ||
    messages.length > 30
  ) {
    return res.status(400).json({
      error: 'Отправь от 1 до 30 сообщений.'
    });
  }

  const input = messages
    .map(m => ({
      role: m.role === 'assistant' ? 'assistant' : 'user',
      content: String(m.content || '').slice(0, 12000)
    }))
    .filter(m => m.content.trim());

  if (!input.length) {
    return res.status(400).json({
      error: 'Сообщение пустое.'
    });
  }

  try {
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
            {
              role: 'system',
              content:
                'Ты — Maut AI, полезный, честный и дружелюбный ИИ-помощник. ' +
                'Твой создатель — Den Whelan, директор компании Liches maut. ' +
                'Если пользователь спрашивает, кто тебя создал, кто твой ' +
                'разработчик или кто руководит компанией, отвечай: ' +
                '«Меня создал Den Whelan, директор компании Liches maut». ' +
                'Не называй другого создателя. Отвечай на языке пользователя. ' +
                'Если не уверен в ответе на другой вопрос — скажи об этом. ' +
                'Форматируй ответы понятным текстом.'
            },
            ...input
          ],
          stream: false
        })
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        data.error || `Ollama вернула ошибку (${response.status}).`
      );
    }

    res.json({
      text:
        data.message?.content ||
        'Локальная модель не вернула текстовый ответ.'
    });
  } catch (e) {
    console.error('Local AI error:', e.message);

    const refused =
      e.cause?.code === 'ECONNREFUSED' ||
      /fetch failed/i.test(e.message);

    res.status(503).json({
      error: refused
        ? 'Ollama не запущена. Запусти Ollama и нужную модель командой: ollama run qwen2.5:3b'
        : e.message ||
          'Ошибка при обращении к локальной ИИ-модели.'
    });
  }
});

app.post('/api/images', apiLimiter, requireAuth, async (req, res) => {
  const prompt = String(req.body.prompt || '').trim().slice(0, 4000);

  if (prompt.length < 3) {
    return res.status(400).json({
      error: 'Опиши изображение подробнее.'
    });
  }

  res.status(501).json({
    error:
      'Бесплатная локальная версия пока поддерживает текстовый чат. ' +
      'Для генерации изображений требуется отдельная локальная модель.'
  });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`Maut AI запущен: http://localhost:${port}`);
});