// server.js
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
const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;

// Render находится за прокси. Это важно для secure cookies.
if (isProduction) {
  app.set('trust proxy', 1);
}

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

// Создаём папку для базы данных.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const dbPath = path.join(DATA_DIR, 'maut.db');

// База пользователей.
const db = new Database(dbPath);
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

// Сессии хранятся отдельно от cookie браузера.
const SQLiteStore = SQLiteStoreFactory(session);

const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: DATA_DIR,
  concurrentDB: true,
  table: 'sessions'
});

const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error(
    'ОШИБКА: установи SESSION_SECRET длиной минимум 32 символа в Render Environment.'
  );
  process.exit(1);
}

app.use(
  session({
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
  })
);

// Ограничение частоты запросов.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Слишком много попыток. Попробуй позже.' }
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Слишком много запросов к чату. Подожди минуту.' }
});

// Проверка авторизации.
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Сначала войди в аккаунт.'
    });
  }

  next();
}

// Проверка имени пользователя.
function normalizeUsername(value) {
  if (typeof value !== 'string') return null;

  const username = value.trim();

  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
    return null;
  }

  return username;
}

// --------------------
// Проверка текущего пользователя
// --------------------
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');

  if (!req.session.user) {
    return res.json({ user: null });
  }

  res.json({
    user: {
      id: req.session.user.id,
      username: req.session.user.username
    }
  });
});

// --------------------
// Регистрация
// --------------------
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const password = req.body?.password;

    if (!username) {
      return res.status(400).json({
        error: 'Имя должно содержать 3–24 символа: латинские буквы, цифры или _.'
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

    const existing = db
      .prepare('SELECT id FROM users WHERE username = ?')
      .get(username);

    if (existing) {
      return res.status(409).json({
        error: 'Это имя пользователя уже занято.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db
      .prepare(
        'INSERT INTO users (username, password_hash) VALUES (?, ?)'
      )
      .run(username, passwordHash);

    const user = {
      id: Number(result.lastInsertRowid),
      username
    };

    // Создаём новую сессию после регистрации.
    req.session.regenerate((err) => {
      if (err) {
        console.error('Ошибка создания сессии:', err);
        return res.status(500).json({
          error: 'Не удалось создать сессию.'
        });
      }

      req.session.user = user;

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error('Ошибка сохранения сессии:', saveErr);
          return res.status(500).json({
            error: 'Не удалось сохранить вход.'
          });
        }

        res.status(201).json({ user });
      });
    });
  } catch (err) {
    if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({
        error: 'Это имя пользователя уже занято.'
      });
    }

    console.error('Ошибка регистрации:', err);
    res.status(500).json({
      error: 'Ошибка сервера при регистрации.'
    });
  }
});

// --------------------
// Вход
// --------------------
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
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

    const row = db
      .prepare(
        'SELECT id, username, password_hash FROM users WHERE username = ?'
      )
      .get(username);

    if (!row) {
      return res.status(401).json({
        error: 'Неверное имя пользователя или пароль.'
      });
    }

    const passwordIsValid = await bcrypt.compare(
      password,
      row.password_hash
    );

    if (!passwordIsValid) {
      return res.status(401).json({
        error: 'Неверное имя пользователя или пароль.'
      });
    }

    const user = {
      id: row.id,
      username: row.username
    };

    // Смена ID сессии защищает от session fixation.
    req.session.regenerate((err) => {
      if (err) {
        console.error('Ошибка создания сессии:', err);
        return res.status(500).json({
          error: 'Не удалось выполнить вход.'
        });
      }

      req.session.user = user;

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error('Ошибка сохранения сессии:', saveErr);
          return res.status(500).json({
            error: 'Не удалось сохранить вход.'
          });
        }

        res.json({ user });
      });
    });
  } catch (err) {
    console.error('Ошибка входа:', err);
    res.status(500).json({
      error: 'Ошибка сервера при входе.'
    });
  }
});

// --------------------
// Выход
// --------------------
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Ошибка завершения сессии:', err);
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

// --------------------
// Чат
// --------------------
app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    const message = req.body?.message;
    const history = req.body?.history;

    if (
      typeof message !== 'string' ||
      !message.trim() ||
      message.length > 12000
    ) {
      return res.status(400).json({
        error: 'Сообщение пустое или слишком длинное.'
      });
    }

    const safeHistory = Array.isArray(history)
      ? history
          .filter(
            (item) =>
              item &&
              ['user', 'assistant'].includes(item.role) &&
              typeof item.content === 'string'
          )
          .slice(-12)
          .map((item) => ({
            role: item.role,
            content: item.content.slice(0, 12000)
          }))
      : [];

    const systemPrompt = `
Ты Maut AI — дружелюбный ИИ-помощник.
Отвечай на языке пользователя.
Будь полезным, точным и понятным.
Не утверждай, что выполнил действия, если ты их не выполнял.
`;

    const messages = [
      { role: 'system', content: systemPrompt },
      ...safeHistory,
      { role: 'user', content: message.trim() }
    ];

    // Сначала пробуем Groq, если ключ задан.
    const groqKey = process.env.GROQ_API_KEY;
    const groqModel =
      process.env.GROQ_MODEL || 'openai/gpt-oss-120b';

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
              model: groqModel,
              messages,
              temperature: 0.7,
              max_tokens: 2048
            }),
            signal: AbortSignal.timeout(60000)
          }
        );

        const data = await response.json();

        if (!response.ok) {
          console.error('Groq error:', data);
          throw new Error(
            data?.error?.message || 'Ошибка Groq API'
          );
        }

        const answer = data?.choices?.[0]?.message?.content;

        if (typeof answer === 'string' && answer.trim()) {
          return res.json({
            reply: answer.trim(),
            provider: 'groq'
          });
        }

        throw new Error('Groq вернул пустой ответ');
      } catch (err) {
        console.error('Groq недоступен:', err.message);
        // Продолжаем с Ollama, если он настроен.
      }
    }

    // Запасной вариант: Ollama.
    const ollamaUrl =
      process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
    const ollamaModel =
      process.env.OLLAMA_MODEL || 'llama3.2';

    const ollamaResponse = await fetch(
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

    const ollamaData = await ollamaResponse.json();

    if (!ollamaResponse.ok) {
      console.error('Ollama error:', ollamaData);
      return res.status(502).json({
        error: 'ИИ-сервис недоступен. Проверь настройки модели.'
      });
    }

    const reply = ollamaData?.message?.content;

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
    console.error('Ошибка чата:', err);

    res.status(500).json({
      error: 'Не удалось получить ответ. Попробуй ещё раз.'
    });
  }
});

// --------------------
// Генерация изображений
// --------------------
app.post('/api/images', requireAuth, async (req, res) => {
  // Здесь пока нет подключённого сервиса генерации изображений.
  res.status(501).json({
    error: 'Генерация изображений пока не подключена.'
  });
});

// --------------------
// Статические файлы сайта
// --------------------
app.use(express.static(__dirname));

// Главная страница.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Неизвестный API маршрут.
app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API маршрут не найден.'
  });
});

// Общая обработка ошибок.
app.use((err, req, res, next) => {
  console.error('Необработанная ошибка:', err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: 'Внутренняя ошибка сервера.'
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Maut AI запущен на порту ${PORT}`);
});

// Аккуратное завершение.
function shutdown() {
  console.log('Завершение Maut AI...');

  server.close(() => {
    sessionStore.close?.();
    db.close();
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
