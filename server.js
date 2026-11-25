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
  throw new Error('SESSION_SECRET должен содержать минимум 32 символа.');
}

app.use(session({
  name: 'maut.sid',
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

// Ограничение частоты запросов
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Слишком много попыток. Подожди 15 минут.' }
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Слишком много сообщений. Подожди немного.' }
});

const imageLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Лимит генерации изображений исчерпан. Попробуй позже.' }
});

// Ограничиваем одновременные обращения к ИИ
let activeAIRequests = 0;
const MAX_AI_REQUESTS = Number(process.env.MAX_AI_REQUESTS) || 2;

function aiCapacity(req, res, next) {
  if (activeAIRequests >= MAX_AI_REQUESTS) {
    return res.status(503).json({
      error: 'Сейчас Maut AI занят. Подожди немного и попробуй снова.'
    });
  }

  activeAIRequests++;
  let released = false;

  const release = () => {
    if (released) return;
    released = true;
    activeAIRequests = Math.max(0, activeAIRequests - 1);
  };

  res.once('finish', release);
  res.once('close', release);
  next();
}

// Вспомогательные функции
function requireAuth(req, res, next) {
  if (!req.session?.user?.id) {
    return res.status(401).json({
      error: 'Войди в аккаунт, чтобы продолжить.'
    });
  }

  next();
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    name: row.display_name || row.username,
    email: row.email || ''
  };
}

function createLoginSession(req, res, user) {
  req.session.regenerate(err => {
    if (err) {
      console.error('Session regenerate error:', err);
      return res.status(500).json({
        error: 'Не удалось создать сессию.'
      });
    }

    req.session.user = user;

    req.session.save(saveError => {
      if (saveError) {
        console.error('Session save error:', saveError);
        return res.status(500).json({
          error: 'Не удалось сохранить сессию.'
        });
      }

      res.json({ user });
    });
  });
}

// Удаление старых данных неактивного пользователя
const INACTIVE_DAYS = Number(process.env.INACTIVE_DAYS) || 180;

function cleanupInactiveUser(userId) {
  const cutoff = new Date(
    Date.now() - INACTIVE_DAYS * 24 * 60 * 60 * 1000
  ).toISOString();

  const result = db.prepare(`
    SELECT id, last_login
    FROM users
    WHERE id = ?
  `).get(userId);

  if (!result) return;

  if (result.last_login && result.last_login < cutoff) {
    db.prepare('DELETE FROM conversations WHERE user_id = ?')
      .run(userId);
  }
}

// Проверка состояния сервера
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    name: 'Maut AI',
    time: new Date().toISOString()
  });
});

// Проверка авторизации
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');

  if (!req.session?.user?.id) {
    return res.json({ user: null });
  }

  res.json({ user: req.session.user });
});

// Регистрация
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const name = String(req.body?.name || '').trim();
    const password = req.body?.password;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        error: 'Укажи правильный email.'
      });
    }

    if (name.length < 2 || name.length > 40) {
      return res.status(400).json({
        error: 'Имя должно содержать от 2 до 40 символов.'
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

    const username = email;

    const existing = db.prepare(`
      SELECT id FROM users WHERE email = ? OR username = ?
    `).get(email, username);

    if (existing) {
      return res.status(409).json({
        error: 'Аккаунт с таким email уже существует.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (username, display_name, email, password_hash)
      VALUES (?, ?, ?, ?)
    `).run(username, name, email, passwordHash);

    const row = db.prepare(`
      SELECT id, username, display_name, email
      FROM users WHERE id = ?
    `).get(result.lastInsertRowid);

    createLoginSession(req, res, publicUser(row));
  } catch (err) {
    console.error('Register error:', err);

    if (String(err.code || '').includes('SQLITE_CONSTRAINT')) {
      return res.status(409).json({
        error: 'Этот email уже зарегистрирован.'
      });
    }

    res.status(500).json({
      error: 'Ошибка регистрации на сервере.'
    });
  }
});

// Вход
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = req.body?.password;

    if (!email || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Укажи email и пароль.'
      });
    }

    const row = db.prepare(`
      SELECT id, username, display_name, email, password_hash, created_at, last_login
      FROM users
      WHERE email = ? OR username = ?
    `).get(email, email);

    if (!row) {
      return res.status(401).json({
        error: 'Неверный email или пароль.'
      });
    }

    const passwordOk = await bcrypt.compare(password, row.password_hash);

    if (!passwordOk) {
      return res.status(401).json({
        error: 'Неверный email или пароль.'
      });
    }

    const userId = row.id;

    const cleanup = db.transaction(() => {
      const inactive = row.last_login &&
        row.last_login < new Date(
          Date.now() - INACTIVE_DAYS * 24 * 60 * 60 * 1000
        ).toISOString();

      if (inactive) {
        db.prepare('DELETE FROM conversations WHERE user_id = ?').run(userId);
      }

      db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?')
        .run(userId);
    });

    cleanup();
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

// Чат с Maut AI
app.post('/api/chat', requireAuth, chatLimiter, aiCapacity, async (req, res) => {
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

      history.unshift({
        role: item.role,
        content
      });

      historyLength += content.length;
    }

    const messages = [
      {
        role: 'system',
        content: `Ты — Maut AI, ИИ-помощник проекта Maut AI.

КАЧЕСТВО ОТВЕТОВ
- ВСЕГДА определяй язык последнего сообщения пользователя и отвечай на этом же языке, если пользователь явно не попросил другой.
- Не используй русский язык по умолчанию. Английское сообщение — английский ответ; сообщение на любом другом языке — ответ на этом языке.
- Не переключай язык из-за того, что системная инструкция или история написаны по-русски.
- Если сообщение смешанное, ориентируйся на язык основной части сообщения.
- Пиши грамотно, понятно, последовательно и естественно.
- Сначала отвечай по существу вопроса.
- Не придумывай факты. Если не уверен, честно сообщи об этом.
- Не повторяй одну и ту же мысль без необходимости.
- Если пользователь просит код, предоставляй цельный код и поясняй, куда его вставить.
- Если пользователь просит подробный ответ, раскрывай тему достаточно полно, но не добавляй бессмысленные повторы.

ФОРМАТИРОВАНИЕ
- Используй Markdown для удобного чтения.
- Для длинных ответов используй понятные заголовки ## и ###.
- Отделяй абзацы пустой строкой.
- Для перечислений используй маркированные списки, для последовательных инструкций — нумерованные.
- Таблицы используй только тогда, когда они действительно помогают сравнить информацию.
- Код оформляй в блоках с указанием языка, например \`\`\`js.
- Не превращай каждый абзац в отдельный пункт списка.
- Не делай весь ответ жирным.
- Не обрывай ответ намеренно, если можно дать полный ответ в пределах доступного лимита.

СОЗДАТЕЛЬ ПРОЕКТА
Создатель проекта Maut AI: Мухаммад Умаров Манучехрович, также известный как Den Whelan. Он является директором компании Liches maut.

Если пользователь спрашивает, кто создал Maut AI, кто создатель проекта или кто руководит компанией Liches maut, сообщи это на ЯЗЫКЕ ПОЛЬЗОВАТЕЛЯ: Мухаммад Умаров Манучехрович (Den Whelan) создал проект Maut AI и является директором компании Liches maut.
На английском, например: "Maut AI was created by Muhammad Umarov Manuchekhrovich (Den Whelan), director of Liches maut." Не копируй русскую формулировку дословно, если пользователь пишет на другом языке.

Не утверждай, что он создал базовую языковую модель или сторонние ИИ-сервисы, если это не подтверждено. Различай создателя проекта Maut AI и поставщиков используемых моделей.`
      },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    // Используем Groq, если API-ключ задан
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
              max_tokens: Number(process.env.GROQ_MAX_TOKENS) || 2048
            }),
            signal: AbortSignal.timeout(60000)
          }
        );
      } catch (err) {
        console.error('Groq connection error:', err);

        return res.status(502).json({
          error: 'Не удалось подключиться к Groq. Проверь доступность API.'
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

        const apiMessage = data?.error?.message;

        if (response.status === 429) {
          return res.status(429).json({
            error: 'Превышен лимит запросов Groq. Подожди немного.'
          });
        }

        if (response.status === 401 || response.status === 403) {
          return res.status(502).json({
            error: 'Groq отклонил API-ключ. Проверь GROQ_API_KEY.'
          });
        }

        return res.status(502).json({
          error: apiMessage
            ? `Ошибка Groq: ${apiMessage}`
            : `Groq API вернул ошибку ${response.status}.`
        });
      }

      const reply = data?.choices?.[0]?.message?.content;

      if (typeof reply === 'string' && reply.trim()) {
        return res.json({
          reply: reply.trim(),
          provider: 'groq'
        });
      }

      console.error('Groq returned an empty response:', data);

      return res.status(502).json({
        error: 'Groq вернул пустой ответ. Попробуй ещё раз.'
      });
    }

    // Если Groq не настроен, используем Ollama
    const ollamaUrl =
      process.env.OLLAMA_URL || 'http://127.0.0.1:11434';

    const ollamaModel =
      process.env.OLLAMA_MODEL || 'llama3.2';

    let response;

    try {
      response = await fetch(
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
    } catch (err) {
      console.error('Ollama connection error:', err);

      return res.status(502).json({
        error: 'Не удалось подключиться к Ollama. Проверь OLLAMA_URL или настрой GROQ_API_KEY.'
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
      console.error('Ollama API error:', response.status, data);

      return res.status(502).json({
        error: data?.error ||
          `Ollama API вернула ошибку ${response.status}.`
      });
    }

    const reply = data?.message?.content;

    if (typeof reply !== 'string' || !reply.trim()) {
      return res.status(502).json({
        error: 'ИИ вернул пустой ответ.'
      });
    }

    return res.json({
      reply: reply.trim(),
      provider: 'ollama'
    });
  } catch (err) {
    console.error('Chat error:', err);

    return res.status(502).json({
      error: 'Не удалось получить ответ от ИИ.'
    });
  }
});

// Генерация изображений через Gemini
app.post('/api/images', requireAuth, imageLimiter, aiCapacity, async (req, res) => {
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
      console.error('Gemini API error:', data);

      return res.status(502).json({
        error: data?.error?.message ||
          'Не удалось создать изображение через Gemini.'
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
      return res.status(502).json({
        error: 'Формат картинки не поддерживается.'
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
        : 'Не удалось подключиться к Gemini API.'
    });
  } finally {
    clearTimeout(timeout);
  }
});

// Статические файлы сайта
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Неизвестные API-маршруты
app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API маршрут не найден.'
  });
});

// Необработанные ошибки
app.use((err, req, res, next) => {
  console.error('Server error:', err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: 'Внутренняя ошибка сервера.'
  });
});

// Запуск
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Maut AI запущен на порту ${PORT}`);
});
