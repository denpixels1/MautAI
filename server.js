
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
app.use(express.json({ limit: '15mb' }));

// Постоянная папка для базы данных.
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
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    image TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id)
      ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_conversations_user
    ON conversations(user_id, updated_at);

  CREATE INDEX IF NOT EXISTS idx_messages_conversation
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
  legacyHeaders: false
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Сначала войди в аккаунт.'
    });
  }
  next();
}

function normalizeUsername(value) {
  if (typeof value !== 'string') return null;
  const username = value.trim();

  return /^[a-zA-Z0-9_-]{3,24}$/.test(username)
    ? username
    : null;
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
      console.error('Session error:', err);
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

function getOwnedChat(chatId, userId) {
  return db.prepare(`
    SELECT id, user_id, title, created_at, updated_at
    FROM conversations
    WHERE id = ? AND user_id = ?
  `).get(chatId, userId);
}

// Проверка авторизации.
app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: req.session.user || null });
});

// Регистрация.
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const username = getUsername(req.body);
    const password = req.body?.password;

    if (!username) {
      return res.status(400).json({
        error: 'Имя: 3–24 латинских символа, цифры, _ или -.'
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
        error: 'Это имя уже занято.'
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (username, password_hash)
      VALUES (?, ?)
    `).run(username, hash);

    createLoginSession(req, res, {
      id: Number(result.lastInsertRowid),
      username,
      name: username
    }, 201);
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      error: 'Ошибка регистрации на сервере.'
    });
  }
});

// Вход.
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

    const row = db.prepare(`
      SELECT id, username, password_hash
      FROM users
      WHERE username = ?
    `).get(username);

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

// Выход.
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

// =====================================================
// ИСТОРИЯ ЧАТОВ
// =====================================================

// Получить список чатов текущего пользователя.
app.get('/api/chats', requireAuth, (req, res) => {
  const chats = db.prepare(`
    SELECT
      id,
      title,
      created_at,
      updated_at
    FROM conversations
    WHERE user_id = ?
    ORDER BY updated_at DESC, id DESC
  `).all(req.session.user.id);

  res.set('Cache-Control', 'no-store');
  res.json({ chats });
});

// Создать новый чат.
app.post('/api/chats', requireAuth, (req, res) => {
  const title = typeof req.body?.title === 'string'
    ? req.body.title.trim().slice(0, 200)
    : '';

  const result = db.prepare(`
    INSERT INTO conversations (user_id, title)
    VALUES (?, ?)
  `).run(req.session.user.id, title || 'Новый чат');

  const chat = getOwnedChat(
    Number(result.lastInsertRowid),
    req.session.user.id
  );

  res.status(201).json({ chat });
});

// Загрузить конкретный чат вместе с сообщениями.
app.get('/api/chats/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Неверный ID чата.' });
  }

  const chat = getOwnedChat(id, req.session.user.id);

  if (!chat) {
    return res.status(404).json({ error: 'Чат не найден.' });
  }

  const messages = db.prepare(`
    SELECT id, role, content, image, created_at
    FROM messages
    WHERE conversation_id = ?
    ORDER BY id ASC
  `).all(id);

  res.set('Cache-Control', 'no-store');
  res.json({ chat, messages });
});

// Сохранить сообщение в конкретный чат.
app.post('/api/chats/:id/messages', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const { role, content, image } = req.body || {};

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Неверный ID чата.' });
  }

  const chat = getOwnedChat(id, req.session.user.id);

  if (!chat) {
    return res.status(404).json({ error: 'Чат не найден.' });
  }

  if (!['user', 'assistant'].includes(role)) {
    return res.status(400).json({ error: 'Неверная роль сообщения.' });
  }

  if (typeof content !== 'string' || content.length > 100000) {
    return res.status(400).json({
      error: 'Сообщение слишком длинное.'
    });
  }

  if (
    image != null &&
    (typeof image !== 'string' || image.length > 10_000_000)
  ) {
    return res.status(400).json({
      error: 'Изображение слишком большое.'
    });
  }

  const insert = db.transaction(() => {
    const result = db.prepare(`
      INSERT INTO messages (conversation_id, role, content, image)
      VALUES (?, ?, ?, ?)
    `).run(id, role, content, image || null);

    // Название чата берётся из первого сообщения пользователя.
    if (role === 'user') {
      const firstUserMessage = db.prepare(`
        SELECT content
        FROM messages
        WHERE conversation_id = ? AND role = 'user'
        ORDER BY id ASC
        LIMIT 1
      `).get(id);

      if (firstUserMessage) {
        const title = firstUserMessage.content.trim()
          .replace(/\s+/g, ' ')
          .slice(0, 70) || 'Новый чат';

        db.prepare(`
          UPDATE conversations
          SET title = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND user_id = ?
        `).run(title, id, req.session.user.id);
      }
    } else {
      db.prepare(`
        UPDATE conversations
        SET updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
      `).run(id, req.session.user.id);
    }

    return Number(result.lastInsertRowid);
  });

  const messageId = insert();

  const savedMessage = db.prepare(`
    SELECT id, role, content, image, created_at
    FROM messages WHERE id = ?
  `).get(messageId);

  const updatedChat = getOwnedChat(id, req.session.user.id);

  res.status(201).json({
    message: savedMessage,
    chat: updatedChat
  });
});

// Удалить чат и все его сообщения.
app.delete('/api/chats/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Неверный ID чата.' });
  }

  const result = db.prepare(`
    DELETE FROM conversations
    WHERE id = ? AND user_id = ?
  `).run(id, req.session.user.id);

  if (result.changes === 0) {
    return res.status(404).json({
      error: 'Чат не найден или уже удалён.'
    });
  }

  res.json({ success: true });
});

// =====================================================
// ИИ-ЧАТ
// =====================================================

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

    const ollamaUrl = process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';

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
      return res.status(502).json({ error: 'ИИ вернул пустой ответ.' });
    }

    res.json({ reply: reply.trim(), provider: 'ollama' });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(502).json({
      error: 'Не удалось получить ответ от ИИ.'
    });
  }
});

// Генерация изображений Nano Banana.
app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;

  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({
      error: 'Напиши описание изображения.'
    });
  }

  if (prompt.length > 4000) {
    return res.status(400).json({
      error: 'Описание изображения слишком длинное.'
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
        error: data?.error?.message || 'Не удалось создать изображение.'
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
      provider: 'Nano Banana'
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

// Статические файлы сайта.
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
