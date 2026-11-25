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
const isProduction = process.env.NODE_ENV === 'production';

// Лимиты длинных сообщений
const MAX_MESSAGE_LENGTH = 30000;
const MAX_HISTORY_MESSAGES = 10;
const MAX_HISTORY_TOTAL_LENGTH = 12000;

if (isProduction) app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(express.json({ limit: '20mb' }));

// Папка для базы данных
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

if (!userColumns.includes('rank')) {
  db.exec("ALTER TABLE users ADD COLUMN rank TEXT NOT NULL DEFAULT 'FREE'");
}

db.exec(`
  CREATE TABLE IF NOT EXISTS rank_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    requested_rank TEXT NOT NULL CHECK (requested_rank IN ('PLUS','MODER','ADMIN')),
    message TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS rank_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    rank TEXT NOT NULL CHECK (rank IN ('PLUS', 'MODER')),
    created_by INTEGER,
    used_by INTEGER,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const ADMIN_EMAIL = 'denpixels1@gmail.com';
const userColsForModeration = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);

if (!userColsForModeration.includes('banned')) {
  db.exec('ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0');
}

if (!userColsForModeration.includes('ban_reason')) {
  db.exec('ALTER TABLE users ADD COLUMN ban_reason TEXT');
}

const VALID_RANKS = ['FREE', 'PLUS', 'MODER', 'ADMIN'];

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
  ON users(email)
  WHERE email IS NOT NULL AND email != ''
`);

// Таблицы истории чатов
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
    return res.status(401).json({ error: 'Сначала войди в аккаунт.' });
  }

  const account = db.prepare(
    'SELECT banned, ban_reason FROM users WHERE id = ?'
  ).get(req.session.user.id);

  if (!account || account.banned) {
    req.session.destroy(() => {});
    return res.status(403).json({
      error: account?.ban_reason
        ? `Аккаунт заблокирован: ${account.ban_reason}`
        : 'Аккаунт заблокирован администратором.'
    });
  }

  next();
}

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

function normalizeUsername(value) {
  if (typeof value !== 'string') return null;

  const username = value.trim().toLowerCase();

  if (!/^[a-z0-9_.-]{3,30}$/.test(username)) return null;

  return username;
}

function currentRank(userId) {
  const user = db.prepare(
    'SELECT email, rank FROM users WHERE id = ?'
  ).get(userId);

  if (!user) return 'FREE';

  if (user.email?.toLowerCase() === ADMIN_EMAIL) {
    if (user.rank !== 'ADMIN') {
      db.prepare('UPDATE users SET rank = ? WHERE id = ?')
        .run('ADMIN', userId);
    }
    return 'ADMIN';
  }

  return VALID_RANKS.includes(user.rank) ? user.rank : 'FREE';
}

function requireRank(...allowedRanks) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Сначала войди в аккаунт.' });
    }

    const rank = currentRank(req.session.user.id);

    if (!allowedRanks.includes(rank)) {
      return res.status(403).json({ error: 'Недостаточно прав.' });
    }

    next();
  };
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    name: user.display_name || user.username,
    email: user.email,
    rank: currentRank(user.id)
  };
}

function makeRankCode() {
  return `MAUT-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

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

// Получить список чатов пользователя
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

// Открыть чат и его сообщения
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

// Сохранить сообщение в чате — до 30 000 символов
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
      title = content.trim().replace(/\s+/g, ' ').slice(0, 60) || 'Новый чат';

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

// Maut AI — чат с ИИ
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

    // Берём только последние сообщения и ограничиваем общий размер истории.
    // Это позволяет избежать чрезмерно больших запросов к ИИ.
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
        content: `Ты — Maut AI, полезный, внимательный и дружелюбный ИИ-помощник. Всегда отвечай на языке пользователя, если он не попросил другой язык.

КАЧЕСТВО И СТРУКТУРА ОТВЕТА
- Пиши естественно, грамотно и последовательно. Перед отправкой мысленно проверь, что предложения связаны друг с другом и нет случайных повторов, обрывков слов или бессмысленных символов.
- Если нужен длинный ответ, разбивай его на понятные разделы с короткими заголовками Markdown (## и ###), абзацы разделяй пустой строкой.
- Используй нумерованные списки для последовательности действий и маркированные списки для перечислений. Не превращай каждое предложение в отдельный пункт.
- Для сравнения используй таблицы только тогда, когда они действительно упрощают понимание.
- Формулы оформляй понятно; программный код помещай в fenced code blocks с указанием языка, например, с указанием языка js. Не смешивай пояснения и код в одном неразборчивом блоке.
- Не используй Markdown без необходимости: не делай весь ответ жирным, не добавляй заголовок к каждому короткому ответу и не создавай огромную стену текста.
- Сначала отвечай по существу. Добавляй детали, примеры и итог, если они помогают выполнить просьбу пользователя.
- Не выдавай выдуманные сведения за факты. Если чего-то не знаешь, прямо обозначь неопределённость.
- Если пользователь просит подробный материал, подготовь максимально полный ответ в пределах доступного лимита модели. Не повторяй одну и ту же мысль ради увеличения длины и не обрывай ответ намеренно. Если объём не помещается в один ответ, закончи на логичной границе и кратко укажи, что можно продолжить.
- Не добавляй служебные комментарии о том, что ты следуешь этим инструкциям.

СОЗДАТЕЛЬ ПРОЕКТА
Создатель проекта Maut AI: Мухаммад Умаров Манучехрович, также известный как Den Whelan. Он является директором компании Liches maut.

Если пользователь спрашивает, кто создал Maut AI, кто создатель проекта или кто руководит компанией Liches maut, ответь ясно и уважительно:
«Проект Maut AI создал Мухаммад Умаров Манучехрович (Den Whelan), директор компании Liches maut».

Не утверждай, что он создал базовую языковую модель или сторонние ИИ-сервисы, если это не подтверждено. Различай создателя проекта Maut AI и поставщиков используемых моделей.`
      },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    // Если задан Groq API key, используем Groq.
    // Ошибка Groq возвращается пользователю вместо незаметного переключения
    // на Ollama, которая может быть недоступна на облачном хостинге.
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
          error: 'Не удалось подключиться к Groq. Проверь интернет-соединение сервера и доступность Groq API.'
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
            error: 'Превышен лимит запросов Groq. Подожди немного и попробуй снова.'
          });
        }

        if (response.status === 401 || response.status === 403) {
          return res.status(502).json({
            error: 'Groq отклонил API-ключ. Проверь GROQ_API_KEY в переменных окружения.'
          });
        }

        return res.status(502).json({
          error: apiMessage
            ? `Ошибка Groq: ${apiMessage}`
            : `Groq API вернул ошибку ${response.status}.`
        });
      }

      const reply = data?.choices?.[0]?.message?.content;      if (typeof reply === 'string' && reply.trim()) {
        return res.json({
          reply: reply.trim(),
          provider: 'groq'
        });
      }

      console.error('Groq returned an empty response:', data);

      return res.status(502).json({
        error: 'Groq вернул пустой ответ. Попробуй отправить сообщение ещё раз.'
      });
    }

    // Ollama используется только тогда, когда GROQ_API_KEY не задан.
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
        error: 'Не удалось подключиться к Ollama. Настрой GROQ_API_KEY для работы через Groq или проверь OLLAMA_URL.'
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

// Генерация изображений через Gemini API
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

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return res.status(503).json({
      error: 'Добавь GEMINI_API_KEY в переменные окружения Render.'
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

// ===== MAUT AI RANKS / ADMIN API =====
function currentRank(req) {
  const row = db.prepare('SELECT rank, email FROM users WHERE id = ?').get(req.session.user.id);
  if (!row) return 'FREE';
  if (String(row.email || '').toLowerCase() === ADMIN_EMAIL) return 'ADMIN';
  return VALID_RANKS.includes(row.rank) ? row.rank : 'FREE';
}

function requireRank(...allowed) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Сначала войди в аккаунт.' });
    const rank = currentRank(req);
    if (!allowed.includes(rank)) return res.status(403).json({ error: 'Недостаточно прав.' });
    next();
  };
}

app.get('/api/ranks/me', requireAuth, (req, res) => {
  const rank = currentRank(req);
  req.session.user.rank = rank;
  res.set('Cache-Control', 'no-store');
  res.json({ rank });
});

app.post('/api/ranks/redeem', requireAuth, (req, res) => {
  const code = String(req.body?.code || '').trim().toUpperCase();
  if (!code || code.length > 80) return res.status(400).json({ error: 'Введи корректный код.' });
  try {
    const redeem = db.transaction(() => {
      const item = db.prepare('SELECT id, rank FROM rank_codes WHERE code = ? AND used_by IS NULL').get(code);
      if (!item) return null;
      db.prepare('UPDATE rank_codes SET used_by = ?, used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_by IS NULL').run(req.session.user.id, item.id);
      const changed = db.prepare('SELECT changes() AS n').get().n;
      if (!changed) return null;
      db.prepare('UPDATE users SET rank = ? WHERE id = ?').run(item.rank, req.session.user.id);
      return item.rank;
    });
    const rank = redeem();
    if (!rank) return res.status(400).json({ error: 'Код не найден или уже использован.' });
    req.session.user.rank = rank;
    res.json({ success: true, rank });
  } catch (err) {
    console.error('Redeem code error:', err);
    res.status(500).json({ error: 'Не удалось активировать код.' });
  }
});

// Заявки на повышение ранга. Пользователь может иметь только одну активную заявку.
app.post('/api/ranks/request', requireAuth, (req, res) => {
  const rank = String(req.body?.rank || '').toUpperCase();
  const message = String(req.body?.message || '').trim().slice(0, 500);
  if (!['PLUS','MODER','ADMIN'].includes(rank)) return res.status(400).json({error:'Неверный ранг.'});
  const current = currentRank(req);
  if (current === 'ADMIN' || (current === 'MODER' && rank !== 'ADMIN') || (current === 'PLUS' && rank === 'PLUS')) return res.status(400).json({error:'У тебя уже есть этот или более высокий ранг.'});
  const pending = db.prepare("SELECT id FROM rank_requests WHERE user_id=? AND status='PENDING'").get(req.session.user.id);
  if (pending) return res.status(409).json({error:'У тебя уже есть ожидающая заявка.'});
  const result = db.prepare('INSERT INTO rank_requests(user_id,requested_rank,message) VALUES(?,?,?)').run(req.session.user.id,rank,message);
  res.status(201).json({success:true,id:Number(result.lastInsertRowid)});
});

app.get('/api/admin/requests', requireAuth, requireRank('ADMIN'), (req,res) => {
  const requests = db.prepare(`SELECT r.id,r.requested_rank,r.message,r.created_at,u.id AS user_id,u.display_name,u.username,u.email,u.rank AS current_rank FROM rank_requests r JOIN users u ON u.id=r.user_id WHERE r.status='PENDING' ORDER BY r.id DESC`).all();
  res.set('Cache-Control','no-store'); res.json({requests});
});

app.post('/api/admin/requests/:id/review', requireAuth, requireRank('ADMIN'), (req,res) => {
  const id=Number(req.params.id), decision=String(req.body?.decision||'').toUpperCase();
  if(!Number.isSafeInteger(id)||id<1||!['APPROVE','REJECT'].includes(decision)) return res.status(400).json({error:'Некорректный запрос.'});
  const result=db.transaction(()=>{
    const item=db.prepare("SELECT id,user_id,requested_rank FROM rank_requests WHERE id=? AND status='PENDING'").get(id);
    if(!item) return null;
    if(decision==='APPROVE') db.prepare('UPDATE users SET rank=? WHERE id=?').run(item.requested_rank,item.user_id);
    db.prepare("UPDATE rank_requests SET status=?,reviewed_at=CURRENT_TIMESTAMP,reviewed_by=? WHERE id=?").run(decision==='APPROVE'?'APPROVED':'REJECTED',req.session.user.id,id);
    return item;
  })();
  if(!result) return res.status(404).json({error:'Заявка уже обработана или не найдена.'});
  res.json({success:true});
});

app.get('/api/admin/users', requireAuth, requireRank('ADMIN'), (req, res) => {
  const users = db.prepare(`SELECT id, username, email, display_name, rank, banned, ban_reason, created_at FROM users ORDER BY id DESC`).all();
  res.json({ users });
});

app.post('/api/admin/users/:id/rank', requireAuth, requireRank('ADMIN'), (req, res) => {
  const id=Number(req.params.id), rank=String(req.body?.rank||'').toUpperCase();
  if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'Неверный ID пользователя.'});
  if(!VALID_RANKS.includes(rank)) return res.status(400).json({error:'Неизвестный ранг.'});
  const target=db.prepare('SELECT id,email FROM users WHERE id=?').get(id);
  if(!target) return res.status(404).json({error:'Пользователь не найден.'});
  if(String(target.email||'').toLowerCase()===ADMIN_EMAIL && rank!=='ADMIN') return res.status(403).json({error:'Нельзя изменить ранг владельца.'});
  if(id===req.session.user.id && rank!=='ADMIN') return res.status(403).json({error:'Нельзя снять ранг владельца.'});
  db.prepare('UPDATE users SET rank=? WHERE id=?').run(rank,id); res.json({success:true,rank});
});

app.post('/api/admin/users/:id/ban', requireAuth, requireRank('ADMIN'), (req,res)=>{
  const id=Number(req.params.id), reason=String(req.body?.reason||'Нарушение правил').trim().slice(0,300);
  if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'Неверный ID.'});
  const target=db.prepare('SELECT id,email FROM users WHERE id=?').get(id);
  if(!target) return res.status(404).json({error:'Пользователь не найден.'});
  if(id===req.session.user.id||String(target.email||'').toLowerCase()===ADMIN_EMAIL) return res.status(403).json({error:'Нельзя заблокировать владельца.'});
  db.prepare('UPDATE users SET banned=1,ban_reason=? WHERE id=?').run(reason,id); res.json({success:true});
});
app.post('/api/admin/users/:id/unban', requireAuth, requireRank('ADMIN'), (req,res)=>{
  const id=Number(req.params.id); if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'Неверный ID.'});
  db.prepare('UPDATE users SET banned=0,ban_reason=NULL WHERE id=?').run(id); res.json({success:true});
});

app.post('/api/admin/codes', requireAuth, requireRank('ADMIN'), (req, res) => {
  const rank = String(req.body?.rank || '').toUpperCase();
  const amount = Math.min(20, Math.max(1, Number(req.body?.amount) || 1));
  if (!['PLUS', 'MODER'].includes(rank)) return res.status(400).json({ error: 'Коды доступны для PLUS и MODER.' });
  const create = db.transaction(() => {
    const codes = [];
    for (let i = 0; i < amount; i++) {
      const code = `MAUT-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
      db.prepare('INSERT INTO rank_codes (code, rank, created_by) VALUES (?, ?, ?)').run(code, rank, req.session.user.id);
      codes.push(code);
    }
    return codes;
  });
  res.status(201).json({ success: true, rank, codes: create() });
});

app.get('/api/admin/codes', requireAuth, requireRank('ADMIN'), (req, res) => {
  const codes = db.prepare(`SELECT code, rank, created_at, used_at, used_by FROM rank_codes ORDER BY id DESC LIMIT 100`).all();
  res.json({ codes });
});
// ===== END MAUT AI RANKS / ADMIN API =====

// Статические файлы сайта.
// Поддерживаем обычную папку public, вложенную public/public и корень проекта.
const PUBLIC_CANDIDATES = [
  path.join(__dirname, 'public', 'public'),
  path.join(__dirname, 'public'),
  __dirname
];

const PUBLIC_DIR = PUBLIC_CANDIDATES.find((dir) =>
  fs.existsSync(path.join(dir, 'index.html'))
);

if (!PUBLIC_DIR) {
  throw new Error(
    'Не найден index.html. Проверь папки public/public, public и корень проекта.'
  );
}

console.log('Папка сайта Maut AI:', PUBLIC_DIR);
app.use(express.static(PUBLIC_DIR, { index: false, etag: true, maxAge: '1h' }));

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API маршрут не найден.'
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (res.headersSent) return next(err);

  // Ошибка возникает, например, если JSON-запрос превышает лимит тела.
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Запрос слишком большой. Уменьши размер сообщения или изображения.'
    });
  }

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
