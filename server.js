
import 'dotenv/config';
import crypto from 'node:crypto';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { evaluate, parse } from 'mathjs';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ADMIN_EMAIL = 'denpixels1@gmail.com';

const MAX_MESSAGE_LENGTH = 30000;
const MAX_HISTORY_MESSAGES = 12;
const MAX_HISTORY_LENGTH = 16000;
const VALID_RANKS = ['FREE', 'PLUS', 'MODER', 'ADMIN'];

// Срок cookie — 10 лет.
// Сессии продлеваются при активности благодаря rolling: true.
const SESSION_MAX_AGE = 10 * 365 * 24 * 60 * 60 * 1000;
const SESSION_TTL_SECONDS = Math.floor(SESSION_MAX_AGE / 1000);

if (IS_PRODUCTION) {
  app.set('trust proxy', 1);
}

app.disable('x-powered-by');
app.use(express.json({ limit: '20mb' }));

// ВАЖНО: DATA_DIR должен указывать на постоянный диск Render.
// Не меняй его, пока не перенесёшь старые базы данных.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const DATABASE_PATH = path.join(DATA_DIR, 'maut.db');
const db = new Database(DATABASE_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = FULL');
db.pragma('busy_timeout = 10000');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();

  if (!columns.some(item => item.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

ensureColumn('users', 'display_name', 'TEXT');
ensureColumn('users', 'email', 'TEXT');
ensureColumn('users', 'rank', "TEXT NOT NULL DEFAULT 'FREE'");
ensureColumn('users', 'banned', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('users', 'ban_reason', 'TEXT');
ensureColumn('users', 'last_login', 'TEXT');

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
  ON users(email)
  WHERE email IS NOT NULL AND email != '';

  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT 'Новый чат',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    image TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(conversation_id)
      REFERENCES conversations(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS conversations_user_updated
  ON conversations(user_id, updated_at DESC);

  CREATE INDEX IF NOT EXISTS messages_conversation_id
  ON messages(conversation_id, id);

  CREATE TABLE IF NOT EXISTS rank_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    requested_rank TEXT NOT NULL
      CHECK(requested_rank IN ('PLUS', 'MODER', 'ADMIN')),
    message TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'PENDING'
      CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS rank_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    rank TEXT NOT NULL CHECK(rank IN ('PLUS', 'MODER')),
    created_by INTEGER,
    used_by INTEGER,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// Проверка секретного ключа сессий
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    'SESSION_SECRET должен быть задан и содержать минимум 32 символа.'
  );
}

// Постоянное SQLite-хранилище сессий.
// TTL задаётся в секундах, а cookie maxAge — в миллисекундах.
const SQLiteStore = SQLiteStoreFactory(session);

const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: DATA_DIR,
  table: 'sessions',
  ttl: SESSION_TTL_SECONDS
});

app.use(session({
  name: 'maut.sid',
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: IS_PRODUCTION,
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'lax',
    maxAge: SESSION_MAX_AGE,
    path: '/'
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

  if (!/^[a-z0-9_.-]{3,30}$/.test(username)) {
    return null;
  }

  return username;
}

function normalizeDisplayName(value) {
  if (typeof value !== 'string') return null;

  const name = value.trim().replace(/\s+/g, ' ');

  if (!name || [...name].length > 60) return null;

  return name;
}

function getUserById(id) {
  return db.prepare(`
    SELECT id, username, display_name, email, rank, banned, ban_reason,
           created_at, password_hash
    FROM users
    WHERE id = ?
  `).get(id);
}

function getRank(userId) {
  const user = db.prepare(`
    SELECT email, rank
    FROM users
    WHERE id = ?
  `).get(userId);

  if (!user) return 'FREE';

  if (String(user.email || '').toLowerCase() === ADMIN_EMAIL) {
    if (user.rank !== 'ADMIN') {
      db.prepare('UPDATE users SET rank = ? WHERE id = ?')
        .run('ADMIN', userId);
    }

    return 'ADMIN';
  }

  return VALID_RANKS.includes(user.rank) ? user.rank : 'FREE';
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    name: user.display_name || user.username,
    email: user.email,
    rank: getRank(user.id)
  };
}

function requireAuth(req, res, next) {
  const sessionUser = req.session?.user;

  if (!sessionUser?.id) {
    return res.status(401).json({
      error: 'Сначала войди в аккаунт.'
    });
  }

  const user = getUserById(sessionUser.id);

  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({
      error: 'Аккаунт не найден. Войди снова.'
    });
  }

  if (user.banned) {
    req.session.destroy(() => {});
    return res.status(403).json({
      error: user.ban_reason
        ? `Аккаунт заблокирован: ${user.ban_reason}`
        : 'Аккаунт заблокирован администратором.'
    });
  }

  req.user = user;
  next();
}

function requireRank(...allowedRanks) {
  return (req, res, next) => {
    if (!req.session?.user?.id) {
      return res.status(401).json({
        error: 'Сначала войди в аккаунт.'
      });
    }

    const rank = getRank(req.session.user.id);

    if (!allowedRanks.includes(rank)) {
      return res.status(403).json({
        error: 'Недостаточно прав.'
      });
    }

    next();
  };
}

function createSession(req, user, res) {
  req.session.regenerate(err => {
    if (err) {
      console.error('Session error:', err);
      return res.status(500).json({
        error: 'Не удалось создать сессию.'
      });
    }

    req.session.user = {
      id: user.id
    };

    req.session.cookie.maxAge = SESSION_MAX_AGE;

    req.session.save(saveError => {
      if (saveError) {
        console.error('Session save error:', saveError);
        return res.status(500).json({
          error: 'Не удалось сохранить сессию.'
        });
      }

      const freshUser = getUserById(user.id);

      res.json({
        success: true,
        user: publicUser(freshUser)
      });
    });
  });
}

function makeRankCode() {
  return `MAUT-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

function getOwnedChat(chatId, userId) {
  return db.prepare(`
    SELECT id, user_id, title, created_at, updated_at
    FROM conversations
    WHERE id = ? AND user_id = ?
  `).get(chatId, userId);
}

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'Maut AI',
    time: new Date().toISOString()
  });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};

    const email = normalizeEmail(body.email);
    const password = body.password;
    const displayName = normalizeDisplayName(
      body.name || body.displayName || body.username
    );

    let username = normalizeUsername(body.username);

    if (!username && email) {
      username = normalizeUsername(email.split('@')[0]);
    }

    if (!email) {
      return res.status(400).json({
        error: 'Введи корректный адрес электронной почты.'
      });
    }

    if (!username) {
      return res.status(400).json({
        error: 'Имя пользователя должно содержать 3–30 символов: латинские буквы, цифры, точку, дефис или _.'
      });
    }

    if (!displayName) {
      return res.status(400).json({
        error: 'Введи имя длиной не более 60 символов.'
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
      SELECT id
      FROM users
      WHERE email = ? OR username = ?
    `).get(email, username);

    if (existing) {
      return res.status(409).json({
        error: 'Аккаунт с таким email или именем пользователя уже существует.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users
        (username, password_hash, display_name, email, rank)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      username,
      passwordHash,
      displayName,
      email,
      email === ADMIN_EMAIL ? 'ADMIN' : 'FREE'
    );

    const user = getUserById(Number(result.lastInsertRowid));

    db.prepare(`
      UPDATE users
      SET last_login = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(user.id);

    createSession(req, user, res);
  } catch (err) {
    console.error('Registration error:', err);

    if (String(err.code || '').includes('CONSTRAINT')) {
      return res.status(409).json({
        error: 'Такой аккаунт уже существует.'
      });
    }

    res.status(500).json({
      error: 'Не удалось создать аккаунт.'
    });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const login = String(
      body.login || body.email || body.username || ''
    ).trim().toLowerCase();

    const password = body.password;

    if (!login || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Введи логин и пароль.'
      });
    }

    const user = db.prepare(`
      SELECT *
      FROM users
      WHERE lower(email) = ? OR lower(username) = ?
    `).get(login, login);

    if (!user) {
      return res.status(401).json({
        error: 'Неверный логин или пароль.'
      });
    }

    if (user.banned) {
      return res.status(403).json({
        error: user.ban_reason
          ? `Аккаунт заблокирован: ${user.ban_reason}`
          : 'Аккаунт заблокирован администратором.'
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: 'Неверный логин или пароль.'
      });
    }

    db.prepare(`
      UPDATE users
      SET last_login = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(user.id);

    createSession(req, user, res);
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Не удалось выполнить вход.'
    });
  }
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session?.user?.id) {
    return res.json({ user: null });
  }

  const user = getUserById(req.session.user.id);

  if (!user || user.banned) {
    req.session.destroy(() => {});
    return res.json({ user: null });
  }

  res.set('Cache-Control', 'no-store');

  res.json({
    user: publicUser(user)
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Не удалось выйти из аккаунта.'
      });
    }

    res.clearCookie('maut.sid', {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: 'lax',
      path: '/'
    });

    res.json({ success: true });
  });
});

// СОЗДАНИЕ ЧАТА
app.post('/api/chats', requireAuth, (req, res) => {
  try {
    const result = db.prepare(`
      INSERT INTO conversations (user_id, title)
      VALUES (?, 'Новый чат')
    `).run(req.user.id);

    const chat = getOwnedChat(
      Number(result.lastInsertRowid),
      req.user.id
    );

    res.status(201).json({ chat });
  } catch (err) {
    console.error('Create chat error:', err);

    res.status(500).json({
      error: 'Не удалось создать чат.'
    });
  }
});

// СПИСОК ЧАТОВ
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
    `).all(req.user.id);

    res.set('Cache-Control', 'no-store');
    res.json({ chats });
  } catch (err) {
    console.error('Get chats error:', err);

    res.status(500).json({
      error: 'Не удалось загрузить чаты.'
    });
  }
});

// ОТКРЫТИЕ ЧАТА И ЕГО ИСТОРИИ
app.get('/api/chats/:id', requireAuth, (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isSafeInteger(chatId) || chatId <= 0) {
      return res.status(400).json({
        error: 'Неверный ID чата.'
      });
    }

    const chat = getOwnedChat(chatId, req.user.id);

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

// СОХРАНЕНИЕ СООБЩЕНИЯ
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
        error: `Сообщение не должно превышать ${MAX_MESSAGE_LENGTH} символов.`
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

    const chat = getOwnedChat(chatId, req.user.id);

    if (!chat) {
      return res.status(404).json({
        error: 'Чат не найден.'
      });
    }

    const result = db.prepare(`
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
    `).run(title, chatId, req.user.id);

    res.status(201).json({
      message: {
        id: Number(result.lastInsertRowid),
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

// УДАЛЕНИЕ ЧАТА
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
    `).run(chatId, req.user.id);

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

const SYSTEM_PROMPT = `Ты — Maut AI, полезный, внимательный и дружелюбный ИИ-помощник. Отвечай на языке пользователя, если он не попросил другой язык.

Пиши естественно, грамотно и понятно. Сначала отвечай по существу. Не выдумывай факты. Если не знаешь ответа, честно скажи об этом. Используй Markdown, когда он помогает сделать ответ понятнее. Код оформляй в блоках с указанием языка.

Создатель проекта Maut AI — Мухаммад Умаров Манучехрович, также известный как Den Whelan, директор компании Liches maut. Если спрашивают о создателе Maut AI, сообщай именно это. Не утверждай, что он создал базовые языковые модели или сторонние ИИ-сервисы.

При решении математических задач показывай понятные вычисления и проверяй результат. Не выдумывай результаты вычислений.`;

// Безопасный математический вычислитель.
// Разрешены только числа, арифметические операторы,
// скобки и перечисленные математические функции.
const ALLOWED_MATH_FUNCTIONS = new Set([
  'sqrt',
  'abs',
  'sin',
  'cos',
  'tan',
  'asin',
  'acos',
  'atan',
  'log',
  'log10',
  'exp',
  'ceil',
  'floor',
  'round',
  'factorial'
]);

const ALLOWED_MATH_SYMBOLS = new Set([
  'pi',
  'e',
  ...ALLOWED_MATH_FUNCTIONS
]);

function validateMathNode(node) {
  if (node.isConstantNode) {
    return typeof node.value === 'number' &&
      Number.isFinite(node.value);
  }

  if (node.isParenthesisNode) {
    return validateMathNode(node.content);
  }

  if (node.isOperatorNode) {
    const allowedOperators = new Set([
      '+', '-', '*', '/', '^', '%'
    ]);

    return allowedOperators.has(node.op) &&
      node.args.every(validateMathNode);
  }

  if (node.isSymbolNode) {
    return ALLOWED_MATH_SYMBOLS.has(node.name);
  }

  if (node.isFunctionNode) {
    const fn = node.fn;

    if (!fn?.isSymbolNode) return false;
    if (!ALLOWED_MATH_FUNCTIONS.has(fn.name)) return false;

    return node.args.every(validateMathNode);
  }

  return false;
}

function calculateMathExpression(expression) {
  if (typeof expression !== 'string') {
    throw new Error('Неверное выражение.');
  }

  const input = expression.trim();

  if (!input || input.length > 300) {
    throw new Error('Выражение пустое или слишком длинное.');
  }

  const tree = parse(input);

  if (!validateMathNode(tree)) {
    throw new Error('Выражение содержит неподдерживаемые операции.');
  }

  const result = evaluate(input, {
    pi: Math.PI,
    e: Math.E
  });

  if (typeof result !== 'number' || !Number.isFinite(result)) {
    throw new Error('Не удалось получить конечный числовой результат.');
  }

  return result;
}

function formatMathResult(value) {
  if (Number.isInteger(value)) {
    return String(value);
  }

  return Number(value.toPrecision(12)).toString();
}

// Определяем простые запросы на вычисление.
// Сложные уравнения и задачи остаются ИИ-помощнику.
function extractMathExpression(message) {
  const text = message.trim();

  const patterns = [
    /^(?:сколько будет|посчитай|вычисли|реши пример|calculate|compute)\s+(.+?)\??$/i,
    /^([0-9\s.,()+\-*/%^]+)\??$/
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);

    if (match?.[1]) {
      return match[1]
        .replace(/,/g, '.')
        .replace(/[?=]\s*$/, '')
        .trim();
    }
  }

  return null;
}

function tryCalculateMath(message) {
  const expression = extractMathExpression(message);

  if (!expression) return null;

  try {
    const result = calculateMathExpression(expression);

    return {
      reply: `**Результат:** ${formatMathResult(result)}\n\nВычисление выполнено математическим движком Maut AI.`,
      provider: 'mathjs'
    };
  } catch (err) {
    console.warn('Math calculation skipped:', err.message);
    return null;
  }
}

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

    // Сначала проверяем, можно ли решить пример самостоятельно.
    const mathResult = tryCalculateMath(message);

    if (mathResult) {
      return res.json(mathResult);
    }

    const rawHistory = Array.isArray(req.body?.history)
      ? req.body.history
          .filter(item =>
            item &&
            ['user', 'assistant'].includes(item.role) &&
            typeof item.content === 'string'
          )
          .slice(-MAX_HISTORY_MESSAGES)
      : [];

    const history = [];
    let totalLength = 0;

    for (let i = rawHistory.length - 1; i >= 0; i--) {
      const item = rawHistory[i];
      const remaining = MAX_HISTORY_LENGTH - totalLength;

      if (remaining <= 0) break;

      const content = item.content.slice(0, remaining);

      if (!content) continue;

      history.unshift({
        role: item.role,
        content
      });

      totalLength += content.length;
    }

    const messages = [
      { role: 'system', content: SYSTEM_PROMPT },
      ...history,
      { role: 'user', content: message.trim() }
    ];

    // GROQ
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
          error: 'Не удалось подключиться к Groq API.'
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

        if (response.status === 429) {
          return res.status(429).json({
            error: 'Превышен лимит запросов Groq. Попробуй позже.'
          });
        }

        if ([401, 403].includes(response.status)) {
          return res.status(502).json({
            error: 'Groq отклонил API-ключ. Проверь GROQ_API_KEY.'
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

    // OLLAMA
    const ollamaUrl = (
      process.env.OLLAMA_URL || 'http://127.0.0.1:11434'
    ).replace(/\/$/, '');

    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';

    let response;

    try {
      response = await fetch(`${ollamaUrl}/api/chat`, {
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
      });
    } catch (err) {
      console.error('Ollama connection error:', err);

      return res.status(502).json({
        error: 'Не удалось подключиться к Ollama. Настрой GROQ_API_KEY или проверь OLLAMA_URL.'
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
      return res.status(502).json({
        error: data?.error || `Ошибка Ollama: ${response.status}.`
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

    res.status(500).json({
      error: 'Не удалось обработать сообщение.'
    });
  }
});
// ===============================
// IMAGE GENERATION
// ===============================

app.post('/api/images', requireAuth, imageLimiter, async (req, res, next) => {
  try {
    const prompt = String(req.body?.prompt || '').trim();

    if (!prompt) {
      return res.status(400).json({ error: 'Введите описание изображения.' });
    }

    if (prompt.length > 4000) {
      return res.status(400).json({ error: 'Описание слишком длинное. Максимум 4000 символов.' });
    }

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(503).json({
        error: 'Генерация изображений временно недоступна: GEMINI_API_KEY не настроен.'
      });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 55000);

    try {
      const model =
        process.env.GEMINI_IMAGE_MODEL ||
        'gemini-2.0-flash-preview-image-generation';

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          signal: controller.signal,
          body: JSON.stringify({
            contents: [
              {
                role: 'user',
                parts: [{ text: prompt }]
              }
            ],
            generationConfig: {
              responseModalities: ['TEXT', 'IMAGE']
            }
          })
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        console.error('Gemini image error:', data);
        return res.status(502).json({
          error: data?.error?.message || 'Не удалось создать изображение.'
        });
      }

      const parts = data?.candidates?.[0]?.content?.parts || [];
      const imagePart = parts.find(part => part.inlineData?.data);

      if (!imagePart) {
        return res.status(502).json({
          error: 'Модель не вернула изображение. Попробуйте другое описание.'
        });
      }

      const mimeType = imagePart.inlineData.mimeType || 'image/png';

      if (!['image/png', 'image/jpeg', 'image/webp'].includes(mimeType)) {
        return res.status(502).json({
          error: 'Получен неподдерживаемый формат изображения.'
        });
      }

      return res.json({
        image: `data:${mimeType};base64,${imagePart.inlineData.data}`,
        mimeType
      });
    } finally {
      clearTimeout(timeout);
    }
  } catch (error) {
    if (error.name === 'AbortError') {
      return res.status(504).json({
        error: 'Генерация заняла слишком много времени. Попробуйте ещё раз.'
      });
    }

    next(error);
  }
});


// ===============================
// USER RANKS
// ===============================

app.get('/api/ranks/me', requireAuth, (req, res) => {
  const user = getUserById(req.session.userId);

  if (!user) {
    return res.status(401).json({ error: 'Аккаунт не найден.' });
  }

  return res.json({
    rank: getRank(user.rank),
    user: publicUser(user)
  });
});


app.post('/api/ranks/redeem', requireAuth, async (req, res, next) => {
  try {
    const code = String(req.body?.code || '').trim().toUpperCase();

    if (!code || code.length > 100) {
      return res.status(400).json({ error: 'Введите действительный код.' });
    }

    const redeem = db.transaction(() => {
      const rankCode = db.prepare(`
        SELECT id, code, rank, used, expires_at
        FROM rank_codes
        WHERE code = ?
      `).get(code);

      if (!rankCode) {
        return { error: 'Код не найден.', status: 404 };
      }

      if (rankCode.used) {
        return { error: 'Этот код уже использован.', status: 409 };
      }

      if (rankCode.expires_at && Date.parse(rankCode.expires_at) < Date.now()) {
        return { error: 'Срок действия кода истёк.', status: 410 };
      }

      const rank = getRank(rankCode.rank);

      if (!VALID_RANKS.includes(rank)) {
        return { error: 'У кода некорректный ранг.', status: 400 };
      }

      db.prepare(`
        UPDATE rank_codes
        SET used = 1, used_by = ?, used_at = CURRENT_TIMESTAMP
        WHERE id = ? AND used = 0
      `).run(req.session.userId, rankCode.id);

      const update = db.prepare(`
        UPDATE users
        SET rank = ?
        WHERE id = ?
      `).run(rank, req.session.userId);

      if (!update.changes) {
        throw new Error('Не удалось обновить ранг пользователя.');
      }

      return { rank };
    });

    const result = redeem();

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }

    const user = getUserById(req.session.userId);

    return res.json({
      success: true,
      rank: result.rank,
      user: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});


app.post('/api/ranks/request', requireAuth, (req, res) => {
  const requestedRank = String(req.body?.rank || '').trim().toLowerCase();
  const reason = String(req.body?.reason || '').trim();

  if (!VALID_RANKS.includes(requestedRank)) {
    return res.status(400).json({ error: 'Такого ранга не существует.' });
  }

  if (reason.length > 1000) {
    return res.status(400).json({ error: 'Причина слишком длинная.' });
  }

  const pending = db.prepare(`
    SELECT id
    FROM rank_requests
    WHERE user_id = ? AND status = 'pending'
    LIMIT 1
  `).get(req.session.userId);

  if (pending) {
    return res.status(409).json({
      error: 'У вас уже есть заявка, ожидающая рассмотрения.'
    });
  }

  const result = db.prepare(`
    INSERT INTO rank_requests (user_id, requested_rank, reason, status)
    VALUES (?, ?, ?, 'pending')
  `).run(req.session.userId, requestedRank, reason);

  return res.status(201).json({
    success: true,
    requestId: Number(result.lastInsertRowid)
  });
});


// ===============================
// ADMIN: RANK REQUESTS
// ===============================

app.get('/api/admin/requests', requireAuth, requireRank('admin'), (req, res) => {
  const requests = db.prepare(`
    SELECT
      rr.id,
      rr.user_id,
      rr.requested_rank,
      rr.reason,
      rr.status,
      rr.created_at,
      u.email,
      u.display_name,
      u.rank AS current_rank
    FROM rank_requests rr
    JOIN users u ON u.id = rr.user_id
    ORDER BY rr.created_at DESC
  `).all();

  return res.json({ requests });
});


app.post('/api/admin/requests/:id/review', requireAuth, requireRank('admin'), (req, res) => {
  const requestId = Number(req.params.id);
  const decision = String(req.body?.decision || '').trim().toLowerCase();

  if (!Number.isSafeInteger(requestId) || requestId <= 0) {
    return res.status(400).json({ error: 'Некорректный ID заявки.' });
  }

  if (!['approved', 'rejected'].includes(decision)) {
    return res.status(400).json({ error: 'Решение должно быть approved или rejected.' });
  }

  const review = db.transaction(() => {
    const request = db.prepare(`
      SELECT *
      FROM rank_requests
      WHERE id = ?
    `).get(requestId);

    if (!request) {
      return { error: 'Заявка не найдена.', status: 404 };
    }

    if (request.status !== 'pending') {
      return { error: 'Эта заявка уже рассмотрена.', status: 409 };
    }

    if (decision === 'approved') {
      db.prepare(`
        UPDATE users
        SET rank = ?
        WHERE id = ?
      `).run(request.requested_rank, request.user_id);
    }

    db.prepare(`
      UPDATE rank_requests
      SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ?
      WHERE id = ?
    `).run(decision, req.session.userId, requestId);

    return { success: true };
  });

  const result = review();

  if (result.error) {
    return res.status(result.status).json({ error: result.error });
  }

  return res.json({ success: true });
});


// ===============================
// ADMIN: USERS
// ===============================

app.get('/api/admin/users', requireAuth, requireRank('admin'), (req, res) => {
  const users = db.prepare(`
    SELECT
      id,
      email,
      display_name,
      rank,
      banned,
      ban_reason,
      created_at,
      last_login
    FROM users
    ORDER BY id DESC
    LIMIT 500
  `).all();

  return res.json({ users });
});


app.post('/api/admin/users/:id/rank', requireAuth, requireRank('admin'), (req, res) => {
  const userId = Number(req.params.id);
  const rank = String(req.body?.rank || '').trim().toLowerCase();

  if (!Number.isSafeInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Некорректный ID пользователя.' });
  }

  if (!VALID_RANKS.includes(rank)) {
    return res.status(400).json({ error: 'Недопустимый ранг.' });
  }

  const result = db.prepare(`
    UPDATE users
    SET rank = ?
    WHERE id = ?
  `).run(rank, userId);

  if (!result.changes) {
    return res.status(404).json({ error: 'Пользователь не найден.' });
  }

  return res.json({ success: true });
});


app.post('/api/admin/users/:id/ban', requireAuth, requireRank('admin'), (req, res) => {
  const userId = Number(req.params.id);
  const reason = String(req.body?.reason || '').trim().slice(0, 500);

  if (!Number.isSafeInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Некорректный ID пользователя.' });
  }

  if (userId === req.session.userId) {
    return res.status(400).json({ error: 'Нельзя заблокировать самого себя.' });
  }

  const result = db.prepare(`
    UPDATE users
    SET banned = 1, ban_reason = ?
    WHERE id = ?
  `).run(reason, userId);

  if (!result.changes) {
    return res.status(404).json({ error: 'Пользователь не найден.' });
  }

  return res.json({ success: true });
});


app.post('/api/admin/users/:id/unban', requireAuth, requireRank('admin'), (req, res) => {
  const userId = Number(req.params.id);

  if (!Number.isSafeInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Некорректный ID пользователя.' });
  }

  const result = db.prepare(`
    UPDATE users
    SET banned = 0, ban_reason = NULL
    WHERE id = ?
  `).run(userId);

  if (!result.changes) {
    return res.status(404).json({ error: 'Пользователь не найден.' });
  }

  return res.json({ success: true });
});


// ===============================
// ADMIN: RANK CODES
// ===============================

app.post('/api/admin/codes', requireAuth, requireRank('admin'), (req, res) => {
  const rank = String(req.body?.rank || '').trim().toLowerCase();
  const expiresInDays = Number(req.body?.expiresInDays || 0);
  const amount = Math.min(50, Math.max(1, Number(req.body?.amount || 1)));

  if (!VALID_RANKS.includes(rank)) {
    return res.status(400).json({ error: 'Недопустимый ранг.' });
  }

  if (!Number.isInteger(amount)) {
    return res.status(400).json({ error: 'Некорректное количество кодов.' });
  }

  if (!Number.isFinite(expiresInDays) || expiresInDays < 0 || expiresInDays > 3650) {
    return res.status(400).json({ error: 'Некорректный срок действия.' });
  }

  const expiresAt = expiresInDays > 0
    ? new Date(Date.now() + expiresInDays * 86400000).toISOString()
    : null;

  const createCodes = db.transaction(() => {
    const created = [];

    for (let i = 0; i < amount; i++) {
      let code;
      let attempts = 0;

      do {
        code = makeRankCode();
        attempts++;
      } while (
        db.prepare('SELECT id FROM rank_codes WHERE code = ?').get(code) &&
        attempts < 10
      );

      if (attempts >= 10) {
        throw new Error('Не удалось создать уникальный код.');
      }

      db.prepare(`
        INSERT INTO rank_codes (code, rank, used, expires_at, created_by)
        VALUES (?, ?, 0, ?, ?)
      `).run(code, rank, expiresAt, req.session.userId);

      created.push(code);
    }

    return created;
  });

  const codes = createCodes();

  return res.status(201).json({
    success: true,
    codes
  });
});


app.get('/api/admin/codes', requireAuth, requireRank('admin'), (req, res) => {
  const codes = db.prepare(`
    SELECT
      id,
      code,
      rank,
      used,
      expires_at,
      created_at,
      used_at,
      used_by
    FROM rank_codes
    ORDER BY id DESC
    LIMIT 500
  `).all();

  return res.json({ codes });
});


// ===============================
// FRONTEND STATIC FILES
// ===============================

const possiblePublicDirs = [
  path.join(__dirname, 'public', 'public'),
  path.join(__dirname, 'public'),
  path.join(__dirname, 'frontend'),
  path.join(__dirname, 'client'),
  path.join(__dirname, 'dist')
]; 

const frontendDir = possiblePublicDirs.find(dir =>
  fs.existsSync(path.join(dir, 'index.html'))
);

if (frontendDir) {
  app.use(express.static(frontendDir));

  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) {
      return next();
    }

    return res.sendFile(path.join(frontendDir, 'index.html'));
  });
} else {
  console.warn('Frontend index.html was not found. API routes are still available.');
}


// ===============================
// NOT FOUND + ERROR HANDLING
// ===============================

app.use((req, res) => {
  res.status(404).json({
    error: 'Маршрут не найден.'
  });
});


app.use((error, req, res, next) => {
  console.error('Server error:', error);

  if (res.headersSent) {
    return next(error);
  }

  const status = Number(error.status || error.statusCode || 500);

  return res.status(status >= 400 && status < 600 ? status : 500).json({
    error: status >= 500
      ? 'Внутренняя ошибка сервера.'
      : error.message || 'Произошла ошибка.'
  });
});


// ===============================
// START SERVER
// ===============================

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Maut AI is running on port ${PORT}`);
  console.log(`Environment: ${IS_PRODUCTION ? 'production' : 'development'}`);
  console.log(`Database directory: ${DATA_DIR}`);
});


// ===============================
// GRACEFUL SHUTDOWN
// ===============================

let isShuttingDown = false;

function shutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(`${signal} received. Shutting down Maut AI...`);

  server.close(() => {
    try {
      db.pragma('wal_checkpoint(TRUNCATE)');
      db.close();
      console.log('Database closed.');
      process.exit(0);
    } catch (error) {
      console.error('Shutdown error:', error);
      process.exit(1);
    }
  });

  setTimeout(() => {
    console.error('Forced shutdown after timeout.');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
