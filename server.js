import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) throw new Error('Не задан DATABASE_URL.');
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET должен содержать минимум 32 символа.');
}
if (isProduction) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '12mb' }));

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
pool.on('error', err => console.error('PostgreSQL pool error:', err));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      display_name TEXT,
      email TEXT,
      last_login TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
      ON users(email) WHERE email IS NOT NULL AND email <> '';
    CREATE TABLE IF NOT EXISTS conversations (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Новый чат',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
      content TEXT NOT NULL,
      image TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS conversations_user_updated
      ON conversations(user_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS messages_conversation_id
      ON messages(conversation_id, id);
  `);
}

const PgSession = connectPgSimple(session);
const sessionStore = new PgSession({
  pool,
  tableName: 'sessions',
  createTableIfMissing: true
});

app.use(session({
  name: 'maut.sid',
  secret: process.env.SESSION_SECRET,
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

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
const imageLimiter = rateLimit({ windowMs: 60 * 1000, limit: 4, standardHeaders: 'draft-7', legacyHeaders: false });

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}
function normalizeName(value) {
  if (typeof value !== 'string') return null;
  const name = value.trim().replace(/\s+/g, ' ');
  return name && [...name].length <= 60 ? name : null;
}
function publicUser(row) {
  return { id: Number(row.id), username: row.username, name: row.display_name || row.username, email: row.email || null };
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Сначала войди в аккаунт.' });
  next();
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
        return res.status(500).json({ error: 'Не удалось сохранить сессию.' });
      }
      res.status(statusCode).json({ user });
    });
  });
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'postgresql' });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.get('/api/auth/me', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: req.session.user || null });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = normalizeName(req.body?.name || req.body?.display_name || req.body?.username);
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (!name) return res.status(400).json({ error: 'Введи имя длиной от 1 до 60 символов.' });
    if (!email) return res.status(400).json({ error: 'Введи корректный email.' });
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: 'Пароль должен содержать от 8 до 128 символов.' });
    }
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, display_name, email, last_login)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id, username, display_name, email`,
      [email, hash, name, email]
    );
    createLoginSession(req, res, publicUser(result.rows[0]), 201);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Аккаунт уже существует. Попробуй войти.' });
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Ошибка регистрации на сервере.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const rawLogin = req.body?.email ?? req.body?.username ?? req.body?.login;
    const loginValue = typeof rawLogin === 'string' ? rawLogin.trim() : '';
    const password = req.body?.password;
    if (!loginValue || loginValue.length > 254 || typeof password !== 'string' || password.length > 128) {
      return res.status(400).json({ error: 'Введи логин и пароль.' });
    }
    const login = loginValue.toLowerCase();
    const result = await pool.query(
      `SELECT id, username, password_hash, display_name, email
       FROM users WHERE LOWER(email) = $1 OR LOWER(username) = $1 LIMIT 1`,
      [login]
    );
    const row = result.rows[0];
    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [row.id]);
    createLoginSession(req, res, publicUser(row));
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Ошибка входа на сервере.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Не удалось выйти из аккаунта.' });
    res.clearCookie('maut.sid', { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' });
    res.json({ success: true });
  });
});

app.post('/api/chats', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `INSERT INTO conversations (user_id, title) VALUES ($1, $2)
       RETURNING id, title, created_at, updated_at`,
      [req.session.user.id, 'Новый чат']
    );
    res.status(201).json({ chat: result.rows[0] });
  } catch (err) {
    console.error('Create chat error:', err);
    res.status(500).json({ error: 'Не удалось создать чат.' });
  }
});

app.get('/api/chats', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.title, c.created_at, c.updated_at, COUNT(m.id)::int AS message_count
       FROM conversations c LEFT JOIN messages m ON m.conversation_id = c.id
       WHERE c.user_id = $1 GROUP BY c.id
       ORDER BY c.updated_at DESC, c.id DESC`,
      [req.session.user.id]
    );
    res.set('Cache-Control', 'no-store');
    res.json({ chats: result.rows });
  } catch (err) {
    console.error('List chats error:', err);
    res.status(500).json({ error: 'Не удалось загрузить чаты.' });
  }
});

app.get('/api/chats/:id', requireAuth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    if (!Number.isSafeInteger(chatId) || chatId <= 0) return res.status(400).json({ error: 'Неверный ID чата.' });
    const chatResult = await pool.query(
      'SELECT id, title, created_at, updated_at FROM conversations WHERE id = $1 AND user_id = $2',
      [chatId, req.session.user.id]
    );
    const chat = chatResult.rows[0];
    if (!chat) return res.status(404).json({ error: 'Чат не найден.' });
    const messages = await pool.query(
      'SELECT id, role, content, image, created_at FROM messages WHERE conversation_id = $1 ORDER BY id ASC',
      [chatId]
    );
    res.set('Cache-Control', 'no-store');
    res.json({ chat, messages: messages.rows });
  } catch (err) {
    console.error('Open chat error:', err);
    res.status(500).json({ error: 'Не удалось открыть чат.' });
  }
});

app.post('/api/chats/:id/messages', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const chatId = Number(req.params.id);
    const { role, content, image } = req.body || {};
    if (!Number.isSafeInteger(chatId) || chatId <= 0) return res.status(400).json({ error: 'Неверный ID чата.' });
    if (!['user', 'assistant'].includes(role)) return res.status(400).json({ error: 'Недопустимая роль сообщения.' });
    if (typeof content !== 'string' || content.length > 30000) return res.status(400).json({ error: 'Сообщение слишком длинное.' });
    if (image != null && (typeof image !== 'string' || image.length > 10000000)) return res.status(400).json({ error: 'Изображение слишком большое.' });

    const found = await client.query(
      'SELECT id, title FROM conversations WHERE id = $1 AND user_id = $2',
      [chatId, req.session.user.id]
    );
    const chat = found.rows[0];
    if (!chat) return res.status(404).json({ error: 'Чат не найден.' });

    await client.query('BEGIN');
    const inserted = await client.query(
      `INSERT INTO messages (conversation_id, role, content, image)
       VALUES ($1, $2, $3, $4) RETURNING id, role, content, image, created_at`,
      [chatId, role, content, image || null]
    );
    let title = chat.title;
    if (role === 'user' && title === 'Новый чат') title = content.trim().replace(/\s+/g, ' ').slice(0, 60) || 'Новый чат';
    await client.query(
      'UPDATE conversations SET title = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3',
      [title, chatId, req.session.user.id]
    );
    await client.query('COMMIT');
    res.status(201).json({ message: inserted.rows[0], title });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Save message error:', err);
    res.status(500).json({ error: 'Не удалось сохранить сообщение.' });
  } finally {
    client.release();
  }
});

app.delete('/api/chats/:id', requireAuth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    if (!Number.isSafeInteger(chatId) || chatId <= 0) return res.status(400).json({ error: 'Неверный ID чата.' });
    const result = await pool.query('DELETE FROM conversations WHERE id = $1 AND user_id = $2', [chatId, req.session.user.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Чат не найден.' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete chat error:', err);
    res.status(500).json({ error: 'Не удалось удалить чат.' });
  }
});

app.post('/api/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    const message = req.body?.message;
    if (typeof message !== 'string' || !message.trim() || message.length > 30000) {
      return res.status(400).json({ error: 'Сообщение пустое или слишком длинное.' });
    }
    const history = Array.isArray(req.body?.history)
      ? req.body.history.filter(item => item && ['user', 'assistant'].includes(item.role) && typeof item.content === 'string')
          .slice(-10).map(item => ({ role: item.role, content: item.content.slice(0, 4000) }))
      : [];
    const systemPrompt = `Ты — Maut AI, ИИ-помощник проекта Maut AI.

ОТВЕТЫ:
- Отвечай на языке последнего сообщения пользователя.
- Пиши грамотно, естественно и понятно.
- Сначала отвечай по существу.
- Не придумывай факты.
- Если не уверен, честно скажи об этом.
- Используй Markdown, когда это помогает читать ответ.

СОЗДАТЕЛЬ:
Создатель проекта Maut AI — Мухаммад Умаров Манучехрович, также известный как Den Whelan. Он является директором компании Liches maut.

Если спрашивают о создателе Maut AI, отвечай на языке пользователя:
Мухаммад Умаров Манучехрович (Den Whelan) создал проект Maut AI и является директором компании Liches maut.

Не утверждай, что создатель проекта разработал базовую языковую модель или сторонние ИИ-сервисы.`;
    const messages = [{ role: 'system', content: systemPrompt }, ...history, { role: 'user', content: message.trim() }];

    if (process.env.GROQ_API_KEY) {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: process.env.GROQ_MODEL || 'openai/gpt-oss-120b',
          messages, temperature: 0.5,
          max_tokens: Number(process.env.GROQ_MAX_TOKENS) || 2048
        }),
        signal: AbortSignal.timeout(60000)
      });
      const data = await response.json();
      if (!response.ok) {
        console.error('Groq error:', response.status, data);
        if (response.status === 429) return res.status(429).json({ error: 'Превышен лимит Groq. Попробуй позже.' });
        return res.status(502).json({ error: data?.error?.message || 'Ошибка Groq API.' });
      }
      const reply = data?.choices?.[0]?.message?.content;
      if (typeof reply !== 'string' || !reply.trim()) return res.status(502).json({ error: 'Groq вернул пустой ответ.' });
      return res.json({ reply: reply.trim(), provider: 'groq' });
    }

    const ollamaUrl = process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';
    const response = await fetch(`${ollamaUrl.replace(/\/$/, '')}/api/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: ollamaModel, messages, stream: false }),
      signal: AbortSignal.timeout(60000)
    });
    const data = await response.json();
    if (!response.ok) return res.status(502).json({ error: data?.error || 'Ошибка Ollama API.' });
    const reply = data?.message?.content;
    if (typeof reply !== 'string' || !reply.trim()) return res.status(502).json({ error: 'ИИ вернул пустой ответ.' });
    res.json({ reply: reply.trim(), provider: 'ollama' });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(502).json({ error: 'Не удалось получить ответ от ИИ.' });
  }
});

app.post('/api/images', requireAuth, imageLimiter, async (req, res) => {
  const prompt = req.body?.prompt;
  if (typeof prompt !== 'string' || !prompt.trim()) return res.status(400).json({ error: 'Напиши описание изображения.' });
  if (prompt.length > 4000) return res.status(400).json({ error: 'Описание слишком длинное.' });
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'Не настроен GEMINI_API_KEY.' });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55000);
  try {
    const model = process.env.GEMINI_IMAGE_MODEL || 'gemini-3.1-flash-image';
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
        body: JSON.stringify({
          contents: [{ parts: [{ text: `Create one image based on this prompt: ${prompt.trim()}` }] }],
          generationConfig: { responseModalities: ['TEXT', 'IMAGE'] }
        }),
        signal: controller.signal
      }
    );
    const data = await response.json();
    if (!response.ok) {
      console.error('Gemini error:', response.status, data);
      return res.status(502).json({ error: data?.error?.message || 'Ошибка генерации изображения.' });
    }
    const parts = data?.candidates?.[0]?.content?.parts || [];
    const imagePart = parts.find(part => part.inlineData?.data);
    if (!imagePart) return res.status(502).json({ error: 'Gemini не вернул изображение.' });
    const mimeType = imagePart.inlineData.mimeType || 'image/png';
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(mimeType)) return res.status(502).json({ error: 'Формат изображения не поддерживается.' });
    res.json({ image: `data:${mimeType};base64,${imagePart.inlineData.data}`, provider: 'Gemini' });
  } catch (err) {
    console.error('Image generation error:', err);
    res.status(err.name === 'AbortError' ? 504 : 502).json({
      error: err.name === 'AbortError' ? 'Генерация заняла слишком много времени.' : 'Не удалось подключиться к Gemini.'
    });
  } finally {
    clearTimeout(timeout);
  }
});

app.use(express.static(__dirname));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use('/api', (req, res) => res.status(404).json({ error: 'API маршрут не найден.' }));
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Запрос слишком большой.' });
  res.status(500).json({ error: 'Внутренняя ошибка сервера.' });
});

async function start() {
  await initializeDatabase();
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Maut AI запущен на порту ${PORT}`);
    console.log('Database: Neon PostgreSQL');
  });
  let closing = false;
  async function shutdown() {
    if (closing) return;
    closing = true;
    server.close(async () => {
      try {
        await sessionStore.close();
        await pool.end();
        process.exit(0);
      } catch (err) {
        console.error('Shutdown error:', err);
        process.exit(1);
      }
    });
    setTimeout(() => process.exit(1), 10000).unref();
  }
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}
start().catch(err => {
  console.error('Failed to start Maut AI:', err);
  process.exit(1);
});
