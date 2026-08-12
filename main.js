// main.js — сервер «Komfort» (без библиотеки cors, CORS реализован вручную)
const express      = require('express');
const cookieParser = require('cookie-parser');
const bcrypt       = require('bcrypt');
const { Pool }     = require('pg');
const multer       = require('multer');
const fs           = require('fs');
const path         = require('path');

const app = express();
app.disable('x-powered-by');

// ===================== Ручная замена CORS =====================
// По умолчанию отражаем любой Origin (как cors({ origin: true })).
// Строгий список: ALLOWED_ORIGINS=http://localhost:3000,https://example.com
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

function isOriginAllowed(origin) {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.length === 0) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  if (req.method === 'OPTIONS') {
    if (origin && isOriginAllowed(origin)) {
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        req.headers['access-control-request-headers'] || 'Content-Type, Authorization, X-Requested-With'
      );
      res.setHeader('Access-Control-Max-Age', '86400');
    }
    return res.status(204).end();
  }

  next();
});

// ===================== BODY / COOKIES / STATIC =====================
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ===================== PostgreSQL =====================
const pool = new Pool({
  host:     process.env.DB_HOST     || '127.0.0.1',
  port:     Number(process.env.DB_PORT || 6432),
  database: process.env.DB_NAME     || 'KomfortDatabase',
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || 'Dima0807',
});

const SALT_ROUNDS = 10;
const COOKIE_NAME = 'user_email_hash';
const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

// ===================== Хранилище заявок =====================
const MINIDATA_DIR = path.join(__dirname, 'minidata');
if (!fs.existsSync(MINIDATA_DIR)) fs.mkdirSync(MINIDATA_DIR);

// Multer: только фото/видео, до 5 файлов, до 50 МБ каждый
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 5 },
  fileFilter: (req, file, cb) => {
    // ИСПРАВЛЕНО: было /^(image|video)//  — синтаксическая ошибка, сервер не стартовал
    if (/^(image|video)\//.test(file.mimetype)) return cb(null, true);
    cb(new Error('Допустимы только изображения и видео'));
  },
});

const redirectFor = (status) =>
  String(status || '').toLowerCase() === 'administrator' ? '/applications' : '/dashboard';

// ===================== ИНИЦИАЛИЗАЦИЯ БД + АДМИН =====================
const DEFAULT_ADMIN = {
  name: 'Admin',
  surname: 'Admin',
  email: 'admin',
  password: 'Dima0807',
};

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id       SERIAL PRIMARY KEY,
      name     TEXT,
      surname  TEXT,
      email    TEXT,
      password TEXT,
      status   TEXT DEFAULT 'user'
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS requests (
      id       SERIAL PRIMARY KEY,
      userid   INTEGER,
      entrance INTEGER,
      floor    INTEGER,
      category TEXT DEFAULT 'Уборка',
      status   TEXT DEFAULT 'Оформлено'
    )
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name_plain TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS surname_plain TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_plain TEXT`);
  await ensureDefaultAdminExists();
  console.log('✅ База данных инициализирована');
}

async function ensureDefaultAdminExists() {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE LOWER(email_plain) = LOWER($1) LIMIT 1',
      [DEFAULT_ADMIN.email]
    );
    let adminUser = rows[0] || null;

    // Fallback для старых записей без email_plain — перебор по bcrypt-хэшу
    if (!adminUser) {
      const allUsers = await pool.query('SELECT * FROM users');
      for (const user of allUsers.rows) {
        if (user.email && (await bcrypt.compare(DEFAULT_ADMIN.email, user.email))) {
          adminUser = user;
          break;
        }
      }
    }

    if (adminUser) {
      await pool.query(
        `UPDATE users
         SET status       = 'administrator',
             name_plain    = COALESCE(name_plain, $1),
             surname_plain = COALESCE(surname_plain, $2),
             email_plain   = COALESCE(email_plain, $3)
         WHERE id = $4`,
        [DEFAULT_ADMIN.name, DEFAULT_ADMIN.surname, DEFAULT_ADMIN.email, adminUser.id]
      );
      console.log('✅ Администратор уже существует. Создание пропущено.');
      return adminUser.id;
    }

    const [nameHash, surnameHash, emailHash, passwordHash] = await Promise.all([
      bcrypt.hash(DEFAULT_ADMIN.name, SALT_ROUNDS),
      bcrypt.hash(DEFAULT_ADMIN.surname, SALT_ROUNDS),
      bcrypt.hash(DEFAULT_ADMIN.email, SALT_ROUNDS),
      bcrypt.hash(DEFAULT_ADMIN.password, SALT_ROUNDS),
    ]);

    const insertResult = await pool.query(
      `INSERT INTO users
         (name, surname, email, password, status, name_plain, surname_plain, email_plain)
       VALUES ($1, $2, $3, $4, 'administrator', $5, $6, $7)
       RETURNING id`,
      [
        nameHash, surnameHash, emailHash, passwordHash,
        DEFAULT_ADMIN.name, DEFAULT_ADMIN.surname, DEFAULT_ADMIN.email,
      ]
    );
    console.log('✅ Создан администратор по умолчанию. ID:', insertResult.rows[0].id);
    return insertResult.rows[0].id;
  } catch (err) {
    console.error('❌ Ошибка создания администратора:', err.message);
    throw err;
  }
}

// ===================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====================
async function findUserByRawEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users');
  for (const row of rows) {
    if (await bcrypt.compare(email, row.email)) return row;
  }
  return null;
}

async function findUserByHash(hash) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [hash]);
  return rows[0] || null;
}

async function findUserByIdAdmin(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0] || null;
}

function readRequestData(requestId) {
  const requestDir = path.join(MINIDATA_DIR, String(requestId));
  let mediaFiles = [];
  let description = 'Нет описания';

  if (fs.existsSync(requestDir)) {
    const descPath = path.join(requestDir, 'description.txt');
    if (fs.existsSync(descPath)) {
      description = fs.readFileSync(descPath, 'utf-8');
    }
    mediaFiles = fs
      .readdirSync(requestDir)
      .filter((fileName) => fileName.startsWith('media_'))
      .sort()
      .map((fileName) => ({
        filename: fileName,
        url: `/api/media/${requestId}/${fileName}`,
        type: /\.(mp4|webm|ogg|mov)$/i.test(fileName) ? 'video' : 'image',
      }));
  }
  // The React client reads request.media. Keep the API response aligned with
  // that contract so saved attachments are rendered in both request views.
  return { description, media: mediaFiles };
}

async function getAdminUser(req, res) {
  const hash = req.cookies[COOKIE_NAME];
  if (!hash) {
    res.status(401).json({ success: false, message: 'Не авторизован' });
    return null;
  }
  const user = await findUserByHash(hash);
  if (!user) {
    res.status(401).json({ success: false, message: 'Пользователь не найден' });
    return null;
  }
  if (String(user.status).toLowerCase() !== 'administrator') {
    res.status(403).json({ success: false, message: 'Доступ только для администратора' });
    return null;
  }
  return user;
}

// ===================== АДМИН: ПОЛЬЗОВАТЕЛИ =====================
const ADMIN_ALLOWED_STATUSES = ['user', 'administrator'];

function normalizeUserStatus(status) {
  const s = String(status || '').trim().toLowerCase();
  if (['admin', 'administrator', 'администратор'].includes(s)) return 'administrator';
  if (['user', 'пользователь'].includes(s)) return 'user';
  return null;
}

function toSafeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name_plain || null,
    surname: row.surname_plain || null,
    email: row.email_plain || null,
    status: row.status || 'user',
  };
}

async function findUserByEmailAdmin(email) {
  const originalEmail = String(email || '').trim();
  const lowerEmail = originalEmail.toLowerCase();
  if (!lowerEmail) return null;

  const { rows } = await pool.query(
    'SELECT * FROM users WHERE LOWER(email_plain) = $1 LIMIT 1',
    [lowerEmail]
  );
  if (rows[0]) return rows[0];
  return findUserByRawEmail(originalEmail);
}

async function deleteUserByIdAdmin(admin, userId, deleteRequests) {
  if (!userId || Number(userId) === Number(admin.id)) {
    const err = new Error('Нельзя удалить самого себя');
    err.statusCode = 400;
    throw err;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (deleteRequests) {
      await client.query('DELETE FROM requests WHERE userid = $1', [userId]);
    } else {
      await client.query('UPDATE requests SET userid = NULL WHERE userid = $1', [userId]);
    }
    const { rows } = await client.query('DELETE FROM users WHERE id = $1 RETURNING id', [userId]);
    if (!rows.length) {
      await client.query('ROLLBACK');
      return null;
    }
    await client.query('COMMIT');
    return rows[0].id;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ВАЖНО: роуты /by-email/... зарегистрированы ВЫШЕ /:id, иначе :id поймает "by-email"
app.get('/api/admin/users', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const search = String(req.query.search || '').trim();
    let query = 'SELECT * FROM users';
    const params = [];

    if (search) {
      if (/^\d+$/.test(search)) {
        query += ' WHERE id = $1';
        params.push(parseInt(search, 10));
      } else {
        const escaped = search.toLowerCase().replace(/[%_]/g, '\\$&');
        query += `
          WHERE LOWER(COALESCE(email_plain, '')) LIKE $1
             OR LOWER(COALESCE(name_plain, '')) LIKE $1
             OR LOWER(COALESCE(surname_plain, '')) LIKE $1
        `;
        params.push(`%${escaped}%`);
      }
    }
    query += ' ORDER BY id';

    const { rows } = await pool.query(query, params);
    return res.json({ success: true, users: rows.map(toSafeUser) });
  } catch (err) {
    console.error('ADMIN GET USERS ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.get('/api/admin/users/by-email/:email', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const user = await findUserByEmailAdmin(req.params.email);
    if (!user) return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    return res.json({ success: true, user: toSafeUser(user) });
  } catch (err) {
    console.error('ADMIN GET USER BY EMAIL ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.get('/api/admin/users/:id', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) return res.status(400).json({ success: false, message: 'Неверный id пользователя' });

    const user = await findUserByIdAdmin(userId);
    if (!user) return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    return res.json({ success: true, user: toSafeUser(user) });
  } catch (err) {
    console.error('ADMIN GET USER BY ID ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.patch('/api/admin/users/by-email/:email/status', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const target = await findUserByEmailAdmin(req.params.email);
    if (!target) return res.status(404).json({ success: false, message: 'Пользователь не найден' });

    const newStatus = normalizeUserStatus(req.body?.status);
    if (!ADMIN_ALLOWED_STATUSES.includes(newStatus)) {
      return res.status(400).json({ success: false, message: 'Недопустимый статус' });
    }
    if (target.id === admin.id && newStatus !== 'administrator') {
      return res.status(400).json({ success: false, message: 'Нельзя понизить свой собственный статус' });
    }

    await pool.query('UPDATE users SET status = $1 WHERE id = $2', [newStatus, target.id]);
    return res.json({ success: true, id: target.id, status: newStatus });
  } catch (err) {
    console.error('ADMIN PATCH STATUS BY EMAIL ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.patch('/api/admin/users/:id/status', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) return res.status(400).json({ success: false, message: 'Неверный id пользователя' });

    const target = await findUserByIdAdmin(userId);
    if (!target) return res.status(404).json({ success: false, message: 'Пользователь не найден' });

    const newStatus = normalizeUserStatus(req.body?.status);
    if (!ADMIN_ALLOWED_STATUSES.includes(newStatus)) {
      return res.status(400).json({ success: false, message: 'Недопустимый статус' });
    }
    if (target.id === admin.id && newStatus !== 'administrator') {
      return res.status(400).json({ success: false, message: 'Нельзя понизить свой собственный статус' });
    }

    await pool.query('UPDATE users SET status = $1 WHERE id = $2', [newStatus, userId]);
    return res.json({ success: true, id: userId, status: newStatus });
  } catch (err) {
    console.error('ADMIN PATCH STATUS BY ID ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.delete('/api/admin/users/by-email/:email', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const target = await findUserByEmailAdmin(req.params.email);
    if (!target) return res.status(404).json({ success: false, message: 'Пользователь не найден' });

    const deleteRequests = String(req.query.deleteRequests || '').toLowerCase() === 'true';
    const deletedId = await deleteUserByIdAdmin(admin, target.id, deleteRequests);
    if (!deletedId) return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    return res.json({ success: true, id: deletedId });
  } catch (err) {
    console.error('ADMIN DELETE BY EMAIL ERROR:', err);
    return res.status(err.statusCode || 500).json({ success: false, message: err.message || 'Ошибка сервера' });
  }
});

app.delete('/api/admin/users/:id', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) return res.status(400).json({ success: false, message: 'Неверный id пользователя' });

    const deleteRequests = String(req.query.deleteRequests || '').toLowerCase() === 'true';
    const deletedId = await deleteUserByIdAdmin(admin, userId, deleteRequests);
    if (!deletedId) return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    return res.json({ success: true, id: deletedId });
  } catch (err) {
    console.error('ADMIN DELETE BY ID ERROR:', err);
    return res.status(err.statusCode || 500).json({ success: false, message: err.message || 'Ошибка сервера' });
  }
});

// ===================== АВТОРИЗАЦИЯ =====================
app.post('/api/register', async (req, res) => {
  try {
    const { name, surname, email, password } = req.body || {};
    if (!name || !surname || !email || !password) {
      return res.status(400).json({ success: false, message: 'Заполните все поля' });
    }

    const existing = await findUserByRawEmail(email);
    if (existing) {
      return res.status(409).json({ success: false, message: 'Эта почта уже зарегистрирована' });
    }

    const [nameHash, surnameHash, emailHash, passwordHash] = await Promise.all([
      bcrypt.hash(name, SALT_ROUNDS),
      bcrypt.hash(surname, SALT_ROUNDS),
      bcrypt.hash(email, SALT_ROUNDS),
      bcrypt.hash(password, SALT_ROUNDS),
    ]);

    await pool.query(
      `INSERT INTO users
         (name, surname, email, password, status, name_plain, surname_plain, email_plain)
       VALUES ($1, $2, $3, $4, 'user', $5, $6, $7)`,
      [nameHash, surnameHash, emailHash, passwordHash, name, surname, email]
    );

    res.cookie(COOKIE_NAME, emailHash, COOKIE_OPTIONS);
    return res.json({ success: true, status: 'user', redirect: '/dashboard' });
  } catch (err) {
    console.error('REGISTER ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Введите почту и пароль' });
    }

    const user = await findUserByRawEmail(email);
    if (!user) return res.status(401).json({ success: false, message: 'Неверная почта или пароль' });

    const passwordOk = await bcrypt.compare(password, user.password);
    if (!passwordOk) return res.status(401).json({ success: false, message: 'Неверная почта или пароль' });

    // user.email — это bcrypt-хэш почты
    res.cookie(COOKIE_NAME, user.email, COOKIE_OPTIONS);
    return res.json({ success: true, status: user.status, redirect: redirectFor(user.status) });
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.get('/api/session', async (req, res) => {
  try {
    const hash = req.cookies[COOKIE_NAME];
    if (!hash) return res.json({ authenticated: false });

    const { rows } = await pool.query('SELECT status FROM users WHERE email = $1', [hash]);
    if (!rows.length) {
      res.clearCookie(COOKIE_NAME);
      return res.json({ authenticated: false });
    }
    return res.json({
      authenticated: true,
      status: rows[0].status,
      redirect: redirectFor(rows[0].status),
    });
  } catch (err) {
    console.error('SESSION ERROR:', err);
    return res.json({ authenticated: false });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ success: true });
});

app.get('/api/health', (req, res) => {
  res.json({ success: true, uptime: process.uptime() });
});

// ===================== ЗАЯВКИ =====================
app.post('/api/requests', upload.array('media', 5), async (req, res) => {
  try {
    const hash = req.cookies[COOKIE_NAME];
    if (!hash) return res.status(401).json({ success: false, message: 'Не авторизован' });

    const user = await findUserByHash(hash);
    if (!user) return res.status(401).json({ success: false, message: 'Пользователь не найден' });

    const { entrance, floor, category, description } = req.body;
    const files = req.files || [];

    const { rows } = await pool.query(
      `INSERT INTO requests (userid, entrance, floor, category, status)
       VALUES ($1, $2, $3, $4, 'Оформлено')
       RETURNING id`,
      [user.id, entrance, floor, category || 'Уборка']
    );
    const requestId = rows[0].id;

    const requestDir = path.join(MINIDATA_DIR, String(requestId));
    fs.mkdirSync(requestDir, { recursive: true });
    fs.writeFileSync(path.join(requestDir, 'description.txt'), description || 'Нет описания');

    files.forEach((file, index) => {
      const ext =
        path.extname(file.originalname) ||
        (file.mimetype.startsWith('video') ? '.mp4' : '.jpg');
      fs.writeFileSync(path.join(requestDir, `media_${index}${ext}`), file.buffer);
    });

    return res.json({ success: true, message: 'Заявка успешно создана', requestId });
  } catch (err) {
    console.error('REQUEST CREATE ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка при создании заявки' });
  }
});

app.get('/api/media/:requestId/:filename', (req, res) => {
  const safeRequestId = path.basename(String(req.params.requestId));
  const safeFileName  = path.basename(req.params.filename);
  const filePath = path.join(MINIDATA_DIR, safeRequestId, safeFileName);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ success: false, message: 'Файл не найден' });
  }
  res.sendFile(filePath);
});

app.get('/api/requests/my', async (req, res) => {
  try {
    const hash = req.cookies[COOKIE_NAME];
    if (!hash) return res.status(401).json({ success: false, message: 'Не авторизован' });

    const user = await findUserByHash(hash);
    if (!user) return res.status(401).json({ success: false, message: 'Пользователь не найден' });

    const { rows } = await pool.query(
      `SELECT id, entrance, floor, category, status
       FROM requests
       WHERE userid = $1
       ORDER BY id DESC`,
      [user.id]
    );

    const requests = rows.map((row) => ({
      id: row.id,
      entrance: row.entrance,
      floor: row.floor,
      category: row.category,
      status: row.status,
      ...readRequestData(row.id),
    }));
    return res.json({ success: true, requests });
  } catch (err) {
    console.error('GET MY REQUESTS ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// ⚠️ /api/requests/all зарегистрирован строго ВЫШЕ /api/requests/:id
app.get('/api/requests/all', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const { rows } = await pool.query(`
      SELECT
        r.id, r.userid, r.entrance, r.floor, r.category, r.status,
        u.name_plain    AS user_name,
        u.surname_plain AS user_surname,
        u.email_plain   AS user_email
      FROM requests r
      LEFT JOIN users u ON u.id = r.userid
      ORDER BY r.id DESC
    `);

    const requests = rows.map((row) => ({
      id: row.id,
      entrance: row.entrance,
      floor: row.floor,
      category: row.category,
      status: row.status,
      ...readRequestData(row.id),
      user_name: row.user_name || null,
      user_surname: row.user_surname || null,
      user_email: row.user_email || null,
    }));
    return res.json({ success: true, requests });
  } catch (err) {
    console.error('GET ALL REQUESTS ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.patch('/api/requests/:id/status', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const requestId = parseInt(req.params.id, 10);
    if (isNaN(requestId)) return res.status(400).json({ success: false, message: 'Неверный номер заявки' });

    const { status } = req.body || {};
    const allowed = ['Оформлено', 'В работе', 'Исполнение утверждено'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ success: false, message: 'Недопустимый статус' });
    }

    const { rows } = await pool.query(
      'UPDATE requests SET status = $1 WHERE id = $2 RETURNING id',
      [status, requestId]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Заявка не найдена' });
    return res.json({ success: true, id: requestId, status });
  } catch (err) {
    console.error('UPDATE STATUS ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.get('/api/requests/:id', async (req, res) => {
  try {
    const hash = req.cookies[COOKIE_NAME];
    if (!hash) return res.status(401).json({ success: false, message: 'Не авторизован' });

    const user = await findUserByHash(hash);
    if (!user) return res.status(401).json({ success: false, message: 'Пользователь не найден' });

    const requestId = parseInt(req.params.id, 10);
    if (isNaN(requestId)) {
      return res.status(400).json({ success: false, message: 'Введите числовой номер заявки' });
    }

    const { rows } = await pool.query(
      'SELECT id, userid, entrance, floor, category, status FROM requests WHERE id = $1',
      [requestId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: `Заявка № ${requestId} не найдена` });
    }

    const row = rows[0];
    return res.json({
      success: true,
      request: {
        id: row.id,
        entrance: row.entrance,
        floor: row.floor,
        category: row.category,
        status: row.status,
        ...readRequestData(row.id),
      },
    });
  } catch (err) {
    console.error('GET REQUEST BY ID ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// ===================== 404 ДЛЯ API =====================
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ success: false, message: 'Маршрут не найден' });
  }
  next();
});

// ===================== SPA FALLBACK =====================
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api')) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  next();
});

// ===================== ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ОШИБОК =====================
app.use((err, req, res, next) => {
  console.error('ERROR:', err.message || err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ success: false, message: 'Ошибка загрузки файла: ' + err.message });
  }
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Ошибка сервера',
  });
});

// ===================== СТАРТ =====================
const PORT = Number(process.env.PORT || 5000);

initDatabase().catch((e) => {
  console.error('❌ Ошибка инициализации БД:', e.message);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Сервер запущен: http://0.0.0.0:${PORT}`);
});