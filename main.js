// server.js
const express      = require('express');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt       = require('bcrypt');
const { Pool }     = require('pg');
const multer       = require('multer');
const fs           = require('fs');
const path         = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));

// ===== Подключение к PostgreSQL =====
const pool = new Pool({
  host: '127.0.0.1',
  port: 6432,
  database: 'KomfortDatabase',
  user: 'postgres',
  password: 'Dima0807',
});

const SALT_ROUNDS = 10;
const COOKIE_NAME = 'user_email_hash';
const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

// Директория для хранения данных заявок
const MINIDATA_DIR = path.join(__dirname, 'minidata');
if (!fs.existsSync(MINIDATA_DIR)) {
  fs.mkdirSync(MINIDATA_DIR);
}

// Настройка Multer (хранение в памяти для последующей записи в нужную папку)
const upload = multer({ storage: multer.memoryStorage() });

const redirectFor = (status) =>
  String(status || '').toLowerCase() === 'administrator' ? '/applications' : '/dashboard';

// =====================================================
// АВТО-СОЗДАНИЕ ТАБЛИЦ + PLAINTEXT-КОЛОНКИ.
// bcrypt необратим, поэтому админка может показать
// имя/фамилию/почту ТОЛЬКО из этих колонок.
// Колонки добавятся сами при запуске сервера.
// =====================================================
pool.query(`
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT,
  surname TEXT,
  email TEXT,
  password TEXT,
  status TEXT DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS requests (
  id SERIAL PRIMARY KEY,
  userid INTEGER,
  entrance INTEGER,
  floor INTEGER,
  category TEXT DEFAULT 'Уборка',
  status TEXT DEFAULT 'Оформлено'
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS name_plain TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS surname_plain TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_plain TEXT;
`).catch((e) => console.error('Ошибка создания таблиц:', e.message));

// =====================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =====================================================

// Поиск пользователя по "сырой" почте
async function findUserByRawEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users');
  for (const row of rows) {
    if (await bcrypt.compare(email, row.email)) return row;
  }
  return null;
}

// Поиск пользователя по хэшу (из cookie)
async function findUserByHash(hash) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [hash]);
  return rows[0] || null;
}

// Чтение описания и медиа заявки из minidata
function readRequestData(requestId) {
  const requestDir = path.join(MINIDATA_DIR, String(requestId));
  let mediaFiles = [];
  let description = 'Нет описания';
  if (fs.existsSync(requestDir)) {
    const descPath = path.join(requestDir, 'description.txt');
    if (fs.existsSync(descPath)) {
      description = fs.readFileSync(descPath, 'utf-8');
    }
    const files = fs.readdirSync(requestDir).filter((f) => f.startsWith('media_'));
    mediaFiles = files
      .sort() // media_0, media_1, …
      .map((f) => ({
        filename: f,
        url: `/api/media/${requestId}/${f}`,
        type: /\.(mp4|webm|ogg|mov)$/i.test(f) ? 'video' : 'image',
      }));
  }
  return { description, mediaFiles };
}

// Проверка, что запрос от администратора
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

// ================= РЕГИСТРАЦИЯ =================
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
    // Сохраняем и хэши (для авторизации), и открытые данные (для админки)
    await pool.query(
      `INSERT INTO users (name, surname, email, password, status, name_plain, surname_plain, email_plain)
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

// ================= ВХОД =================
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

    res.cookie(COOKIE_NAME, user.email, COOKIE_OPTIONS);
    return res.json({ success: true, status: user.status, redirect: redirectFor(user.status) });
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// ================= ПРОВЕРКА СЕССИИ =================
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

// ================= ВЫХОД =================
app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ success: true });
});

// ================= СОЗДАНИЕ ЗАЯВКИ =================
app.post('/api/requests', upload.array('media', 5), async (req, res) => {
  try {
    // 1. Проверка авторизации
    const hash = req.cookies[COOKIE_NAME];
    if (!hash) return res.status(401).json({ success: false, message: 'Не авторизован' });

    const user = await findUserByHash(hash);
    if (!user) return res.status(401).json({ success: false, message: 'Пользователь не найден' });

    // 2. Получение данных
    const { entrance, floor, category, description } = req.body;
    const files = req.files || [];

    // 3. Сохранение в БД
    const queryText = `
      INSERT INTO requests (userid, entrance, floor, category, status)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id
    `;
    const values = [
      user.id,
      entrance,
      floor,
      category || 'Уборка',
      'Оформлено',
    ];
    const { rows } = await pool.query(queryText, values);
    const requestId = rows[0].id;

    // 4. Работа с файловой системой (./minidata/{id})
    const requestDir = path.join(MINIDATA_DIR, String(requestId));
    fs.mkdirSync(requestDir, { recursive: true });

    // Сохраняем описание в текстовый файл
    fs.writeFileSync(path.join(requestDir, 'description.txt'), description || 'Нет описания');

    // Сохраняем медиафайлы
    files.forEach((file, index) => {
      const ext = path.extname(file.originalname) || (file.mimetype.startsWith('video') ? '.mp4' : '.jpg');
      const filename = `media_${index}${ext}`;
      fs.writeFileSync(path.join(requestDir, filename), file.buffer);
    });

    // 5. Ответ клиенту
    return res.json({
      success: true,
      message: 'Заявка успешно создана',
      requestId: requestId,
    });
  } catch (err) {
    console.error('REQUEST CREATE ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка при создании заявки' });
  }
});

// ===== Раздача медиафайлов из minidata =====
app.get('/api/media/:requestId/:filename', (req, res) => {
  const { requestId, filename } = req.params;
  // Защита от path traversal
  const safeName = path.basename(filename);
  const filePath = path.join(MINIDATA_DIR, String(requestId), safeName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ success: false, message: 'Файл не найден' });
  }
  res.sendFile(filePath);
});

// ================= ПОЛУЧЕНИЕ ЗАЯВОК ПОЛЬЗОВАТЕЛЯ =================
app.get('/api/requests/my', async (req, res) => {
  try {
    const hash = req.cookies[COOKIE_NAME];
    if (!hash) return res.status(401).json({ success: false, message: 'Не авторизован' });

    const user = await findUserByHash(hash);
    if (!user) return res.status(401).json({ success: false, message: 'Пользователь не найден' });

    const { rows } = await pool.query(
      `SELECT id, entrance, floor, category, status FROM requests WHERE userid = $1 ORDER BY id DESC`,
      [user.id]
    );

    const requests = rows.map((row) => {
      const { description, mediaFiles } = readRequestData(row.id);
      return {
        id: row.id,
        entrance: row.entrance,
        floor: row.floor,
        category: row.category,
        status: row.status,
        description,
        media: mediaFiles,
      };
    });

    return res.json({ success: true, requests });
  } catch (err) {
    console.error('GET MY REQUESTS ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// =====================================================
// ⚠️ ВАЖНО: маршрут /api/requests/all должен стоять
// СТРОГО ВЫШЕ /api/requests/:id, иначе Express примет
// "all" за номер заявки!
// =====================================================

// ================= ВСЕ ЗАЯВКИ (только админ) =================
app.get('/api/requests/all', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const { rows } = await pool.query(`
      SELECT r.id, r.userid, r.entrance, r.floor, r.category, r.status,
             u.name_plain    AS user_name,
             u.surname_plain AS user_surname,
             u.email_plain   AS user_email
      FROM requests r
      LEFT JOIN users u ON u.id = r.userid
      ORDER BY r.id DESC
    `);

    const requests = rows.map((row) => {
      const { description, mediaFiles } = readRequestData(row.id);
      return {
        id: row.id,
        entrance: row.entrance,
        floor: row.floor,
        category: row.category,
        status: row.status,
        description,
        media: mediaFiles,
        user_name: row.user_name || null,
        user_surname: row.user_surname || null,
        user_email: row.user_email || null,
      };
    });

    return res.json({ success: true, requests });
  } catch (err) {
    console.error('GET ALL REQUESTS ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// ================= СМЕНА СТАТУСА ЗАЯВКИ (только админ) =================
app.patch('/api/requests/:id/status', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const requestId = parseInt(req.params.id, 10);
    if (isNaN(requestId)) {
      return res.status(400).json({ success: false, message: 'Неверный номер заявки' });
    }

    const { status } = req.body || {};
    const allowed = ['Оформлено', 'В работе', 'Исполнение утверждено'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ success: false, message: 'Недопустимый статус' });
    }

    const { rows } = await pool.query(
      `UPDATE requests SET status = $1 WHERE id = $2 RETURNING id`,
      [status, requestId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: 'Заявка не найдена' });
    }

    return res.json({ success: true, id: requestId, status });
  } catch (err) {
    console.error('UPDATE STATUS ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// ================= ПОЛУЧЕНИЕ ЗАЯВКИ ПО НОМЕРУ =================
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
      `SELECT id, userid, entrance, floor, category, status
       FROM requests WHERE id = $1`,
      [requestId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: `Заявка № ${requestId} не найдена` });
    }

    const row = rows[0];
    const { description, mediaFiles } = readRequestData(row.id);

    return res.json({
      success: true,
      request: {
        id: row.id,
        entrance: row.entrance,
        floor: row.floor,
        category: row.category,
        status: row.status,
        description,
        media: mediaFiles,
      },
    });
  } catch (err) {
    console.error('GET REQUEST BY ID ERROR:', err);
    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

const PORT = 5000;
app.listen(PORT, () => console.log(`✅ Сервер запущен: http://localhost:${PORT}`));