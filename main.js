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

app.use(express.static(path.join(__dirname, 'public')));

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

// =====================================================
// ADMIN USERS MANAGEMENT
// Управление пользователями: список, поиск, статус, удаление.
// Вставьте этот блок перед const PORT = 5000;
// =====================================================

const ADMIN_ALLOWED_STATUSES = ['user', 'administrator'];

function normalizeUserStatus(status) {
  const s = String(status || '').trim().toLowerCase();

  if (['admin', 'administrator', 'администратор'].includes(s)) {
    return 'administrator';
  }

  if (['user', 'пользователь'].includes(s)) {
    return 'user';
  }

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

async function findUserByIdAdmin(id) {
  const { rows } = await pool.query(
    'SELECT * FROM users WHERE id = $1',
    [id]
  );

  return rows[0] || null;
}

async function findUserByEmailAdmin(email) {
  const originalEmail = String(email || '').trim();
  const lowerEmail = originalEmail.toLowerCase();

  if (!lowerEmail) return null;

  // Сначала ищем по открытой почте, если она сохранена.
  const { rows } = await pool.query(
    'SELECT * FROM users WHERE LOWER(email_plain) = $1 LIMIT 1',
    [lowerEmail]
  );

  if (rows[0]) return rows[0];

  // Fallback для старых записей, где email_plain может быть NULL.
  // Тогда ищем перебором по bcrypt-хэшу почты.
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
      // Полностью удаляем заявки пользователя.
      await client.query(
        'DELETE FROM requests WHERE userid = $1',
        [userId]
      );
    } else {
      // Сохраняем заявки, но отвязываем их от удалённого пользователя.
      await client.query(
        'UPDATE requests SET userid = NULL WHERE userid = $1',
        [userId]
      );
    }

    const { rows } = await client.query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
      [userId]
    );

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

// ================= СПИСОК ПОЛЬЗОВАТЕЛЕЙ =================
// Примеры:
// GET /api/admin/users
// GET /api/admin/users?search=5
// GET /api/admin/users?search=ivan
// GET /api/admin/users?search=user@mail.ru
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
        const escapedSearch = search
          .toLowerCase()
          .replace(/[%_]/g, '\\$&');

        query += `
          WHERE LOWER(COALESCE(email_plain, '')) LIKE $1
             OR LOWER(COALESCE(name_plain, '')) LIKE $1
             OR LOWER(COALESCE(surname_plain, '')) LIKE $1
        `;

        params.push(`%${escapedSearch}%`);
      }
    }

    query += ' ORDER BY id';

    const { rows } = await pool.query(query, params);

    return res.json({
      success: true,
      users: rows.map(toSafeUser),
    });
  } catch (err) {
    console.error('ADMIN GET USERS ERROR:', err);
    return res.status(500).json({
      success: false,
      message: 'Ошибка сервера',
    });
  }
});

// ================= ПОЛЬЗОВАТЕЛЬ ПО EMAIL =================
// GET /api/admin/users/by-email/user@mail.ru
app.get('/api/admin/users/by-email/:email', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const user = await findUserByEmailAdmin(req.params.email);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Пользователь не найден',
      });
    }

    return res.json({
      success: true,
      user: toSafeUser(user),
    });
  } catch (err) {
    console.error('ADMIN GET USER BY EMAIL ERROR:', err);
    return res.status(500).json({
      success: false,
      message: 'Ошибка сервера',
    });
  }
});

// ================= ПОЛЬЗОВАТЕЛЬ ПО ID =================
// GET /api/admin/users/5
app.get('/api/admin/users/:id', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const userId = parseInt(req.params.id, 10);

    if (isNaN(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Неверный id пользователя',
      });
    }

    const user = await findUserByIdAdmin(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Пользователь не найден',
      });
    }

    return res.json({
      success: true,
      user: toSafeUser(user),
    });
  } catch (err) {
    console.error('ADMIN GET USER BY ID ERROR:', err);
    return res.status(500).json({
      success: false,
      message: 'Ошибка сервера',
    });
  }
});

// ================= СМЕНА СТАТУСА ПО EMAIL =================
// PATCH /api/admin/users/by-email/user@mail.ru/status
// body: { "status": "user" } или { "status": "administrator" }
app.patch('/api/admin/users/by-email/:email/status', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const target = await findUserByEmailAdmin(req.params.email);

    if (!target) {
      return res.status(404).json({
        success: false,
        message: 'Пользователь не найден',
      });
    }

    const newStatus = normalizeUserStatus(req.body?.status);

    if (!ADMIN_ALLOWED_STATUSES.includes(newStatus)) {
      return res.status(400).json({
        success: false,
        message: 'Недопустимый статус',
      });
    }

    if (target.id === admin.id && newStatus !== 'administrator') {
      return res.status(400).json({
        success: false,
        message: 'Нельзя понизить свой собственный администраторский статус',
      });
    }

    await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2',
      [newStatus, target.id]
    );

    return res.json({
      success: true,
      id: target.id,
      status: newStatus,
    });
  } catch (err) {
    console.error('ADMIN PATCH USER STATUS BY EMAIL ERROR:', err);
    return res.status(500).json({
      success: false,
      message: 'Ошибка сервера',
    });
  }
});

// ================= СМЕНА СТАТУСА ПО ID =================
// PATCH /api/admin/users/5/status
// body: { "status": "user" } или { "status": "administrator" }
app.patch('/api/admin/users/:id/status', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const userId = parseInt(req.params.id, 10);

    if (isNaN(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Неверный id пользователя',
      });
    }

    const target = await findUserByIdAdmin(userId);

    if (!target) {
      return res.status(404).json({
        success: false,
        message: 'Пользователь не найден',
      });
    }

    const newStatus = normalizeUserStatus(req.body?.status);

    if (!ADMIN_ALLOWED_STATUSES.includes(newStatus)) {
      return res.status(400).json({
        success: false,
        message: 'Недопустимый статус',
      });
    }

    if (target.id === admin.id && newStatus !== 'administrator') {
      return res.status(400).json({
        success: false,
        message: 'Нельзя понизить свой собственный администраторский статус',
      });
    }

    await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2',
      [newStatus, target.id]
    );

    return res.json({
      success: true,
      id: target.id,
      status: newStatus,
    });
  } catch (err) {
    console.error('ADMIN PATCH USER STATUS BY ID ERROR:', err);
    return res.status(500).json({
      success: false,
      message: 'Ошибка сервера',
    });
  }
});

// ================= УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ПО EMAIL =================
// DELETE /api/admin/users/by-email/user@mail.ru
// DELETE /api/admin/users/by-email/user@mail.ru?deleteRequests=true
app.delete('/api/admin/users/by-email/:email', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const target = await findUserByEmailAdmin(req.params.email);

    if (!target) {
      return res.status(404).json({
        success: false,
        message: 'Пользователь не найден',
      });
    }

    const deleteRequests =
      String(req.query.deleteRequests || '').toLowerCase() === 'true';

    const deletedId = await deleteUserByIdAdmin(
      admin,
      target.id,
      deleteRequests
    );

    if (!deletedId) {
      return res.status(404).json({
        success: false,
        message: 'Пользователь не найден',
      });
    }

    return res.json({
      success: true,
      id: deletedId,
    });
  } catch (err) {
    console.error('ADMIN DELETE USER BY EMAIL ERROR:', err);

    if (err.statusCode) {
      return res.status(err.statusCode).json({
        success: false,
        message: err.message,
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Ошибка сервера',
    });
  }
});

// ================= УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ПО ID =================
// DELETE /api/admin/users/5
// DELETE /api/admin/users/5?deleteRequests=true
app.delete('/api/admin/users/:id', async (req, res) => {
  try {
    const admin = await getAdminUser(req, res);
    if (!admin) return;

    const userId = parseInt(req.params.id, 10);

    if (isNaN(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Неверный id пользователя',
      });
    }

    const deleteRequests =
      String(req.query.deleteRequests || '').toLowerCase() === 'true';

    const deletedId = await deleteUserByIdAdmin(
      admin,
      userId,
      deleteRequests
    );

    if (!deletedId) {
      return res.status(404).json({
        success: false,
        message: 'Пользователь не найден',
      });
    }

    return res.json({
      success: true,
      id: deletedId,
    });
  } catch (err) {
    console.error('ADMIN DELETE USER BY ID ERROR:', err);

    if (err.statusCode) {
      return res.status(err.statusCode).json({
        success: false,
        message: err.message,
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Ошибка сервера',
    });
  }
});

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

app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api')) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  next();
});

const PORT = 5000;
app.listen(PORT, () => console.log(`✅ Сервер запущен: http://localhost:${PORT}`));