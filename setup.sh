#!/usr/bin/env bash
# ============================================================
#  setup.sh — полная подготовка Debian 12
#  Node.js + PostgreSQL + зависимости для KomfortDatabase
#
#  Запуск:  sudo ./setup.sh
# ============================================================

set -euo pipefail

# ==================== КОНФИГУРАЦИЯ ====================
DB_NAME="KomfortDatabase"
DB_USER="postgres"
DB_PASS="Dima0807"
DB_PORT=6432
DB_HOST="127.0.0.1"
NODE_MAJOR=20

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[FAIL]${NC} $*"; }
die()   { err "$@"; exit 1; }

# ==================== ПРОВЕРКА ROOT ====================
if [[ $EUID -ne 0 ]]; then
  die "Запустите от root:  sudo ./setup.sh"
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  KomfortDatabase — полная установка (Debian 12)     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Проект: ${PROJECT_DIR}"
echo ""

# ============================================================
#  1. СИСТЕМНЫЕ ПАКЕТЫ
# ============================================================
info "1/8 — Обновление системы и базовые пакеты..."
apt-get update -yqq
apt-get install -yqq curl gnupg2 lsb-release ca-certificates wget build-essential
ok "Системные пакеты установлены"

# ============================================================
#  2. УСТАНОВКА NODE.JS 20 LTS
# ============================================================
info "2/8 — Установка Node.js ${NODE_MAJOR}.x ..."

if command -v node &>/dev/null; then
  CURRENT_NODE=$(node -v)
  ok "Node.js уже установлен: ${CURRENT_NODE}"
else
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -yqq nodejs
  ok "Node.js установлен: $(node -v)"
fi

# npm отдельно на всякий случай
if ! command -v npm &>/dev/null; then
  apt-get install -yqq npm
fi
ok "npm: $(npm -v)"

# ============================================================
#  3. УСТАНОВКА POSTGRESQL
# ============================================================
info "3/8 — Установка PostgreSQL..."

if command -v psql &>/dev/null; then
  PG_VER=$(psql --version | awk '{print $3}' | cut -d. -f1)
  ok "PostgreSQL уже установлен (версия ${PG_VER})"
else
  apt-get install -yqq postgresql postgresql-contrib
  ok "PostgreSQL установлен"
fi

# Определяем версию и пути
PG_VER=$(ls /etc/postgresql/ | sort -n | tail -1)
PG_CONF="/etc/postgresql/${PG_VER}/main/postgresql.conf"
PG_HBA="/etc/postgresql/${PG_VER}/main/pg_hba.conf"
info "PostgreSQL ${PG_VER}, конфиг: ${PG_CONF}"

# ============================================================
#  4. НАСТРОЙКА POSTGRESQL (порт + аутентификация)
# ============================================================
info "4/8 — Настройка PostgreSQL (порт ${DB_PORT}, auth)..."

# Порт
sed -i "s/^#\?\s*port\s*=.*/port = ${DB_PORT}/" "$PG_CONF"

# Слушаем только localhost
sed -i "s/^#\?\s*listen_addresses\s*=.*/listen_addresses = 'localhost'/" "$PG_CONF"

# pg_hba.conf — парольная аутентификация для TCP
cp "$PG_HBA" "${PG_HBA}.bak.$(date +%s)"
cat > "$PG_HBA" << 'EOF'
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
EOF
chown postgres:postgres "$PG_HBA"
chmod 640 "$PG_HBA"

ok "Порт ${DB_PORT}, аутентификация scram-sha-256"

# ============================================================
#  5. ЗАПУСК POSTGRESQL + СОЗДАНИЕ БД
# ============================================================
info "5/8 — Запуск PostgreSQL и создание БД..."

systemctl daemon-reload
systemctl enable postgresql
systemctl restart postgresql

# Ждём готовности
for i in $(seq 1 20); do
  if su - postgres -c "pg_isready -h ${DB_HOST} -p ${DB_PORT}" &>/dev/null; then
    break
  fi
  [[ $i -eq 20 ]] && die "PostgreSQL не запустился. Проверьте: journalctl -u postgresql"
  sleep 1
done
ok "PostgreSQL запущен на порту ${DB_PORT}"

# Пароль
su - postgres -c "psql -p ${DB_PORT} -c \"ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';\""
ok "Пароль для ${DB_USER} установлен"

# База данных
DB_EXISTS=$(su - postgres -c "psql -p ${DB_PORT} -tAc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\"")
if [[ "$DB_EXISTS" != "1" ]]; then
  su - postgres -c "psql -p ${DB_PORT} -c \"CREATE DATABASE \\\"${DB_NAME}\\\";\""
  ok "База ${DB_NAME} создана"
else
  ok "База ${DB_NAME} уже существует"
fi

# ============================================================
#  6. СОЗДАНИЕ ТАБЛИЦ
# ============================================================
info "6/8 — Создание таблиц..."

su - postgres -c "psql -p ${DB_PORT} -d \"${DB_NAME}\"" << 'EOSQL'

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    name          TEXT,
    surname       TEXT,
    email         TEXT,
    password      TEXT,
    status        TEXT DEFAULT 'user',
    name_plain    TEXT,
    surname_plain TEXT,
    email_plain   TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id       SERIAL PRIMARY KEY,
    userid   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    entrance INTEGER,
    floor    INTEGER,
    category TEXT DEFAULT 'Уборка',
    status   TEXT DEFAULT 'Оформлено'
);

CREATE INDEX IF NOT EXISTS idx_requests_userid ON requests(userid);
CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);

EOSQL

ok "Таблицы users и requests готовы"

# ============================================================
#  7. NPM-ЗАВИСИМОСТИ ПРОЕКТА
# ============================================================
info "7/8 — Установка npm-зависимостей (express, multer, pg, bcrypt)..."

cd "$PROJECT_DIR"

# Создаём package.json если его нет
if [[ ! -f "package.json" ]]; then
  cat > package.json << 'EOPKG'
{
  "name": "komfort-server",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "start": "node main.js",
    "dev": "node main.js"
  },
  "dependencies": {
    "express": "^4.21.0",
    "cors": "^2.8.5",
    "cookie-parser": "^1.4.6",
    "bcrypt": "^5.1.1",
    "pg": "^8.13.0",
    "multer": "^1.4.5-lts.1"
  }
}
EOPKG
  info "package.json создан"
fi

npm install
ok "Зависимости установлены:"
echo ""
echo "   express       — HTTP-сервер и роутинг"
echo "   cors          — кросс-доменные запросы"
echo "   cookie-parser — чтение cookie"
echo "   bcrypt        — хэширование паролей"
echo "   pg            — клиент PostgreSQL"
echo "   multer        — загрузка файлов (фото/видео)"
echo ""

# ============================================================
#  8. ПРОВЕРКА ВСЕГО
# ============================================================
info "8/8 — Финальная проверка..."

# Папка minidata
mkdir -p "${PROJECT_DIR}/minidata"
ok "Папка minidata: ${PROJECT_DIR}/minidata"

# Проверка подключения Node.js → PostgreSQL
node -e "
const { Pool } = require('pg');
const pool = new Pool({
  host: '${DB_HOST}',
  port: ${DB_PORT},
  database: '${DB_NAME}',
  user: '${DB_USER}',
  password: '${DB_PASS}',
});
pool.query('SELECT version()')
  .then(r => {
    console.log('   PostgreSQL:', r.rows[0].version.split(',')[0]);
    process.exit(0);
  })
  .catch(e => { console.error('   Ошибка:', e.message); process.exit(1); });
" && ok "Node.js → PostgreSQL: подключение работает" \
  || die "Не удалось подключиться к PostgreSQL"

# Проверка что все модули ставятся
node -e "
require('express');
require('cors');
require('cookie-parser');
require('bcrypt');
require('pg');
require('multer');
console.log('   Все модули загружаются корректно');
" && ok "Все npm-модули доступны" \
  || die "Ошибка загрузки модулей"

# ============================================================
#  ИТОГ
# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║            ✅  ВСЁ УСТАНОВЛЕНО И ГОТОВО             ║${NC}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}                                                    ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  Node.js     : $(node -v)                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  npm         : $(npm -v)                            ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  PostgreSQL  : ${PG_VER} (порт ${DB_PORT})                  ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  База данных : ${DB_NAME}                ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  Пароль      : ${DB_PASS}                       ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}                                                    ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  Запуск сервера:                                   ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    node main.js                                    ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}                                                    ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  Или в фоне:                                       ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    npm i -g pm2 && pm2 start main.js --name komfort ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}                                                    ${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""