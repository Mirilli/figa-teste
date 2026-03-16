'use strict';

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH || './data/granovita.db';

// Garante que o diretório existe
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH, {
  // WAL mode: leituras não bloqueiam escritas
  verbose: process.env.NODE_ENV === 'development' ? null : null,
});

// ─── Pragmas de segurança e performance ───────────────────────────────────────
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = FULL');  // Garante durabilidade dos dados
db.pragma('secure_delete = ON');  // Apaga dados fisicamente ao deletar

// ─── Schema ───────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    email         TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    DATETIME DEFAULT (datetime('now')),
    updated_at    DATETIME DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT    NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    ip         TEXT,
    created_at DATETIME DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sku         TEXT    UNIQUE NOT NULL,
    name        TEXT    NOT NULL,
    description TEXT,
    price       REAL    NOT NULL CHECK(price > 0),
    stock       INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
    weight_g    INTEGER NOT NULL DEFAULT 400,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME DEFAULT (datetime('now')),
    updated_at  DATETIME DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS orders (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    status           TEXT    NOT NULL DEFAULT 'pending'
                     CHECK(status IN ('pending','awaiting_payment','paid','processing',
                                      'shipped','delivered','cancelled','refunded')),
    subtotal         REAL    NOT NULL,
    shipping_cost    REAL    NOT NULL DEFAULT 0,
    total            REAL    NOT NULL,
    -- HMAC-SHA256 dos itens + preços + user_id — impede adulteração entre criação e pagamento
    integrity_hash   TEXT    NOT NULL,
    mp_preference_id TEXT,
    mp_payment_id    TEXT,
    mp_status        TEXT,
    shipping_name    TEXT,
    shipping_phone   TEXT,
    shipping_address TEXT,   -- JSON com logradouro, numero, bairro, cidade, estado, cep
    notes            TEXT,
    paid_at          DATETIME,
    shipped_at       DATETIME,
    delivered_at     DATETIME,
    created_at       DATETIME DEFAULT (datetime('now')),
    updated_at       DATETIME DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id    INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id  INTEGER NOT NULL REFERENCES products(id),
    product_sku TEXT    NOT NULL,  -- snapshot para histórico
    product_name TEXT   NOT NULL,  -- snapshot para histórico
    unit_price  REAL    NOT NULL,  -- preço NO MOMENTO da compra (imutável)
    quantity    INTEGER NOT NULL CHECK(quantity > 0),
    subtotal    REAL    NOT NULL   -- unit_price * quantity (calculado e armazenado)
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    action     TEXT    NOT NULL,
    entity     TEXT,
    entity_id  INTEGER,
    ip         TEXT,
    user_agent TEXT,
    details    TEXT,   -- JSON com contexto adicional
    created_at DATETIME DEFAULT (datetime('now'))
  );

  -- Índices para queries comuns
  CREATE INDEX IF NOT EXISTS idx_orders_user    ON orders(user_id);
  CREATE INDEX IF NOT EXISTS idx_orders_status  ON orders(status);
  CREATE INDEX IF NOT EXISTS idx_orders_mp_pref ON orders(mp_preference_id);
  CREATE INDEX IF NOT EXISTS idx_order_items    ON order_items(order_id);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens ON refresh_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_audit_log      ON audit_log(user_id, created_at);
`);

// ─── Seed: produtos padrão ─────────────────────────────────────────────────
const seedProducts = db.prepare(`
  INSERT OR IGNORE INTO products (sku, name, description, price, stock, weight_g)
  VALUES (?, ?, ?, ?, ?, ?)
`);

const seedAll = db.transaction(() => {
  seedProducts.run('GV-CLA-400', 'Granola Clássica Mel & Castanhas',
    'Aveia tostada com mel puro, castanhas, nozes e amendoim. Sem conservantes.', 32.90, 100, 400);
  seedProducts.run('GV-TRO-400', 'Granola Tropical Frutas & Coco',
    'Coco ralado, manga desidratada, abacaxi e castanha de caju. Sem açúcar refinado.', 35.90, 100, 400);
  seedProducts.run('GV-DRK-400', 'Granola Dark Cacau & Avelã',
    'Cacau 70%, avelãs torradas e gotas de chocolate amargo. Proteica e irresistível.', 38.90, 100, 400);
  seedProducts.run('GV-KIT-3X', 'Kit Família (3 sabores)',
    'Os 3 sabores com 17% de desconto + frete grátis.', 89.90, 50, 1200);
});

seedAll();

// ─── Seed: admin inicial ───────────────────────────────────────────────────
async function ensureAdmin() {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?')
    .get(process.env.ADMIN_EMAIL);
  if (existing) return;

  const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
  db.prepare(`
    INSERT INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, 'admin')
  `).run('Administrador', process.env.ADMIN_EMAIL, hash);

  console.log(`[DB] Admin criado: ${process.env.ADMIN_EMAIL}`);
}

ensureAdmin().catch(console.error);

// ─── Limpeza automática de tokens expirados (a cada 1h) ──────────────────
setInterval(() => {
  const deleted = db.prepare(
    `DELETE FROM refresh_tokens WHERE expires_at < datetime('now')`
  ).run();
  if (deleted.changes > 0)
    console.log(`[DB] ${deleted.changes} refresh token(s) expirado(s) removido(s)`);
}, 3_600_000);

module.exports = db;
