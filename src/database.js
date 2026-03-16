'use strict';

const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on('error', (err) => console.error('[DB] Pool error:', err.message));

async function query(text, params) {
  try {
    return await pool.query(text, params);
  } catch (err) {
    console.error('[DB] Query error:', err.message, '\n→', text.slice(0, 120));
    throw err;
  }
}

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function migrate() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      name          TEXT        NOT NULL,
      email         TEXT        UNIQUE NOT NULL,
      password_hash TEXT        NOT NULL,
      role          TEXT        NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin')),
      active        BOOLEAN     NOT NULL DEFAULT TRUE,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT        NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      ip         TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS products (
      id          SERIAL PRIMARY KEY,
      sku         TEXT           UNIQUE NOT NULL,
      name        TEXT           NOT NULL,
      description TEXT,
      price       NUMERIC(10,2)  NOT NULL CHECK(price > 0),
      stock       INTEGER        NOT NULL DEFAULT 0 CHECK(stock >= 0),
      weight_g    INTEGER        NOT NULL DEFAULT 400,
      active      BOOLEAN        NOT NULL DEFAULT TRUE,
      created_at  TIMESTAMPTZ    DEFAULT NOW(),
      updated_at  TIMESTAMPTZ    DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orders (
      id               SERIAL PRIMARY KEY,
      user_id          INTEGER        NOT NULL REFERENCES users(id),
      status           TEXT           NOT NULL DEFAULT 'pending'
                       CHECK(status IN ('pending','awaiting_payment','paid','processing',
                                        'shipped','delivered','cancelled','refunded')),
      subtotal         NUMERIC(10,2)  NOT NULL,
      shipping_cost    NUMERIC(10,2)  NOT NULL DEFAULT 0,
      total            NUMERIC(10,2)  NOT NULL,
      integrity_hash   TEXT           NOT NULL,
      mp_preference_id TEXT,
      mp_payment_id    TEXT,
      mp_status        TEXT,
      shipping_name    TEXT,
      shipping_phone   TEXT,
      shipping_address JSONB,
      notes            TEXT,
      paid_at          TIMESTAMPTZ,
      shipped_at       TIMESTAMPTZ,
      delivered_at     TIMESTAMPTZ,
      created_at       TIMESTAMPTZ    DEFAULT NOW(),
      updated_at       TIMESTAMPTZ    DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS order_items (
      id           SERIAL PRIMARY KEY,
      order_id     INTEGER       NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      product_id   INTEGER       NOT NULL REFERENCES products(id),
      product_sku  TEXT          NOT NULL,
      product_name TEXT          NOT NULL,
      unit_price   NUMERIC(10,2) NOT NULL,
      quantity     INTEGER       NOT NULL CHECK(quantity > 0),
      subtotal     NUMERIC(10,2) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER     REFERENCES users(id),
      action     TEXT        NOT NULL,
      entity     TEXT,
      entity_id  INTEGER,
      ip         TEXT,
      user_agent TEXT,
      details    JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_orders_user    ON orders(user_id);
    CREATE INDEX IF NOT EXISTS idx_orders_status  ON orders(status);
    CREATE INDEX IF NOT EXISTS idx_orders_mp_pref ON orders(mp_preference_id);
    CREATE INDEX IF NOT EXISTS idx_order_items    ON order_items(order_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens ON refresh_tokens(token_hash);
    CREATE INDEX IF NOT EXISTS idx_audit_log      ON audit_log(user_id, created_at);
  `);
  console.log('[DB] Migração concluída.');
}

async function seedProducts() {
  const products = [
    ['GV-CLA-400', 'Granola Clássica Mel & Castanhas',  'Aveia tostada com mel puro, castanhas, nozes e amendoim. Sem conservantes.', 32.90, 100, 400],
    ['GV-TRO-400', 'Granola Tropical Frutas & Coco',    'Coco ralado, manga desidratada, abacaxi e castanha de caju. Sem açúcar refinado.', 35.90, 100, 400],
    ['GV-DRK-400', 'Granola Dark Cacau & Avelã',        'Cacau 70%, avelãs torradas e gotas de chocolate amargo. Proteica e irresistível.', 38.90, 100, 400],
    ['GV-KIT-3X',  'Kit Família (3 sabores)',            'Os 3 sabores com 17% de desconto + frete grátis.', 89.90, 50, 1200],
  ];
  for (const [sku, name, desc, price, stock, weight] of products) {
    await query(
      `INSERT INTO products (sku, name, description, price, stock, weight_g)
       VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (sku) DO NOTHING`,
      [sku, name, desc, price, stock, weight]
    );
  }
}

async function seedAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;
  const exists = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
  if (exists.rows.length > 0) return;
  const hash = await bcrypt.hash(password, 12);
  await query(
    `INSERT INTO users (name, email, password_hash, role) VALUES ($1,$2,$3,'admin')`,
    ['Administrador', email.toLowerCase(), hash]
  );
  console.log(`[DB] Admin criado: ${email}`);
}

setInterval(async () => {
  try {
    const r = await query(`DELETE FROM refresh_tokens WHERE expires_at < NOW()`);
    if (r.rowCount > 0) console.log(`[DB] ${r.rowCount} token(s) expirado(s) removido(s)`);
  } catch (e) { console.error('[DB] Limpeza error:', e.message); }
}, 3_600_000);

async function init() {
  await query('SELECT 1');
  console.log('[DB] Conectado ao PostgreSQL.');
  await migrate();
  await seedProducts();
  await seedAdmin();
}

module.exports = { pool, query, withTransaction, init };
