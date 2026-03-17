'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const bcrypt   = require('bcryptjs');

const DB_PATH = process.env.DB_PATH || './data/granovita.db';
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = FULL');
db.pragma('secure_delete = ON');

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
    image_url   TEXT,
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
    integrity_hash   TEXT    NOT NULL,
    mp_preference_id TEXT,
    mp_payment_id    TEXT,
    mp_status        TEXT,
    shipping_name    TEXT,
    shipping_phone   TEXT,
    shipping_address TEXT,
    notes            TEXT,
    paid_at          DATETIME,
    shipped_at       DATETIME,
    delivered_at     DATETIME,
    created_at       DATETIME DEFAULT (datetime('now')),
    updated_at       DATETIME DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS order_items (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id     INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id   INTEGER NOT NULL REFERENCES products(id),
    product_sku  TEXT    NOT NULL,
    product_name TEXT    NOT NULL,
    unit_price   REAL    NOT NULL,
    quantity     INTEGER NOT NULL CHECK(quantity > 0),
    subtotal     REAL    NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    action     TEXT    NOT NULL,
    entity     TEXT,
    entity_id  INTEGER,
    ip         TEXT,
    user_agent TEXT,
    details    TEXT,
    created_at DATETIME DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS site_sections (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    type     TEXT    NOT NULL,
    label    TEXT    NOT NULL,
    active   INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL DEFAULT 0,
    content  TEXT    NOT NULL DEFAULT '{}'
  );
  CREATE INDEX IF NOT EXISTS idx_orders_user    ON orders(user_id);
  CREATE INDEX IF NOT EXISTS idx_orders_status  ON orders(status);
  CREATE INDEX IF NOT EXISTS idx_orders_mp_pref ON orders(mp_preference_id);
  CREATE INDEX IF NOT EXISTS idx_order_items    ON order_items(order_id);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens ON refresh_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_audit_log      ON audit_log(user_id, created_at);
`);

// Migração segura: adiciona image_url em produtos se não existir
try { db.exec(`ALTER TABLE products ADD COLUMN image_url TEXT`); } catch (_) {}

// ─── Seed: produtos ────────────────────────────────────────────────────────────
const seedProducts = db.prepare(`
  INSERT OR IGNORE INTO products (sku, name, description, price, stock, weight_g)
  VALUES (?, ?, ?, ?, ?, ?)
`);
db.transaction(() => {
  seedProducts.run('GV-CLA-400','Granola Clássica Mel & Castanhas','Aveia tostada com mel puro, castanhas, nozes e amendoim. Sem conservantes.',32.90,100,400);
  seedProducts.run('GV-TRO-400','Granola Tropical Frutas & Coco','Coco ralado, manga desidratada, abacaxi e castanha de caju. Sem açúcar refinado.',35.90,100,400);
  seedProducts.run('GV-DRK-400','Granola Dark Cacau & Avelã','Cacau 70%, avelãs torradas e gotas de chocolate amargo. Proteica e irresistível.',38.90,100,400);
  seedProducts.run('GV-KIT-3X','Kit Família (3 sabores)','Os 3 sabores com 17% de desconto + frete grátis.',89.90,50,1200);
})();

// ─── Seed: seções do site ─────────────────────────────────────────────────────
const hasSections = db.prepare('SELECT COUNT(*) as n FROM site_sections').get().n;
if (hasSections === 0) {
  const ins = db.prepare(`INSERT INTO site_sections (type,label,active,position,content) VALUES (?,?,1,?,?)`);
  db.transaction(() => {
    ins.run('hero','Hero (Topo)',0,JSON.stringify({
      tag:'🌿 100% Natural · Sem conservantes',
      title:'Granola que faz\nseu dia <em>mais gostoso</em>',
      subtitle:'Receitas artesanais com ingredientes selecionados. Sem conservantes, sem corantes — só natureza.',
      cta1_text:'Ver granolas ✦', cta1_url:'#produtos',
      cta2_text:'Kit Família →',  cta2_url:'#kit',
      stat1_num:'+2.400', stat1_label:'Clientes satisfeitos',
      stat2_num:'4.9★',   stat2_label:'Avaliação média',
      stat3_num:'3',       stat3_label:'Sabores exclusivos',
    }));
    ins.run('benefits','Benefícios',1,JSON.stringify({ items:[
      {icon:'🚫',title:'Sem conservantes',   desc:'Ingredientes que você reconhece.'},
      {icon:'🌾',title:'Aveia integral',      desc:'Fibras, vitaminas B e energia duradoura.'},
      {icon:'🚚',title:'Entrega nacional',    desc:'Para todo Brasil em até 7 dias úteis.'},
      {icon:'💳',title:'Pague com segurança', desc:'Pix, cartão ou boleto via Mercado Pago.'},
    ]}));
    ins.run('products','Produtos',2,JSON.stringify({
      tag:'🥣 Nossos sabores',
      title:'Escolha a sua <em>favorita</em>',
      subtitle:'Produzida em pequenos lotes para garantir frescor em cada embalagem.',
    }));
    ins.run('kit','Kit Família',3,JSON.stringify({
      tag:'💝 Melhor custo-benefício',
      title:'O <em>Kit Família</em>\ncom os 3 sabores',
      desc:'Experimente tudo com desconto. Perfeito para a semana toda ou para presentear.',
      items:['Granola Clássica Mel & Castanhas (400g)','Granola Tropical Frutas & Coco (400g)','Granola Dark Cacau & Avelã (400g)','Frete GRÁTIS para todo o Brasil','Embalagem presente com cartão'],
      old_price:'R$ 107,70', new_price:'R$ 89,90', discount:'-17% OFF',
      cta:'Quero o Kit Família 🎁',
    }));
    ins.run('testimonials','Depoimentos',4,JSON.stringify({ items:[
      {stars:5,text:'"Melhor granola que já provei! A crocância é perfeita e o sabor é incrível."',name:'Mariana Costa',location:'São Paulo, SP',avatar:'👩'},
      {stars:5,text:'"Comprei o Kit Família e me apaixonei pela Dark. Chegou fresquíssima!"',name:'Ricardo Alves',location:'Curitiba, PR',avatar:'👨'},
      {stars:5,text:'"Faço pedido todo mês. A Tropical com iogurte é outra dimensão!"',name:'Fernanda Lima',location:'Florianópolis, SC',avatar:'👩‍🦱'},
    ]}));
    ins.run('faq','Perguntas Frequentes',5,JSON.stringify({ items:[
      {q:'A granola tem conservantes?',a:'Não. Sem conservantes, sem corantes artificiais, sem aromatizantes sintéticos.'},
      {q:'Como é feita a entrega?',a:'Enviamos pelos Correios (PAC/SEDEX) para todo o Brasil. Prazo de 3 a 7 dias úteis após confirmação.'},
      {q:'Posso pagar parcelado?',a:'Sim! Cartão em até 3x sem juros, Pix (5% desconto) ou boleto. Processado pelo Mercado Pago.'},
      {q:'Qual é o prazo de validade?',a:'6 meses da fabricação em local fresco e seco. Após abrir, consuma em até 30 dias.'},
    ]}));
    ins.run('newsletter','Newsletter',6,JSON.stringify({
      title:'Ganhe 10% no primeiro pedido',
      subtitle:'Cadastre seu e-mail e receba um cupom exclusivo.',
    }));
  })();
}

// ─── Seed: admin ──────────────────────────────────────────────────────────────
async function ensureAdmin() {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(process.env.ADMIN_EMAIL);
  if (existing) return;
  const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
  db.prepare(`INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'admin')`)
    .run('Administrador', process.env.ADMIN_EMAIL, hash);
  console.log(`[DB] Admin criado: ${process.env.ADMIN_EMAIL}`);
}
ensureAdmin().catch(console.error);

setInterval(() => {
  const d = db.prepare(`DELETE FROM refresh_tokens WHERE expires_at < datetime('now')`).run();
  if (d.changes > 0) console.log(`[DB] ${d.changes} token(s) expirado(s) removido(s)`);
}, 3_600_000);

module.exports = db;
