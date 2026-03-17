'use strict';

const express = require('express');
const { body, param, validationResult } = require('express-validator');

const db = require('../database');
const { requireAuth, requireAdmin }  = require('../middleware/auth');
const { auditLog, sanitizeUser }     = require('../middleware/security');

const router = express.Router();

// Todos os endpoints requerem auth + role admin
router.use(requireAuth, requireAdmin);

// ─── GET /api/admin/dashboard ─────────────────────────────────────────────────
router.get('/dashboard', (req, res) => {
  const stats = {
    orders: db.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'paid'       THEN 1 ELSE 0 END) AS paid,
        SUM(CASE WHEN status = 'shipped'    THEN 1 ELSE 0 END) AS shipped,
        SUM(CASE WHEN status = 'pending' OR status = 'awaiting_payment' THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status = 'cancelled'  THEN 1 ELSE 0 END) AS cancelled,
        SUM(CASE WHEN status = 'paid' OR status = 'shipped' OR status = 'delivered'
            THEN total ELSE 0 END) AS revenue_total,
        SUM(CASE WHEN date(created_at) = date('now') THEN 1 ELSE 0 END) AS today,
        SUM(CASE WHEN created_at >= datetime('now', '-7 days')
            AND (status = 'paid' OR status = 'shipped' OR status = 'delivered')
            THEN total ELSE 0 END) AS revenue_7d
      FROM orders
    `).get(),

    users: db.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN date(created_at) = date('now') THEN 1 ELSE 0 END) AS today,
        SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS last_7d
      FROM users WHERE role = 'customer'
    `).get(),

    products: db.prepare(`
      SELECT COUNT(*) AS total, SUM(stock) AS total_stock,
             SUM(CASE WHEN stock = 0 THEN 1 ELSE 0 END) AS out_of_stock
      FROM products WHERE active = 1
    `).get(),

    recentOrders: db.prepare(`
      SELECT o.id, o.status, o.total, o.created_at,
             u.name AS customer_name, u.email AS customer_email
      FROM orders o JOIN users u ON u.id = o.user_id
      ORDER BY o.created_at DESC LIMIT 10
    `).all(),

    topProducts: db.prepare(`
      SELECT oi.product_name, SUM(oi.quantity) AS qty_sold,
             SUM(oi.subtotal) AS revenue
      FROM order_items oi
      JOIN orders o ON o.id = oi.order_id
      WHERE o.status IN ('paid','shipped','delivered')
      GROUP BY oi.product_sku
      ORDER BY qty_sold DESC LIMIT 5
    `).all(),
  };

  return res.json(stats);
});

// ─── GET /api/admin/orders ────────────────────────────────────────────────────
router.get('/orders', (req, res) => {
  const { status, page = 1, limit = 20, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let where = 'WHERE 1=1';
  const params = [];
  if (status) { where += ' AND o.status = ?'; params.push(status); }
  if (search) {
    where += ' AND (u.name LIKE ? OR u.email LIKE ? OR CAST(o.id AS TEXT) = ?)';
    params.push(`%${search}%`, `%${search}%`, search);
  }

  const orders = db.prepare(`
    SELECT o.id, o.status, o.subtotal, o.shipping_cost, o.total,
           o.mp_payment_id, o.created_at, o.paid_at, o.shipped_at,
           o.shipping_name, o.shipping_address,
           u.name AS customer_name, u.email AS customer_email,
           (SELECT COUNT(*) FROM order_items oi WHERE oi.order_id = o.id) AS item_count
    FROM orders o JOIN users u ON u.id = o.user_id
    ${where}
    ORDER BY o.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), offset);

  const { total_count } = db.prepare(`
    SELECT COUNT(*) AS total_count FROM orders o
    JOIN users u ON u.id = o.user_id ${where}
  `).get(...params);

  return res.json({ orders, total: total_count, page: parseInt(page), limit: parseInt(limit) });
});

// ─── GET /api/admin/orders/:id ────────────────────────────────────────────────
router.get('/orders/:id', (req, res) => {
  const order = db.prepare(`
    SELECT o.*, u.name AS customer_name, u.email AS customer_email
    FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?
  `).get(req.params.id);

  if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });

  const items = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(order.id);
  const { integrity_hash, ...safeOrder } = order;
  return res.json({ ...safeOrder, items });
});

// ─── PATCH /api/admin/orders/:id/status ───────────────────────────────────────
router.patch('/orders/:id/status',
  param('id').isInt(),
  body('status').isIn(['pending','awaiting_payment','paid','processing','shipped','delivered','cancelled','refunded']),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
    if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });

    const { status } = req.body;
    const extra = {};
    if (status === 'shipped') extra.shipped_at = "datetime('now')";
    if (status === 'delivered') extra.delivered_at = "datetime('now')";

    db.prepare(`
      UPDATE orders SET status = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(status, order.id);

    auditLog(req.user.id, 'order_status_updated', req, {
      entity: 'order', entityId: order.id,
      details: { from: order.status, to: status },
    });

    return res.json({ message: 'Status atualizado.', id: order.id, status });
  }
);

// ─── GET /api/admin/users ─────────────────────────────────────────────────────
router.get('/users', (req, res) => {
  const { page = 1, limit = 20, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let where = "WHERE u.role = 'customer'";
  const params = [];
  if (search) {
    where += ' AND (u.name LIKE ? OR u.email LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }

  const users = db.prepare(`
    SELECT u.id, u.name, u.email, u.active, u.created_at,
           COUNT(o.id) AS order_count,
           SUM(CASE WHEN o.status IN ('paid','shipped','delivered') THEN o.total ELSE 0 END) AS total_spent
    FROM users u
    LEFT JOIN orders o ON o.user_id = u.id
    ${where}
    GROUP BY u.id
    ORDER BY u.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), offset);

  const { total_count } = db.prepare(`
    SELECT COUNT(*) AS total_count FROM users u ${where}
  `).get(...params);

  return res.json({ users, total: total_count });
});

// ─── PATCH /api/admin/users/:id/active ───────────────────────────────────────
router.patch('/users/:id/active',
  param('id').isInt(),
  body('active').isBoolean(),
  (req, res) => {
    if (parseInt(req.params.id) === req.user.id) {
      return res.status(400).json({ error: 'Não é possível desativar o próprio usuário.' });
    }
    db.prepare('UPDATE users SET active = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .run(req.body.active ? 1 : 0, req.params.id);

    auditLog(req.user.id, 'user_active_changed', req, {
      entity: 'user', entityId: req.params.id,
      details: { active: req.body.active },
    });

    return res.json({ message: 'Usuário atualizado.' });
  }
);

// ─── GET /api/admin/products ──────────────────────────────────────────────────
router.get('/products', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY created_at DESC').all();
  return res.json(products);
});

// ─── PATCH /api/admin/products/:id/stock ─────────────────────────────────────
router.patch('/products/:id/stock',
  param('id').isInt(),
  body('stock').isInt({ min: 0 }),
  (req, res) => {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });

    db.prepare('UPDATE products SET stock = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .run(req.body.stock, product.id);

    auditLog(req.user.id, 'product_stock_updated', req, {
      entity: 'product', entityId: product.id,
      details: { from: product.stock, to: req.body.stock },
    });

    return res.json({ message: 'Estoque atualizado.', id: product.id, stock: req.body.stock });
  }
);

// ─── PATCH /api/admin/products/:id/price ─────────────────────────────────────
router.patch('/products/:id/price',
  param('id').isInt(),
  body('price').isFloat({ min: 0.01 }),
  (req, res) => {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });

    db.prepare('UPDATE products SET price = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .run(req.body.price, product.id);

    auditLog(req.user.id, 'product_price_updated', req, {
      entity: 'product', entityId: product.id,
      details: { from: product.price, to: req.body.price },
    });

    return res.json({ message: 'Preço atualizado.' });
  }
);

// ─── GET /api/admin/audit-log ─────────────────────────────────────────────────
router.get('/audit-log', (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const logs = db.prepare(`
    SELECT al.*, u.name AS user_name, u.email AS user_email
    FROM audit_log al
    LEFT JOIN users u ON u.id = al.user_id
    ORDER BY al.created_at DESC
    LIMIT ? OFFSET ?
  `).all(parseInt(limit), offset);

  return res.json(logs);
});

module.exports = router;

// ─── POST /api/admin/products ── Criar produto ────────────────────────────────
router.post('/products',
  body('sku').trim().isLength({ min: 2, max: 30 }).withMessage('SKU inválido.'),
  body('name').trim().isLength({ min: 2, max: 120 }).withMessage('Nome inválido.'),
  body('description').trim().isLength({ min: 2 }).withMessage('Descrição inválida.'),
  body('price').isFloat({ min: 0.01 }).withMessage('Preço inválido.'),
  body('stock').isInt({ min: 0 }).withMessage('Estoque inválido.'),
  body('weight_g').isInt({ min: 1 }).withMessage('Peso inválido.'),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array().map(e => e.msg) });

    const { sku, name, description, price, stock, weight_g } = req.body;

    const existing = db.prepare('SELECT id FROM products WHERE sku = ?').get(sku.toUpperCase());
    if (existing) return res.status(409).json({ error: 'Já existe um produto com este SKU.' });

    const result = db.prepare(`
      INSERT INTO products (sku, name, description, price, stock, weight_g)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sku.toUpperCase(), name, description, price, stock, weight_g);

    auditLog(req.user.id, 'product_created', req, {
      entity: 'product', entityId: result.lastInsertRowid,
      details: { sku, name, price },
    });

    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(result.lastInsertRowid);
    return res.status(201).json(product);
  }
);

// ─── PUT /api/admin/products/:id ── Editar produto completo ──────────────────
router.put('/products/:id',
  param('id').isInt(),
  body('name').trim().isLength({ min: 2, max: 120 }),
  body('description').trim().isLength({ min: 2 }),
  body('price').isFloat({ min: 0.01 }),
  body('stock').isInt({ min: 0 }),
  body('weight_g').isInt({ min: 1 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array().map(e => e.msg) });

    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });

    const { name, description, price, stock, weight_g } = req.body;

    db.prepare(`
      UPDATE products
      SET name = ?, description = ?, price = ?, stock = ?, weight_g = ?, image_url = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(name, description, price, stock, weight_g, req.body.image_url || null, product.id);

    auditLog(req.user.id, 'product_updated', req, {
      entity: 'product', entityId: product.id,
      details: { before: { name: product.name, price: product.price, stock: product.stock }, after: { name, price, stock } },
    });

    const updated = db.prepare('SELECT * FROM products WHERE id = ?').get(product.id);
    return res.json(updated);
  }
);

// ─── PATCH /api/admin/products/:id/active ── Ativar/Arquivar ─────────────────
router.patch('/products/:id/active',
  param('id').isInt(),
  body('active').isBoolean(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array().map(e => e.msg) });

    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });

    db.prepare(`UPDATE products SET active = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(req.body.active ? 1 : 0, product.id);

    auditLog(req.user.id, 'product_active_changed', req, {
      entity: 'product', entityId: product.id,
      details: { active: req.body.active },
    });

    return res.json({ message: req.body.active ? 'Produto ativado.' : 'Produto arquivado.', id: product.id });
  }
);

// ═══════════════════════════════════════════════════════════
//  SECTIONS CRUD
// ═══════════════════════════════════════════════════════════

// GET /api/admin/sections — todas as seções (ativas e inativas)
router.get('/sections', (req, res) => {
  const sections = db.prepare(`
    SELECT * FROM site_sections ORDER BY position ASC
  `).all().map(s => ({ ...s, content: JSON.parse(s.content || '{}') }));
  return res.json(sections);
});

// PATCH /api/admin/sections/:id/active — ativar/desativar seção
router.patch('/sections/:id/active',
  param('id').isInt(),
  body('active').isBoolean(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ error: 'Dados inválidos.' });

    const section = db.prepare('SELECT * FROM site_sections WHERE id = ?').get(req.params.id);
    if (!section) return res.status(404).json({ error: 'Seção não encontrada.' });

    db.prepare('UPDATE site_sections SET active = ? WHERE id = ?')
      .run(req.body.active ? 1 : 0, section.id);

    auditLog(req.user.id, 'section_active_changed', req, {
      entity: 'section', entityId: section.id,
      details: { label: section.label, active: req.body.active },
    });
    return res.json({ message: 'Seção atualizada.' });
  }
);

// PATCH /api/admin/sections/:id/position — reordenar seção
router.patch('/sections/:id/position',
  param('id').isInt(),
  body('direction').isIn(['up', 'down']),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ error: 'Dados inválidos.' });

    const all = db.prepare('SELECT * FROM site_sections ORDER BY position ASC').all();
    const idx = all.findIndex(s => s.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'Seção não encontrada.' });

    const swapIdx = req.body.direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= all.length)
      return res.status(400).json({ error: 'Não é possível mover nessa direção.' });

    const swap = db.transaction(() => {
      db.prepare('UPDATE site_sections SET position = ? WHERE id = ?')
        .run(all[swapIdx].position, all[idx].id);
      db.prepare('UPDATE site_sections SET position = ? WHERE id = ?')
        .run(all[idx].position, all[swapIdx].id);
    });
    swap();

    auditLog(req.user.id, 'section_reordered', req, {
      entity: 'section', entityId: all[idx].id,
    });
    return res.json({ message: 'Ordem atualizada.' });
  }
);

// PUT /api/admin/sections/:id/content — edita conteúdo de uma seção
router.put('/sections/:id/content',
  param('id').isInt(),
  body('content').isObject(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ error: 'Dados inválidos.' });

    const section = db.prepare('SELECT * FROM site_sections WHERE id = ?').get(req.params.id);
    if (!section) return res.status(404).json({ error: 'Seção não encontrada.' });

    db.prepare('UPDATE site_sections SET content = ? WHERE id = ?')
      .run(JSON.stringify(req.body.content), section.id);

    auditLog(req.user.id, 'section_content_updated', req, {
      entity: 'section', entityId: section.id,
      details: { label: section.label },
    });
    return res.json({ message: 'Conteúdo salvo.' });
  }
);

// POST /api/admin/sections — cria seção personalizada (tipo banner)
router.post('/sections',
  body('label').trim().isLength({ min: 2 }),
  body('type').isIn(['banner', 'custom_text']),
  body('content').isObject(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array().map(e => e.msg) });

    const maxPos = db.prepare('SELECT MAX(position) as m FROM site_sections').get().m || 0;
    const result = db.prepare(`
      INSERT INTO site_sections (type, label, active, position, content)
      VALUES (?, ?, 1, ?, ?)
    `).run(req.body.type, req.body.label, maxPos + 1, JSON.stringify(req.body.content));

    auditLog(req.user.id, 'section_created', req, {
      entity: 'section', entityId: result.lastInsertRowid,
    });
    return res.status(201).json(
      db.prepare('SELECT * FROM site_sections WHERE id = ?').get(result.lastInsertRowid)
    );
  }
);

// DELETE /api/admin/sections/:id — remove seções personalizadas (banner/custom_text)
router.delete('/sections/:id',
  param('id').isInt(),
  (req, res) => {
    const section = db.prepare('SELECT * FROM site_sections WHERE id = ?').get(req.params.id);
    if (!section) return res.status(404).json({ error: 'Seção não encontrada.' });
    if (!['banner','custom_text'].includes(section.type))
      return res.status(400).json({ error: 'Seções padrão não podem ser excluídas, apenas desativadas.' });

    db.prepare('DELETE FROM site_sections WHERE id = ?').run(section.id);
    auditLog(req.user.id, 'section_deleted', req, {
      entity: 'section', entityId: section.id, details: { label: section.label },
    });
    return res.json({ message: 'Seção removida.' });
  }
);

// ─── Produto com imagem (image_url já é salvo pelo PUT /products/:id) ─────────

// ═══════════════════════════════════════════════════════════
//  STORE SETTINGS
// ═══════════════════════════════════════════════════════════

// GET /api/admin/settings
router.get('/settings', (req, res) => {
  const rows = db.prepare('SELECT key, value FROM store_settings').all();
  return res.json(Object.fromEntries(rows.map(r => [r.key, r.value])));
});

// PUT /api/admin/settings  — salva múltiplos campos de uma vez
router.put('/settings',
  body('settings').isObject(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ error: 'Dados inválidos.' });

    const ALLOWED = [
      'store_name','store_tagline','store_email','store_phone','store_whatsapp',
      'store_cnpj','store_instagram','store_facebook','hero_image_url',
      'cloudinary_cloud','cloudinary_preset','footer_address',
      'meta_pixel_id','gtm_id',
    ];

    const upsert = db.prepare(`
      INSERT INTO store_settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);

    const save = db.transaction(() => {
      for (const [key, value] of Object.entries(req.body.settings)) {
        if (ALLOWED.includes(key)) upsert.run(key, String(value));
      }
    });
    save();

    auditLog(req.user.id, 'settings_updated', req, {
      details: { keys: Object.keys(req.body.settings) },
    });

    return res.json({ message: 'Configurações salvas.' });
  }
);

// ─── Produto com imagem (image_url já é salvo pelo PUT /products/:id) ─────────
// GET /api/admin/products — já retorna image_url do schema atualizado

module.exports = router;
