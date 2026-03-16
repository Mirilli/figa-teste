'use strict';

const express = require('express');
const { body, param, validationResult } = require('express-validator');

const { query }                           = require('../database');
const { requireAuth, requireAdmin }       = require('../middleware/auth');
const { auditLog }                        = require('../middleware/security');

const router = express.Router();
router.use(requireAuth, requireAdmin);

// ── GET /api/admin/dashboard ──────────────────────────────────────────────────
router.get('/dashboard', async (req, res) => {
  const [orders, users, products, recentOrders, topProducts] = await Promise.all([
    query(`
      SELECT
        COUNT(*)::int                                               AS total,
        SUM(CASE WHEN status='paid'    THEN 1 ELSE 0 END)::int     AS paid,
        SUM(CASE WHEN status='shipped' THEN 1 ELSE 0 END)::int     AS shipped,
        SUM(CASE WHEN status IN ('pending','awaiting_payment') THEN 1 ELSE 0 END)::int AS pending,
        SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END)::int   AS cancelled,
        SUM(CASE WHEN status IN ('paid','shipped','delivered') THEN total ELSE 0 END)::float AS revenue_total,
        SUM(CASE WHEN created_at::date = CURRENT_DATE THEN 1 ELSE 0 END)::int AS today,
        SUM(CASE WHEN created_at >= NOW()-INTERVAL '7 days'
                  AND status IN ('paid','shipped','delivered') THEN total ELSE 0 END)::float AS revenue_7d
      FROM orders`),
    query(`
      SELECT COUNT(*)::int AS total,
             SUM(CASE WHEN created_at::date=CURRENT_DATE THEN 1 ELSE 0 END)::int AS today,
             SUM(CASE WHEN created_at >= NOW()-INTERVAL '7 days' THEN 1 ELSE 0 END)::int AS last_7d
      FROM users WHERE role='customer'`),
    query(`
      SELECT COUNT(*)::int AS total, COALESCE(SUM(stock),0)::int AS total_stock,
             SUM(CASE WHEN stock=0 THEN 1 ELSE 0 END)::int AS out_of_stock
      FROM products WHERE active=TRUE`),
    query(`
      SELECT o.id, o.status, o.total::float, o.created_at,
             u.name AS customer_name, u.email AS customer_email
      FROM orders o JOIN users u ON u.id=o.user_id
      ORDER BY o.created_at DESC LIMIT 10`),
    query(`
      SELECT oi.product_name, SUM(oi.quantity)::int AS qty_sold,
             SUM(oi.subtotal)::float AS revenue
      FROM order_items oi
      JOIN orders o ON o.id=oi.order_id
      WHERE o.status IN ('paid','shipped','delivered')
      GROUP BY oi.product_sku, oi.product_name
      ORDER BY qty_sold DESC LIMIT 5`),
  ]);

  return res.json({
    orders: orders.rows[0],
    users: users.rows[0],
    products: products.rows[0],
    recentOrders: recentOrders.rows,
    topProducts: topProducts.rows,
  });
});

// ── GET /api/admin/orders ─────────────────────────────────────────────────────
router.get('/orders', async (req, res) => {
  const { status, page = 1, limit = 20, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const conditions = ['1=1'];
  const params = [];
  if (status)  { params.push(status);               conditions.push(`o.status = $${params.length}`); }
  if (search)  { params.push(`%${search}%`, `%${search}%`, search);
    conditions.push(`(u.name ILIKE $${params.length-2} OR u.email ILIKE $${params.length-1} OR o.id::text = $${params.length})`); }

  const where = conditions.join(' AND ');
  params.push(parseInt(limit), offset);

  const [rows, countRow] = await Promise.all([
    query(
      `SELECT o.id, o.status, o.subtotal::float, o.shipping_cost::float, o.total::float,
              o.mp_payment_id, o.created_at, o.paid_at, o.shipped_at,
              o.shipping_name, o.shipping_address,
              u.name AS customer_name, u.email AS customer_email,
              (SELECT COUNT(*)::int FROM order_items oi WHERE oi.order_id=o.id) AS item_count
       FROM orders o JOIN users u ON u.id=o.user_id
       WHERE ${where}
       ORDER BY o.created_at DESC
       LIMIT $${params.length-1} OFFSET $${params.length}`,
      params
    ),
    query(
      `SELECT COUNT(*)::int AS total FROM orders o JOIN users u ON u.id=o.user_id WHERE ${where}`,
      params.slice(0, -2)
    ),
  ]);

  return res.json({ orders: rows.rows, total: countRow.rows[0].total, page: parseInt(page), limit: parseInt(limit) });
});

// ── GET /api/admin/orders/:id ─────────────────────────────────────────────────
router.get('/orders/:id', async (req, res) => {
  const r = await query(
    `SELECT o.*, u.name AS customer_name, u.email AS customer_email
     FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=$1`,
    [req.params.id]
  );
  if (!r.rows.length) return res.status(404).json({ error: 'Pedido não encontrado.' });
  const items = await query('SELECT * FROM order_items WHERE order_id=$1', [r.rows[0].id]);
  const { integrity_hash, ...safeOrder } = r.rows[0];
  return res.json({ ...safeOrder, items: items.rows });
});

// ── PATCH /api/admin/orders/:id/status ────────────────────────────────────────
router.patch('/orders/:id/status',
  param('id').isInt(),
  body('status').isIn(['pending','awaiting_payment','paid','processing','shipped','delivered','cancelled','refunded']),
  async (req, res) => {
    if (!validationResult(req).isEmpty()) return res.status(422).json({ error: 'Dados inválidos.' });
    const orderRes = await query('SELECT status FROM orders WHERE id=$1', [req.params.id]);
    if (!orderRes.rows.length) return res.status(404).json({ error: 'Pedido não encontrado.' });

    const { status } = req.body;
    await query(
      `UPDATE orders SET status=$1,
         shipped_at  = CASE WHEN $1='shipped'   THEN NOW() ELSE shipped_at  END,
         delivered_at= CASE WHEN $1='delivered' THEN NOW() ELSE delivered_at END,
         updated_at  = NOW()
       WHERE id=$2`,
      [status, req.params.id]
    );
    await auditLog(req.user.id, 'order_status_updated', req, {
      entity: 'order', entityId: parseInt(req.params.id),
      details: { from: orderRes.rows[0].status, to: status },
    });
    return res.json({ message: 'Status atualizado.', id: parseInt(req.params.id), status });
  }
);

// ── GET /api/admin/users ──────────────────────────────────────────────────────
router.get('/users', async (req, res) => {
  const { page = 1, limit = 20, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const conditions = ["u.role='customer'"];
  const params = [];
  if (search) {
    params.push(`%${search}%`, `%${search}%`);
    conditions.push(`(u.name ILIKE $${params.length-1} OR u.email ILIKE $${params.length})`);
  }
  const where = conditions.join(' AND ');
  params.push(parseInt(limit), offset);

  const [rows, countRow] = await Promise.all([
    query(
      `SELECT u.id, u.name, u.email, u.active, u.created_at,
              COUNT(o.id)::int AS order_count,
              COALESCE(SUM(CASE WHEN o.status IN ('paid','shipped','delivered') THEN o.total ELSE 0 END),0)::float AS total_spent
       FROM users u LEFT JOIN orders o ON o.user_id=u.id
       WHERE ${where}
       GROUP BY u.id ORDER BY u.created_at DESC
       LIMIT $${params.length-1} OFFSET $${params.length}`,
      params
    ),
    query(`SELECT COUNT(*)::int AS total FROM users u WHERE ${where}`, params.slice(0,-2)),
  ]);
  return res.json({ users: rows.rows, total: countRow.rows[0].total });
});

// ── PATCH /api/admin/users/:id/active ────────────────────────────────────────
router.patch('/users/:id/active', param('id').isInt(), body('active').isBoolean(), async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Não é possível desativar o próprio usuário.' });
  await query('UPDATE users SET active=$1, updated_at=NOW() WHERE id=$2', [req.body.active, req.params.id]);
  await auditLog(req.user.id, 'user_active_changed', req, {
    entity: 'user', entityId: parseInt(req.params.id), details: { active: req.body.active },
  });
  return res.json({ message: 'Usuário atualizado.' });
});

// ── GET /api/admin/products ───────────────────────────────────────────────────
router.get('/products', async (req, res) => {
  const r = await query('SELECT * FROM products ORDER BY created_at DESC');
  return res.json(r.rows);
});

// ── PATCH /api/admin/products/:id/stock ──────────────────────────────────────
router.patch('/products/:id/stock', param('id').isInt(), body('stock').isInt({ min: 0 }), async (req, res) => {
  const p = await query('SELECT * FROM products WHERE id=$1', [req.params.id]);
  if (!p.rows.length) return res.status(404).json({ error: 'Produto não encontrado.' });
  await query('UPDATE products SET stock=$1, updated_at=NOW() WHERE id=$2', [req.body.stock, req.params.id]);
  await auditLog(req.user.id, 'product_stock_updated', req, {
    entity: 'product', entityId: parseInt(req.params.id),
    details: { from: p.rows[0].stock, to: req.body.stock },
  });
  return res.json({ message: 'Estoque atualizado.' });
});

// ── PATCH /api/admin/products/:id/price ──────────────────────────────────────
router.patch('/products/:id/price', param('id').isInt(), body('price').isFloat({ min: 0.01 }), async (req, res) => {
  const p = await query('SELECT * FROM products WHERE id=$1', [req.params.id]);
  if (!p.rows.length) return res.status(404).json({ error: 'Produto não encontrado.' });
  await query('UPDATE products SET price=$1, updated_at=NOW() WHERE id=$2', [req.body.price, req.params.id]);
  await auditLog(req.user.id, 'product_price_updated', req, {
    entity: 'product', entityId: parseInt(req.params.id),
    details: { from: parseFloat(p.rows[0].price), to: req.body.price },
  });
  return res.json({ message: 'Preço atualizado.' });
});

// ── GET /api/admin/audit-log ──────────────────────────────────────────────────
router.get('/audit-log', async (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const r = await query(
    `SELECT al.*, u.name AS user_name, u.email AS user_email
     FROM audit_log al LEFT JOIN users u ON u.id=al.user_id
     ORDER BY al.created_at DESC
     LIMIT $1 OFFSET $2`,
    [parseInt(limit), offset]
  );
  return res.json(r.rows);
});

module.exports = router;
