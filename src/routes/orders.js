'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');

const { query, withTransaction }             = require('../database');
const { requireAuth }                        = require('../middleware/auth');
const { generateOrderHash, auditLog }        = require('../middleware/security');

const router = express.Router();

const SHIPPING_COST       = parseFloat(process.env.SHIPPING_COST) || 15.90;
const FREE_SHIPPING_LIMIT = parseFloat(process.env.FREE_SHIPPING_THRESHOLD) || 100;

// ── GET /api/orders ───────────────────────────────────────────────────────────
router.get('/', requireAuth, async (req, res) => {
  const result = await query(
    `SELECT o.id, o.status, o.subtotal::float, o.shipping_cost::float, o.total::float,
            o.mp_payment_id, o.paid_at, o.shipped_at, o.delivered_at, o.created_at,
            COALESCE(
              json_agg(json_build_object(
                'name', oi.product_name, 'sku', oi.product_sku,
                'qty', oi.quantity, 'unit_price', oi.unit_price::float,
                'subtotal', oi.subtotal::float
              )) FILTER (WHERE oi.id IS NOT NULL),
              '[]'
            ) AS items
     FROM orders o
     LEFT JOIN order_items oi ON oi.order_id = o.id
     WHERE o.user_id = $1
     GROUP BY o.id
     ORDER BY o.created_at DESC
     LIMIT 50`,
    [req.user.id]
  );
  return res.json(result.rows);
});

// ── GET /api/orders/:id ───────────────────────────────────────────────────────
router.get('/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'ID inválido.' });

  const orderRes = await query(
    `SELECT o.*, u.name AS customer_name, u.email AS customer_email
     FROM orders o JOIN users u ON u.id = o.user_id
     WHERE o.id = $1 AND (o.user_id = $2 OR $3 = 'admin')`,
    [id, req.user.id, req.user.role]
  );
  if (!orderRes.rows.length) return res.status(404).json({ error: 'Pedido não encontrado.' });

  const order = orderRes.rows[0];
  const itemsRes = await query('SELECT * FROM order_items WHERE order_id = $1', [order.id]);
  const { integrity_hash, ...safeOrder } = order;
  return res.json({ ...safeOrder, items: itemsRes.rows });
});

// ── POST /api/orders ──────────────────────────────────────────────────────────
router.post('/',
  requireAuth,
  [
    body('items').isArray({ min: 1 }),
    body('items.*.productId').isInt({ min: 1 }),
    body('items.*.quantity').isInt({ min: 1, max: 20 }),
    body('shipping').isObject(),
    body('shipping.name').trim().isLength({ min: 2 }),
    body('shipping.phone').trim().isLength({ min: 8 }),
    body('shipping.address').trim().isLength({ min: 5 }),
    body('shipping.city').trim().isLength({ min: 2 }),
    body('shipping.state').trim().isLength({ min: 2 }),
    body('shipping.zip').trim().matches(/^\d{5}-?\d{3}$/),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array().map(e => e.msg) });

    const { items: requestedItems, shipping } = req.body;

    try {
      const orderId = await withTransaction(async (client) => {
        // 1. Valida produtos e estoque
        const enriched = [];
        for (const item of requestedItems) {
          const pRes = await client.query(
            'SELECT * FROM products WHERE id = $1 AND active = TRUE', [item.productId]
          );
          const product = pRes.rows[0];
          if (!product) throw Object.assign(new Error(`Produto ID ${item.productId} não encontrado.`), { status: 400 });
          if (product.stock < item.quantity) throw Object.assign(
            new Error(`Estoque insuficiente para "${product.name}". Disponível: ${product.stock}.`), { status: 409 }
          );
          enriched.push({
            productId: product.id, productSku: product.sku, productName: product.name,
            unitPrice: parseFloat(product.price),
            quantity: item.quantity,
            subtotal: +(parseFloat(product.price) * item.quantity).toFixed(2),
          });
        }

        // 2. Calcula totais (no servidor)
        const subtotal     = +enriched.reduce((s, i) => s + i.subtotal, 0).toFixed(2);
        const shippingCost = subtotal >= FREE_SHIPPING_LIMIT ? 0 : SHIPPING_COST;
        const total        = +(subtotal + shippingCost).toFixed(2);

        // 3. Decrementa estoque atomicamente
        for (const item of enriched) {
          const upd = await client.query(
            'UPDATE products SET stock = stock - $1 WHERE id = $2 AND stock >= $1 RETURNING id',
            [item.quantity, item.productId]
          );
          if (!upd.rows.length) throw Object.assign(new Error(`Estoque insuficiente para produto ID ${item.productId}.`), { status: 409 });
        }

        // 4. Gera hash de integridade
        const integrityHash = generateOrderHash({
          userId: req.user.id,
          items: enriched.map(i => ({ productId: i.productId, quantity: i.quantity, unitPrice: i.unitPrice })),
          total,
        });

        // 5. Insere pedido
        const orderRes = await client.query(
          `INSERT INTO orders
             (user_id, status, subtotal, shipping_cost, total, integrity_hash,
              shipping_name, shipping_phone, shipping_address)
           VALUES ($1,'awaiting_payment',$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
          [
            req.user.id, subtotal, shippingCost, total, integrityHash,
            shipping.name, shipping.phone,
            JSON.stringify({ address: shipping.address, number: shipping.number||'',
              complement: shipping.complement||'', city: shipping.city,
              state: shipping.state, zip: shipping.zip }),
          ]
        );
        const newOrderId = orderRes.rows[0].id;

        // 6. Insere itens
        for (const item of enriched) {
          await client.query(
            `INSERT INTO order_items
               (order_id, product_id, product_sku, product_name, unit_price, quantity, subtotal)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [newOrderId, item.productId, item.productSku, item.productName,
             item.unitPrice, item.quantity, item.subtotal]
          );
        }
        return newOrderId;
      });

      await auditLog(req.user.id, 'order_created', req, { entity: 'order', entityId: orderId });

      // Busca totais para retornar
      const oRes = await query('SELECT subtotal::float, shipping_cost::float, total::float FROM orders WHERE id = $1', [orderId]);
      const o = oRes.rows[0];
      return res.status(201).json({ orderId, ...o, message: 'Pedido criado. Prossiga para o pagamento.' });
    } catch (err) {
      if (err.status) return res.status(err.status).json({ error: err.message });
      console.error('[Orders/Create]', err.message);
      return res.status(500).json({ error: 'Erro ao criar pedido.' });
    }
  }
);

module.exports = router;
