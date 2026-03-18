'use strict';

const express = require('express');
const { body, param, validationResult } = require('express-validator');

const db = require('../database');
const { requireAuth }                        = require('../middleware/auth');
const { generateOrderHash, auditLog }        = require('../middleware/security');
const { calculateShipping }                  = require('../shipping');

const router = express.Router();

// ─── GET /api/orders — lista pedidos do usuário logado ────────────────────────
router.get('/', requireAuth, (req, res) => {
  const orders = db.prepare(`
    SELECT
      o.id, o.status, o.subtotal, o.shipping_cost, o.total,
      o.mp_payment_id, o.paid_at, o.shipped_at, o.delivered_at, o.created_at,
      (
        SELECT json_group_array(json_object(
          'name', oi.product_name,
          'sku',  oi.product_sku,
          'qty',  oi.quantity,
          'unit_price', oi.unit_price,
          'subtotal',   oi.subtotal
        ))
        FROM order_items oi WHERE oi.order_id = o.id
      ) AS items_json
    FROM orders o
    WHERE o.user_id = ?
    ORDER BY o.created_at DESC
    LIMIT 50
  `).all(req.user.id);

  const result = orders.map(o => ({
    ...o,
    items: JSON.parse(o.items_json || '[]'),
    items_json: undefined,
  }));

  return res.json(result);
});

// ─── GET /api/orders/:id — detalhe de um pedido ───────────────────────────────
router.get('/:id', requireAuth, param('id').isInt(), (req, res) => {
  const order = db.prepare(`
    SELECT o.*, u.name AS customer_name, u.email AS customer_email
    FROM orders o
    JOIN users u ON u.id = o.user_id
    WHERE o.id = ? AND (o.user_id = ? OR ? = 'admin')
  `).get(req.params.id, req.user.id, req.user.role);

  if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });

  const items = db.prepare(`
    SELECT * FROM order_items WHERE order_id = ?
  `).all(order.id);

  // Oculta dados sensíveis de endereço para outros usuários que não sejam admin
  if (req.user.role !== 'admin' && order.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }

  const { integrity_hash, ...safeOrder } = order;
  return res.json({ ...safeOrder, items });
});

// ─── POST /api/orders — cria novo pedido ─────────────────────────────────────
router.post('/',
  requireAuth,
  [
    body('items').isArray({ min: 1 }).withMessage('Carrinho vazio.'),
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
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array().map(e => e.msg) });
    }

    const { items: requestedItems, shipping } = req.body;

    try {
      // ── 1. Busca produtos e valida estoque ──────────────────────────────
      const enriched = [];
      for (const item of requestedItems) {
        const product = db.prepare(`
          SELECT * FROM products WHERE id = ? AND active = 1
        `).get(item.productId);

        if (!product) {
          return res.status(400).json({ error: `Produto ID ${item.productId} não encontrado.` });
        }
        if (product.stock < item.quantity) {
          return res.status(409).json({
            error: `Estoque insuficiente para "${product.name}". Disponível: ${product.stock}.`,
          });
        }
        enriched.push({
          productId: product.id,
          productSku: product.sku,
          productName: product.name,
          unitPrice: product.price,   // ← preço REAL do banco, nunca do cliente
          quantity: item.quantity,
          subtotal: +(product.price * item.quantity).toFixed(2),
        });
      }

      // ── 2. Calcula totais no servidor ────────────────────────────────────
      const subtotal = +enriched.reduce((s, i) => s + i.subtotal, 0).toFixed(2);
      const shippingCost = subtotal >= FREE_SHIPPING_LIMIT ? 0 : SHIPPING_COST;
      const total = +(subtotal + shippingCost).toFixed(2);

      // ── 3. Persiste pedido em transação atômica ──────────────────────────
      const createOrder = db.transaction(() => {
        // Decrementa estoque
        for (const item of enriched) {
          db.prepare(`
            UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?
          `).run(item.quantity, item.productId, item.quantity);
        }

        // Gera hash de integridade ANTES de inserir
        const integrityHash = generateOrderHash({
          userId: req.user.id,
          items: enriched.map(i => ({
            productId: i.productId,
            quantity: i.quantity,
            unitPrice: i.unitPrice,
          })),
          total,
        });

        const orderResult = db.prepare(`
          INSERT INTO orders
            (user_id, status, subtotal, shipping_cost, total, integrity_hash,
             shipping_name, shipping_phone, shipping_address)
          VALUES (?, 'awaiting_payment', ?, ?, ?, ?, ?, ?, ?)
        `).run(
          req.user.id, subtotal, shippingCost, total, integrityHash,
          shipping.name, shipping.phone,
          JSON.stringify({
            address: shipping.address,
            number: shipping.number || '',
            complement: shipping.complement || '',
            neighborhood: shipping.neighborhood || '',
            city: shipping.city,
            state: shipping.state,
            zip: shipping.zip,
          })
        );

        const orderId = orderResult.lastInsertRowid;
        const insertItem = db.prepare(`
          INSERT INTO order_items
            (order_id, product_id, product_sku, product_name, unit_price, quantity, subtotal)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        for (const item of enriched) {
          insertItem.run(
            orderId, item.productId, item.productSku, item.productName,
            item.unitPrice, item.quantity, item.subtotal
          );
        }

        return orderId;
      });

      const orderId = createOrder();
      auditLog(req.user.id, 'order_created', req, { entity: 'order', entityId: orderId });

      return res.status(201).json({
        orderId,
        subtotal,
        shippingCost,
        shippingZone: shippingCalc.zone,
        shippingLabel: shippingCalc.label,
        shippingDays: shippingCalc.days,
        shippingFree: shippingCalc.free,
        total,
        message: 'Pedido criado. Prossiga para o pagamento.',
      });
    } catch (err) {
      console.error('[Orders/Create]', err.message);
      return res.status(500).json({ error: 'Erro ao criar pedido. Tente novamente.' });
    }
  }
);

module.exports = router;
