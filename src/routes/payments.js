'use strict';

const express = require('express');
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');

const { query, withTransaction }                          = require('../database');
const { requireAuth }                                     = require('../middleware/auth');
const { verifyMercadoPagoWebhook, verifyOrderHash, auditLog } = require('../middleware/security');

const router = express.Router();

const mpClient = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: { timeout: 10_000 },
});

// ── POST /api/payments/checkout/:orderId ──────────────────────────────────────
router.post('/checkout/:orderId', requireAuth, async (req, res) => {
  const orderId = parseInt(req.params.orderId);
  if (isNaN(orderId)) return res.status(400).json({ error: 'ID inválido.' });

  const orderRes = await query(
    `SELECT o.*, u.email, u.name AS customer_name
     FROM orders o JOIN users u ON u.id = o.user_id
     WHERE o.id = $1 AND o.user_id = $2`,
    [orderId, req.user.id]
  );
  const order = orderRes.rows[0];
  if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (order.status !== 'awaiting_payment') return res.status(409).json({ error: 'Pedido já processado.' });

  const itemsRes = await query('SELECT * FROM order_items WHERE order_id = $1', [orderId]);
  const items = itemsRes.rows;

  if (!verifyOrderHash(order, items)) {
    await auditLog(req.user.id, 'order_integrity_violation', req, { entity: 'order', entityId: orderId });
    return res.status(409).json({ error: 'Inconsistência no pedido. Entre em contato.' });
  }

  try {
    const preference = new Preference(mpClient);
    const mpItems = items.map(i => ({
      id: String(i.product_id), title: i.product_name, description: i.product_sku,
      quantity: i.quantity, currency_id: 'BRL', unit_price: parseFloat(i.unit_price),
    }));
    if (parseFloat(order.shipping_cost) > 0) {
      mpItems.push({ id: 'SHIPPING', title: 'Frete', quantity: 1,
        currency_id: 'BRL', unit_price: parseFloat(order.shipping_cost) });
    }

    const prefResponse = await preference.create({ body: {
      external_reference: String(orderId),
      items: mpItems,
      payer: { name: order.customer_name, email: order.email },
      payment_methods: { installments: 3, default_installments: 1 },
      back_urls: {
        success: `${process.env.BASE_URL}/pedido-confirmado.html?order=${orderId}`,
        failure: `${process.env.BASE_URL}/pedido-erro.html?order=${orderId}`,
        pending: `${process.env.BASE_URL}/pedido-pendente.html?order=${orderId}`,
      },
      auto_return: 'approved',
      notification_url: `${process.env.BASE_URL}/api/payments/webhook`,
      statement_descriptor: 'GRANOVITA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    }});

    await query(
      `UPDATE orders SET mp_preference_id = $1, updated_at = NOW() WHERE id = $2`,
      [prefResponse.id, orderId]
    );
    await auditLog(req.user.id, 'checkout_initiated', req, {
      entity: 'order', entityId: orderId, details: { prefId: prefResponse.id },
    });

    return res.json({
      checkoutUrl: process.env.NODE_ENV === 'production'
        ? prefResponse.init_point : prefResponse.sandbox_init_point,
      preferenceId: prefResponse.id,
    });
  } catch (err) {
    console.error('[Payments/Checkout]', err.message);
    return res.status(502).json({ error: 'Erro ao criar checkout.' });
  }
});

// ── POST /api/payments/webhook ────────────────────────────────────────────────
router.post('/webhook', verifyMercadoPagoWebhook, async (req, res) => {
  res.sendStatus(200);
  const { type, data } = req.body;
  if (type !== 'payment' || !data?.id) return;

  try {
    const paymentApi = new Payment(mpClient);
    const payment    = await paymentApi.get({ id: data.id });
    const orderId    = parseInt(payment.external_reference);
    if (isNaN(orderId)) return;

    const orderRes = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
    const order    = orderRes.rows[0];
    if (!order) return;

    const itemsRes = await query('SELECT * FROM order_items WHERE order_id = $1', [orderId]);
    if (!verifyOrderHash(order, itemsRes.rows)) {
      await auditLog(null, 'webhook_integrity_violation', null, {
        entity: 'order', entityId: orderId, details: { paymentId: payment.id },
      });
      return;
    }

    const mpStatus  = payment.status;
    let   newStatus = order.status;

    if (mpStatus === 'approved') {
      newStatus = 'paid';
    } else if (['cancelled', 'rejected', 'charged_back'].includes(mpStatus)) {
      newStatus = 'cancelled';
      await withTransaction(async (client) => {
        for (const item of itemsRes.rows) {
          await client.query('UPDATE products SET stock = stock + $1 WHERE id = $2', [item.quantity, item.product_id]);
        }
      });
    }

    await query(
      `UPDATE orders SET status=$1, mp_payment_id=$2, mp_status=$3,
         paid_at = CASE WHEN $1='paid' THEN NOW() ELSE paid_at END,
         updated_at = NOW()
       WHERE id = $4`,
      [newStatus, String(payment.id), mpStatus, orderId]
    );
    await auditLog(null, 'payment_webhook_processed', null, {
      entity: 'order', entityId: orderId,
      details: { paymentId: payment.id, mpStatus, newStatus },
    });
  } catch (err) {
    console.error('[Payments/Webhook]', err.message);
  }
});

// ── GET /api/payments/status/:orderId ─────────────────────────────────────────
router.get('/status/:orderId', requireAuth, async (req, res) => {
  const r = await query(
    `SELECT id, status, total::float, mp_payment_id, paid_at
     FROM orders WHERE id = $1 AND user_id = $2`,
    [req.params.orderId, req.user.id]
  );
  if (!r.rows.length) return res.status(404).json({ error: 'Pedido não encontrado.' });
  return res.json(r.rows[0]);
});

module.exports = router;
