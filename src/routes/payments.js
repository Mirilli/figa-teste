'use strict';

const express = require('express');
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');

const db = require('../database');
const { requireAuth }                                     = require('../middleware/auth');
const { verifyMercadoPagoWebhook, verifyOrderHash, auditLog } = require('../middleware/security');

const router = express.Router();

// Instancia o cliente do Mercado Pago
const mpClient = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: { timeout: 10_000 },
});

// ─── POST /api/payments/checkout/:orderId ─────────────────────────────────────
// Cria uma preferência no Mercado Pago e retorna a URL de checkout
router.post('/checkout/:orderId', requireAuth, async (req, res) => {
  const orderId = parseInt(req.params.orderId);
  if (isNaN(orderId)) return res.status(400).json({ error: 'ID inválido.' });

  const order = db.prepare(`
    SELECT o.*, u.email, u.name AS customer_name
    FROM orders o
    JOIN users u ON u.id = o.user_id
    WHERE o.id = ? AND o.user_id = ?
  `).get(orderId, req.user.id);

  if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (order.status !== 'awaiting_payment') {
    return res.status(409).json({ error: 'Este pedido já foi processado.' });
  }

  const items = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(orderId);

  // ── Verifica integridade do pedido antes de enviar ao MP ─────────────────
  if (!verifyOrderHash(order, items)) {
    auditLog(req.user.id, 'order_integrity_violation', req, {
      entity: 'order', entityId: orderId,
    });
    return res.status(409).json({ error: 'Inconsistência no pedido detectada. Entre em contato.' });
  }

  try {
    const preference = new Preference(mpClient);

    // O Mercado Pago exige que unit_price seja exato e com no máximo 2 casas decimais.
    // Usamos parseFloat + toFixed(2) para garantir consistência.
    const round2 = (n) => parseFloat(parseFloat(n).toFixed(2));

    const mpItems = items.map(i => ({
      id: String(i.product_id),
      title: i.product_name,
      description: i.product_sku,
      quantity: Number(i.quantity),
      currency_id: 'BRL',
      unit_price: round2(i.unit_price),
    }));

    // Frete como item separado
    if (round2(order.shipping_cost) > 0) {
      mpItems.push({
        id: 'FRETE',
        title: 'Frete',
        description: 'Entrega via Correios',
        quantity: 1,
        currency_id: 'BRL',
        unit_price: round2(order.shipping_cost),
      });
    }

    // Verifica que o total dos itens bate com o total do pedido
    const mpTotal = mpItems.reduce((s, i) => s + round2(i.unit_price * i.quantity), 0);
    const orderTotal = round2(order.total);
    if (Math.abs(mpTotal - orderTotal) > 0.01) {
      console.error(`[Payments] Divergência: MP=${mpTotal} Order=${orderTotal}`);
      auditLog(req.user.id, 'payment_total_mismatch', req, {
        entity: 'order', entityId: orderId,
        details: { mpTotal, orderTotal },
      });
    }

    const prefResponse = await preference.create({
      body: {
        external_reference: String(orderId),  // liga o webhook ao pedido
        items: mpItems,
        payer: {
          name: order.customer_name,
          email: order.email,
        },
        payment_methods: {
          installments: 3,
          default_installments: 1,
        },
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
      },
    });

    // Armazena o preference_id para correlacionar no webhook
    db.prepare(`
      UPDATE orders SET mp_preference_id = ?, updated_at = datetime('now') WHERE id = ?
    `).run(prefResponse.id, orderId);

    auditLog(req.user.id, 'checkout_initiated', req, {
      entity: 'order', entityId: orderId,
      details: { prefId: prefResponse.id },
    });

    return res.json({
      checkoutUrl: process.env.NODE_ENV === 'production'
        ? prefResponse.init_point
        : prefResponse.sandbox_init_point,
      preferenceId: prefResponse.id,
    });
  } catch (err) {
    console.error('[Payments/Checkout]', err.message);
    return res.status(502).json({ error: 'Erro ao criar checkout. Tente novamente.' });
  }
});

// ─── POST /api/payments/webhook ───────────────────────────────────────────────
// Recebe notificações do Mercado Pago (IPN / Webhook)
router.post('/webhook', verifyMercadoPagoWebhook, async (req, res) => {
  // Responde 200 imediatamente (MP aguarda confirmação rápida)
  res.sendStatus(200);

  const { type, data } = req.body;
  if (type !== 'payment' || !data?.id) return;

  try {
    const paymentApi = new Payment(mpClient);
    const payment = await paymentApi.get({ id: data.id });

    const orderId = parseInt(payment.external_reference);
    if (isNaN(orderId)) return;

    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
    if (!order) return;

    // ── Re-verifica integridade antes de confirmar pagamento ──────────────
    const items = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(orderId);
    if (!verifyOrderHash(order, items)) {
      auditLog(null, 'webhook_integrity_violation', null, {
        entity: 'order', entityId: orderId,
        details: { paymentId: payment.id },
      });
      return; // Não processa pagamento com hash inválido
    }

    const mpStatus = payment.status;
    let newStatus = order.status;

    if (mpStatus === 'approved') {
      newStatus = 'paid';
    } else if (['cancelled', 'rejected', 'charged_back'].includes(mpStatus)) {
      newStatus = 'cancelled';
      // Devolve estoque
      const restoreStock = db.transaction(() => {
        for (const item of items) {
          db.prepare('UPDATE products SET stock = stock + ? WHERE id = ?')
            .run(item.quantity, item.product_id);
        }
      });
      restoreStock();
    }

    db.prepare(`
      UPDATE orders
      SET status = ?, mp_payment_id = ?, mp_status = ?,
          paid_at = CASE WHEN ? = 'paid' THEN datetime('now') ELSE paid_at END,
          updated_at = datetime('now')
      WHERE id = ?
    `).run(newStatus, String(payment.id), mpStatus, newStatus, orderId);

    auditLog(null, 'payment_webhook_processed', null, {
      entity: 'order', entityId: orderId,
      details: { paymentId: payment.id, mpStatus, newStatus },
    });
  } catch (err) {
    console.error('[Payments/Webhook]', err.message);
  }
});

// ─── GET /api/payments/status/:orderId ────────────────────────────────────────
router.get('/status/:orderId', requireAuth, (req, res) => {
  const order = db.prepare(`
    SELECT id, status, total, mp_payment_id, paid_at
    FROM orders WHERE id = ? AND user_id = ?
  `).get(req.params.orderId, req.user.id);

  if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });
  return res.json(order);
});

module.exports = router;
