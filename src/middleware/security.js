'use strict';

const rateLimit = require('express-rate-limit');
const crypto   = require('crypto');
const db       = require('../database');

// ─── Rate Limiters ────────────────────────────────────────────────────────────

/** Limite geral da API */
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Aguarde alguns minutos.' },
  skip: (req) => req.user?.role === 'admin',
});

/** Limite estrito para login (brute-force protection) */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,      // 15 minutos
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas de login. Aguarde 15 minutos.' },
  keyGenerator: (req) => req.ip + (req.body?.email || ''),
});

/** Limite para criação de conta */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,      // 1 hora
  max: 10,
  message: { error: 'Muitos cadastros deste IP. Aguarde.' },
});

/** Limite para webhooks do Mercado Pago */
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: '',
});

// ─── Integridade de Pedido ─────────────────────────────────────────────────

/**
 * Gera HMAC-SHA256 dos dados críticos do pedido.
 * Impede que valores sejam alterados entre a criação do pedido e o webhook de confirmação.
 *
 * @param {Object} data - { userId, items: [{productId, qty, unitPrice}], total }
 * @returns {string} hash hex
 */
function generateOrderHash(data) {
  const canonical = JSON.stringify({
    userId: data.userId,
    items: data.items
      .map(i => ({ id: i.productId, qty: i.quantity, price: i.unitPrice }))
      .sort((a, b) => a.id - b.id),
    total: Number(data.total).toFixed(2),
  });
  return crypto
    .createHmac('sha256', process.env.JWT_ACCESS_SECRET)
    .update(canonical)
    .digest('hex');
}

/**
 * Verifica se o hash do pedido bate com os dados armazenados.
 */
function verifyOrderHash(order, items) {
  const expected = generateOrderHash({
    userId: order.user_id,
    items: items.map(i => ({
      productId: i.product_id,
      quantity: i.quantity,
      unitPrice: i.unit_price,
    })),
    total: order.total,
  });
  return crypto.timingSafeEqual(
    Buffer.from(expected, 'hex'),
    Buffer.from(order.integrity_hash, 'hex')
  );
}

// ─── Verificação de Webhook do Mercado Pago ───────────────────────────────

/**
 * Valida a assinatura HMAC-SHA256 do webhook do Mercado Pago.
 * Ref: https://www.mercadopago.com.br/developers/pt/docs/your-integrations/notifications/webhooks
 */
function verifyMercadoPagoWebhook(req, res, next) {
  const signatureHeader = req.headers['x-signature'];
  const requestId       = req.headers['x-request-id'];

  if (!signatureHeader || !requestId) {
    return res.status(400).json({ error: 'Webhook inválido: assinatura ausente.' });
  }

  // Formato: ts=<timestamp>,v1=<hash>
  const parts = Object.fromEntries(
    signatureHeader.split(',').map(p => p.split('='))
  );
  const { ts, v1 } = parts;
  if (!ts || !v1) return res.status(400).json({ error: 'Assinatura malformada.' });

  const dataId = req.query?.data?.id || req.body?.data?.id || '';
  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;

  const expected = crypto
    .createHmac('sha256', process.env.MP_WEBHOOK_SECRET)
    .update(manifest)
    .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1))) {
    auditLog(null, 'webhook_invalid_signature', req);
    return res.status(401).json({ error: 'Assinatura do webhook inválida.' });
  }

  // Previne replay: timestamp não pode ter mais de 5 minutos
  const age = Math.abs(Date.now() / 1000 - parseInt(ts));
  if (age > 300) {
    return res.status(400).json({ error: 'Webhook expirado (replay attack).' });
  }

  next();
}

// ─── Audit Log ────────────────────────────────────────────────────────────────

/**
 * Registra ações sensíveis no banco de dados.
 */
function auditLog(userId, action, req, extra = {}) {
  try {
    db.prepare(`
      INSERT INTO audit_log (user_id, action, entity, entity_id, ip, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      userId || null,
      action,
      extra.entity || null,
      extra.entityId || null,
      req?.ip || null,
      req?.headers?.['user-agent'] || null,
      extra.details ? JSON.stringify(extra.details) : null
    );
  } catch (e) {
    console.error('[AuditLog] Falha ao registrar:', e.message);
  }
}

// ─── Sanitização de saída — remove campos sensíveis ──────────────────────

function sanitizeUser(user) {
  if (!user) return null;
  const { password_hash, ...safe } = user;
  return safe;
}

module.exports = {
  apiLimiter,
  loginLimiter,
  registerLimiter,
  webhookLimiter,
  generateOrderHash,
  verifyOrderHash,
  verifyMercadoPagoWebhook,
  auditLog,
  sanitizeUser,
};
