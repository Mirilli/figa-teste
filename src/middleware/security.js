'use strict';

const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');
const { query } = require('../database');

const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas requisições. Aguarde alguns minutos.' },
  skip: (req) => req.user?.role === 'admin',
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas tentativas de login. Aguarde 15 minutos.' },
  keyGenerator: (req) => req.ip + (req.body?.email || ''),
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  message: { error: 'Muitos cadastros deste IP. Aguarde.' },
});

const webhookLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: '' });

function generateOrderHash(data) {
  const canonical = JSON.stringify({
    userId: data.userId,
    items: data.items
      .map(i => ({ id: i.productId, qty: i.quantity, price: String(i.unitPrice) }))
      .sort((a, b) => a.id - b.id),
    total: Number(data.total).toFixed(2),
  });
  return crypto
    .createHmac('sha256', process.env.JWT_ACCESS_SECRET)
    .update(canonical)
    .digest('hex');
}

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
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(order.integrity_hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function verifyMercadoPagoWebhook(req, res, next) {
  const signatureHeader = req.headers['x-signature'];
  const requestId       = req.headers['x-request-id'];
  if (!signatureHeader || !requestId) return res.status(400).json({ error: 'Webhook inválido.' });

  const parts = Object.fromEntries(signatureHeader.split(',').map(p => p.split('=')));
  const { ts, v1 } = parts;
  if (!ts || !v1) return res.status(400).json({ error: 'Assinatura malformada.' });

  const dataId   = req.query?.data?.id || req.body?.data?.id || '';
  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
  const expected = crypto.createHmac('sha256', process.env.MP_WEBHOOK_SECRET).update(manifest).digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1))) {
    auditLog(null, 'webhook_invalid_signature', req);
    return res.status(401).json({ error: 'Assinatura inválida.' });
  }
  if (Math.abs(Date.now() / 1000 - parseInt(ts)) > 300) {
    return res.status(400).json({ error: 'Webhook expirado.' });
  }
  next();
}

async function auditLog(userId, action, req, extra = {}) {
  try {
    await query(
      `INSERT INTO audit_log (user_id, action, entity, entity_id, ip, user_agent, details)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        userId || null,
        action,
        extra.entity || null,
        extra.entityId || null,
        req?.ip || null,
        req?.headers?.['user-agent'] || null,
        extra.details ? extra.details : null,
      ]
    );
  } catch (e) {
    console.error('[AuditLog] Falha:', e.message);
  }
}

function sanitizeUser(user) {
  if (!user) return null;
  const { password_hash, ...safe } = user;
  return safe;
}

module.exports = {
  apiLimiter, loginLimiter, registerLimiter, webhookLimiter,
  generateOrderHash, verifyOrderHash, verifyMercadoPagoWebhook,
  auditLog, sanitizeUser,
};
