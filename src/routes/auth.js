'use strict';

const express   = require('express');
const bcrypt    = require('bcryptjs');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const db = require('../database');
const { generateTokens }               = require('../middleware/auth');
const { loginLimiter, registerLimiter, auditLog, sanitizeUser } = require('../middleware/security');

const router = express.Router();

// ─── Validações ───────────────────────────────────────────────────────────────
const registerRules = [
  body('name').trim().isLength({ min: 2, max: 80 }).withMessage('Nome inválido.'),
  body('email').isEmail().normalizeEmail().withMessage('E-mail inválido.'),
  body('password')
    .isLength({ min: 8 })
    .matches(/[A-Z]/).withMessage('A senha deve ter ao menos uma letra maiúscula.')
    .matches(/[0-9]/).withMessage('A senha deve ter ao menos um número.'),
];

const loginRules = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
];

// ─── POST /api/auth/register ──────────────────────────────────────────────────
router.post('/register', registerLimiter, registerRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array().map(e => e.msg) });
  }

  const { name, email, password } = req.body;

  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      // Mensagem genérica – não revela se o email existe (user enumeration)
      return res.status(409).json({ error: 'Não foi possível criar a conta. Tente outro e-mail.' });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(`
      INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)
    `).run(name, email, hash);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    const { accessToken, refreshToken } = generateTokens(user);

    await storeRefreshToken(user.id, refreshToken, req.ip);
    auditLog(user.id, 'user_registered', req);

    setRefreshCookie(res, refreshToken);
    return res.status(201).json({ user: sanitizeUser(user), accessToken });
  } catch (err) {
    console.error('[Register]', err.message);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }
});

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login', loginLimiter, loginRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ error: 'Dados inválidos.' });
  }

  const { email, password } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    // Sempre executa bcrypt (mesmo se usuário não existe) para prevenir timing attack
    const dummyHash = '$2a$12$AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const match = await bcrypt.compare(password, user?.password_hash || dummyHash);

    if (!user || !match || !user.active) {
      auditLog(user?.id || null, 'login_failed', req, { details: { email } });
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    const { accessToken, refreshToken } = generateTokens(user);
    await storeRefreshToken(user.id, refreshToken, req.ip);
    auditLog(user.id, 'login_success', req);

    setRefreshCookie(res, refreshToken);
    return res.json({ user: sanitizeUser(user), accessToken });
  } catch (err) {
    console.error('[Login]', err.message);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// ─── POST /api/auth/refresh ───────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: 'Sem refresh token.' });

  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      algorithms: ['HS256'],
      issuer: 'granovita',
      audience: 'granovita-refresh',
    });

    const tokenHash = hashToken(token);
    const stored = db.prepare(`
      SELECT rt.*, u.email, u.role, u.active
      FROM refresh_tokens rt
      JOIN users u ON u.id = rt.user_id
      WHERE rt.token_hash = ? AND rt.expires_at > datetime('now')
    `).get(tokenHash);

    if (!stored || !stored.active) {
      // Possível roubo de token – invalida todos os tokens do usuário
      if (stored) {
        db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(stored.user_id);
        auditLog(stored.user_id, 'refresh_token_reuse_detected', req);
      }
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Sessão inválida.' });
    }

    // Rotação do refresh token (token rotation)
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
    const { accessToken, refreshToken: newRefresh } = generateTokens(user);

    db.prepare('DELETE FROM refresh_tokens WHERE token_hash = ?').run(tokenHash);
    await storeRefreshToken(user.id, newRefresh, req.ip);
    setRefreshCookie(res, newRefresh);

    return res.json({ accessToken });
  } catch (err) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  }
});

// ─── POST /api/auth/logout ────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  const token = req.cookies?.refreshToken;
  if (token) {
    db.prepare('DELETE FROM refresh_tokens WHERE token_hash = ?').run(hashToken(token));
  }
  clearRefreshCookie(res);
  return res.json({ message: 'Logout realizado.' });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function storeRefreshToken(userId, token, ip) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    .toISOString().replace('T', ' ').split('.')[0];

  db.prepare(`
    INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip)
    VALUES (?, ?, ?, ?)
  `).run(userId, hashToken(token), expiresAt, ip);
}

function setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/api/auth',
  });
}

function clearRefreshCookie(res) {
  res.clearCookie('refreshToken', { path: '/api/auth' });
}

module.exports = router;
