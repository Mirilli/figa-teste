'use strict';

const express = require('express');
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const jwt     = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const { query }                              = require('../database');
const { generateTokens }                     = require('../middleware/auth');
const { loginLimiter, registerLimiter, auditLog, sanitizeUser } = require('../middleware/security');

const router = express.Router();

const registerRules = [
  body('name').trim().isLength({ min: 2, max: 80 }),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/[A-Z]/).matches(/[0-9]/),
];
const loginRules = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
];

// ── POST /api/auth/register ───────────────────────────────────────────────────
router.post('/register', registerLimiter, registerRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array().map(e => e.msg) });

  const { name, email, password } = req.body;
  try {
    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0)
      return res.status(409).json({ error: 'Não foi possível criar a conta. Tente outro e-mail.' });

    const hash = await bcrypt.hash(password, 12);
    const result = await query(
      `INSERT INTO users (name, email, password_hash) VALUES ($1,$2,$3) RETURNING *`,
      [name, email, hash]
    );
    const user = result.rows[0];
    const { accessToken, refreshToken } = generateTokens(user);
    await storeRefreshToken(user.id, refreshToken, req.ip);
    await auditLog(user.id, 'user_registered', req);
    setRefreshCookie(res, refreshToken);
    return res.status(201).json({ user: sanitizeUser(user), accessToken });
  } catch (err) {
    console.error('[Register]', err.message);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
router.post('/login', loginLimiter, loginRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ error: 'Dados inválidos.' });

  const { email, password } = req.body;
  try {
    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    const dummy = '$2a$12$AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const match = await bcrypt.compare(password, user?.password_hash || dummy);

    if (!user || !match || !user.active) {
      await auditLog(user?.id || null, 'login_failed', req, { details: { email } });
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    const { accessToken, refreshToken } = generateTokens(user);
    await storeRefreshToken(user.id, refreshToken, req.ip);
    await auditLog(user.id, 'login_success', req);
    setRefreshCookie(res, refreshToken);
    return res.json({ user: sanitizeUser(user), accessToken });
  } catch (err) {
    console.error('[Login]', err.message);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// ── POST /api/auth/refresh ────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: 'Sem refresh token.' });

  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      algorithms: ['HS256'], issuer: 'granovita', audience: 'granovita-refresh',
    });

    const tokenHash = hashToken(token);
    const stored = await query(
      `SELECT rt.*, u.email, u.role, u.active
       FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1 AND rt.expires_at > NOW()`,
      [tokenHash]
    );

    if (!stored.rows.length || !stored.rows[0].active) {
      if (stored.rows.length) {
        await query('DELETE FROM refresh_tokens WHERE user_id = $1', [stored.rows[0].user_id]);
        await auditLog(stored.rows[0].user_id, 'refresh_token_reuse_detected', req);
      }
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Sessão inválida.' });
    }

    const userRes = await query('SELECT * FROM users WHERE id = $1', [payload.sub]);
    const user = userRes.rows[0];
    const { accessToken, refreshToken: newRefresh } = generateTokens(user);

    await query('DELETE FROM refresh_tokens WHERE token_hash = $1', [tokenHash]);
    await storeRefreshToken(user.id, newRefresh, req.ip);
    setRefreshCookie(res, newRefresh);
    return res.json({ accessToken });
  } catch {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Sessão expirada.' });
  }
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (token) await query('DELETE FROM refresh_tokens WHERE token_hash = $1', [hashToken(token)]).catch(() => {});
  clearRefreshCookie(res);
  return res.json({ message: 'Logout realizado.' });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function hashToken(t) { return crypto.createHash('sha256').update(t).digest('hex'); }

async function storeRefreshToken(userId, token, ip) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip) VALUES ($1,$2,$3,$4)`,
    [userId, hashToken(token), expiresAt, ip]
  );
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
function clearRefreshCookie(res) { res.clearCookie('refreshToken', { path: '/api/auth' }); }

module.exports = router;
