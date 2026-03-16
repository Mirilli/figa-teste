'use strict';

const jwt = require('jsonwebtoken');

/**
 * Verifica o Access Token (JWT de curta duração) enviado no header Authorization.
 * Em caso de falha, retorna 401 sem revelar detalhes internos.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Autenticação necessária.' });
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: 'granovita',
      audience: 'granovita-web',
    });
    req.user = { id: payload.sub, role: payload.role, email: payload.email };
    next();
  } catch (err) {
    // Não revela se o token está expirado ou inválido (evita oracle)
    return res.status(401).json({ error: 'Sessão inválida ou expirada. Faça login novamente.' });
  }
}

/**
 * Verifica se o usuário autenticado tem role 'admin'.
 * Deve ser usado APÓS requireAuth.
 */
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  next();
}

/**
 * Geração de tokens JWT.
 */
function generateTokens(user) {
  const basePayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    iss: 'granovita',
    aud: 'granovita-web',
  };

  const accessToken = jwt.sign(basePayload, process.env.JWT_ACCESS_SECRET, {
    algorithm: 'HS256',
    expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m',
  });

  const refreshToken = jwt.sign(
    { sub: user.id, iss: 'granovita', aud: 'granovita-refresh' },
    process.env.JWT_REFRESH_SECRET,
    { algorithm: 'HS256', expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' }
  );

  return { accessToken, refreshToken };
}

/**
 * Rota opcional: soft-auth (não rejeita se não houver token,
 * apenas popula req.user se válido — útil para rotas públicas com personalizações).
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) return next();
  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: 'granovita',
      audience: 'granovita-web',
    });
    req.user = { id: payload.sub, role: payload.role, email: payload.email };
  } catch (_) {
    // silencioso
  }
  next();
}

module.exports = { requireAuth, requireAdmin, generateTokens, optionalAuth };
