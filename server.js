'use strict';

require('dotenv').config();
const express     = require('express');
const helmet      = require('helmet');
const compression = require('compression');
const cors        = require('cors');
const morgan      = require('morgan');
const cookieParser = require('cookie-parser');
const path        = require('path');

const { apiLimiter } = require('./src/middleware/security');

// ─── Rotas ────────────────────────────────────────────────────────────────────
const authRoutes     = require('./src/routes/auth');
const ordersRoutes   = require('./src/routes/orders');
const paymentsRoutes = require('./src/routes/payments');
const adminRoutes    = require('./src/routes/admin');
const sectionsRoutes = require('./src/routes/sections');

const app = express();

// ─── Trust proxy (necessário em produção atrás de Nginx/Load Balancer) ────────
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);

// ─── Segurança: Headers HTTP ───────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        'https://sdk.mercadopago.com',
        'https://www.googletagmanager.com',
        'https://connect.facebook.net',
        'https://fonts.googleapis.com',
        // Permite inline scripts com nonce (requer ajuste para gerar nonce por request em produção)
        "'unsafe-inline'",
      ],
      styleSrc: ["'self'", 'https://fonts.googleapis.com', "'unsafe-inline'"],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.mercadopago.com'],
      frameSrc: ['https://sdk.mercadopago.com'],
      scriptSrcAttr: ["'unsafe-hashes'", "'unsafe-inline'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// ─── CORS – permite apenas origens explícitas ─────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || process.env.BASE_URL || 'http://localhost:3000')
  .split(',').map(s => s.trim());

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('Origem não permitida.'));
  },
  credentials: true,
}));

// ─── Compressão e parsing ─────────────────────────────────────────────────────
app.use(compression());
app.use(express.json({ limit: '64kb' }));     // limite de payload
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(cookieParser());

// ─── Log de requests (apenas desenvolvimento) ─────────────────────────────────
if (process.env.NODE_ENV !== 'production') app.use(morgan('dev'));

// ─── API Rate Limiting ────────────────────────────────────────────────────────
app.use('/api', apiLimiter);

// ─── Produtos (público) ───────────────────────────────────────────────────────
const db = require('./src/database');

app.get('/api/products', (req, res) => {
  const products = db.prepare(`
    SELECT id, sku, name, description, price, stock, weight_g, image_url
    FROM products WHERE active = 1 ORDER BY id
  `).all();
  res.json(products);
});

// ─── Rotas de API ─────────────────────────────────────────────────────────────
app.use('/api/auth',     authRoutes);
app.use('/api/orders',   ordersRoutes);
app.use('/api/payments', paymentsRoutes);
app.use('/api/admin',    adminRoutes);
app.use('/api/sections', sectionsRoutes);

// ─── Saúde do servidor ────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

// ─── Arquivos estáticos (frontend) ───────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true,
}));

// SPA fallback para páginas frontend
app.get('/admin*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Error handler global ────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  // Não vaza stack trace em produção
  console.error('[Error]', err.message);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Erro interno do servidor.' : err.message,
  });
});

// ─── Inicializa ───────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT) || 3000;
app.listen(PORT, () => {
  console.log(`\n🌾  GranoVita rodando em http://localhost:${PORT}`);
  console.log(`    Ambiente: ${process.env.NODE_ENV || 'development'}\n`);
});

module.exports = app;
