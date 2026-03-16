'use strict';

require('dotenv').config();
const express      = require('express');
const helmet       = require('helmet');
const compression  = require('compression');
const cors         = require('cors');
const morgan       = require('morgan');
const cookieParser = require('cookie-parser');
const path         = require('path');

const { init, query }  = require('./src/database');
const { apiLimiter }   = require('./src/middleware/security');

const authRoutes     = require('./src/routes/auth');
const ordersRoutes   = require('./src/routes/orders');
const paymentsRoutes = require('./src/routes/payments');
const adminRoutes    = require('./src/routes/admin');

const app = express();

if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'","'unsafe-inline'",'https://sdk.mercadopago.com',
                   'https://www.googletagmanager.com','https://connect.facebook.net','https://fonts.googleapis.com'],
      styleSrc:   ["'self'","'unsafe-inline'",'https://fonts.googleapis.com'],
      fontSrc:    ["'self'",'https://fonts.gstatic.com'],
      imgSrc:     ["'self'",'data:','https:'],
      connectSrc: ["'self'",'https://api.mercadopago.com'],
      frameSrc:   ['https://sdk.mercadopago.com'],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

const allowedOrigins = (process.env.ALLOWED_ORIGINS || process.env.BASE_URL || 'http://localhost:3000')
  .split(',').map(s => s.trim());

app.use(cors({
  origin: (origin, cb) => (!origin || allowedOrigins.includes(origin)) ? cb(null, true) : cb(new Error('Origem não permitida.')),
  credentials: true,
}));

app.use(compression());
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(cookieParser());
if (process.env.NODE_ENV !== 'production') app.use(morgan('dev'));

app.use('/api', apiLimiter);

app.get('/api/products', async (req, res) => {
  const r = await query('SELECT id,sku,name,description,price::float,stock,weight_g FROM products WHERE active=TRUE ORDER BY id');
  res.json(r.rows);
});

app.use('/api/auth',     authRoutes);
app.use('/api/orders',   ordersRoutes);
app.use('/api/payments', paymentsRoutes);
app.use('/api/admin',    adminRoutes);
app.get('/api/health',   (_, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true,
}));
app.get('/admin*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*',       (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Erro interno do servidor.' : err.message,
  });
});

const PORT = parseInt(process.env.PORT) || 3000;

// Inicia o banco ANTES de abrir o servidor
init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n🌾  GranoVita rodando em http://localhost:${PORT}`);
      console.log(`    Ambiente: ${process.env.NODE_ENV || 'development'}\n`);
    });
  })
  .catch((err) => {
    console.error('[FATAL] Falha ao inicializar banco de dados:', err.message);
    process.exit(1);
  });

module.exports = app;
