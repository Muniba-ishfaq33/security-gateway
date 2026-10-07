require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');

const { init } = require('./src/db');
const passport = require('./src/passport');
const sanitize = require('./src/middleware/sanitize');
const authRoutes = require('./src/routes/auth');
const protectedRoutes = require('./src/routes/protected');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1); // Railway/Render sit behind a proxy

// 1) Helmet: secure HTTP headers + CSP
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'"],
      'style-src': ["'self'", 'https://cdn.jsdelivr.net'],
      'upgrade-insecure-requests': isProd ? [] : null,
    },
  },
}));

// 2) Strict CORS: only whitelisted origins
const allowed = [process.env.BASE_URL, ...(process.env.CLIENT_ORIGIN || '').split(',')]
  .map((s) => (s || '').trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => (!origin || allowed.includes(origin) ? cb(null, true) : cb(new Error('CORS blocked'))),
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
}));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(sanitize); // 3) XSS / NoSQL-operator cleaning
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false }));
app.use(passport.initialize());

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok' }));
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1', protectedRoutes);

app.use('/api', (req, res) => res.status(404).json({ message: 'Route not found' }));
app.use((err, req, res, next) => {
  console.error(err.message);
  if (err.message === 'CORS blocked') return res.status(403).json({ message: 'CORS policy blocked this origin' });
  res.status(500).json({ message: 'Internal server error' });
});

const PORT = process.env.PORT || 5000;
init()
  .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
  .catch((e) => { console.error('DB init failed:', e.message); process.exit(1); });
