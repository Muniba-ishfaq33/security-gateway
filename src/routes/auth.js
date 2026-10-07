const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { pool } = require('../db');
const passport = require('../passport');
const {
  sha256, COOKIE_NAME, signAccessToken, issueRefreshToken, clearRefreshCookie,
} = require('../tokens');

const router = express.Router();

// Rate limit: max 5 failed login attempts per 15 minutes (successful logins not counted)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many failed login attempts. Try again after 15 minutes.' },
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASS_RE = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, provider: u.provider });

// ---------- REGISTER ----------
router.post('/register', async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !EMAIL_RE.test(email || '')) {
      return res.status(400).json({ message: 'Valid name and email are required' });
    }
    if (!PASS_RE.test(password || '')) {
      return res.status(400).json({ message: 'Password must be 8+ chars with a letter and a number' });
    }
    const [exists] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ message: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12); // salted + hashed
    // Role is ALWAYS Employee on public signup (prevents privilege escalation)
    const [r] = await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'Employee')",
      [name, email, hash]
    );
    res.status(201).json({ message: 'Registered successfully', userId: r.insertId });
  } catch (e) { next(e); }
});

// ---------- LOGIN ----------
router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const [rows] = await pool.query(
      'SELECT *, (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked FROM users WHERE email = ?',
      [email]
    );
    const user = rows[0];

    if (!user || !user.password_hash) {
      await bcrypt.compare(password, DUMMY_HASH); // same timing, no user enumeration
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    if (user.is_locked) {
      return res.status(423).json({ message: 'Account locked for 15 minutes due to failed attempts' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      const attempts = user.failed_attempts + 1;
      if (attempts >= 5) {
        await pool.query('UPDATE users SET failed_attempts = 0, locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE id = ?', [user.id]);
      } else {
        await pool.query('UPDATE users SET failed_attempts = ? WHERE id = ?', [attempts, user.id]);
      }
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    await pool.query('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
    await issueRefreshToken(res, user);
    res.json({ accessToken: signAccessToken(user), user: publicUser(user) });
  } catch (e) { next(e); }
});

// ---------- REFRESH (rotation + reuse detection) ----------
router.post('/refresh', async (req, res, next) => {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ message: 'No refresh token' });

    let payload;
    try { payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET); }
    catch { clearRefreshCookie(res); return res.status(401).json({ message: 'Invalid refresh token' }); }

    const [rows] = await pool.query('SELECT * FROM refresh_tokens WHERE token_hash = ?', [sha256(token)]);
    const stored = rows[0];

    if (!stored || stored.revoked) {
      // Old token used again = possible theft -> kill all sessions of this user
      await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?', [payload.sub]);
      clearRefreshCookie(res);
      return res.status(401).json({ message: 'Refresh token reuse detected. Please login again.' });
    }

    await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?', [stored.id]); // rotate
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [payload.sub]);
    if (!users[0]) { clearRefreshCookie(res); return res.status(401).json({ message: 'User not found' }); }

    await issueRefreshToken(res, users[0]);
    res.json({ accessToken: signAccessToken(users[0]), user: publicUser(users[0]) });
  } catch (e) { next(e); }
});

// ---------- LOGOUT (revocation) ----------
router.post('/logout', async (req, res, next) => {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (token) await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?', [sha256(token)]);
    clearRefreshCookie(res);
    res.json({ message: 'Logged out' });
  } catch (e) { next(e); }
});

// ---------- SOCIAL LOGIN ----------
function oauthRoutes(provider, scope) {
  router.get(`/${provider}`, (req, res, next) => {
    if (!passport._strategy(provider)) return res.status(501).json({ message: `${provider} login not configured` });
    passport.authenticate(provider, { scope, session: false })(req, res, next);
  });
  router.get(`/${provider}/callback`,
    (req, res, next) => passport.authenticate(provider, { session: false, failureRedirect: '/?oauth=failed' })(req, res, next),
    async (req, res, next) => {
      try {
        await issueRefreshToken(res, req.user); // refresh cookie set, frontend then calls /refresh
        res.redirect('/?oauth=success');
      } catch (e) { next(e); }
    });
}
oauthRoutes('google', ['profile', 'email']);
oauthRoutes('github', ['user:email']);

module.exports = router;
