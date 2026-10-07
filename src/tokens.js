const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool } = require('./db');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const COOKIE_NAME = 'refreshToken';
const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;

const cookieOptions = {
  httpOnly: true,       // JS cannot read it (XSS safe)
  secure: true,         // only over HTTPS
  sameSite: 'strict',   // CSRF protection
  path: '/api/v1/auth',
  maxAge: SEVEN_DAYS,
};

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: '15m' }
  );
}

async function issueRefreshToken(res, user) {
  const token = jwt.sign(
    { sub: user.id, jti: crypto.randomUUID() },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
  await pool.query(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))',
    [user.id, sha256(token)]
  );
  res.cookie(COOKIE_NAME, token, cookieOptions);
}

function clearRefreshCookie(res) {
  res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: undefined });
}

module.exports = { sha256, COOKIE_NAME, signAccessToken, issueRefreshToken, clearRefreshCookie };
