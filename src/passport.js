const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Strategy: GitHubStrategy } = require('passport-github2');
const { pool } = require('./db');

async function findOrCreate(provider, profile) {
  const email =
    (profile.emails && profile.emails[0] && profile.emails[0].value) ||
    `${profile.username || profile.id}@${provider}.local`;
  const name = profile.displayName || profile.username || email.split('@')[0];

  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  if (rows[0]) {
    if (!rows[0].provider_id) {
      await pool.query('UPDATE users SET provider = ?, provider_id = ? WHERE id = ?', [provider, String(profile.id), rows[0].id]);
    }
    return rows[0];
  }
  const [result] = await pool.query(
    "INSERT INTO users (name, email, provider, provider_id, role) VALUES (?, ?, ?, ?, 'Employee')",
    [name, email, provider, String(profile.id)]
  );
  const [created] = await pool.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
  return created[0];
}

const done = (provider) => async (_a, _r, profile, cb) => {
  try { cb(null, await findOrCreate(provider, profile)); } catch (e) { cb(e); }
};

const base = process.env.BASE_URL || 'http://localhost:5000';

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${base}/api/v1/auth/google/callback`,
  }, done('google')));
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${base}/api/v1/auth/github/callback`,
    scope: ['user:email'],
  }, done('github')));
}

module.exports = passport;
