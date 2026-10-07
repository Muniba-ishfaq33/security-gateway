const xss = require('xss');

// Cleans one value: strips HTML/JS (XSS) from strings.
function clean(value) {
  if (typeof value === 'string') return xss(value.trim());
  if (Array.isArray(value)) return value.map(clean);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      // Block NoSQL-style operator keys ($gt, $ne ...) and dotted keys
      if (key.startsWith('$') || key.includes('.')) continue;
      out[key] = clean(value[key]);
    }
    return out;
  }
  return value;
}

// SQL injection is stopped separately: every query uses "?" placeholders.
module.exports = function sanitize(req, res, next) {
  if (req.body) req.body = clean(req.body);
  if (req.query) {
    const q = clean(req.query);
    for (const k of Object.keys(req.query)) delete req.query[k];
    Object.assign(req.query, q);
  }
  next();
};
