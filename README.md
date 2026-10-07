# Enterprise Multi-Tenant Security Gateway (CSC337 – Lab 05)

Node.js + Express + MySQL project that implements:

- **Hybrid auth**: Local (bcrypt) + Social OAuth 2.0 (Google / GitHub via Passport.js)
- **Tokens**: Access token (15 min, Bearer header) + Refresh token (7 days, `httpOnly`, `Secure`, `SameSite=Strict` cookie) with **rotation**, **reuse detection** and **revocation on logout**
- **RBAC**: `SuperAdmin`, `Manager`, `Employee` via `checkRole([...])` middleware
- **OWASP hardening**: Helmet, strict CORS, XSS sanitization, parameterized SQL (no SQL injection), rate limiting + account lockout, 10kb body limit

## Live Links
- Live App: `https://YOUR-APP.up.railway.app`
- API Base URL: `https://YOUR-APP.up.railway.app/api/v1`

## Test Credentials
| Role | Email | Password |
|------|-------|----------|
| SuperAdmin | superadmin@test.com | Admin@12345 |
| Manager | manager@test.com | Manager@12345 |
| Employee | employee@test.com | Employee@12345 |

## API Endpoints
| Method | Route | Access |
|--------|-------|--------|
| POST | /api/v1/auth/register | Public (role = Employee) |
| POST | /api/v1/auth/login | Public (5 attempts / 15 min) |
| POST | /api/v1/auth/refresh | Refresh cookie (rotates token) |
| POST | /api/v1/auth/logout | Revokes refresh token |
| GET | /api/v1/auth/google , /github | Social login |
| GET | /api/v1/employee/profile | All authenticated roles |
| POST | /api/v1/payroll/approve | Manager, SuperAdmin |
| DELETE | /api/v1/users/:id | SuperAdmin only |

## Local Setup (Laragon + MySQL)
```bash
npm install
cp .env.example .env      # then fill values (create DB `security_gateway` in Laragon first)
npm run seed              # creates the 3 test accounts
npm start                 # http://localhost:5000
```

## OAuth Setup
- **Google**: Google Cloud Console → Credentials → OAuth client ID (Web). Redirect URI: `BASE_URL/api/v1/auth/google/callback`
- **GitHub**: Settings → Developer settings → OAuth Apps. Callback URL: `BASE_URL/api/v1/auth/github/callback`

## Security Notes
- Passwords: bcrypt (cost 12), salted automatically. No plain-text storage.
- Refresh tokens are stored **hashed (SHA-256)** in DB; reuse of an old token revokes all sessions of that user.
- Role is never accepted from the client on register.
- All SQL uses `?` placeholders; input is cleaned by `xss` and operator keys (`$...`) are dropped.

## Deployment (Railway)
Add a MySQL service + deploy this repo. Set env vars from `.env.example` (`MYSQL_URL` = `${{MySQL.MYSQL_URL}}`, `NODE_ENV=production`, `BASE_URL` = your Railway URL). Run `npm run seed` once.

## Viva Demo Checklist (Postman)
1. **OAuth Login** – open `/` → "Login with Google/GitHub".
2. **Refresh Rotation** – login, call `POST /auth/refresh` twice; reuse the *old* cookie → 401 "reuse detected".
3. **Rate limit / Lockout** – 6 wrong passwords on `/auth/login` → 429 / 423.
4. **RBAC** – Employee token on `POST /payroll/approve` → 403; Manager token on `DELETE /users/:id` → 403.
