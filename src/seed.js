require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool, init } = require('./db');

const accounts = [
  ['Super Admin', 'superadmin@test.com', 'Admin@12345', 'SuperAdmin'],
  ['Manager User', 'manager@test.com', 'Manager@12345', 'Manager'],
  ['Employee User', 'employee@test.com', 'Employee@12345', 'Employee'],
];

(async () => {
  await init();
  for (const [name, email, pass, role] of accounts) {
    const hash = await bcrypt.hash(pass, 12);
    await pool.query(
      `INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role), failed_attempts = 0, locked_until = NULL`,
      [name, email, hash, role]
    );
    console.log(`Seeded ${role}: ${email}`);
  }
  await pool.end();
})().catch((e) => { console.error(e); process.exit(1); });
