const express = require('express');
const { pool } = require('../db');
const { authenticate, checkRole } = require('../middleware/auth');

const router = express.Router();

// All authenticated roles
router.get('/employee/profile', authenticate, checkRole(['SuperAdmin', 'Manager', 'Employee']), async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, role, provider, created_at FROM users WHERE id = ?', [req.user.id]);
    res.json({ profile: rows[0] });
  } catch (e) { next(e); }
});

// Manager + SuperAdmin only
router.post('/payroll/approve', authenticate, checkRole(['Manager', 'SuperAdmin']), (req, res) => {
  const { employeeId, amount } = req.body || {};
  if (!employeeId || !Number(amount) || Number(amount) <= 0) {
    return res.status(400).json({ message: 'employeeId and a positive amount are required' });
  }
  res.json({ message: `Payroll of ${Number(amount)} approved for employee ${employeeId}`, approvedBy: req.user.email });
});

// SuperAdmin only
router.delete('/users/:id', authenticate, checkRole(['SuperAdmin']), async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ message: 'Invalid user id' });
    const [r] = await pool.query('DELETE FROM users WHERE id = ?', [id]);
    if (!r.affectedRows) return res.status(404).json({ message: 'User not found' });
    res.json({ message: `User ${id} deleted` });
  } catch (e) { next(e); }
});

module.exports = router;
