let accessToken = null; // kept in memory only (never localStorage)
const $ = (id) => document.getElementById(id);
const out = (title, status, data) => { $('output').textContent = `${title}\nHTTP ${status}\n\n${JSON.stringify(data, null, 2)}`; };

async function api(method, path, body) {
  const res = await fetch('/api/v1' + path, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(accessToken ? { Authorization: 'Bearer ' + accessToken } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty */ }
  return { status: res.status, data };
}

function setUser(data) {
  if (data.accessToken) {
    accessToken = data.accessToken;
    $('status').className = 'alert alert-success';
    $('status').textContent = `Logged in: ${data.user.email} (${data.user.role}) via ${data.user.provider}`;
  }
}

async function silentRefresh() {
  const { status, data } = await api('POST', '/auth/refresh');
  if (status === 200) setUser(data);
  return { status, data };
}

$('btnRegister').onclick = async () => {
  const r = await api('POST', '/auth/register', { name: $('rName').value, email: $('rEmail').value, password: $('rPass').value });
  out('REGISTER', r.status, r.data);
};
$('btnLogin').onclick = async () => {
  const r = await api('POST', '/auth/login', { email: $('lEmail').value, password: $('lPass').value });
  setUser(r.data); out('LOGIN', r.status, r.data);
};
$('btnProfile').onclick = async () => { const r = await api('GET', '/employee/profile'); out('GET /employee/profile', r.status, r.data); };
$('btnPayroll').onclick = async () => { const r = await api('POST', '/payroll/approve', { employeeId: 3, amount: 50000 }); out('POST /payroll/approve', r.status, r.data); };
$('btnDelete').onclick = async () => { const r = await api('DELETE', '/users/999'); out('DELETE /users/999', r.status, r.data); };
$('btnRefresh').onclick = async () => { const r = await silentRefresh(); out('REFRESH (token rotated)', r.status, r.data); };
$('btnLogout').onclick = async () => {
  const r = await api('POST', '/auth/logout'); accessToken = null;
  $('status').className = 'alert alert-secondary'; $('status').textContent = 'Not logged in';
  out('LOGOUT', r.status, r.data);
};

// After OAuth redirect, get an access token using the refresh cookie
const oauthState = new URLSearchParams(location.search).get('oauth');
if (oauthState === 'success') {
  silentRefresh().then((r) => { out('OAUTH LOGIN', r.status, r.data); history.replaceState({}, '', '/'); });
} else if (oauthState === 'failed') {
  out('OAUTH LOGIN', 401, { message: 'OAuth login failed' });
}
