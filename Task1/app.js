"use strict";
/* ---------- Helpers ---------- */
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const mem = {};
const store = (area) => ({
  get(k, d) { try { const v = window[area].getItem(k); return v ? JSON.parse(v) : d; } catch { return k in mem ? mem[k] : d; } },
  set(k, v) { try { window[area].setItem(k, JSON.stringify(v)); } catch { mem[k] = v; } },
  del(k) { try { window[area].removeItem(k); } catch { delete mem[k]; } }
});
const db = store('localStorage'), ses = store('sessionStorage');

/* ---------- Password hashing (PBKDF2-SHA256 via Web Crypto) ---------- */
const ITER = 310000, IDLE_MS = 15 * 60 * 1000, MAX_FAILS = 5, LOCK_MS = 30000;
async function hashPw(pw, salt, iter = ITER) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, 256));
}
function safeEq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
async function makeRecord(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { salt: b64(salt), hash: b64(await hashPw(pw, salt)), iter: ITER };
}

/* ---------- Validation ---------- */
const RULES = [[/.{10,}/, 'At least 10 characters'], [/[a-z]/, 'A lowercase letter'], [/[A-Z]/, 'An uppercase letter'], [/\d/, 'A number'], [/[^A-Za-z0-9]/, 'A symbol']];
const pwOk = p => RULES.every(([re]) => re.test(p));
const emailOk = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);

/* ---------- User store ---------- */
const users = () => db.get('gh_users', {});
const saveUsers = u => db.set('gh_users', u);
async function seed() {
  const u = users();
  if (!Object.values(u).some(x => x.role === 'admin')) {
    u['admin@example.com'] = { email: 'admin@example.com', name: 'Demo Admin', role: 'admin', created: Date.now(), ...(await makeRecord('Admin@12345')) };
    saveUsers(u);
  }
}
async function register(name, email, pw) {
  name = name.trim(); email = email.trim().toLowerCase();
  if (name.length < 2) throw new Error('Enter your name.');
  if (!emailOk(email)) throw new Error('Enter a valid email address.');
  if (!pwOk(pw)) throw new Error('Password does not meet all requirements.');
  const u = users();
  if (u[email]) throw new Error('An account with this email already exists. Try signing in.');
  u[email] = { email, name, role: 'user', created: Date.now(), ...(await makeRecord(pw)) };
  saveUsers(u);
}

/* ---------- Login with throttling ---------- */
async function login(email, pw) {
  email = email.trim().toLowerCase();
  const fails = db.get('gh_fails', {}), f = fails[email] || { n: 0, until: 0 };
  if (f.until > Date.now()) throw new Error(`Too many attempts. Try again in ${Math.ceil((f.until - Date.now()) / 1000)}s.`);
  const user = users()[email];
  // Hash even for unknown emails so response time doesn't reveal whether an account exists.
  const salt = user ? unb64(user.salt) : crypto.getRandomValues(new Uint8Array(16));
  const h = await hashPw(pw, salt, user ? user.iter : ITER);
  if (!user || !safeEq(h, unb64(user.hash))) {
    f.n++; if (f.n >= MAX_FAILS) { f.until = Date.now() + LOCK_MS; f.n = 0; }
    fails[email] = f; db.set('gh_fails', fails);
    throw new Error('Incorrect email or password.');
  }
  delete fails[email]; db.set('gh_fails', fails);
  const token = b64(crypto.getRandomValues(new Uint8Array(32)));
  ses.set('gh_session', { token, email, exp: Date.now() + IDLE_MS });
}

/* ---------- Session ---------- */
function current() {
  const s = ses.get('gh_session', null);
  if (!s) return null;
  const user = users()[s.email];
  if (s.exp < Date.now() || !user) { ses.del('gh_session'); return null; }
  return { ...user, token: s.token, exp: s.exp };
}
function touch() { const s = ses.get('gh_session', null); if (s && s.exp > Date.now()) { s.exp = Date.now() + IDLE_MS; ses.set('gh_session', s); } }
function logout(msg) { ses.del('gh_session'); flash = msg ? { t: 'info', m: msg } : null; location.hash = '#/login'; route(); }

/* ---------- Router with guards ---------- */
let flash = null, nextPath = null;
const routes = {
  '': { view: vHome },
  login: { view: vLogin, guest: true },
  register: { view: vRegister, guest: true },
  dashboard: { view: vDash, auth: true },
  profile: { view: vProfile, auth: true },
  admin: { view: vAdmin, auth: true, roles: ['admin'] }
};
function route() {
  const path = location.hash.replace(/^#\/?/, '');
  const r = routes[path];
  const user = current();
  renderNav(user, path);
  if (!r) return view(`<div class="text-center py-5"><h1 class="h3">Page not found</h1><a href="#/" class="btn btn-primary mt-3">Go home</a></div>`);
  if (r.auth && !user) { nextPath = path; flash = { t: 'warning', m: 'Sign in to view that page.' }; location.hash = '#/login'; return; }
  if (r.guest && user) { location.hash = '#/dashboard'; return; }
  if (r.roles && !r.roles.includes(user.role)) {
    return view(`<div class="text-center py-5"><h1 class="h3">403 – Access denied</h1><p class="text-body-secondary">Your role (<strong>${esc(user.role)}</strong>) can't open this page.</p><a href="#/dashboard" class="btn btn-primary">Back to dashboard</a></div>`);
  }
  touch();
  r.view(user);
}
function view(html) {
  const f = flash ? `<div class="alert alert-${flash.t} auth-card" role="alert">${esc(flash.m)}</div>` : '';
  flash = null; $('#app').innerHTML = f + html; const el = $('#app input'); if (el) el.focus({ preventScroll: true });
}
function renderNav(user, path) {
  const l = (h, t) => `<li class="nav-item"><a class="nav-link ${path === h ? 'active fw-bold' : ''}" href="#/${h}">${t}</a></li>`;
  $('#nav').innerHTML = user
    ? l('dashboard', 'Dashboard') + l('profile', 'Profile') + (user.role === 'admin' ? l('admin', 'Admin') : '') +
      `<li class="nav-item"><button class="btn btn-outline-secondary btn-sm ms-2" id="lo">Sign out</button></li>`
    : l('login', 'Sign in') + `<li class="nav-item"><a class="btn btn-primary btn-sm ms-1" href="#/register">Create account</a></li>`;
  const lo = $('#lo'); if (lo) lo.onclick = () => logout('You have been signed out.');
}
function bindForm(id, fn) {
  const f = $(id), err = f.querySelector('.err');
  f.addEventListener('submit', async e => {
    e.preventDefault(); err.innerHTML = '';
    const btn = f.querySelector('[type=submit]'); btn.disabled = true;
    try { await fn(Object.fromEntries(new FormData(f)), f); }
    catch (x) { err.innerHTML = `<div class="alert alert-danger py-2" role="alert">${esc(x.message)}</div>`; }
    finally { btn.disabled = false; }
  });
}
const pwField = (name, label, auto, extra = '') => `
  <div class="mb-3"><label class="form-label" for="${name}">${label}</label>
  <div class="input-group"><input class="form-control" type="password" id="${name}" name="${name}" autocomplete="${auto}" required ${extra}>
  <button class="btn btn-outline-secondary" type="button" data-show="${name}">Show</button></div></div>`;
function bindShow() {
  document.querySelectorAll('[data-show]').forEach(b => b.onclick = () => {
    const i = $('#' + b.dataset.show), show = i.type === 'password'; i.type = show ? 'text' : 'password'; b.textContent = show ? 'Hide' : 'Show';
  });
}
function bindStrength(inputId) {
  const i = $(inputId), box = $('#rules');
  const upd = () => {
    const v = i.value, n = RULES.filter(([re]) => re.test(v)).length;
    $('#meter').style.width = (n / RULES.length * 100) + '%';
    $('#meter').className = 'progress-bar ' + (n < 3 ? 'bg-danger' : n < 5 ? 'bg-warning' : 'bg-success');
    box.innerHTML = RULES.map(([re, t]) => `<li class="${re.test(v) ? 'rule-ok' : 'rule-no'}">${re.test(v) ? '✓' : '○'} ${t}</li>`).join('');
  };
  i.addEventListener('input', upd); upd();
}
const strengthUI = `<div class="progress mb-2" style="height:6px"><div id="meter" class="progress-bar" style="width:0"></div></div><ul id="rules" class="list-unstyled small mb-3"></ul>`;

/* ---------- Views ---------- */
function vHome() {
  view(`<div class="hero text-center mx-auto py-4" style="max-width:720px">
    <h1>Sign in once. Reach only what your role allows.</h1>
    <p class="lead text-body-secondary my-4">A working authentication demo: registration, salted password hashing, expiring sessions, and role-based protected routes.</p>
    <a href="#/register" class="btn btn-primary btn-lg me-2">Create account</a><a href="#/login" class="btn btn-outline-secondary btn-lg">Sign in</a></div>
    <div class="row g-3 mt-3">
    ${[['Password hashing', 'PBKDF2-SHA256, 310,000 iterations, unique random salt per user.'],
       ['Session management', 'Random 256-bit token, 15-minute idle timeout, cleared when the tab closes.'],
       ['Role-based access', 'Routes declare which roles may enter. Admin pages return 403 for everyone else.']]
      .map(([t, d]) => `<div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h6">${t}</h2><p class="mb-0 small text-body-secondary">${d}</p></div></div></div>`).join('')}
    </div>
    <p class="text-center small text-body-secondary mt-4">Demo admin: <code>admin@example.com</code> / <code>Admin@12345</code></p>`);
}
function vLogin() {
  view(`<div class="card auth-card"><div class="card-body p-4">
    <h1 class="h4 mb-4">Sign in</h1>
    <form id="f" novalidate><div class="err"></div>
      <div class="mb-3"><label class="form-label" for="email">Email</label><input class="form-control" id="email" name="email" type="email" autocomplete="username" required></div>
      ${pwField('password', 'Password', 'current-password')}
      <button class="btn btn-primary w-100" type="submit">Sign in</button></form>
    <p class="small text-center mt-3 mb-0">New here? <a href="#/register">Create an account</a></p></div></div>`);
  bindShow();
  bindForm('#f', async d => {
    await login(d.email, d.password);
    const to = nextPath || 'dashboard'; nextPath = null; location.hash = '#/' + to;
  });
}
function vRegister() {
  view(`<div class="card auth-card"><div class="card-body p-4">
    <h1 class="h4 mb-4">Create your account</h1>
    <form id="f" novalidate><div class="err"></div>
      <div class="mb-3"><label class="form-label" for="name">Full name</label><input class="form-control" id="name" name="name" autocomplete="name" required></div>
      <div class="mb-3"><label class="form-label" for="email">Email</label><input class="form-control" id="email" name="email" type="email" autocomplete="username" required></div>
      ${pwField('password', 'Password', 'new-password')}${strengthUI}
      ${pwField('confirm', 'Confirm password', 'new-password')}
      <button class="btn btn-primary w-100" type="submit">Create account</button></form>
    <p class="small text-center mt-3 mb-0">Already registered? <a href="#/login">Sign in</a></p></div></div>`);
  bindShow(); bindStrength('#password');
  bindForm('#f', async d => {
    if (d.password !== d.confirm) throw new Error('Passwords do not match.');
    await register(d.name, d.email, d.password);
    flash = { t: 'success', m: 'Account created. Sign in to continue.' }; location.hash = '#/login';
  });
}
function vDash(u) {
  const card = (h, t, d, href) => `<div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h6">${t}</h2><p class="small text-body-secondary">${d}</p><a href="#/${h}" class="btn btn-sm btn-outline-primary">Open</a></div></div></div>`;
  view(`<h1 class="h3 mb-1">Welcome, ${esc(u.name)}</h1>
    <p class="text-body-secondary">Signed in as ${esc(u.email)} · role <span class="badge text-bg-${u.role === 'admin' ? 'danger' : 'secondary'}">${esc(u.role)}</span></p>
    <div class="row g-3 mb-4">
      ${card('profile', 'Profile', 'Change your password.')}
      ${u.role === 'admin' ? card('admin', 'User management', 'View accounts and change roles. Visible to admins only.') : `<div class="col-md-4"><div class="card h-100 border-dashed"><div class="card-body"><h2 class="h6">User management</h2><p class="small text-body-secondary mb-0">Requires the admin role.</p></div></div></div>`}
    </div>
    <div class="card"><div class="card-body"><h2 class="h6">Current session</h2>
      <p class="small mb-1">Token: <span class="token">${esc(u.token.slice(0, 16))}…</span></p>
      <p class="small mb-0">Idle timeout in <strong id="cd"></strong></p></div></div>`);
}
function vProfile(u) {
  view(`<div class="card auth-card"><div class="card-body p-4"><h1 class="h4 mb-1">Profile</h1>
    <p class="text-body-secondary small mb-4">${esc(u.name)} · ${esc(u.email)}</p>
    <h2 class="h6">Change password</h2>
    <form id="f" novalidate><div class="err"></div>
      ${pwField('cur', 'Current password', 'current-password')}${pwField('password', 'New password', 'new-password')}${strengthUI}
      <button class="btn btn-primary" type="submit">Update password</button></form></div></div>`);
  bindShow(); bindStrength('#password');
  bindForm('#f', async (d, f) => {
    const all = users(), me = all[u.email];
    if (!safeEq(await hashPw(d.cur, unb64(me.salt), me.iter), unb64(me.hash))) throw new Error('Current password is incorrect.');
    if (!pwOk(d.password)) throw new Error('New password does not meet all requirements.');
    all[u.email] = { ...me, ...(await makeRecord(d.password)) }; saveUsers(all);
    f.reset(); bindStrength('#password');
    f.querySelector('.err').innerHTML = '<div class="alert alert-success py-2">Password updated.</div>';
  });
}
function vAdmin(u) {
  const rows = Object.values(users()).map(x => `<tr>
    <td>${esc(x.name)}</td><td>${esc(x.email)}</td>
    <td><select class="form-select form-select-sm" data-role="${esc(x.email)}" ${x.email === u.email ? 'disabled' : ''}>
      ${['user', 'admin'].map(r => `<option ${x.role === r ? 'selected' : ''}>${r}</option>`).join('')}</select></td>
    <td class="text-end"><button class="btn btn-sm btn-outline-danger" data-del="${esc(x.email)}" ${x.email === u.email ? 'disabled' : ''}>Delete</button></td></tr>`).join('');
  view(`<h1 class="h3 mb-3">User management</h1>
    <div class="card"><div class="table-wrap"><table class="table align-middle mb-0"><thead><tr><th>Name</th><th>Email</th><th style="width:140px">Role</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>
    <p class="small text-body-secondary mt-2">You can't change or delete your own account here.</p>`);
  document.querySelectorAll('[data-role]').forEach(s => s.onchange = () => { const all = users(); all[s.dataset.role].role = s.value; saveUsers(all); });
  document.querySelectorAll('[data-del]').forEach(b => b.onclick = () => {
    if (!confirm('Delete ' + b.dataset.del + '?')) return;
    const all = users(); delete all[b.dataset.del]; saveUsers(all); vAdmin(u);
  });
}

/* ---------- Boot ---------- */
setInterval(() => {
  const s = ses.get('gh_session', null);
  if (!s) return;
  if (s.exp < Date.now()) return logout('Your session expired. Sign in again.');
  const cd = $('#cd'); if (cd) { const t = Math.max(0, Math.round((s.exp - Date.now()) / 1000)); cd.textContent = Math.floor(t / 60) + 'm ' + String(t % 60).padStart(2, '0') + 's'; }
}, 1000);
['click', 'keydown'].forEach(ev => addEventListener(ev, touch, { passive: true }));
addEventListener('hashchange', route);
const mq = matchMedia('(prefers-color-scheme: dark)');
const theme = () => document.documentElement.setAttribute('data-bs-theme', mq.matches ? 'dark' : 'light');
mq.addEventListener('change', theme); theme();
seed().then(route);
