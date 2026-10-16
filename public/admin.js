// IT staff queue: open/close a session, show the rotating session code, and
// approve or reject requests after checking the student's ID card in person.
// Passwords are never sent to this page.
const POLL_MS = 2000;
const STATUS = {
  pending: ['Waiting for you', 'off'], approved: ['Approved, waiting for worker', 'on'],
  processing: ['Resetting…', 'on'], done: ['Password changed', 'on'],
  rejected: ['Rejected', 'off'], failed: ['Failed', 'bad'],
};
const FAIL_REASON = {
  policy: 'the password does not meet the domain password policy',
  not_found: 'no student account with this ID in the Student Users OU',
  not_unique: 'more than one account matched this ID',
  payload_mismatch: 'the encrypted data did not match this request',
  decrypt_failed: 'the worker could not decrypt the request (wrong key?)',
  dry_run: 'dry run: account found, password NOT changed',
  error: 'unexpected error on the worker; check its console',
};

let data = null, loggedIn = null, lastJson = '', loginError = '', busy = false;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ago = (ms, now) => { const s = Math.max(0, Math.round((now - ms) / 1000)); return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)} min ago`; };

async function api(path, body) {
  const r = await fetch('/api/admin/' + path, body === undefined
    ? { cache: 'no-store' }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (r.status === 401) { loggedIn = false; data = null; }
  return r;
}

async function refresh() {
  try {
    const r = await api('state');
    if (r.ok) { loggedIn = true; data = await r.json(); data.clientOffset = Date.now() - data.now; }
  } catch (e) { /* keep showing the last state */ }
  const json = JSON.stringify([loggedIn, data && { ...data, now: 0, clientOffset: 0 }, loginError, busy]);
  if (json !== lastJson) { lastJson = json; render(); } else updateClock();
}

function loginView() {
  return `<form class="panel login" id="login">
    <h2>IT staff sign-in</h2>
    <label class="muted" for="pw">Admin password</label>
    <input id="pw" type="password" autocomplete="current-password" required autofocus>
    ${loginError ? `<div class="error">${esc(loginError)}</div>` : ''}
    <button class="btn primary" type="submit">Sign in</button>
  </form>`;
}

function ticketView(t, now) {
  const [label, cls] = STATUS[t.status] || [t.status, 'off'];
  const reason = t.status === 'failed' ? `<div class="t-meta">${esc(FAIL_REASON[t.error] || t.error)}</div>` : '';
  const actions = t.status === 'pending'
    ? `<div class="row"><button class="btn ok" data-approve="${esc(t.id)}">Approve</button><button class="btn danger" data-reject="${esc(t.id)}">Reject</button></div>`
    : `<span class="pill ${cls}">${esc(label)}</span>`;
  return `<div class="ticket ${t.status}">
    <div><div class="t-name">${esc(t.name)}</div><div class="t-id">${esc(t.studentId)}</div>
      <div class="t-meta">Requested ${ago(t.createdAt, now)}${t.status === 'pending' ? '' : ' · ' + esc(label)}</div>${reason}</div>
    ${actions}
  </div>`;
}

function mainView() {
  const s = data.session, now = data.now, w = data.worker;
  const worker = w.connected
    ? `<span class="pill on">Worker connected</span>`
    : `<span class="pill bad">Worker not connected${w.lastSeen ? ' · last seen ' + ago(w.lastSeen, now) : ''}</span>`;
  const sessionPanel = s.open
    ? `<div class="panel"><div class="session">
        <div><div class="muted">Session code: show this to students in the room</div>
          <div class="code" id="code">${esc(s.code.slice(0, 3))} ${esc(s.code.slice(3))}</div>
          <div class="muted" id="clock"></div></div>
        <div class="row" style="flex-direction:column;align-items:stretch">
          <span class="pill on">Session open</span>${worker}
          <button class="btn" data-act="rotate">New code now</button>
          <button class="btn danger" data-act="close">Close session</button></div>
      </div></div>`
    : `<div class="panel"><div class="session">
        <div><h2>No session open</h2><div class="muted">Students cannot send requests until you open a session.</div></div>
        <div class="row" style="flex-direction:column;align-items:stretch">${worker}<button class="btn primary" data-act="open">Open session</button></div>
      </div></div>`;
  const pending = data.tickets.filter(t => t.status === 'pending');
  const queue = s.open ? `<div class="panel">
      <h2>Requests (${pending.length} waiting)</h2>
      <div class="reminder">Before approving, check the student's ID card: the <b>name</b> and <b>student ID</b> must match the card and the student's phone screen.</div>
      <div class="tickets">${data.tickets.length ? data.tickets.map(t => ticketView(t, now)).join('') : '<div class="empty">No requests yet.</div>'}</div>
    </div>` : '';
  return sessionPanel + queue;
}

function render() {
  const app = document.getElementById('app');
  if (loggedIn === null) { app.innerHTML = ''; return; }
  app.innerHTML = `<div class="wrap">
    <div class="top"><b>South Bank Colleges · Password reset</b>${loggedIn ? '<button class="link" data-act="logout">Sign out</button>' : ''}</div>
    ${loggedIn && data ? mainView() : loginView()}
  </div>`;
  updateClock();
}

function updateClock() {
  const el = document.getElementById('clock');
  if (!el || !data || !data.session.open) return;
  const left = Math.max(0, Math.round((data.session.codeExpiresAt - (Date.now() - data.clientOffset)) / 1000));
  el.textContent = `Changes in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} (the previous code keeps working for one more round)`;
}

document.addEventListener('submit', async e => {
  if (e.target.id !== 'login') return;
  e.preventDefault();
  const r = await api('login', { password: document.getElementById('pw').value });
  loginError = r.ok ? '' : r.status === 429 ? 'Too many attempts. Wait 10 minutes.' : 'Wrong password.';
  await refresh();
});

document.addEventListener('click', async e => {
  const b = e.target.closest('button'); if (!b || busy) return;
  const d = b.dataset;
  let call = null;
  if (d.approve) call = () => api(`tickets/${encodeURIComponent(d.approve)}/approve`, {});
  else if (d.reject) call = () => api(`tickets/${encodeURIComponent(d.reject)}/reject`, {});
  else if (d.act === 'open') call = () => api('session', { open: true });
  else if (d.act === 'rotate') call = () => api('session', { rotate: true });
  else if (d.act === 'close') {
    if (!confirm('Close the session? Students can no longer send requests, and all requests in the queue are deleted.')) return;
    call = () => api('session', { open: false });
  } else if (d.act === 'logout') call = () => api('logout', {});
  if (!call) return;
  busy = true;
  try { await call(); } finally { busy = false; await refresh(); }
});

refresh();
setInterval(refresh, POLL_MS);
setInterval(updateClock, 1000);
