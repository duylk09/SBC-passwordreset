// HTTP API and static file server for the student password reset service.
//
// All state is held in memory on purpose: tickets only live for the length of a
// supervised session, and the only secret material (password ciphertext) is
// deleted as soon as a ticket is finished. Run exactly one instance.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/admin': ['admin.html', 'text/html; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/admin.css': ['admin.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/admin.js': ['admin.js', 'text/javascript; charset=utf-8'],
  '/i18n.js': ['i18n.js', 'text/javascript; charset=utf-8'],
};

const STUDENT_ID_RE = /^[A-Za-z0-9]{3,20}$/;
const CODE_RE = /^\d{6}$/;
const CIPHERTEXT_RE = /^[A-Za-z0-9_-]{16,1024}$/;
const ERROR_CODES = new Set(['policy', 'not_found', 'not_unique', 'payload_mismatch', 'decrypt_failed', 'dry_run', 'error']);

export const DEFAULTS = {
  codeRotateMs: 5 * 60_000,     // session code changes every 5 minutes
  ticketTtlMs: 30 * 60_000,     // finished/abandoned tickets disappear after 30 minutes
  adminSessionMs: 12 * 3600_000,
  workerStaleMs: 15_000,        // worker shown as disconnected after this long without polling
  codeFailLimitPerIp: 10,       // wrong session codes per IP per window
  codeFailLimitGlobal: 50,      // wrong codes (all IPs) before the code is rotated early
  loginFailLimitPerIp: 5,
  rateWindowMs: 10 * 60_000,
  maxActiveTickets: 200,
};

const b64url = buf => Buffer.from(buf).toString('base64url');
const randomId = (bytes = 16) => b64url(crypto.randomBytes(bytes));
const sha256 = s => crypto.createHash('sha256').update(s).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
const newCode = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');

export function validatePublicKey(jwk) {
  if (!jwk || jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
    throw new Error('PUBLIC_KEY_JWK must be an RSA public key in JWK form');
  }
  if (jwk.d) throw new Error('PUBLIC_KEY_JWK contains a private key. Use only the public part.');
  const bits = Buffer.from(jwk.n, 'base64url').length * 8;
  if (bits < 3072) throw new Error(`PUBLIC_KEY_JWK must be at least 3072 bits (got ${bits})`);
  return { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RSA-OAEP-256' };
}

export function createApp(options) {
  const cfg = { ...DEFAULTS, ...options };
  if (!cfg.adminPassword || cfg.adminPassword.length < 12) throw new Error('ADMIN_PASSWORD must be set (12+ characters)');
  if (!cfg.workerToken || cfg.workerToken.length < 32) throw new Error('WORKER_TOKEN must be set (32+ characters)');
  const publicKey = validatePublicKey(cfg.publicKeyJwk);
  const now = cfg.now || Date.now;

  let session = null;                 // { id, openedAt, code, prevCode, codeFrom, codeFails }
  const tickets = new Map();          // id -> ticket
  const adminTokens = new Map();      // sha256(token) hex -> expiry
  const failures = new Map();         // `${kind}:${ip}` -> [timestamps]
  let workerLastSeen = 0;

  // ---- helpers --------------------------------------------------------------

  function rotateIfDue() {
    if (!session) return;
    if (now() - session.codeFrom >= cfg.codeRotateMs) rotateCode();
  }
  function rotateCode() {
    session.prevCode = session.code;
    session.code = newCode();
    session.codeFrom = now();
    session.codeFails = 0;
  }
  function codeMatches(code) {
    rotateIfDue();
    if (!session) return false;
    // The previous code is still accepted, so a student who read it just before
    // it changed is not turned away.
    return safeEqual(code, session.code) || (session.prevCode !== null && safeEqual(code, session.prevCode));
  }
  function sweep() {
    const t = now();
    for (const [id, tk] of tickets) {
      if (tk.status !== 'processing' && t - tk.createdAt > cfg.ticketTtlMs) tickets.delete(id);
    }
    for (const [k, exp] of adminTokens) if (exp < t) adminTokens.delete(k);
    for (const [k, list] of failures) {
      const kept = list.filter(x => t - x < cfg.rateWindowMs);
      if (kept.length) failures.set(k, kept); else failures.delete(k);
    }
  }
  function failCount(kind, ip) {
    const t = now();
    return (failures.get(`${kind}:${ip}`) || []).filter(x => t - x < cfg.rateWindowMs).length;
  }
  function recordFail(kind, ip) {
    const k = `${kind}:${ip}`;
    failures.set(k, [...(failures.get(k) || []), now()]);
  }
  function finish(tk, status, error = null) {
    tk.status = status;
    tk.error = error;
    tk.updatedAt = now();
    tk.ciphertext = null; // never keep ciphertext once a ticket is decided
  }
  function closeSession() {
    session = null;
    tickets.clear(); // pending tickets (and their ciphertext) are discarded
  }

  function clientIp(req) {
    if (cfg.trustProxy) {
      const fwd = req.headers['x-forwarded-for'];
      if (fwd) return String(fwd).split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
  }
  function isAdmin(req) {
    const m = /(?:^|;\s*)sbc_admin=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '');
    if (!m) return false;
    const exp = adminTokens.get(sha256(m[1]).toString('hex'));
    return !!exp && exp > now();
  }
  function isWorker(req) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    return !!m && safeEqual(m[1], cfg.workerToken);
  }
  // State-changing admin calls must be same-origin JSON requests (CSRF guard on
  // top of the SameSite=Strict cookie).
  function sameOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return true;
    try { return new URL(origin).host === req.headers.host; } catch { return false; }
  }

  function send(res, status, body, headers = {}) {
    const data = body === undefined ? '' : JSON.stringify(body);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    });
    res.end(data);
  }
  function readJson(req) {
    return new Promise((resolve, reject) => {
      if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) return reject(Object.assign(new Error('json'), { status: 415 }));
      let size = 0; const chunks = [];
      req.on('data', c => {
        size += c.length;
        if (size > 8192) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
        catch { reject(Object.assign(new Error('bad json'), { status: 400 })); }
      });
      req.on('error', reject);
    });
  }

  function publicTicket(tk) {
    return { id: tk.id, studentId: tk.studentId, name: tk.name, status: tk.status, error: tk.error, createdAt: tk.createdAt, updatedAt: tk.updatedAt };
  }

  // ---- routes ---------------------------------------------------------------

  async function handleApi(req, res, url) {
    const p = url.pathname, m = req.method;
    sweep();

    if (p === '/api/config' && m === 'GET') {
      return send(res, 200, { sessionOpen: !!session, sessionId: session ? session.id : null, publicKey });
    }

    if (p === '/api/tickets' && m === 'POST') {
      const ip = clientIp(req);
      if (failCount('code', ip) >= cfg.codeFailLimitPerIp) return send(res, 429, { error: 'rate_limited' });
      const body = await readJson(req);
      if (!session) return send(res, 409, { error: 'closed' });
      const studentId = String(body.studentId || '');
      const name = String(body.name || '').trim().replace(/\s+/g, ' ');
      const sessionCode = String(body.sessionCode || '');
      const ciphertext = String(body.ciphertext || '');
      if (!STUDENT_ID_RE.test(studentId) || name.length < 2 || name.length > 80 || !CIPHERTEXT_RE.test(ciphertext) || !CODE_RE.test(sessionCode)) {
        return send(res, 400, { error: 'invalid' });
      }
      if (!codeMatches(sessionCode)) {
        recordFail('code', ip);
        if (++session.codeFails >= cfg.codeFailLimitGlobal) rotateCode();
        return send(res, 403, { error: 'bad_code' });
      }
      if (tickets.size >= cfg.maxActiveTickets) return send(res, 503, { error: 'busy' });
      // A new request for the same ID replaces an earlier one that has not started yet.
      for (const tk of tickets.values()) {
        if (tk.studentId.toLowerCase() === studentId.toLowerCase() && tk.status === 'pending') finish(tk, 'replaced');
      }
      const tk = {
        id: randomId(), token: randomId(24), sessionId: session.id,
        studentId, name, ciphertext, status: 'pending', error: null,
        createdAt: now(), updatedAt: now(),
      };
      tickets.set(tk.id, tk);
      return send(res, 201, { ticketId: tk.id, token: tk.token });
    }

    let mm;
    if ((mm = /^\/api\/tickets\/([A-Za-z0-9_-]+)$/.exec(p)) && m === 'GET') {
      const tk = tickets.get(mm[1]);
      if (!tk || !safeEqual(req.headers['x-ticket-token'] || '', tk.token)) return send(res, 404, { error: 'not_found' });
      return send(res, 200, { status: tk.status, error: tk.error });
    }

    // ---- admin ----
    if (p.startsWith('/api/admin/')) {
      if (m !== 'GET' && !sameOrigin(req)) return send(res, 403, { error: 'origin' });

      if (p === '/api/admin/login' && m === 'POST') {
        const ip = clientIp(req);
        if (failCount('login', ip) >= cfg.loginFailLimitPerIp) return send(res, 429, { error: 'rate_limited' });
        const body = await readJson(req);
        if (!safeEqual(String(body.password || ''), cfg.adminPassword)) {
          recordFail('login', ip);
          return send(res, 401, { error: 'bad_password' });
        }
        const token = randomId(32);
        adminTokens.set(sha256(token).toString('hex'), now() + cfg.adminSessionMs);
        const secure = cfg.secureCookies ? '; Secure' : '';
        return send(res, 200, { ok: true }, { 'set-cookie': `sbc_admin=${token}; HttpOnly; SameSite=Strict; Path=/api/admin${secure}; Max-Age=${cfg.adminSessionMs / 1000}` });
      }

      if (!isAdmin(req)) return send(res, 401, { error: 'login_required' });

      if (p === '/api/admin/logout' && m === 'POST') {
        const tok = /(?:^|;\s*)sbc_admin=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '');
        if (tok) adminTokens.delete(sha256(tok[1]).toString('hex'));
        return send(res, 200, { ok: true }, { 'set-cookie': 'sbc_admin=; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=0' });
      }

      if (p === '/api/admin/state' && m === 'GET') {
        rotateIfDue();
        return send(res, 200, {
          session: session ? {
            open: true, openedAt: session.openedAt, code: session.code,
            codeExpiresAt: session.codeFrom + cfg.codeRotateMs,
          } : { open: false },
          tickets: [...tickets.values()].filter(t => t.status !== 'replaced').map(publicTicket).sort((a, b) => b.createdAt - a.createdAt),
          worker: { lastSeen: workerLastSeen || null, connected: now() - workerLastSeen < cfg.workerStaleMs },
          now: now(),
        });
      }

      if (p === '/api/admin/session' && m === 'POST') {
        const body = await readJson(req);
        if (body.open === true) {
          if (!session) session = { id: randomId(), openedAt: now(), code: newCode(), prevCode: null, codeFrom: now(), codeFails: 0 };
        } else if (body.open === false) {
          closeSession();
        } else if (body.rotate === true && session) {
          rotateCode();
        } else {
          return send(res, 400, { error: 'invalid' });
        }
        return send(res, 200, { ok: true });
      }

      if ((mm = /^\/api\/admin\/tickets\/([A-Za-z0-9_-]+)\/(approve|reject)$/.exec(p)) && m === 'POST') {
        const tk = tickets.get(mm[1]);
        if (!tk) return send(res, 404, { error: 'not_found' });
        if (tk.status !== 'pending') return send(res, 409, { error: 'not_pending' });
        if (mm[2] === 'approve') { tk.status = 'approved'; tk.updatedAt = now(); }
        else finish(tk, 'rejected');
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'not_found' });
    }

    // ---- worker ----
    if (p.startsWith('/api/worker/')) {
      if (!isWorker(req)) return send(res, 401, { error: 'unauthorized' });
      workerLastSeen = now();

      if (p === '/api/worker/next' && m === 'POST') {
        const tk = [...tickets.values()].filter(t => t.status === 'approved').sort((a, b) => a.updatedAt - b.updatedAt)[0];
        if (!tk) return send(res, 200, { ticket: null });
        tk.status = 'processing';
        tk.updatedAt = now();
        return send(res, 200, { ticket: { id: tk.id, sessionId: tk.sessionId, studentId: tk.studentId, ciphertext: tk.ciphertext } });
      }

      if ((mm = /^\/api\/worker\/tickets\/([A-Za-z0-9_-]+)\/result$/.exec(p)) && m === 'POST') {
        const body = await readJson(req);
        const tk = tickets.get(mm[1]);
        if (!tk) return send(res, 404, { error: 'not_found' });
        if (tk.status !== 'processing') return send(res, 409, { error: 'not_processing' });
        if (body.ok === true) finish(tk, 'done');
        else finish(tk, 'failed', ERROR_CODES.has(body.error) ? body.error : 'error');
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'not_found' });
    }

    return send(res, 404, { error: 'not_found' });
  }

  function securityHeaders(res) {
    res.setHeader('content-security-policy', [
      "default-src 'self'", "script-src 'self'", "connect-src 'self'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com", "font-src https://fonts.gstatic.com",
      "img-src 'self' data:", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'",
    ].join('; '));
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
    if (cfg.secureCookies) res.setHeader('strict-transport-security', 'max-age=31536000');
  }

  const server = http.createServer(async (req, res) => {
    securityHeaders(res);
    try {
      const url = new URL(req.url, 'http://x');
      if (url.pathname === '/healthz') return send(res, 200, { ok: true });
      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
      const entry = STATIC[url.pathname];
      if (!entry || (req.method !== 'GET' && req.method !== 'HEAD')) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('Not found'); }
      const body = fs.readFileSync(path.join(PUBLIC_DIR, entry[0]));
      res.writeHead(200, { 'content-type': entry[1], 'cache-control': 'no-cache' });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch (err) {
      if (!res.headersSent) send(res, err.status || 500, { error: err.status ? 'bad_request' : 'server_error' });
      if (!err.status) console.error('request failed:', err.message);
    }
  });

  return { server, _debug: { tickets, get session() { return session; } } };
}
