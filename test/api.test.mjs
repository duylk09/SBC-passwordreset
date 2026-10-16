import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createApp, validatePublicKey } from '../server/app.js';
import { openPayload, pollOnce } from '../worker/mock-worker.mjs';

const ADMIN_PASSWORD = 'test-admin-password';
const WORKER_TOKEN = 'test-worker-token-0123456789abcdef0123';
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKeyJwk = publicKey.export({ format: 'jwk' });

let clock = Date.now();
let app, base, cookie = '';

before(async () => {
  app = createApp({ adminPassword: ADMIN_PASSWORD, workerToken: WORKER_TOKEN, publicKeyJwk, now: () => clock });
  await new Promise(r => app.server.listen(0, r));
  base = `http://127.0.0.1:${app.server.address().port}`;
});
after(() => app.server.close());

// Same encryption as public/app.js, using WebCrypto.
async function encrypt(cfg, studentId, pw) {
  const key = await crypto.subtle.importKey('jwk', cfg.publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const header = JSON.stringify({ v: 1, sid: cfg.sessionId, id: studentId, n: 'nonce' });
  return Buffer.from(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, new TextEncoder().encode(header + '\n' + pw))).toString('base64url');
}

const get = (p, headers = {}) => fetch(base + p, { headers: { cookie, ...headers } });
const post = (p, body, headers = {}) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', cookie, ...headers }, body: JSON.stringify(body) });
const admin = async () => (await get('/api/admin/state')).json();
const config = async () => (await get('/api/config')).json();
async function submit(studentId, pw, code, extra = {}) {
  const cfg = await config();
  return post('/api/tickets', { studentId, name: 'Test Student', sessionCode: code, ciphertext: await encrypt(cfg, studentId, pw), ...extra });
}
const worker = (onReset) => pollOnce({ serverUrl: base, workerToken: WORKER_TOKEN, privateKeyPem, onReset });

test('rejects unsafe public keys', () => {
  assert.throws(() => validatePublicKey(privateKey.export({ format: 'jwk' })), /private key/);
  const small = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
  assert.throws(() => validatePublicKey(small), /3072/);
});

test('form is closed until a session is opened', async () => {
  assert.equal((await config()).sessionOpen, false);
  const r = await post('/api/tickets', { studentId: '12345678', name: 'A B', sessionCode: '123456', ciphertext: 'x'.repeat(40) });
  assert.equal(r.status, 409);
});

test('admin login', async () => {
  assert.equal((await get('/api/admin/state')).status, 401);
  assert.equal((await post('/api/admin/login', { password: 'wrong' })).status, 401);
  const r = await post('/api/admin/login', { password: ADMIN_PASSWORD });
  assert.equal(r.status, 200);
  cookie = r.headers.get('set-cookie').split(';')[0];
  assert.match(r.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
});

test('cross-origin admin calls are refused', async () => {
  const r = await post('/api/admin/session', { open: true }, { origin: 'https://evil.example' });
  assert.equal(r.status, 403);
});

test('full flow: submit, approve, worker resets, ciphertext deleted', async () => {
  assert.equal((await post('/api/admin/session', { open: true })).status, 200);
  const { session } = await admin();
  assert.match(session.code, /^\d{6}$/);

  assert.equal((await submit('12345678', 'BlueTiger427#', session.code === '000000' ? '111111' : '000000')).status, 403);
  const r = await submit('12345678', 'BlueTiger427#', session.code);
  assert.equal(r.status, 201);
  const { ticketId, token } = await r.json();

  const status = async () => (await (await get(`/api/tickets/${ticketId}`, { 'x-ticket-token': token })).json()).status;
  assert.equal(await status(), 'pending');
  assert.equal((await get(`/api/tickets/${ticketId}`, { 'x-ticket-token': 'wrong' })).status, 404);

  // The admin view never includes ciphertext.
  const st = await admin();
  assert.equal(st.tickets.length, 1);
  assert.equal(JSON.stringify(st).includes('ciphertext'), false);

  assert.equal(await worker(), null, 'worker gets nothing before approval');
  assert.equal((await post(`/api/admin/tickets/${ticketId}/approve`, {})).status, 200);

  let seen;
  const out = await worker((id, pwBuf) => { seen = { id, pw: pwBuf.toString('utf8') }; return { ok: true }; });
  assert.deepEqual(seen, { id: '12345678', pw: 'BlueTiger427#' });
  assert.equal(out.ok, true);
  assert.equal(await status(), 'done');
  assert.equal(app._debug.tickets.get(ticketId).ciphertext, null);
});

test('worker refuses ciphertext that belongs to another student', async () => {
  const { session } = await admin();
  const cfg = await config();
  const ciphertext = await encrypt(cfg, '99999999', 'BlueTiger427#');
  const r = await post('/api/tickets', { studentId: '12345678', name: 'Test Student', sessionCode: session.code, ciphertext });
  const { ticketId } = await r.json();
  await post(`/api/admin/tickets/${ticketId}/approve`, {});
  let called = false;
  const out = await worker(() => { called = true; return { ok: true }; });
  assert.equal(called, false);
  assert.equal(out.error, 'payload_mismatch');
  const t = (await admin()).tickets.find(x => x.id === ticketId);
  assert.equal(t.status, 'failed');
  assert.equal(t.error, 'payload_mismatch');
});

test('reject, and a new request replaces a pending one for the same ID', async () => {
  const { session } = await admin();
  const a = await (await submit('55555555', 'BlueTiger427#', session.code)).json();
  const b = await (await submit('55555555', 'RedLion1234!', session.code)).json();
  assert.equal((await (await get(`/api/tickets/${a.ticketId}`, { 'x-ticket-token': a.token })).json()).status, 'replaced');
  assert.equal((await post(`/api/admin/tickets/${a.ticketId}/approve`, {})).status, 409);
  assert.equal((await post(`/api/admin/tickets/${b.ticketId}/reject`, {})).status, 200);
  assert.equal((await (await get(`/api/tickets/${b.ticketId}`, { 'x-ticket-token': b.token })).json()).status, 'rejected');
});

test('worker endpoints need the worker token', async () => {
  assert.equal((await fetch(base + '/api/worker/next', { method: 'POST' })).status, 401);
  assert.equal((await fetch(base + '/api/worker/next', { method: 'POST', headers: { authorization: 'Bearer nope' } })).status, 401);
});

test('code rotation keeps the previous code for one round only', async () => {
  const first = (await admin()).session.code;
  clock += 5 * 60_000;
  const second = (await admin()).session.code;
  assert.notEqual(first, second);
  assert.equal((await submit('22222222', 'BlueTiger427#', first)).status, 201);
  clock += 5 * 60_000;
  await admin();
  assert.equal((await submit('22222223', 'BlueTiger427#', first)).status, 403);
  assert.equal((await submit('22222224', 'BlueTiger427#', second)).status, 201);
});

test('closing the session deletes the queue', async () => {
  const { session } = await admin();
  const t = await (await submit('33333333', 'BlueTiger427#', session.code)).json();
  assert.equal((await post('/api/admin/session', { open: false })).status, 200);
  assert.equal((await get(`/api/tickets/${t.ticketId}`, { 'x-ticket-token': t.token })).status, 404);
  assert.equal(app._debug.tickets.size, 0);
  assert.equal((await config()).sessionOpen, false);
});

test('wrong session codes are rate limited per IP', async () => {
  clock += 11 * 60_000; // clear failures recorded by earlier tests
  await post('/api/admin/session', { open: true });
  const { session } = await admin();
  const wrong = session.code === '000000' ? '111111' : '000000';
  for (let i = 0; i < 10; i++) assert.equal((await submit('44444444', 'BlueTiger427#', wrong)).status, 403);
  assert.equal((await submit('44444444', 'BlueTiger427#', session.code)).status, 429);
});

test('openPayload rejects garbage', () => {
  assert.equal(openPayload(privateKeyPem, { ciphertext: 'AAAA', sessionId: 'x', studentId: 'y' }).error, 'decrypt_failed');
});
