// Runs the real PowerShell worker (key setup, decryption, result reporting)
// against the server. Active Directory is replaced by a test hook. Skipped when
// PowerShell 7 (pwsh) is not installed; set PWSH=/path/to/pwsh to point at it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
import { createApp } from '../server/app.js';

const PWSH = process.env.PWSH || 'pwsh';
const hasPwsh = spawnSync(PWSH, ['-NoProfile', '-c', 'exit 0']).status === 0;
const WORKER = path.resolve('worker');

test('PowerShell worker decrypts browser ciphertext and reports results', { skip: !hasPwsh && 'pwsh not installed' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbc-worker-'));
  const env = { ...process.env, SBC_WORKER_TEST_PLAINTEXT: '1' };
  const runSync = (script, args, extra = {}) => execFileSync(PWSH, ['-NoProfile', '-File', path.join(WORKER, script), ...args], { env: { ...env, ...extra }, encoding: 'utf8' });

  // The server runs in this process, so the worker must run asynchronously.
  const run = async (script, args, extra = {}) => (await promisify(execFile)(PWSH, ['-NoProfile', '-File', path.join(WORKER, script), ...args], { env: { ...env, ...extra }, encoding: 'utf8' })).stdout;

  // Setup prints the two values for the cloud host.
  const out = runSync('Setup-Worker.ps1', ['-ServerUrl', 'http://localhost:1', '-StudentOU', 'OU=Student Users,DC=test,DC=local', '-OutDir', dir]);
  const lines = out.split('\n').map(s => s.trim());
  const publicKeyJwk = JSON.parse(lines[lines.indexOf('PUBLIC_KEY_JWK') + 1]);
  const workerToken = lines[lines.indexOf('WORKER_TOKEN') + 1];
  assert.equal(publicKeyJwk.d, undefined);

  const app = createApp({ adminPassword: 'test-admin-password', workerToken, publicKeyJwk });
  await new Promise(r => app.server.listen(0, r));
  const base = `http://localhost:${app.server.address().port}`;
  const cfgPath = path.join(dir, 'worker-config.json');
  const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8').replace(/^﻿/, ''));
  fs.writeFileSync(cfgPath, JSON.stringify({ ...cfg, ServerUrl: base }));

  try {
    const login = await fetch(base + '/api/admin/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"password":"test-admin-password"}' });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const adminPost = (p, b) => fetch(base + '/api/admin/' + p, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify(b) });
    await adminPost('session', { open: true });
    const state = async () => (await fetch(base + '/api/admin/state', { headers: { cookie } })).json();
    const { session } = await state();
    const config = await (await fetch(base + '/api/config')).json();

    async function ticket(studentId, pw, headerId = studentId) {
      const key = await crypto.subtle.importKey('jwk', config.publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
      const header = JSON.stringify({ v: 1, sid: config.sessionId, id: headerId, n: 'x' });
      const ciphertext = Buffer.from(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, new TextEncoder().encode(header + '\n' + pw))).toString('base64url');
      const r = await fetch(base + '/api/tickets', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ studentId, name: 'PS Test', sessionCode: session.code, ciphertext }) });
      const { ticketId } = await r.json();
      await adminPost(`tickets/${ticketId}/approve`, {});
      return ticketId;
    }
    const result = async id => (await state()).tickets.find(t => t.id === id);
    const work = (extra = {}, args = []) => run('Start-ResetWorker.ps1', ['-ConfigPath', cfgPath, '-Once', ...args], { SBC_WORKER_FAKE_AD: '1', ...extra });

    // Non-ASCII special character (£) checks the UTF-8 path into the SecureString.
    const pw = 'BlueTiger427£';
    const t1 = await ticket('12345678', pw);
    const log1 = await work({ SBC_WORKER_FAKE_AD_EXPECT: pw });
    assert.equal((await result(t1)).status, 'done', log1);
    assert.equal(log1.includes(pw), false, 'worker output must not contain the password');

    const t2 = await ticket('12345678', 'RedLion1234!', '99999999');
    await work();
    assert.deepEqual([(await result(t2)).status, (await result(t2)).error], ['failed', 'payload_mismatch']);

    const t3 = await ticket('22222222', 'GoldMoon5678#');
    await work({}, ['-DryRun']);
    assert.equal((await result(t3)).error, 'dry_run');
  } finally {
    app.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
