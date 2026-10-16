// Mock worker for local development and tests. It does exactly what the real
// PowerShell worker does, except the Active Directory step: it polls the queue,
// decrypts each approved ticket, checks the payload belongs to that ticket, and
// reports success. It never prints the password.
//
//   SERVER_URL=http://localhost:3000 WORKER_TOKEN=... MOCK_PRIVATE_KEY=.dev/private.pem node worker/mock-worker.mjs

import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

// Payload format (see public/app.js): UTF-8 `<header JSON>\n<password>`.
export function openPayload(privateKeyPem, ticket) {
  let plain;
  try {
    plain = crypto.privateDecrypt(
      { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(ticket.ciphertext, 'base64url'));
  } catch { return { error: 'decrypt_failed' }; }
  const nl = plain.indexOf(0x0a);
  if (nl < 0) return { error: 'payload_mismatch' };
  let header;
  try { header = JSON.parse(plain.subarray(0, nl).toString('utf8')); } catch { return { error: 'payload_mismatch' }; }
  if (header.v !== 1 || header.sid !== ticket.sessionId || header.id !== ticket.studentId) {
    plain.fill(0);
    return { error: 'payload_mismatch' };
  }
  const password = plain.subarray(nl + 1); // caller must zero this buffer when done
  return { header, password, wipe: () => plain.fill(0) };
}

export async function pollOnce({ serverUrl, workerToken, privateKeyPem, onReset = () => ({ ok: true }) }) {
  const auth = { authorization: `Bearer ${workerToken}` };
  const r = await fetch(`${serverUrl}/api/worker/next`, { method: 'POST', headers: auth });
  if (!r.ok) throw new Error(`queue returned ${r.status}`);
  const { ticket } = await r.json();
  if (!ticket) return null;
  const opened = openPayload(privateKeyPem, ticket);
  let result;
  if (opened.error) result = { ok: false, error: opened.error };
  else {
    try { result = await onReset(ticket.studentId, opened.password); } finally { opened.wipe(); }
  }
  await fetch(`${serverUrl}/api/worker/tickets/${ticket.id}/result`, {
    method: 'POST', headers: { ...auth, 'content-type': 'application/json' }, body: JSON.stringify(result),
  });
  return { ticketId: ticket.id, studentId: ticket.studentId, ...result };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const serverUrl = process.env.SERVER_URL || 'http://localhost:3000';
  const workerToken = process.env.WORKER_TOKEN;
  const privateKeyPem = fs.readFileSync(process.env.MOCK_PRIVATE_KEY || '.dev/private.pem', 'utf8');
  console.log(`Mock worker polling ${serverUrl} (no Active Directory calls are made)`);
  for (;;) {
    try {
      const out = await pollOnce({ serverUrl, workerToken, privateKeyPem });
      if (out) console.log(`${new Date().toISOString()} ticket ${out.ticketId} student ${out.studentId}: ${out.ok ? 'reset (simulated)' : 'failed: ' + out.error}`);
    } catch (e) { console.error('poll failed:', e.message); }
    await new Promise(r => setTimeout(r, 2000));
  }
}
