// Local development: creates a throwaway key pair in .dev/, then starts the
// server and the mock worker. Do not use these keys or secrets anywhere real.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawn } from 'node:child_process';

fs.mkdirSync('.dev', { recursive: true });
if (!fs.existsSync('.dev/private.pem')) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
  fs.writeFileSync('.dev/private.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync('.dev/public.jwk', JSON.stringify(publicKey.export({ format: 'jwk' })));
}
const env = {
  ...process.env,
  PUBLIC_KEY_JWK: fs.readFileSync('.dev/public.jwk', 'utf8'),
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'dev-admin-password',
  WORKER_TOKEN: process.env.WORKER_TOKEN || 'dev-worker-token-0123456789abcdef0123',
  INSECURE_DEV: '1',
  PORT: process.env.PORT || '3000',
};
console.log(`Student form: http://localhost:${env.PORT}/   Admin: http://localhost:${env.PORT}/admin   (admin password: ${env.ADMIN_PASSWORD})`);
const server = spawn(process.execPath, ['server/server.js'], { env, stdio: 'inherit' });
setTimeout(() => {
  const worker = spawn(process.execPath, ['worker/mock-worker.mjs'], {
    env: { ...env, SERVER_URL: `http://localhost:${env.PORT}`, MOCK_PRIVATE_KEY: '.dev/private.pem' }, stdio: 'inherit',
  });
  const stop = () => { server.kill(); worker.kill(); process.exit(0); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}, 500);
