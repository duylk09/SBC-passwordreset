// Entry point. Configuration comes from environment variables only.
import { createApp } from './app.js';

function env(name) {
  const v = process.env[name];
  if (!v) { console.error(`Missing required environment variable ${name}. See README.md.`); process.exit(1); }
  return v;
}

let publicKeyJwk;
try { publicKeyJwk = JSON.parse(env('PUBLIC_KEY_JWK')); }
catch { console.error('PUBLIC_KEY_JWK is not valid JSON.'); process.exit(1); }

const { server } = createApp({
  adminPassword: env('ADMIN_PASSWORD'),
  workerToken: env('WORKER_TOKEN'),
  publicKeyJwk,
  trustProxy: process.env.TRUST_PROXY === '1',
  secureCookies: process.env.INSECURE_DEV !== '1',
});

const port = Number(process.env.PORT || 3000);
server.listen(port, () => console.log(`Password reset service listening on port ${port}`));
