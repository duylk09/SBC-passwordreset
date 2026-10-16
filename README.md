# South Bank Colleges – student password reset

A supervised, in-person password reset for students. A student fills in the form on their phone, an IT staff
member checks their ID card and approves the request, and a worker script on the staff PC sets the new password
in on-prem Active Directory.

```
 Student phone                 Cloud (Render)                    IT staff PC (on campus)
 ─────────────                 ──────────────                    ───────────────────────
 form + live rules             student form, admin queue         Start-ResetWorker.ps1
 encrypts password  ──POST──▶  stores ciphertext only   ◀─poll──  decrypts with private key
 with public key               (in memory)                         Set-ADAccountPassword
                               admin page: approve/reject  ─────▶  (Student Users OU only)
                                         ▲                         reports done/failed
                     IT staff ───────────┘ checks ID card
```

- The password is encrypted in the browser (RSA-OAEP-256, 3072-bit) with the worker's public key. The cloud
  host only ever sees ciphertext; the private key never leaves the staff PC.
- The admin page shows the name and student ID only, never the password.
- The staff PC makes outbound HTTPS requests only. It never opens a port.
- Students need the 6-digit session code shown on the admin page. The code changes every 5 minutes, and the
  previous code keeps working for one more round.
- Closing the session deletes every request in the queue, including pending ones, and the form stops accepting
  requests immediately.
- "Must change password at next logon" is turned off after the reset.

## Layout

| Path | What it is |
| --- | --- |
| `public/` | Student form (`index.html`, `app.js`, `i18n.js`, 16 languages) and admin page (`admin.html`, `admin.js`) |
| `server/` | Node.js server with no dependencies: static files plus the queue API. All state is in memory. |
| `worker/Setup-Worker.ps1` | One-time setup on the staff PC: creates the key pair and worker token |
| `worker/Start-ResetWorker.ps1` | The worker: polls, decrypts, resets in AD |
| `worker/mock-worker.mjs` | Same as the worker minus AD, for local development and tests |
| `test/` | API tests and a test that runs the real PowerShell worker (with AD stubbed) |

## Try it locally

Requires Node.js 22+.

```
npm run dev
```

This creates throwaway keys in `.dev/` and starts the server plus the mock worker.
Student form: <http://localhost:3000/> · Admin: <http://localhost:3000/admin> (password `dev-admin-password`).
Open a session on the admin page, then submit a request from the student form.

Tests: `npm test`. The PowerShell worker test runs only if `pwsh` is installed (set `PWSH=/path/to/pwsh`).

## Deploy

### 1. Staff PC (do this first; it produces the values the cloud needs)

1. Sign in to Windows as the **service identity** that has been delegated *Reset Password* on the Student Users
   OU (nothing broader). The worker's secret files are protected with DPAPI and only work for this account on
   this PC.
2. Install RSAT's ActiveDirectory PowerShell module.
3. Copy the `worker/` folder to the PC and run:
   ```powershell
   .\Setup-Worker.ps1 -ServerUrl https://<your-app>.onrender.com `
       -StudentOU "OU=Student Users,DC=lambeth,DC=ac,DC=uk"
   ```
   It prints `PUBLIC_KEY_JWK` and `WORKER_TOKEN`. Copy both into the cloud host (next step), then clear the window.

### 2. Render

1. New → Blueprint → pick this repository (`render.yaml`). The plan is *Starter*: the free plan sleeps and
   restarts, which loses the in-memory queue.
2. Set the environment variables:

   | Variable | Value |
   | --- | --- |
   | `PUBLIC_KEY_JWK` | from `Setup-Worker.ps1` |
   | `WORKER_TOKEN` | from `Setup-Worker.ps1` |
   | `ADMIN_PASSWORD` | a long password for IT staff (12+ characters) |
   | `TRUST_PROXY` | `1` (already set in `render.yaml`) |

3. Keep it at **one instance**. A second instance would have its own separate queue.

### 3. Running a session

1. On the staff PC: `.\Start-ResetWorker.ps1 -DryRun` for the first trial (it finds the account but does not change
   the password), then `.\Start-ResetWorker.ps1` for real.
2. Open `/admin`, sign in, press **Open session**, and show the code to the room.
3. For each request: check the student's ID card against the name and ID on the queue and on their phone, then
   **Approve** or **Reject**.
4. Press **Close session** at the end.

## Security notes and known limits

- **Encryption protects the data, not the page.** The cloud host serves the JavaScript that does the encryption.
  Someone who controls the host could serve a modified page that leaks passwords. The design stops leaks of
  stored data and logs, not a compromised host. Protect the Render account (MFA, few people).
- **Ciphertext is bound to its request.** The encrypted payload includes the session ID and student ID. The worker
  refuses to use it for any other ticket.
- **The worker never handles the password as a string.** It is decrypted to bytes, copied into a `SecureString`
  for `Set-ADAccountPassword`, and the buffers are wiped. It is never logged or passed on a command line.
  PowerShell transcription only records console output, which never includes the password. The worker warns if
  transcription is enabled by policy.
- **The account lookup is limited to the Student Users OU.** IDs must be 3–20 letters or digits. This happens
  before the LDAP search, even if the delegation is broader than intended.
- **Rate limits:** 10 wrong session codes per IP per 10 minutes. After 50 wrong codes from anyone, the code
  rotates early. 5 wrong admin passwords per IP per 10 minutes.
- **Stuck requests:** if the worker loses its network between taking a request and reporting back, the request
  stays "Resetting…" on the admin page. Check the account in ADUC.
- **The password rules on the form** (12+ characters, and so on) come from the original design. They must be
  checked against `Get-ADDefaultDomainPasswordPolicy`. If AD refuses the password, the request shows "Failed:
  password does not meet the domain password policy".
- **Name and date-of-birth check:** the student answers this themselves. It is a reminder, not a control.
- **Translations** of the student pages are machine-assisted and need review by native speakers. This matters
  most for Somali, Luganda, Amharic and Kurdish (Sorani).

## Before production

- [ ] Confirm the Student Users OU distinguished name
- [ ] Delegate Reset Password (only) on that OU to the service identity
- [ ] Align the form's rules with `Get-ADDefaultDomainPasswordPolicy`
- [ ] Run `Setup-Worker.ps1` and `Start-ResetWorker.ps1 -DryRun` on the real staff PC (the Windows/DPAPI code path
      has not been run on Windows yet)
- [ ] Sign-off from IT/security
