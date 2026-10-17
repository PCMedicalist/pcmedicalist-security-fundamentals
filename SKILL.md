---
name: pcmedicalist-security-fundamentals
description: Use when implementing or fixing access-control, auth, crypto, validation, and supply-chain security across PCMedicalist services.
version: 1.0.0
author: PCMedicalist
license: CC-BY-4.0 (PCMedicalist attribution required)
metadata:
  hermes:
    tags: [security, authorization, cryptography, authentication, validation, pcmedicalist]
    related_skills: [pcmedicalist-sql-injection, pcmedicalist-xss, pcmedicalist-csrf, pcmedicalist-cors-policy, pcmedicalist-ssrf, pcmedicalist-secret-hygiene, pcmedicalist-jwt-rotation, pcmedicalist-oauth, pcmedicalist-webhooks-hmac, pcmedicalist-waf-ddos, pcmedicalist-ddos-protection, pcmedicalist-tls-termination, pcmedicalist-encryption-at-rest]
---

# PCMedicalist Security Fundamentals

## When to Use
- Building or auditing any PCMedicalist endpoint that accepts untrusted input, gates access, stores credentials, or processes payments/tokens.
- Reviewing a service for OWASP-class weaknesses: broken access control (IDOR, mass assignment), crypto failures (weak hashing, plaintext secrets), auth gaps (session fixation, missing MFA), and supply-chain risk.
- Remediating a CVE/incident tied to one of the 26 topics below.
- Onboarding a new agent or pipeline that touches auth, secrets, file uploads, or headers.

## Portfolio Reality
PCMedicalist today runs: baseLINE (Node/Express + Postgres + Redis + PM2 on DreamHost VPS <DEPLOY_HOST>), the 0x-agents fleet (Telegram bots), RetroByte (local Ollama + Discord/Telegram bridge), and the PCMedicalist Creative Studio pipeline. Auth is Privy (single login) + Twitch OAuth for streamers. Secrets live in `baseline/ecosystem.config.cjs` (PM2 env) + a git-ignored `.env` (mode 600) that is the local source of truth. Privy app secrets, Bankr keys, and TWITCH_* creds are the crown jewels. The agent-system home (`.hermes`) is mirrored to `<PRIVATE_AGENT_REPO>` under a `secret-shield` pre-commit hook.

**This skill is the umbrella for fundamentals NOT covered by the narrower skills** (sql-injection, xss, csrf, cors-policy, ssrf, secret-hygiene, jwt-rotation, oauth, webhooks-hmac, tls-termination, encryption-at-rest, encryption-in-transit, waf-ddos, ddos-protection). If a topic exists as its own skill, defer to that skill.

## Topics Covered
1. IDOR — Insecure Direct Object Reference
2. Path Traversal
3. Mass Assignment
4. Clickjacking
5. Content Security Policy (CSP)
6. Security Headers
7. Input Validation
8. Server-Side Authorization
9. Row-Level Security (RLS)
10. Least Privilege
11. RBAC — Role-Based Access Control
12. Hashing vs Encryption
13. Password Salting
14. bcrypt & Argon2
15. JWT Expiry
16. Refresh Tokens
17. OpenID Connect (OIDC)
18. Session Fixation
19. MFA — Multi-Factor Authentication
20. Brute Force Protection
21. Account Enumeration
22. Timing Attacks
23. File Upload Validation
24. HSTS — HTTP Strict Transport Security
25. Supply Chain Attacks
26. Threat Modeling

Each topic below follows the same shape: **Threat → Pattern → Validate → Fix**.

---

## 1. IDOR — Insecure Direct Object Reference
**Threat:** An authenticated user manipulates an object identifier (`:id` in a URL/path) to access or mutate records they don't own. Classic broken-access-control (OWASP #1). On baseLINE this means tipping a creator's payout record or reading another user's wallet config.

**Pattern (Node/Express):**
```ts
// WRONG — trusts client-supplied id, no ownership check
app.get('/api/tips/:id', async (req, res) => {
  const tip = await db.tips.findUnique({ where: { id: req.params.id } });
  res.json(tip);
});

// RIGHT — enforce ownership server-side
app.get('/api/tips/:id', requireAuth, async (req, res) => {
  const tip = await db.tips.findUnique({ where: { id: req.params.id } });
  if (!tip) return res.status(404).json({ error: 'not_found' });
  if (tip.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json(tip);
});
```
Use UUIDs (not sequential integers) for external object IDs to avoid enumeration (see topic 60 in database-deep-dive). Indirect reference maps (session-stored token→real-id) are an extra layer but never a substitute for the server-side ownership check.

**Validate:** As user A, request `/api/tips/<user-B-tip-id>`. Expect `403`. Automated: a test that swaps the id in a saved response and replays it.

**Fix:** Add an ownership/tenancy assertion on every object-returning handler. Centralize as middleware: `enforceOwner(resource, req.user)`. Audit all `:id` routes with a grep for `findUnique`/`findFirst` lacking a `userId`/`tenantId` filter.

---

## 2. Path Traversal
**Threat:** User-supplied filename/filepath escapes the intended directory (`../../etc/passwd`, `..%2f..%2f`). On a file-serving endpoint this reads secrets or overwrites system files.

**Pattern:**
```ts
import { resolve, normalize, join } from 'path';
import { existsSync } from 'fs';

const ROOT = resolve('/var/www/baseline/uploads');
app.get('/files/:name', (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, ''); // strip path chars
  const target = resolve(join(ROOT, safeName));
  if (target !== ROOT && !target.startsWith(ROOT + '/')) {
    return res.status(400).json({ error: 'invalid_path' });
  }
  if (!existsSync(target)) return res.status(404).end();
  res.sendFile(target);
});
```
Never pass raw user input to `fs.readFile`, `path.join`, or `sendFile` without canonicalization + prefix check. Reject `..`, absolute paths, and null bytes.

**Validate:** Request `/files/..%2f..%2f..%2fetc%2fpasswd`. Expect `400`, not passwd contents.

**Fix:** Canonicalize with `path.resolve`, assert the result is within the allowed root, and use an allowlist of characters for the basename. Prefer serving via a CDN/object store keyed by opaque ID rather than filesystem paths.

---

## 3. Mass Assignment
**Threat:** A JSON body with unexpected fields (`{"username":"x","isAdmin":true,"role":"admin"}`) is bound directly to an ORM model, letting a user escalate privileges or set internal-only fields.

**Pattern:**
```ts
// WRONG — spreads untrusted body straight into update
await db.users.update({ where: { id }, data: req.body });

// RIGHT — explicit allowlist
const UPDATABLE = ['displayName', 'avatarUrl', 'bio'] as const;
const data = pick(req.body, UPDATABLE);
await db.users.update({ where: { id }, data });
```
For Prisma, use `select`/`include` and a DTO. Never `Object.assign(model, req.body)`.

**Validate:** POST `{"role":"admin"}` to a profile-update endpoint as a normal user. Expect the role to be unchanged (or `400`).

**Fix:** Define per-route DTOs. For every ORM write, enumerate the exact columns the caller may set. Add a CI check (eslint rule `no-unsafe-assignment` + a custom lint for `data: req.body`).

---

## 4. Clickjacking
**Threat:** An attacker frames your app in an invisible `<iframe>` and tricks the user into clicking (e.g. confirming a tip). Protection = `X-Frame-Options` / CSP `frame-ancestors`.

**Pattern:**
```ts
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  next();
});
```
`frame-ancestors 'none'` supersedes `X-Frame-Options` in modern browsers; keep both for legacy coverage. For pages that must be framed (Twitch extension panels), scope `frame-ancestors` to the exact extension origin only.

**Validate:** Embed the app in an `<iframe>` on a hostile page; the browser refuses to render it (check DevTools console for a CSP/frame-ancestors block).

**Fix:** Add the middleware globally. For Twitch panels, set `frame-ancestors https://<ext-id>.ext-twitch.tv` and nothing else.

---

## 5. Content Security Policy (CSP)
**Threat:** Without a CSP, injected scripts (even post-XSS-mitigation) can execute; third-party scripts can exfiltrate data. CSP is defense-in-depth, not a replacement for output encoding.

**Pattern (strict, nonce-based):**
```ts
import { randomBytes } from 'crypto';
app.use((req, res, next) => {
  const nonce = randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  res.setHeader('Content-Security-Policy',
    `default-src 'self'; ` +
    `script-src 'self' 'nonce-${nonce}' https://baseline.click; ` +
    `style-src 'self' 'unsafe-inline'; ` +   // tighten later
    `img-src 'self' data: https:; ` +
    `connect-src 'self' https://api.bankr.bot; ` +
    `frame-ancestors 'none'; ` +
    `object-src 'none'; ` +
    `base-uri 'self'; ` +
    `form-action 'self'`
  );
  next();
});
```
Inject `<script nonce="<%= nonce %>">` in templates. Avoid `'unsafe-inline'` in `script-src` — it nullifies the policy. Report-only mode (`Content-Security-Policy-Report-Only`) lets you stage a policy before enforcing.

**Validate:** A PoC `<script>fetch('https://evil.example')</script>` injected into a comment field is blocked (no outbound request in the network tab).

**Fix:** Start with `default-src 'self'` + report-only, expand via violation reports, then enforce. For the Creative Studio / Twitch panels, allowlist only the required origins (Privy, WalletConnect, hCaptcha, Coinbase, base.org, api.bankr.bot, coingecko).

---

## 6. Security Headers
**Threat:** Missing headers leave users exposed to MIME sniffing, framing, and downgrade attacks.

**Pattern — full baseline set:**
```ts
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  next();
});
```
Scan with https://securityheaders.com after deploy. Target grade A.

**Validate:** `curl -I https://baseline.click` shows all of the above. No missing headers.

**Fix:** Global middleware. For the Vercel-deployed PCMedicalist surfaces, set these in `next.config` headers array, not per-route.

---

## 7. Input Validation
**Threat:** Unvalidated input is the root enabler of injection, IDOR, overflow, and logic bugs. Validate at the boundary; never trust the client.

**Pattern (zod schema at the edge):**
```ts
import { z } from 'zod';
const TipSchema = z.object({
  amountWei: z.string().regex(/^[0-9]+$/).refine(v => BigInt(v) > 0n),
  creatorId: z.string().uuid(),
  note: z.string().max(280).optional(),
});
app.post('/api/tips', requireAuth, (req, res) => {
  const parsed = TipSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ errors: parsed.error.flatten() });
  // ... proceed with parsed.data
});
```
Validate type, range, length, format, and business rules. Reject unknown keys (`.strict()`) to catch mass assignment too.

**Validate:** Send `amountWei: -5`, `creatorId: 'not-a-uuid'`, `note: <300 chars>`. Expect `422` with field errors.

**Fix:** Adopt zod (or similar) for every inbound request. Add a lint rule banning `req.body` access before a schema parse. Validate on the server even if the client also validates.

---

## 8. Server-Side Authorization
**Threat:** Authn (who you are) is checked but authz (what you may do) is not, or is checked only in the UI. Attackers call the API directly.

**Pattern:**
```ts
// Centralized authorization middleware factory
function requireRole(...roles: Role[]) {
  return (req: AuthedReq, res: Response, next: NextFn) => {
    if (!req.user) return res.status(401).end();
    if (!roles.includes(req.user.role)) return res.status(403).end();
    next();
  };
}
app.delete('/api/users/:id', requireRole('admin'), handler);
```
Never rely on a hidden button or disabled UI control for security. Every protected route MUST re-check server-side.

**Validate:** Call a protected endpoint with a non-admin token. Expect `403`, even if the UI hides the button.

**Fix:** Inventory every route; tag each with required role/permission. Build a route→permission matrix. Gate at the router level, not inside handlers (avoids forgotten checks).

---

## 9. Row-Level Security (RLS)
**Threat:** At the DB layer, a bug in app code or a compromised connection can read/update rows across tenants. RLS enforces tenancy in Postgres itself.

**Pattern (Postgres RLS):**
```sql
ALTER TABLE tips ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tips
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
-- App sets: SET app.tenant_id = '<uuid>'; per connection (via pool hook)
```
RLS is defense-in-depth beneath app-level authz. Pair with a connection that sets the tenant claim from the authenticated JWT. Beware: RLS + superuser bypass — ensure the app DB user is NOT superuser.

**Validate:** Connect as the app role, `SET app.tenant_id='A'`; `SELECT * FROM tips` returns only tenant A rows even though other tenants exist.

**Fix:** Enable RLS on every multi-tenant table. Test with `EXPLAIN` to confirm the policy predicate is applied (no full scan from a missing index on `tenant_id`).

---

## 10. Least Privilege
**Threat:** An over-permissioned process/role/DB-user magnifies any single compromise. The app DB user having DDL or superuser = one SQLi = total loss.

**Pattern:**
- App runtime DB user: `GRANT SELECT, INSERT, UPDATE, DELETE` on needed tables only — no `CREATE`, no `DROP`, no `SUPER`.
- Container: run as non-root (see infrastructure-ops skill, topic 191). Drop `CAP_NET_RAW` etc.
- Cloud: IAM role scoped to exact bucket/queue, not `*` actions.
- Cron jobs: each job's credentials scoped to what it touches.

**Validate:** `SHOW GRANTS FOR 'baseline_app'@'%'` lists only DML on `baseline.*`, no global grants. The container `ps` shows a non-root UID.

**Fix:** Create per-service DB roles. Revoke `SUPER`, `FILE`, `GRANT OPTION`. Run `REVOKE ALL` then grant only what's used. Re-test the app after tightening.

---

## 11. RBAC — Role-Based Access Control
**Threat:** Ad-hoc role checks (`if (user.isAdmin)`) scattered across code drift and miss edge cases. A central model scales and audits cleanly.

**Pattern:**
```ts
type Role = 'guest' | 'user' | 'creator' | 'moderator' | 'admin';
type Perm = 'tip:create' | 'tip:read:own' | 'tip:read:any' | 'user:ban' | 'config:write';
const MATRIX: Record<Role, Perm[]> = {
  guest: [],
  user: ['tip:create', 'tip:read:own'],
  creator: ['tip:create', 'tip:read:own', 'config:write'],
  moderator: ['tip:read:any', 'user:ban'],
  admin: ['tip:read:any', 'user:ban', 'config:write'],
};
function can(role: Role, p: Perm) { return MATRIX[role].includes(p); }
```
Store roles in the JWT (or a fast lookup), evaluate permissions centrally. For fine-grained needs, move to ABAC (attribute-based) — but RBAC covers 90% of cases.

**Validate:** A `user` calling `user:ban` → denied. A `moderator` calling `tip:read:any` → allowed. Matrix changes are code-reviewed, not inline hacks.

**Fix:** Extract all inline role checks into the matrix. Add a unit test per (role, perm) pair. Document the matrix in the runbook.

---

## 12. Hashing vs Encryption
**Threat:** Confusing the two leads to encrypting passwords (reversible — breach = exposed) or hashing data you need to recover (lossy). Rule: **hash secrets you never need to read back; encrypt data you must decrypt.**

**Pattern:**
- Hash: passwords, API-key *verification tokens*, integrity checksums. One-way.
- Encrypt: PII at rest you must query, wallet seed backups (with a KMS key), session cookies containing state.
- Hashing is NOT encryption. `bcrypt(password)` cannot be reversed; `AES.encrypt(ssn, key)` can be.

**Validate:** A stored password column contains `$2b$12$...` (bcrypt) not plaintext or AES ciphertext. Encrypted PII decrypts with the KMS key but the password column never does.

**Fix:** Identify every stored secret; if it's a credential, hash it. If it's recoverable user data, encrypt with envelope encryption (KMS data key). Never store decryption keys in the same DB.

---

## 13. Password Salting
**Threat:** Unsalted (or single global-salt) hashes let attackers crack via rainbow tables / precomputation across your whole user base at once.

**Pattern:** Use a **per-user random salt** generated by the hashing library (bcrypt/Argon2 embed the salt in the output — you don't manage it manually). If you ever hand-roll, `salt = crypto.randomBytes(16)` and store it alongside the hash, unique per user.

**Validate:** Two users with password `password123` have different stored hashes. No column named `global_salt` shared across rows.

**Fix:** Migrate to bcrypt/Argon2 (which salt internally). If legacy salted-SHA is present, flag for rehash-on-login to the modern scheme.

---

## 14. bcrypt & Argon2
**Threat:** Fast hashes (MD5, SHA1, even SHA256) are crackable at billions/sec on GPUs. Adaptive/ memory-hard functions slow attackers.

**Pattern:**
```ts
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);          // cost 12+
const ok = await bcrypt.compare(password, hash);

// Argon2id (preferred for new systems — memory-hard):
import argon2 from 'argon2';
const hash2 = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3 });
const ok2 = await argon2.verify(hash2, password);
```
Use **Argon2id** for new code (best trade-off against GPU + side-channel). bcrypt is acceptable and widely supported. Never use PBKDF2 with low iterations for new systems. Cost factors: bcrypt ≥12, Argon2id memoryCost ≥64MB.

**Validate:** Hashing one password takes ≥200ms (tune cost to your hardware budget). A timing test shows no two hashes equal for the same input.

**Fix:** Replace any `crypto.createHash('md5'|'sha1')` password path. Add a rehash-on-login if the stored cost is below policy.

---

## 15. JWT Expiry
**Threat:** Non-expiring or long-lived JWTs are bearer tokens — if leaked, they're valid forever. Short expiry limits blast radius.

**Pattern:**
```ts
import jwt from 'jsonwebtoken';
const access = jwt.sign({ sub: user.id, role }, process.env.JWT_SECRET!, { expiresIn: '15m' });
```
Access tokens: 5–15 min. Always set `exp`. Reject tokens with missing/`exp` in ver
ification (`jwt.verify` enforces by default). Pair with refresh tokens (topic 16) for UX.

**Validate:** Decode a token — `exp` is ~15 min out. A token past `exp` → `401` with `TokenExpiredError`.

**Fix:** Add `expiresIn` to all sign calls. Rotate `JWT_SECRET` periodically (see jwt-rotation skill). Never put secrets in the payload.

---

## 16. Refresh Tokens
**Threat:** Long-lived sessions need a way to get new access tokens without re-login, but refresh tokens are high-value theft targets.

**Pattern:**
- Store refresh tokens server-side (hashed, in DB/Redis) with `expiresAt` and `revokedAt`.
- Rotate on use: each refresh issues a NEW refresh token and invalidates the old (detects reuse → revoke the whole family).
- Bind to `deviceId` / `user-agent` fingerprint; mismatch → challenge.
- Absolute lifetime cap (e.g. 30 days) + idle timeout.

```ts
app.post('/api/refresh', async (req, res) => {
  const stored = await redis.get(`rt:${req.body.refreshTokenHash}`);
  if (!stored || stored.revokedAt) return res.status(401).end();
  // rotation: revoke old, issue new
  await redis.del(`rt:${req.body.refreshTokenHash}`);
  const newRt = crypto.randomBytes(48).toString('hex');
  await redis.set(`rt:${hash(newRt)}`, { userId, exp: Date.now()+30*864e5 }, 'EX', 30*86400);
  res.json({ access: issueAccess(stored.userId), refresh: newRt });
});
```
**Validate:** Replay a used refresh token → `401`. A fresh token works. DB shows only the latest refresh token hash for the user.

**Fix:** If refresh tokens are currently stateless/JWT-only, move to server-side hashed storage with rotation. Add a "revoke all sessions" admin action.

---

## 17. OpenID Connect (OIDC)
**Threat:** Rolling your own identity or misconfiguring OIDC (accepting unverified ID-token claims, ignoring `aud`/`iss`, no `nonce`) lets attackers impersonate users.

**Pattern (verify before trust):**
```ts
import { jwtVerify } from 'jose';
const { payload } = await jwtVerify(idToken, JWKS, {
  issuer: 'https://your-idp.example',
  audience: process.env.OIDC_CLIENT_ID,
});
// nonce must match the one stored at auth start (CSRF/replay defense)
if (payload.nonce !== session.nonce) throw new Error('nonce_mismatch');
```
Use a vetted library (openid-client / jose), NOT manual JWT parsing. Validate `iss`, `aud`, `exp`, `nonce`. Fetch JWKS from the discovery document, pin/cache it. Privy (baseLINE's provider) wraps OIDC — never bypass its session checks.

**Validate:** A token with `aud: "someone-else"` is rejected. A replayed token with a stale `nonce` is rejected.

**Fix:** If any OIDC flow parses tokens manually, replace with a library. Add `nonce` to every auth request/response. Document the trusted `issuer` allowlist.

---

## 18. Session Fixation
**Threat:** Attacker sets a known session ID (e.g. via a link `?sid=abc`), victim logs in, attacker rides the now-authenticated session.

**Pattern:**
```ts
// On successful login, ALWAYS regenerate the session id
app.post('/login', async (req, res) => {
  await authenticate(req.body);
  req.session.regenerate(err => {           // critical: new id
    if (err) return res.status(500).end();
    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});
```
Also set `Cookie: HttpOnly; Secure; SameSite=Lax; Path=/`. For JWT, issue a brand-new token on login (never reuse a pre-login token).

**Validate:** Capture the session cookie before login, log in, confirm the cookie value changes (new id).

**Fix:** Audit every auth path for `regenerate`/`rotate`. If using JWT, ensure login returns a fresh token distinct from any pre-auth token.

---

## 19. MFA — Multi-Factor Authentication
**Threat:** Password-only auth is one breach (phish, leak) from full compromise. MFA adds a possession/inherence factor.

**Pattern (TOTP + WebAuthn):**
```ts
import { authenticator } from 'otplib';
// Enroll: show otpauth:// URI + QR; store the secret encrypted per user
// Verify on login:
const ok = authenticator.verify({ token: req.body.totp, secret: user.totpSecret });
if (!ok) return res.status(401).json({ error: 'invalid_mfa' });
```
Prefer **WebAuthn/passkeys** (phishing-resistant) where supported; TOTP as fallback. Enforce MFA for admin/creator roles. Provide recovery codes (hashed, shown once).

**Validate:** Login with correct password but wrong TOTP → `401`. A replayed TOTP within the window is rejected (used-once counter for WebAuthn; TOTP allows clock-skew ±1 step).

**Fix:** Add an MFA enrollment + verification step to the auth flow. Gate privileged roles. Store secrets encrypted at rest, never in plaintext.

---

## 20. Brute Force Protection
**Threat:** Unlimited login attempts → credential stuffing / password guessing.

**Pattern (rate limit + lockout + backoff):**
```ts
import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,                         // 5 attempts / 15 min / IP
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});
app.post('/login', loginLimiter, handler);
```
Add per-account lockout after N failures (with exponential backoff) and a global CAPTCHA after threshold. Use a shared store (Redis) so limits hold across multiple app instances. Pair with MFA (19) so a guessed password still needs the second factor.

**Validate:** 6th login attempt in 15 min from one IP → `429`. A distributed attack across 1000 IPs still hits per-account lockout.

**Fix:** If no limiter exists, add `express-rate-limit` with a Redis store. Add per-account failure counters. See waf-ddos / ddos-protection skills for edge-level protection.

---

## 21. Account Enumeration
**Threat:** Different responses for "user exists" vs "user doesn't" let attackers build a list of valid accounts for targeted attacks.

**Pattern (uniform responses):**
```ts
// WRONG — leaks existence
if (!user) return res.status(404).json({ error: 'no_such_user' });
if (!bcrypt.compare(...)) return res.status(401).json({ error: 'bad_password' });

// RIGHT — identical response either way
const user = await findUser(req.body.email);
const valid = user ? await bcrypt.compare(req.body.password, user.hash) : false;
if (!user || !valid) {
  return res.status(401).json({ error: 'invalid_credentials' }); // same message, same status
}
```
Also: identical timing (don't short-circuit on missing user — compare against a dummy hash), identical rate-limit behavior, and a generic "if this account exists, a reset link was sent" on password reset.

**Validate:** `login` with known-user vs unknown-user returns byte-identical status + body. Password-reset response is identical regardless of existence.

**Fix:** Replace all `404 no_such_user` / `401 bad_password` splits. Add dummy-hash comparison for missing users. Audit reset/register endpoints too.

---

## 22. Timing Attacks
**Threat:** String comparison (`==`, `===`) short-circuits on the first differing byte, leaking match length via response time — enough to forge tokens/HMACs.

**Pattern (constant-time compare):**
```ts
import { timingSafeEqual } from 'crypto';
const a = Buffer.from(providedToken);
const b = Buffer.from(storedToken);
if (a.length !== b.length || !timingSafeEqual(a, b)) return res.status(401).end();
```
Use `crypto.timingSafeEqual` for ALL secret comparisons: tokens, HMACs, API keys, session IDs. Never use `===` on secrets. (See webhooks-hmac skill for signature verification.)

**Validate:** A fuzz test measuring response-time variance between near-miss and far-miss tokens shows no statistically significant difference.

**Fix:** Grep for `===` / `==` on token/secret/HMAC variables. Replace with `timingSafeEqual`. Ensure buffers are equal length before compare (avoid length leak).

---

## 23. File Upload Validation
**Threat:** Malicious uploads → RCE (`.php` executed), XSS (SVG with script), storage exhaustion, or phishing payloads.

**Pattern:**
```ts
import multer from 'multer';
import { fileTypeFromBuffer } from 'file-type';
const ALLOWED = new Set(['image/png', 'image/jpeg', 'image/webp']);
const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } });

app.post('/avatar', upload.single('file'), async (req, res) => {
  const ft = await fileTypeFromBuffer(req.file.buffer);   // magic-byte check, NOT extension
  if (!ft || !ALLOWED.has(ft.mime)) return res.status(400).json({ error: 'bad_type' });
  // strip metadata (EXIF), rename to random uuid, store outside webroot or in object store
  const key = `${crypto.randomUUID()}.${ft.ext}`;
  await s3.putObject({ Bucket, Key: key, Body: req.file.buffer, ContentType: ft.mime });
  res.json({ url: `/cdn/${key}` });
});
```
Rules: allowlist MIME + extension, verify **magic bytes** (not trust the client), cap size, randomize filename (no user input in path — see Path Traversal), strip EXIF, serve with `Content-Disposition: attachment` for non-images, never execute uploads. Scan with ClamAV/object-store AV for malware.

**Validate:** Upload `evil.php` renamed `.png` → rejected (magic-byte mismatch). Upload a 6MB file → `413`. Upload an SVG with `<script>` → rejected or sanitized.

**Fix:** If uploads currently trust extension or skip size checks, add magic-byte validation + limits + random names. Move storage to an object store/CDN, not the webroot.

---

## 24. HSTS — HTTP Strict Transport Security
**Threat:** Without HSTS, a user's first request (or any http:// link) can be intercepted/downgraded (SSL stripping) before the redirect to https.

**Pattern:**
```ts
res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
```
Max-age ≥ 1 year (63072000s). Add `includeSubDomains` and submit to the HSTS preload list only after confirming ALL subdomains serve https. Pair with a permanent 301 from http→https at the edge (nginx/Vercel).

**Validate:** `curl -I https://baseline.click` includes the header. `curl -I http://baseline.click` 301→https. SSL Labs / hstspreload.org confirms listing.

**Fix:** Add the header at the edge (nginx `add_header` or Vercel headers). Ensure no mixed-content (http sub-resources) before enabling `includeSubDomains` + preload (preload is hard to undo).

---

## 25. Supply Chain Attacks
**Threat:** Compromised dependencies, malicious packages (typosquats), poisoned build steps, or a hijacked CI token → code runs in your deploy with full trust.

**Pattern:**
- **Pin + lock:** commit `package-lock.json` / `poetry.lock` (see lockfiles skill, topic 196). Use `npm ci` not `npm install` in CI.
- **Advisory scanning:** `npm audit`, `pip-audit`, and Dependabot/Renovate in CI — fail builds on high/critical (topic 38, dependency vulnerabilities).
- **Provenance:** prefer packages with signed releases; verify hashes. Avoid installing from git URLs or `-git` forks unless reviewed.
- **Least-privilege CI:** CI tokens scoped; OIDC short-lived creds (topic 182, GitOps) instead of long-lived secrets.
- **SBOM:** generate a CycloneDX/SPDX bill of materials per build; diff on release.
- **Private registry mirror** for critical deps so a removed/nuked upstream package can't break or hijack you.

**Validate:** `npm ci` in a clean checkout reproduces the exact tree (no lockfile drift). `npm audit --audit-level=high` is clean. CI blocks a PR that adds a package with a critical advisory.

**Fix:** If lockfiles aren't committed or `npm install` is used in CI, fix that first (see lockfiles skill). Add SCA to the pipeline. Review the top-20 transitive deps for maintainer health.

---

## 26. Threat Modeling
**Threat:** Shipping without modeling the attack surface means you defend the wrong things and miss the high-value paths (payments, auth, secrets).

**Pattern (STRIDE + data-flow, lightweight per service):**
1. **Map** the system: actors, assets, data flows, trust boundaries (draw a DFD).
2. **STRIDE** each element: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege.
3. **Rank** by likelihood × impact (use the 198-item checklist as a prompt library).
4. **Mitigate** each top risk with a control from this skill or a sibling.
5. **Verify** the control with the topic's Validate step.
6. **Revisit** on every significant change (new endpoint, new integration).

Example baseLINE assets: Privy app secret, Bankr key, TWITCH_* creds, user wallets, tip records, creator payouts. Trust boundary: browser ↔ Privy ↔ baseLINE API ↔ Postgres/Redis ↔ Bankr/on-chain.

**Validate:** Every external endpoint in the DFD has at least one mapped control from topics 1–25. High-impact STRIDE items have tickets + tests.

**Fix:** If no threat model exists for a service, run the 6-step pass. Record the DFD + STRIDE table in the service's `docs/THREAT_MODEL.md`. Re-run quarterly.

---

## Validation Checklist (all 26 topics)
- [ ] Every `:id` route enforces ownership (1)
- [ ] File paths canonicalized + rooted (2)
- [ ] ORM writes use explicit DTOs (3)
- [ ] `frame-ancestors 'none'` set (4)
- [ ] CSP enforced, no `unsafe-inline` in script-src (5)
- [ ] Full security-header set present (6)
- [ ] zod (or equiv) parses every inbound body (7)
- [ ] Server-side authz on every protected route (8)
- [ ] RLS enabled on multi-tenant tables (9)
- [ ] DB/app roles least-privilege (10)
- [ ] RBAC matrix centralized + tested (11)
- [ ] Passwords hashed, not encrypted (12)
- [ ] Per-user salt via bcrypt/Argon2 (13)
- [ ] Argon2id/bcrypt ≥ policy cost (14)
- [ ] JWT `exp` ≤ 15 min (15)
- [ ] Refresh tokens server-side + rotated (16)
- [ ] OIDC verified with library + nonce (17)
- [ ] Session regenerated on login (18)
- [ ] MFA on privileged roles (19)
- [ ] Rate limit + lockout on auth (20)
- [ ] Uniform auth responses (21)
- [ ] `timingSafeEqual` on all secrets (22)
- [ ] Uploads magic-byte + size + random name (23)
- [ ] HSTS ≥ 1y + preload (24)
- [ ] Lockfiles + SCA in CI (25)
- [ ] Threat model DFD + STRIDE per service (26)

## Fix Recipes (common remediation paths)
- **"We have no authz layer"** → topics 8, 11: add `requireRole` middleware + RBAC matrix, gate at router level.
- **"Passwords might be weak-hashed"** → topics 12–14: migrate to Argon2id, rehash-on-login.
- **"Tokens never expire"** → topics 15–16: add `exp`, introduce rotated refresh tokens.
- **"Users can see each other's data"** → topics 1, 9: ownership checks + RLS.
- **"Upload endpoint is open"** → topics 23, 2: magic-byte validation + path canonicalization.

## Cross-References
- `pcmedicalist-sql-injection` — topic 1's data layer
- `pcmedicalist-xss` — pairs with CSP (5)
- `pcmedicalist-csrf` — state-changing requests
- `pcmedicalist-cors-policy` — cross-origin surface
- `pcmedicalist-ssrf` — server-side URL fetching
- `pcmedicalist-secret-hygiene` — topics 17, 25 secret storage
- `pcmedicalist-jwt-rotation` — topic 15 key lifecycle
- `pcmedicalist-oauth` — topic 26 (OAuth 2.0); OIDC (17) builds on it
- `pcmedicalist-webhooks-hmac` — topic 22 timing-safe verify
- `pcmedicalist-tls-termination` — underpins HSTS (24)
- `pcmedicalist-encryption-at-rest` — topic 12 encrypt path
- `pcmedicalist-waf-ddos` / `pcmedicalist-ddos-protection` — topic 20 edge limits
- `pcmedicalist-database-deep-dive` — topic 9 RLS implementation detail, UUIDs (60)
- `pcmedicalist-infrastructure-ops` — non-root containers (191), image scanning (192)
- `pcmedicalist-lockfiles` — topic 25 supply-chain
- `pcmedicalist-gitops` — topic 25 CI provenance
