# Indiko Security Audit — Findings

Adversarial review of indiko (https://indiko.dunkirk.sh), conducted 2026-07-28.
Code audit + live instance probing. Ordered by severity.

---

## Critical

### C1. Login challenge lookup uses "latest row wins" — cross-session challenge confusion / login DoS
**File:** `src/routes/auth.ts:576-598`

```ts
const challenge = db.query(
  "SELECT challenge, expires_at FROM challenges WHERE username = ? AND type = 'authentication' ORDER BY created_at DESC LIMIT 1"
).get(challengeUsername)
```

The server never checks that the challenge inside the signed WebAuthn assertion corresponds to the challenge it issued *for this specific login attempt*. It just grabs the most recent challenge for the username (or empty username for conditional UI) and hands it to `verifyAuthenticationResponse` as `expectedChallenge`.

**Attack:**
- **DoS against any user:** Attacker calls `POST /auth/login/options` with `{"username":"victim"}` in a loop. Each call inserts a new challenge row. When the victim completes their real passkey ceremony, `loginVerify` reads the attacker's newer challenge, not the victim's. Verification fails. Repeat indefinitely → victim can't log in.
- **DoS against all conditional-UI logins:** Conditional UI challenges are stored under `username = ""`. Any anonymous caller can request new conditional challenges, racing every legitimate conditional login on the site.

**Verified live:** Two back-to-back conditional `loginOptions` calls returned different challenges; both are stored, only the newest is ever used.

**Fix:** Generate a random `challenge_id`, return it to the client, require the client to submit it in `loginVerify`, look up by `(challenge_id, username)`. Burn the challenge on *any* verify attempt (success or failure), not just success.

---

### C2. Invite consumption race — loser keeps account + session
**File:** `src/routes/auth.ts:339-351`

```ts
const result = db.query(
  "UPDATE invites SET current_uses = current_uses + 1 WHERE id = ? AND current_uses < max_uses"
).run(inviteId);

if (result.changes === 0) {
  return Response.json({ error: "Invite code fully used" }, { status: 403 });
}
```

The atomic increment is good. But the user row, credential row, and session row were **already inserted** at lines 307-332, 374-379. The loser of the race walks away with:
- A registered account (username taken)
- A passkey credential
- A valid 24h session cookie + Bearer token

For a single-use LDAP-locked invite, that's two provisioned accounts from one invite.

**Attack:** Attacker intercepts an invite link (referer leak, shared chat log), races the legitimate invitee's registration with their own WebAuthn ceremony on the same code. Whoever loses the atomic race still has a working session.

**Fix:** Wrap the whole registration (user insert, credential insert, session insert, invite increment) in a SQLite transaction. Roll back everything if the invite UPDATE returns 0 changes.

---

### C3. Consent POST does not re-validate `redirect_uri` against registered list — attacker-minted authorization codes
**File:** `src/routes/oauth/authorize.ts:281-413`

The GET path carefully validates `redirectUri ∈ app.redirect_uris` at line 96. The POST handler (consent form submission) re-canonicalizes the POSTed `redirect_uri` at lines 333-334 but **never checks it against `allowedRedirects`** and never re-runs `ensureApp`.

**Attack:**
1. Attacker registers a malicious app with `redirect_uri=https://attacker.com/cb` (any URL-based client can publish any same-host redirect).
2. Victim goes through the OAuth flow with the attacker's client_id.
3. The consent page renders hidden inputs including `redirect_uri=https://attacker.com/cb` and `code_challenge=attacker-controlled`.
4. Attacker tricks the victim into submitting the form (or uses a MITM on an http:// client).
5. Server inserts an authcode bound to `client_id` + `redirect_uri=https://attacker.com/cb` and 302s the victim there with a valid authorization code.
6. Attacker exchanges the code for access + refresh tokens in the victim's name.

PKCE doesn't help because the attacker chose the `code_challenge` and knows the verifier.

**Mitigating factor:** The consent form has no CSRF token, and the session cookie uses `SameSite=Lax`, which blocks cross-site POST cookies in modern browsers. So pure CSRF is blunted. But a malicious client can still do this by rewriting the POST body in transit (http:// clients are allowed per `validateClientURL`), or via social engineering.

**Fix:** In `authorizePost`, after canonicalizing `redirectUri`, look up the app and enforce `allowedRedirects.includes(redirectUri)` exactly like the GET path. Also consider binding the consent state (client_id + redirect_uri + code_challenge) with a server-side nonce to prevent tampering.

---

## High

### H1. SSRF via unauthenticated client metadata fetch — no DNS resolution validation
**File:** `src/lib/ssrf-safe-fetch.ts:207-253`, used by `src/lib/oauth/client-metadata.ts:102`

`validateExternalURL` blocks literal private IPs and local hostnames, but a hostname like `attacker.com` resolving to `10.0.0.5` or `169.254.169.254` passes every check. There is **no DNS resolution + IP validation step**, and no post-connect validation.

The fetch is triggered **unauthenticated**:
- `GET /auth/authorize?client_id=https://rebinding.attacker.com&redirect_uri=...` → `ensureApp` → `fetchClientMetadata` → `safeFetch`

**Verified live:** The authorize endpoint runs `ensureApp` *before* the login check. An unauthenticated attacker can force the server to fetch any URL.

**DNS rebinding:** Trivial. First DNS resolution (for validation) returns a public IP. Second resolution (for the actual fetch, done by Bun's HTTP client) returns the target private IP. Since validation never resolves at all, you don't even need rebinding — one A record pointing at the target works.

**Redirect chain bypass:** The redirect re-validation at line 243-251 checks `response.url` *after* the redirect was already followed by `fetch(..., redirect: "follow")`. The target has already been fetched; only the response body usage is blocked. For cloud metadata endpoints (AWS IMDSv1), credentials are already in the TCP stream.

**IPv6 bypass:** `isPrivateIP` handles `[::ffff:10.1.1.1]` (dotted-quad after `::ffff:`) but not hex-form mapped addresses like `[::ffff:a01:101]` — the regex at line 73 only matches dotted-quad.

**Port blocklist:** Only blocks 22, 23, 25, 53, 110, 143, 445, 3306, 5432, 6379, 11211, 27017. Any internal service on 8080, 3000, 9090, 2375 (Docker), 8500 (Consul), etc. is reachable.

**Attack scenario:** Unauthenticated attacker hits `/auth/authorize?client_id=http://attacker-controlled.example&redirect_uri=...` where the A record points to an internal IP reachable from the server (Proxmox, TrueNAS, LAN services). Response body isn't shown directly, but `ensureApp` error messages include fetch failure details — an oracle for host/port scanning of the internal network.

**Fix:**
1. Resolve the hostname with `dns.resolve`, validate every returned A/AAAA against `isPrivateIP`, then connect by IP with the `Host`/TLS SNI of the original hostname (or pin resolution via a custom fetch dispatcher).
2. Use `redirect: "manual"` and validate each hop before following.
3. Fix the IPv6 parser to canonicalize hex-mapped forms before prefix checks.
4. Consider blocking all non-standard ports for metadata fetches (only allow 80/443).

---

### H2. Device-flow user code brute force — no rate limiting on verification endpoint
**File:** `src/routes/oauth/device-verify.ts:172-318`

The user code is 8 chars from a 20-char alphabet (~34.6 bits, ~2.5×10¹⁰). RFC 8628 §5.2 explicitly warns about this and demands rate limiting. There is none.

**Attack:**
- Attacker initiates their own device flow to see the code format.
- Attacker polls `/device?code=XXXX-XXXX` in a loop. No lockout, no CAPTCHA.
- With N pending codes, expected guesses ≈ 2.5×10¹⁰ / N. Against a busy server with 1000 pending codes, ~2.5×10⁷ guesses — feasible in hours.
- Once guessed, the attacker *approves the victim's pending device code as themselves* (`devicePost` sets `user_id` to the session user). The victim's device (TV/CLI) then receives a token for the **attacker's** account.

The phishing direction is worse: attacker initiates a device code, sends the victim `verification_uri_complete` (provided at `device.ts:90`), victim clicks and approves → attacker's polling client gets the **victim's** token.

**Fix:** Rate-limit `/device` verification attempts per session/IP (e.g., 10 failures → 15-min lockout). Increase code entropy (or shorten TTL below 600s). Log/alert on failed lookups.

---

### H3. Device-code polling `client_id` check is optional — cross-client device-code confusion
**File:** `src/routes/oauth/token.ts:186-222`

```ts
clientId = rawClientId ? canonicalizeURL(rawClientId) : undefined;
...
if (clientId && deviceCode.client_id !== clientId) { ... }
```

If the caller omits `client_id` entirely, the check is skipped. Anyone holding a `device_code` can poll for it.

**Verified live:** `POST /auth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=...` (no `client_id`) returns `authorization_pending`. With a mismatched `client_id`, it returns `client_id mismatch`. The oracle confirms the check is skipped when `client_id` is absent.

RFC 8628 §3.4 requires `client_id` for public clients. The `device_code` itself is 32 random bytes so this isn't directly guessable, but it breaks the binding between the device authorization and its client. A leaked `device_code` (logs, screenshots) can be redeemed by any client.

**Also:** The device grant path never calls `verifyClientCredentials`, so a **confidential client's** device code can be redeemed without its secret at all.

**Fix:** Require `client_id` on the device_code grant and match it. For pre-registered (confidential) clients, also require the client secret via `verifyClientCredentials`.

---

### H4. Token endpoint has zero rate limiting — brute force oracle
**File:** `src/routes/oauth/token.ts:21-57`

No throttling anywhere on `/auth/token`. Practical consequences:

1. `verifyClientCredentials` (lines 340-382) is an online oracle for `iks_...` secrets. nanoid(43) is ~254 bits, so brute force is infeasible, but there's also no lockout/alerting. A leaked-prefix secret can be ground against the endpoint indefinitely. The 401 vs 400 responses distinguish "unknown client" from "wrong secret" from "missing secret," aiding enumeration.
2. Authorization codes are 32 bytes — safe from guessing, but each *failed* PKCE verify costs a SHA-256 + DB hit. Unauthenticated CPU-DoS amplifier.
3. `tokenIntrospect` (lines 623-686) is unauthenticated and returns token validity + scopes + username for any presented token. Fine against 32-byte tokens, but it's an oracle that never locks out.

**Mitigating factor:** Cloudflare in front provides some rate limiting (observed 429s during testing). But the app should not rely solely on the edge.

**Fix:** Per-IP + per-client sliding-window rate limit on `/auth/token` (e.g., 20 req/min burst for public clients). Exponential backoff after repeated `invalid_client`. Uniform error responses (don't distinguish unknown client from wrong secret).

---

### H5. Refresh-token rotation race — concurrent refresh yields two valid tokens
**File:** `src/routes/oauth/token.ts:59-170`

The flow: SELECT token row → check `rotated === 0` → `UPDATE ... SET rotated = 1 WHERE id = ?` → INSERT new row. There is **no transaction** and the UPDATE isn't conditional (`WHERE id = ? AND rotated = 0`).

Two concurrent requests with the same refresh token both pass the `rotated === 1` check, both issue new access+refresh tokens in the same family. This defeats the reuse-detection model (RFC 9700 §4.14.2 assumes exactly one winner) and doubles token lifetime for a racing client. An attacker holding a stolen refresh token races the legitimate client and both win, without ever tripping family revocation.

**Fix:** Wrap in `db.transaction`, or make rotation atomic: `UPDATE tokens SET rotated = 1 WHERE id = ? AND rotated = 0` and bail with `invalid_grant` when `changes === 0` (then revoke family per your reuse policy).

---

### H6. OIDC: ID token `sub` is mutable user website URL — identity instability + userinfo mismatch
**File:** `src/oidc.ts:120-138`, `src/routes/oauth/token.ts:580-617`

- `sub = meValue` (token.ts:582) where `meValue` is `user.url` if set — the user can change `user.url` anytime via `/api/profile`, changing their `sub` at every RP.
- OIDC Core §8: `sub` MUST be locally unique and **never reassigned**. Stability matters.
- `userinfo` (userinfo.ts:55) uses the stable `/u/username` — so `sub` differs between the ID token and userinfo for the same user, violating OIDC Core §5.7 ("the sub value in ID token and userinfo MUST match").
- An RP keying accounts on ID-token `sub` lets a user hop identities by changing their URL (including, after verification, to a URL previously owned by someone else's account).

**Fix:** `sub = origin/u/username` always (put the `me` delegation in a custom claim or `website`). Add `at_hash` (SHA-256 left-half, base64url) since access tokens are always issued alongside.

---

## Medium

### M1. XSS via attacker-controlled `client_name` in error-page `hint` (unescaped HTML)
**File:** `src/lib/oauth/pages.ts:160`, `src/routes/oauth/authorize.ts:116`

```ts
${opts.hint ? `<p class="hint">${opts.hint}</p>` : ""}
```

`opts.hint` is **not escaped** (intentional, since callers embed `<code>`). Callers in `authorize.ts:116` build the hint with `` `<strong>${appName}</strong>` `` where `appName = app.name || clientId`. `app.name` comes from attacker-controlled client metadata (`client_name` in the fetched JSON document).

**Attack:** Attacker registers a client with `client_name = "<script>...</script>"` or `<img onerror=...>`, gets any user to start an authorize flow with a *mismatched* `redirect_uri` (easy — the attacker's own site initiates it), and the error page renders the stored `client_name` as raw HTML in the user's authenticated origin.

Session cookie is `HttpOnly` so no direct theft, but the injected JS can:
- Fetch `/api/*` with Bearer tokens (if any are stored in localStorage)
- Approve devices (`/device` POST)
- Complete OAuth flows as the victim
- Modify the user's profile

**Fix:** Escape `appName` before interpolating into `hint`, or make `hint` accept structured data and escape by default.

---

### M2. No CSRF token on consent POST and device approve POST
**File:** `src/routes/oauth/authorize.ts:281`, `src/routes/oauth/device-verify.ts:258`

Both rely solely on `SameSite=Lax`. Lax blocks cross-site POST cookies in modern browsers, but:
- Top-level GET navigation from attacker site *carries* the cookie, and `deviceGet` with `?code=` shows the confirmation. Combined with auto-`verification_uri_complete`, an attacker can frame the whole phish in one link.
- Clickjacking is blocked by `frame-ancestors 'none'` (good), but a user following an emailed `verification_uri_complete` + clicking "allow" is one click from authorizing the attacker's device.

**Fix:** Add per-page CSRF nonces on both POSTs. Check `Sec-Fetch-Site` headers.

---

### M3. `authorizeGet` auto-approve path builds redirect with raw string interpolation of `state`
**File:** `src/routes/oauth/authorize.ts:209`, `:344`, `:411`

```ts
Response.redirect(`${redirectUri}?code=${code}&state=${state}&iss=${encodeURIComponent(origin)}`)
```

`state` is attacker-controlled and inserted unencoded. A state of `x&code=INJECTED` or `x#` lets the attacker append/override query params of the redirect URL.

**Attack:** `state = legit&code=AAA` produces `...?code=REAL&state=legit&code=AAA&iss=...` — many client-side parsers take the *last* `code`, so the attacker controls which code value the client sees. With `error` appended: `state=x&error=access_denied` — spoofed error responses.

**Fix:** Use `URLSearchParams` to build the redirect URL, or at minimum `encodeURIComponent(state)`.

---

### M4. Suspended users keep passkey management — divergent session parsing
**File:** `src/routes/passkeys.ts:12-331`

Every handler duplicates a raw `sessions` lookup (`expires_at > strftime('%s','now')`) instead of `getSessionUser`/`validateSession`. Unlike `session.ts:34`, these never check `users.status === 'active'`.

A **suspended user can still list, add, rename, and delete passkeys** as long as an unexpired session token exists. `disableUser` deletes sessions, so the window is small. But LDAP-orphan suspension (`LDAP_ORPHAN_ACTION=suspend`) and `loginOptions`-triggered suspension do **not** delete sessions — a suspended LDAP user keeps full passkey management until token expiry, and `addPasskeyVerify` lets them plant a *new* credential persisting beyond suspension.

Also `listPasskeys` regex-parses the cookie (`match(/indiko_session=([^;]+)/)`) differently from `getUserFromCookie` — divergent parsing is asking for edge-case auth confusion.

**Fix:** Consolidate all session checks on `session.ts`. Add `status === 'active'` check to passkey routes. Delete sessions on suspension.

---

### M5. LDAP group-vs-credentials error split → LDAP user enumeration
**File:** `src/routes/auth.ts:719-733`

`ldapVerify` returns 401 "Invalid credentials" vs 403 "not a member of the required group". That distinction confirms *valid LDAP usernames* to unauthenticated callers.

**Fix:** Return a single uniform error for both cases.

---

### M6. Unauthenticated unbounded dynamic registration — DB DoS + phishing clients
**File:** `src/routes/oauth/register.ts:41-112`

`POST /oauth/register` is unauthenticated with no rate limit. Comment says "rate limiting is out of scope here."

Risks:
- Mass registration = one-line loop DoS (each call inserts a row)
- Cheap CPU exhaustion
- Attacker registers a client whose `client_name` contains HTML hoping some admin page renders it raw
- `redirect_uris` like `https://victim.com` let the attacker create a confusingly-named confidential client for phishing consent screens ("Acme Corp — sign in"), since they control name/logo freely

**Fix:** Rate-limit by IP. Cap `redirect_uris.length`. Require https for redirect_uris (or explicitly allow http localhost only). Consider an `INITIAL_ACCESS_TOKEN` env-gate for the endpoint.

---

### M7. Passkey counter regression not enforced — cloned authenticator detection gap
**File:** `src/routes/auth.ts:596-623`

`verifyAuthenticationResponse` is called with `credential.counter` from DB, and `authenticationInfo.newCounter` is stored back (lines 617-623). But SimpleWebAuthn only *returns* the values; enforcement of counter progression is on the caller.

If `newCounter <= storedCounter` (and storedCounter > 0), that's a cloned authenticator. The code doesn't reject it.

**Fix:** Add `if (newCounter <= credential.counter && credential.counter !== 0) reject`.

---

### M8. OIDC key IDs are millisecond timestamps — guessable/enumerable
**File:** `src/oidc.ts:31`

```ts
const kid = `indiko-oidc-key-${Date.now()}`;
```

Millisecond timestamp kids are guessable/enumerable. Low impact since the JWKS endpoint is public anyway, but use a random UUID instead.

---

## Low

### L1. Duplicated `if (refreshToken)` block (dead code)
**File:** `src/routes/oauth/token.ts:571-573`

```ts
if (refreshToken) { response.refresh_token = refreshToken; }
if (refreshToken) { response.refresh_token = refreshToken; }  // duplicate
```

Sloppy, no vuln.

---

### L2. `verifyPKCE` uses `===` string comparison, not constant-time
**File:** `src/lib/oauth/urls.ts:182-185`

The challenge is a hash of a high-entropy verifier, so timing gives the attacker nothing useful. Low.

---

### L3. `canonicalizeURL` passes non-http(s) strings through unchanged
**File:** `src/lib/oauth/urls.ts:2-15`

`ikc_xxx` IDs are fine, but `javascript:...` survives canonicalization and only later gets rejected by `validateClientURL`. A footgun for future callers.

---

### L4. `hasDotSegments` doesn't decode percent-encoded dots
**File:** `src/lib/oauth/urls.ts:83-92`

`%2e%2e` isn't decoded, so `https://example.com/%2e%2e/x` passes. `new URL` keeps `%2e` encoded in pathname. Impact limited since downstream comparisons use canonical strings consistently.

---

### L5. Introspection returns `username` — non-standard claim
**File:** `src/routes/oauth/token.ts:680`

Leaks the local login name to any caller holding any valid token. Information disclosure, low.

---

### L6. `errorPage` returns HTTP 400 for all error pages
**File:** `src/lib/oauth/pages.ts:127-129`

Semantics only. Some errors should be 401, 403, or 500.

---

## Live Instance Observations

- **Cloudflare in front** provides rate limiting (observed 429s), DDoS protection, and some WAF coverage. The app should not rely solely on this.
- **Security headers present:** `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy` (implicit via Caddy). Good.
- **No `Strict-Transport-Security` header observed.** Add `max-age=31536000; includeSubDomains; preload`.
- **No `X-Content-Type-Options: nosniff`.** Add it.
- **JWKS endpoint returns empty keys array** until first OIDC token is issued. This is fine functionally but may confuse RPs that pre-fetch keys.

---

## Priority Fix Order

1. **C3** — One `allowedRedirects.includes(redirectUri)` check in `authorizePost`. Small, surgical, closes a real code-issuance bypass.
2. **C1** — Key login challenges by client-returned ID. Burn on any verify attempt. Small change, kills login DoS.
3. **H1** — DNS-resolve-and-pin in `safeFetch`. Manual redirect handling. The meatiest fix but the highest impact.
4. **C2 / H5** — Transactions around invite consumption and refresh rotation.
5. **H2 / H4** — A tiny in-memory rate limiter on `/device` verify and `/auth/token`.
6. **H6** — Stable `sub` + `at_hash`. Spec compliance + identity stability.
7. **M1** — Escape `appName` in error-page hints. One-line fix.
8. **M3** — Encode `state` in success redirects. One-line fix.

---

## Defense-in-Depth Recommendations

- Add `Strict-Transport-Security` and `X-Content-Type-Options` headers globally.
- Add structured logging for security events (failed logins, invite races, token reuse detection, SSRF blocks).
- Consider a `Content-Security-Policy` beyond `frame-ancestors` for the consent/error pages (restrict script-src to self).
- Add a `Referrer-Policy: strict-origin-when-cross-origin` header.
- Consider requiring `Sec-Fetch-Site: same-origin` on sensitive POSTs (defense in depth alongside SameSite=Lax).
