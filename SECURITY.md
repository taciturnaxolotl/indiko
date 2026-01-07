# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in Indiko, please report it privately:

- **Email:** security@dunkirk.sh
- **Do not** open public issues for security vulnerabilities
- You will receive a response within 48 hours

We appreciate responsible disclosure and will credit researchers who report vulnerabilities (unless you prefer to remain anonymous).

---

## Security Architecture

### Authentication Model

Indiko uses **WebAuthn/Passkeys** for passwordless authentication:

- **No passwords stored** - eliminates credential stuffing, dictionary attacks, and password database breaches
- **Public key cryptography** - private keys never leave the user's device
- **Phishing resistant** - cryptographic binding to domain prevents phishing
- **Platform authenticators** - biometric authentication (Face ID, Touch ID, Windows Hello)

### OAuth 2.0 Implementation

**Authorization Code Flow with PKCE:**

- All authorization codes are **single-use** and expire in 60 seconds
- **PKCE (S256)** required for public clients (auto-registered apps)
- **Client secrets** (SHA-256 hashed) required for pre-registered confidential clients
- Redirect URIs validated against registered allowlist

**Session Management:**

- Session tokens: cryptographically random UUIDs (128-bit entropy)
- 24-hour session expiry with automatic cleanup (runs hourly)
- HttpOnly cookies prevent XSS token theft
- Secure flag enabled in production (HTTPS-only transmission)
- SameSite=Lax provides CSRF protection

### Database Security

- **SQLite with WAL mode** for concurrent access
- **Foreign keys enabled** for referential integrity
- **Parameterized queries** throughout - no SQL injection vectors
- **Credential data** stored as Buffers with proper encoding

---

## Known Security Considerations

### LDAP Account Provisioning ⚠️

When using LDAP authentication, accounts are provisioned on first successful LDAP login. **Important:** If a user is subsequently deleted from LDAP, their Indiko account **remains active**. This is by design—account lifecycle is managed independently from LDAP.

**Admin responsibilities:**

- **Audit provisioned accounts:** Query the `provisioned_via_ldap` column to identify LDAP-provisioned users
- **Manual deprovisioning:** Suspended or delete accounts in Indiko when users are removed from LDAP
- **Document policy:** Establish clear procedures for account deletion when LDAP users are removed

**Example audit query:**

```sql
SELECT username, created_at, status FROM users WHERE provisioned_via_ldap = 1;
```

To suspend an LDAP account:

```sql
UPDATE users SET status = 'suspended' WHERE username = 'username_here';
```

### Rate Limiting ⚠️

Indiko does **not** currently implement rate limiting. This is acceptable for:

- Personal homelab deployments
- Small team internal authentication
- Deployments behind a reverse proxy with rate limiting (nginx, Caddy, Cloudflare)

If exposing Indiko to the public internet, implement rate limiting:

```typescript
// Suggested limits per IP:
- Challenge generation: 10 requests/minute
- Login/registration: 5 attempts/minute
- Token exchange: 20 requests/minute
- Admin endpoints: 20 requests/minute
```

### Bootstrap Mode

**First user registration** automatically becomes admin without invite code.

**Security implications:**

- Expose Indiko only after creating your admin account
- Consider disabling bootstrap mode after first user (future feature)

### Invite Code Security

Invite codes use 16 bytes of cryptographic randomness (base64url encoded, ~128 bits entropy).

### Client Secret Management

Client secrets for pre-registered OAuth apps use 43-character nanoid (~256 bits entropy).

- Secrets shown **only once** at creation
- Stored as SHA-256 hashes
- No recovery mechanism - regenerate if lost
- Rotate secrets if compromised or annually

---

## Production Deployment

Indiko is designed to run behind a reverse proxy in production. See the [README deployment section](README.md#production-deployment) for complete nginx/Caddy configurations with security headers.

**Environment Variables:**

- `ORIGIN` must be HTTPS URL in production (validated at startup)
- `RP_ID` must match ORIGIN domain (validated at startup)
- `NODE_ENV=production` enables Secure cookie flag

---

## Notes

### For Developers (OAuth Clients)

1. **Use PKCE:**

   - Always generate code_verifier (43+ character random string)
   - Use S256 code_challenge_method
   - Never reuse verifiers across authorization flows

2. **Protect client secrets:**

   - Store in environment variables or secret manager
   - Never commit to version control
   - Never expose in client-side code
   - Rotate if compromised

3. **Validate tokens:**

   - Check `me` field matches expected user identity
   - Verify `scope` includes required permissions
   - Handle token errors gracefully
   - Don't cache profile data indefinitely

4. **Respect user privacy:**
   - Request minimum necessary scopes
   - Provide clear app description and logo
   - Implement logout/revoke functionality
   - Don't share user data with third parties

---

## Compliance Notes

### GDPR (EU General Data Protection Regulation)

**Personal data stored:**

- Username, name, email (optional), photo URL (optional)
- Passkey credential data (public keys only)
- Session tokens (temporary)
- OAuth authorization history

**User rights:**

- **Right to access:** Users can view profile at `/`
- **Right to erasure:** Users can delete their account at `/`
- **Right to data portability:** Export database manually (SQLite dump)
- **Right to rectification:** Users can edit profile at `/`

**Data retention:**

- Active data retained while account exists
- Expired sessions/challenges automatically cleaned hourly
- Deleted accounts immediately remove all personal data (foreign key cascade)

### CCPA (California Consumer Privacy Act)

Indiko does not sell personal information. Users can initiate data deletion via dashboard.

### Cookie Policy

| Cookie Name      | Purpose                | Duration | Type      |
| ---------------- | ---------------------- | -------- | --------- |
| `indiko_session` | Authentication session | 24 hours | Essential |

No tracking or analytics cookies are set by Indiko.

---

## Contact

- **Security Issues:** <security@dunkirk.sh>
- **General Support:** <https://tangled.org/@dunkirk.sh/indiko>
- **Maintainer:** Kieran Klukas (@taciturnaxolotl)

---

_Last Updated: December 18, 2025_
