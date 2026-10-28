# Crush Memory - Indiko Project

## User Preferences

- **DO NOT** run the server - user will always run it themselves
- **DO NOT** test the server by starting it
- Use Bun's `routes` object in server config, not manual fetch handler routing

## Architecture Patterns

### Route Organization
- Use separate route files in `src/routes/` directory
- OAuth/IndieAuth/OIDC endpoints live in `src/routes/oauth/` subdirectory
- Export handler functions that accept `Request` and return `Response`
- Import handlers in `src/index.ts` and wire them in the `routes` object
- Use Bun's built-in routing: `routes: { "/path": handler }`
- Dynamic params via Bun's `:param` syntax (e.g., `/u/:username`), accessed via `req.params.username`
- Method dispatch is manual per-route: check `req.method` and return 405 for unsupported methods

### Project Structure
```
src/
├── db.ts              # Database setup and exports
├── index.ts           # Main server entry point (routes, startup validation, cleanup jobs)
├── oidc.ts            # OIDC key management, ID token signing (jose), discovery document
├── ldap-cleanup.ts    # LDAP sync, orphan detection, on-login verification
├── routes/            # Route handlers (server-side)
│   ├── auth.ts        # Passkey registration/login options + verify
│   ├── api.ts         # User-facing API (profile, apps) and admin user management
│   ├── clients.ts     # Admin OAuth client CRUD (create, update, delete, secret regen)
│   ├── passkeys.ts    # Passkey management (list, add, rename, delete)
│   └── oauth/         # OAuth 2.0 / IndieAuth / OIDC endpoints
│       ├── authorize.ts   # Authorization endpoint (GET shows consent, POST processes)
│       ├── token.ts       # Token exchange, refresh, introspection, revocation
│       ├── discovery.ts   # Well-known metadata endpoints
│       ├── userinfo.ts    # OIDC userinfo endpoint + logout
│       ├── profile.ts     # Public profile page (/u/:username) with h-card
│       └── invites.ts     # Invite CRUD
├── lib/               # Shared server-side utilities
│   ├── accept.ts      # Accept-header negotiation (acceptmarkdown.com)
│   ├── content-pages.ts # Markdown-backed public pages + JSON-LD/meta shell
│   ├── frontmatter.ts # Shared `---` frontmatter parser
│   ├── session.ts     # Session auth (Bearer token and cookie), SessionUser type, cookie helpers, session-bound CSRF
│   ├── rate-limit.ts  # In-memory fixed-window RateLimiter (no-op under NODE_ENV=test)
│   ├── client-ip.ts   # getClientIp via server.requestIP (setServer) with optional TRUSTED_PROXY headers
│   ├── ssrf-safe-fetch.ts  # SSRF-safe fetch wrapper (blocks private IPs, validates redirects)
│   └── oauth/         # OAuth-specific helpers
│       ├── client-metadata.ts  # Client registration, metadata fetch/validation
│       ├── pages.ts            # Server-rendered HTML (consent page, error pages, escapeHtml)
│       ├── urls.ts             # URL canonicalization and validation per IndieAuth spec
│       ├── client-display.ts   # clientDisplayName / clientRegistration (never throw on ikc_ ids)
│       └── errors.ts           # OAuth error responses
├── client/            # Client-side TypeScript modules
│   ├── ds/            # Design system (Elena web components + CSS)
│   │   ├── index.ts       # Import once per page to register all components
│   │   ├── tokens.css     # Design tokens (colors, spacing, typography)
│   │   ├── components.css # Component styles
│   │   ├── button.ts      # <i-button>
│   │   ├── card.ts        # <i-card>
│   │   ├── nav.ts         # <i-nav>
│   │   ├── passkey-row.ts # <i-passkey-row>
│   │   ├── scope-list.ts  # <i-scope-list>
│   │   └── toast.ts       # <i-toast>
│   ├── login.ts       # Login page logic
│   ├── index.ts       # Dashboard logic
│   ├── admin.ts       # Admin panel logic
│   ├── admin-clients.ts  # Admin client management
│   ├── admin-invites.ts  # Admin invite management
│   ├── apps.ts        # Authorized apps page
│   ├── docs.ts        # Docs page
│   ├── site.ts        # Public pages, robots.txt, sitemap.xml, llms.txt, 404
│   └── oauth-test.ts  # OAuth test client
├── html/              # HTML templates (Bun bundles them with script imports)
│   ├── login.html
│   ├── index.html
│   ├── admin.html
│   ├── admin-clients.html
│   ├── admin-invites.html
│   ├── apps.html
│   ├── docs.html
│   ├── oauth-test.html
│   └── admin-shared.css
├── migrations/        # SQL migrations (001 through 017; see `ls src/migrations` for the latest)
│   ├── 001_init.sql
│   ├── 002_add_me_to_authcodes.sql
│   ├── 003_add_tokens_table.sql
│   ├── 004_add_refresh_tokens.sql
│   ├── 005_add_user_tier.sql
│   ├── 006_add_passkey_names.sql
│   ├── 007_add_ldap_support.sql
│   ├── 008_add_oidc_keys.sql
│   ├── ...
│   ├── 015_add_authcode_family.sql
│   ├── 016_add_app_registration.sql
│   └── 017_add_authcode_issue_refresh.sql
├── styles.css         # Global styles (non-component)
scripts/               # Utility scripts (run with `bun scripts/<name>.ts`)
│   ├── audit-ldap-orphans.ts  # Audit/cleanup LDAP-orphaned accounts
│   └── reset-passkey.ts       # Reset a user's passkey, generate re-registration link
test/                  # Tests (bun:test)
│   ├── helpers/db.ts  # In-memory DB setup, test factories (createUser, createSession)
│   ├── session.test.ts
│   ├── token.test.ts
│   ├── urls.test.ts
│   └── pages.test.ts
```

### Database Migrations

**Migration Versioning:**
- SQLite uses `PRAGMA user_version` to track migration state
- Version starts at 0, increments by 1 for each migration
- The `bun-sqlite-migrations` package handles version tracking
- Migrations are stored in `src/migrations/` directory

**Creating a New Migration:**

1. **Name the file**: Use 3-digit prefix (e.g., `009_add_feature.sql`)
   - Next available number = highest existing number + 1
   - Use descriptive name (e.g., `009_add_auth_tokens.sql`)

2. **Write SQL statements**: Add schema changes in the file
   ```sql
   -- Add new column to users table
   ALTER TABLE users ADD COLUMN new_field TEXT DEFAULT '';

   -- Create new table
   CREATE TABLE IF NOT EXISTS new_table (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     name TEXT NOT NULL
   );
   ```

3. **Migration execution**:
   - Migrations run automatically when server starts (`src/db.ts`)
   - Only new migrations (version > current) are executed
   - Each migration increments `user_version` by 1

**Version Tracking:**
- Check current version: `sqlite3 data/indiko.db "PRAGMA user_version;"`
- The migration system compares `user_version` against migration files
- No manual version updates needed - handled by `bun-sqlite-migrations`

**Best Practices:**
- Use `ALTER TABLE` for adding columns to existing tables
- Use `CREATE TABLE IF NOT EXISTS` for new tables
- Use `DEFAULT` values when adding non-null columns
- Add comments with `--` to explain changes
- When a table needs schema changes that SQLite can't `ALTER` (e.g., adding constraints), create `table_new`, copy data, drop old, rename (see 004, 005 for examples)
- Test migrations locally before committing

### Public Site Pages

- `/` is a signpost, not a page: signed-out visitors 302 to `/login`, a valid session cookie 302s to `/dashboard` (the bundled dashboard HTML), and a request asking for markdown 302s to `/docs`. It varies on `Accept, Cookie`
- `/about`, `/contact`, `/privacy` render from `src/content/*.md` through `src/lib/content-pages.ts`
- Those pages, plus `/docs`, negotiate on `Accept`: `text/markdown` (or `text/plain`) gets the raw markdown, anything unservable gets a 406, and every response sets `Vary: Accept, Accept-Encoding` (see https://acceptmarkdown.com)
- Unmatched paths hit the `fetch` fallback in `src/index.ts` → `notFound()`, a real 404 with a markdown body listing where to go next
- `/robots.txt`, `/sitemap.xml`, and `/llms.txt` are generated from the same page list, so adding a content page updates all three
- AI-crawler policy is Cloudflare's: its managed block appends `Disallow: /` groups for ChatGPT/Claude/GPTBot/etc. The app's robots.txt names no AI user-agents on purpose, so the two files cannot contradict each other
- `/about` carries the JSON-LD identity graph (`SoftwareApplication`, `Organization` with contactPoint + address, `WebSite`, `WebPage`); the other content pages carry everything but `SoftwareApplication`. `/og.png` is the shared social image

### Client-Side Code
- Extract JavaScript from HTML into separate TypeScript modules in `src/client/`
- Import client modules into HTML with `<script type="module" src="../client/file.ts"></script>`
- Bun will bundle the imports automatically
- Static assets (images, favicons) in `public/` are served at root path
- In HTML files: use paths relative to server root (e.g., `/logo.svg`, `/favicon.svg`) since Bun bundles HTML and resolves paths from server context
- Design system lives in `src/client/ds/` — import `./ds/index` once per page to register all web components
- Built on Elena (`@elenajs/core`) web components; each component is a class extending `Elena(HTMLElement)` with `tagName`, `props`, and `define()`

### IndieAuth/OAuth 2.0 + OIDC Implementation
- Full IndieAuth server supporting OAuth 2.0 with PKCE (S256 only)
- OIDC layer on top: RS256 ID tokens, discovery document, JWKS endpoint, userinfo endpoint
- Authorization code flow with single-use, short-lived codes (60 seconds)
- Refresh tokens with separate expiry
- Token introspection and revocation endpoints
- Auto-registration of public clients on first authorization (client_id = URL)
- Pre-registered confidential clients (admin-created, client_secret auth)
- Consent screen with scope selection and app role assignment
- Auto-approval for previously approved apps
- Session-based SSO (users only authenticate once with passkey)
- User profile endpoints with h-card microformats
- Invite-based registration for new users (admin only)
- **`me` parameter is a hint**: `trustedMeHint()` in `authorize.ts` keeps it only if it is one of the signed-in user's own identities (`/u/{username}` or their verified `url`); otherwise it is dropped. The token endpoint always returns the verified identity (indieauth.rocks S220)
- **Scope-less requests**: no `scope` param means identity only. The consent page says so, the authcode stores `[]`, and the token endpoint returns `{me, iss}` with no access token and no `tokens` row (S320/S321)
- **Redirect URI policy** (`isRedirectAllowed` in `lib/oauth/client-metadata.ts`): pre-registered clients get exact match on their stored list; URL clients with a published `redirect_uris` list get exact match; URL clients publishing nothing get same-origin only. `ensureApp(clientId, redirectUri | null)` re-fetches metadata when a redirect misses the stored list (throttled to once a minute per client) so the stored list is the client's *published* list, not whatever was seen first. Pass `null` for flows with no redirect (device)
- **Duplicate params**: `/auth/authorize` refuses any repeated single-value parameter (S213) with an error page, not a redirect
- **PKCE**: `code_challenge_method=S256` is required explicitly; a challenge without a method is refused (missing means plain per RFC 7636)
- **Code reuse**: exchanging a code sets `authcodes.family` and tokens inherit it; a replayed code revokes every token in that family (S303, RFC 9700 §4.5)
- **Refresh scope**: `scope` on a refresh request may narrow but never widen (`invalid_scope`)
- **Refresh token issuance**: `offline_access` (OIDC) or the consent-screen "stay signed in" checkbox for IndieAuth-style requests (`offersStaySignedIn` in `lib/oauth/refresh-choice.ts`: scoped, no `openid`, no `offline_access`). The answer rides on `authcodes.issue_refresh` (migration 017) so the client's `scope` is never widened; the grant remembers it as `offline_access` in `permissions.scopes` for auto-approval
- **Introspection requires auth**: a live Bearer access token or confidential `client_id`+`client_secret`; otherwise 401 with no token info (S801/S802)
- **CORS**: token, revoke, userinfo, OIDC discovery and JWKS send `Access-Control-Allow-Origin: *` (never with credentials) and answer `OPTIONS`; helpers in `lib/oauth/errors.ts` (`withCors`, `corsPreflight`, `methodNotAllowed`)
- **indieauth.rocks**: `test/indieauth-rocks.test.ts` mirrors the server test suite by test id (S2xx-S9xx). Run the live suite at https://indieauth.rocks after deploying by entering a `/u/{username}` profile URL
- OIDC nonce support and auth_time tracking in authcodes
- Signing keys stored in `oidc_keys` table, auto-generated on first use (RS256, 2048-bit)

### Client Metadata
- Public clients: `client_id` is a URL; metadata (name, logo, redirect_uris) fetched from the client_id URL via SSRF-safe fetch
- Confidential clients: pre-registered by admin, have `client_secret_hash`, use `client_secret_post` auth method
- Apps table has `is_preregistered` flag, `available_roles`, `default_role` for per-app RBAC
- Permissions table stores per-user scopes and role per client

### LDAP Integration
- Optional LDAP authentication (`ldap-authentication` package)
- LDAP-provisioned users tracked via `provisioned_via_ldap` flag
- Invites can be restricted to specific LDAP usernames (`ldap_username` column)
- On-login LDAP verification: checks user still exists in LDAP before allowing login
- Hourly background job detects orphaned accounts (in Indiko but not in LDAP)
- Grace period (default 7 days) before action is taken on orphans
- Configurable orphan action: `suspend`, `deactivate`, or `remove` (via `LDAP_ORPHAN_ACTION` env)
- Group verification: optionally require membership in a specific LDAP group
- Manual audit script: `bun scripts/audit-ldap-orphans.ts [--suspend|--deactivate|--dry-run]`

### Database Schema
- **users**: username, name, email, photo, url, status, role, tier, is_admin, provisioned_via_ldap, last_ldap_verified_at
  - **tier**: User access level - 'admin' (full access), 'developer' (can create apps), 'user' (can only authenticate with apps)
  - **is_admin**: Legacy flag, automatically synced with tier (1 if tier='admin', 0 otherwise)
  - **provisioned_via_ldap**: Flag tracking if user was created via LDAP authentication (0 = local, 1 = LDAP)
  - **last_ldap_verified_at**: Timestamp of last successful LDAP existence check (NULL if never checked)
- **credentials**: passkey credentials (credential_id, public_key, counter, name)
- **sessions**: user sessions with 24-hour expiry
- **challenges**: WebAuthn challenges (5-minute expiry)
- **apps**: OAuth clients (client_id, redirect_uris, name, logo_url, is_preregistered, registration ('admin' | 'dcr' | 'url'), client_secret_hash, available_roles, default_role). For URL clients `redirect_uris` is the *published* list (`[]` when the client publishes none)
- **permissions**: per-user, per-app granted scopes and role; written by consent, device approval (`recordDeviceGrant`), and invite roles. Revoking (`revokeGrant` in api.ts) also revokes tokens and device codes
- **authcodes**: short-lived authorization codes (60-second expiry, single-use), includes username, `me` hint, `nonce` and `auth_time` for OIDC, `family` set at exchange so a replay can revoke the tokens it minted
- **tokens**: access tokens with optional refresh_token and refresh_expires_at
- **invites**: admin-created invite codes, includes `ldap_username` for LDAP-provisioned accounts
- **invite_roles**: pre-assign app roles to invites
- **invite_uses**: tracks which users redeemed which invites
- **oidc_keys**: RSA signing keys for ID tokens (kid, private_key PEM, public_key PEM, is_active)

### Session Auth
- Two auth patterns in `src/lib/session.ts`:
  - `getSessionUser(req)` - Bearer token auth for API requests, returns `SessionUser | Response` (401/403)
  - `getUserFromCookie(req)` - Cookie auth for browser pages, returns `SessionUser | null`
- Session cookies named `indiko_session`
- Authorization header: `Bearer {token}`
- CSRF: `indiko_csrf` cookie value is `csrfTokenFor(sessionToken)` (sha256 of a prefix + session token). Checks recompute it from the session cookie via `getCsrfToken(req)` and compare with `csrfTokenMatches` (constant time); the csrf cookie itself is never trusted. Tests must derive the form/header token with `csrfTokenFor(cookie)`, not invent one
- Cookie `Secure` flag comes from `ORIGIN` starting with `https://`, not `NODE_ENV`
- Sessions join against users table, check expiry and status='active'

### WebAuthn/Passkey Settings
- **Registration**: residentKey="required", userVerification="required"
- **Authentication**: omit allowCredentials to show all passkeys (discoverable credentials)
- **Credential lookup**: credential_id stored as Buffer, compare using base64url string
- Passkeys are discoverable so password managers can show them without hints
- Multiple passkeys per user, each with a user-editable name
- Re-registration allowed to reset passkey (via `scripts/reset-passkey.ts` generating a reset link)

### Rate Limiting
- `src/lib/rate-limit.ts` `RateLimiter({ max, windowMs })` keyed by string, `hit(key)` returns `{ limited, retryAfter }`; `rateLimitedResponse()` builds the 429
- Applied: token endpoint (30/min/IP, inline map in token.ts), DCR and device authorization (inline maps), passkey options/verify (60/min/IP), `/api/ldap-verify` (20/15min/IP and 5/15min/username)
- All limiters skip under `NODE_ENV=test`; `getClientIp` falls back to `"direct"` when no server is registered (tests, scripts)

### Background Jobs
- Hourly cleanup job (in `src/index.ts`): deletes expired sessions, challenges, authcodes, tokens
- Hourly LDAP orphan cleanup job: checks LDAP for missing users, applies configured action after grace period

### Environment Variables
- **Required**: `ORIGIN` (must be HTTPS in production), `RP_ID` (must match ORIGIN domain)
- **Optional**: `PORT` (default 3000), `NODE_ENV`, `DATABASE_URL` (default `data/indiko.db`)
- **LDAP**: `LDAP_ENABLED`, `LDAP_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PASSWORD`, `LDAP_USER_SEARCH_BASE`, `LDAP_USERNAME_ATTRIBUTE`, `LDAP_ORPHAN_ACTION`, `LDAP_ORPHAN_GRACE_PERIOD`, `LDAP_CHECK_INTERVAL`, `LDAP_GROUP_DN`, `LDAP_GROUP_CLASS`, `LDAP_GROUP_MEMBER_ATTRIBUTE`
- Startup validation in `src/index.ts` exits on missing/invalid required vars

## Commands

- `bun run dev` - Start dev server with hot reload
- `bun run start` - Start production server
- `bun run format` - Format all files with Biome
- `bun test` - Run tests (bun:test)
- `bun scripts/seed-dev.ts` - Seed database with dev data (6 users, 5 apps, permissions, invites, tokens)
- `bun scripts/seed-dev.ts --reset` - Wipe tables then seed
- `bun scripts/audit-ldap-orphans.ts [--suspend|--deactivate|--dry-run]` - Audit LDAP orphans
- `bun scripts/reset-passkey.ts <username>` - Reset user passkey

## Code Style

- Use tabs for indentation
- TypeScript with Bun runtime
- Use SQLite with WAL mode, foreign_keys ON, synchronous NORMAL
- Route handlers: `(req: Request) => Response` (or `Promise<Response>` for async)
- Biome for formatting (config in `biome.json`, excludes `components.css` and `data/`)
- No test framework config needed - bun:test is built in
