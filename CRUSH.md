# Crush Memory - Indiko Project

## User Preferences

- **DO NOT** run the server - user will always run it themselves
- **DO NOT** test the server by starting it
- Use Bun's `routes` object in server config, not manual fetch handler routing

## Architecture Patterns

### Route Organization
- Use separate route files in `src/routes/` directory
- Export handler functions that accept `Request` and return `Response`
- Import handlers in `src/index.ts` and wire them in the `routes` object
- Use Bun's built-in routing: `routes: { "/path": handler }`
- Example: `src/routes/auth.ts` contains authentication-related routes
- IndieAuth/OAuth 2.0 endpoints in `src/routes/indieauth.ts`

### Project Structure
```
src/
├── db.ts              # Database setup and exports
├── index.ts           # Main server entry point
├── routes/            # Route handlers (server-side)
│   ├── auth.ts        # Passkey authentication routes
│   ├── api.ts         # API endpoints (hello, users, profile)
│   └── indieauth.ts   # IndieAuth/OAuth 2.0 server endpoints
├── client/            # Client-side TypeScript modules
│   ├── login.ts       # Login page logic
│   ├── index.ts       # Dashboard logic
│   └── profile.ts     # Profile editing logic
├── html/              # HTML templates (Bun bundles them with script imports)
│   ├── login.html
│   ├── index.html
│   └── profile.html
├── migrations/        # SQL migrations
│   ├── 001_init.sql
│   ├── 002_add_user_status_role.sql
│   ├── 003_add_indieauth_tables.sql
│   └── 007_add_ldap_support.sql
```

### Database Migrations

**Migration Versioning:**
- SQLite uses `PRAGMA user_version` to track migration state
- Version starts at 0, increments by 1 for each migration
- The `bun-sqlite-migrations` package handles version tracking
- Migrations are stored in `src/migrations/` directory

**Creating a New Migration:**

1. **Name the file**: Use 3-digit prefix (e.g., `008_add_feature.sql`)
   - Next available number = highest existing number + 1
   - Use descriptive name (e.g., `008_add_auth_tokens.sql`)

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
- Test migrations locally before committing

### Client-Side Code
- Extract JavaScript from HTML into separate TypeScript modules in `src/client/`
- Import client modules into HTML with `<script type="module" src="../client/file.ts"></script>`
- Bun will bundle the imports automatically
- Static assets (images, favicons) in `public/` are served at root path
- In HTML files: use paths relative to server root (e.g., `/logo.svg`, `/favicon.svg`) since Bun bundles HTML and resolves paths from server context

### IndieAuth/OAuth 2.0 Implementation
- Full IndieAuth server supporting OAuth 2.0 with PKCE
- Authorization code flow with single-use, short-lived codes (60 seconds)
- Auto-registration of client apps on first authorization
- Consent screen with scope selection
- Auto-approval for previously approved apps
- Session-based SSO (users only authenticate once with passkey)
- User profile endpoints with h-card microformats
- Token exchange endpoint for client apps
- Invite-based registration for new users (admin only)
- **`me` parameter delegation**: When a client passes `me=https://example.com` in the authorization request and it matches the user's website URL, the token response returns that URL instead of the canonical `/u/{username}` URL

### Database Schema
- **users**: username, name, email, photo, url, status, role, tier, is_admin, provisioned_via_ldap, last_ldap_verified_at
  - **tier**: User access level - 'admin' (full access), 'developer' (can create apps), 'user' (can only authenticate with apps)
  - **is_admin**: Legacy flag, automatically synced with tier (1 if tier='admin', 0 otherwise)
  - **provisioned_via_ldap**: Flag tracking if user was created via LDAP authentication (0 = local, 1 = LDAP)
  - **last_ldap_verified_at**: Timestamp of last successful LDAP existence check (NULL if never checked)
- **credentials**: passkey credentials (credential_id, public_key, counter)
- **sessions**: user sessions with 24-hour expiry
- **challenges**: WebAuthn challenges (5-minute expiry)
- **apps**: auto-registered OAuth clients
- **permissions**: per-user, per-app granted scopes
- **authcodes**: short-lived authorization codes (60-second expiry, single-use), includes username and `me` parameter for delegation
- **invites**: admin-created invite codes, includes `ldap_username` for LDAP-provisioned accounts

### WebAuthn/Passkey Settings
- **Registration**: residentKey="required", userVerification="required"
- **Authentication**: omit allowCredentials to show all passkeys (discoverable credentials)
- **Credential lookup**: credential_id stored as Buffer, compare using base64url string
- Passkeys are discoverable so password managers can show them without hints

## Commands

(Add test/lint/build commands here as discovered)

## Code Style

- Use tabs for indentation
- TypeScript with Bun runtime
- Use SQLite with WAL mode
- Route handlers: `(req: Request) => Response`
- Session cookies named `indiko_session`
- Authorization header: `Bearer {token}`
