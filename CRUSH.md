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
└── migrations/        # SQL migrations
    ├── 001_init.sql
    ├── 002_add_user_status_role.sql
    └── 003_add_indieauth_tables.sql
```

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
- **users**: username, name, email, photo, url, status, role, is_admin
- **credentials**: passkey credentials (credential_id, public_key, counter)
- **sessions**: user sessions with 24-hour expiry
- **challenges**: WebAuthn challenges (5-minute expiry)
- **apps**: auto-registered OAuth clients
- **permissions**: per-user, per-app granted scopes
- **authcodes**: short-lived authorization codes (60-second expiry, single-use), includes `me` parameter for delegation
- **invites**: admin-created invite codes

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
