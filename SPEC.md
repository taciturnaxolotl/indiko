# indiko - IndieAuth Server Specification

## Overview

**indiko** is a centralized authentication and user management system for personal projects. It provides:
- Passkey-based authentication (WebAuthn)
- IndieAuth server implementation
- User profile management
- Per-app access control
- Invite-based user registration

## Core Concepts

### Single Source of Truth
- Authentication via passkeys
- User profiles (name, email, picture, URL)
- Authorization with per-app scoping
- User management (admin + invite system)

### Trust Model
- First user becomes admin
- Admin can create invite links
- Apps auto-register on first use
- Users grant/revoke app access via consent

## User Identifier Format

Users are identified by: `https://indiko.yourdomain.com/u/{username}`

## Data Structures

### Users
```
user:{username} -> {
  credential: {
    credentialID: Uint8Array,
    publicKey: Uint8Array,
    counter: number
  },
  isAdmin: boolean,
  profile: {
    name: string,
    email: string,
    photo: string,  // URL
    url: string     // personal website
  },
  createdAt: timestamp
}
```

### Admin Marker
```
admin:user -> username  // marks first/admin user
```

### Sessions
```
session:{token} -> {
  username: string,
  expiresAt: timestamp
}
// TTL: 24 hours
```

### Apps

There are two types of OAuth clients in indiko:

#### Auto-registered Apps (IndieAuth)
```
app:{client_id} -> {
  client_id: string,           // e.g. "https://blog.kierank.dev" (any valid URL)
  redirect_uris: string[],
  is_preregistered: 0,         // indicates auto-registered
  first_seen: timestamp,
  last_used: timestamp,
  name?: string,               // optional, from client metadata
  logo_url?: string            // optional, from client metadata
}
```

**Features:**
- Client ID is any valid URL per IndieAuth spec
- No client secret (public client)
- MUST use PKCE (code_verifier)
- Automatically registered on first authorization
- Metadata fetched from client_id URL
- Cannot use role-based access control

#### Pre-registered Apps (OAuth 2.0 with secrets)
```
app:{client_id} -> {
  client_id: string,           // e.g. "ikc_xxxxxxxxxxxxxxxxxxxxx" (generated ID)
  redirect_uris: string[],
  is_preregistered: 1,         // indicates pre-registered
  client_secret_hash: string,  // SHA-256 hash of client secret
  available_roles?: string[],  // optional list of allowed roles
  default_role?: string,       // optional role auto-assigned on first auth
  first_seen: timestamp,
  last_used: timestamp,
  name?: string,
  logo_url?: string,
  description?: string
}
```

**Features:**
- Client ID format: `ikc_` + 21 character nanoid
- Client secret format: `iks_` + 43 character nanoid (shown once on creation)
- MUST use PKCE (code_verifier) AND client_secret
- Supports role-based access control
- Admin-managed metadata
- Created via admin interface

### User Permissions (Per-App)
```
permission:{user_id}:{client_id} -> {
  scopes: string[],            // e.g. ["profile", "email"]
  role?: string,               // optional, only for pre-registered clients
  granted_at: timestamp,
  last_used: timestamp
}
```

### Authorization Codes (Short-lived)
```
authcode:{code} -> {
  username: string,
  client_id: string,
  redirect_uri: string,
  scopes: string[],
  code_challenge: string,      // PKCE
  expires_at: timestamp,
  used: boolean
}
// TTL: 60 seconds
// Single-use only
```

### Invites
```
invite:{code} -> {
  code: string,
  created_by: string,          // admin username
  created_at: timestamp,
  used: boolean,
  used_by?: string,
  used_at?: timestamp
}
```

### Challenges (WebAuthn)
```
challenge:{challenge} -> {
  username: string,
  type: "registration" | "authentication",
  expires_at: timestamp
}
// TTL: 5 minutes
```

### Device Codes (RFC 8628)
```
device_code:{device_code} -> {
  user_code: string,          // e.g. "WDJB-MJHT"
  client_id: string,
  scope: string,
  expires_at: timestamp,      // 10 minutes
  interval: number,           // poll interval in seconds (default 5)
  last_polled_at: timestamp,
  status: "pending" | "approved" | "denied",
  user_id?: number            // set on approval
}
// TTL: 10 minutes
// Single-use: deleted after successful token exchange
```

## Supported Scopes

- `profile` - Name, photo, URL
- `email` - Email address
- (Future: custom scopes as needed)

## Routes

### Authentication (WebAuthn/Passkey)

#### `GET /login`
- Login/registration page
- Shows passkey auth interface
- First user: admin registration flow
- With `?invite=CODE`: invite-based registration

#### `GET /auth/can-register`
- Check if open registration allowed
- Returns `{ canRegister: boolean }`

#### `POST /auth/register/options`
- Generate WebAuthn registration options
- Body: `{ username: string, inviteCode?: string }`
- Validates invite code if not first user
- Returns registration options

#### `POST /auth/register/verify`
- Verify WebAuthn registration response
- Body: `{ username: string, response: RegistrationResponseJSON, inviteCode?: string }`
- Creates user, stores credential
- First user marked as admin
- Returns `{ token: string, username: string }`

#### `POST /auth/login/options`
- Generate WebAuthn authentication options
- Body: `{ username: string }`
- Returns authentication options

#### `POST /auth/login/verify`
- Verify WebAuthn authentication response
- Body: `{ username: string, response: AuthenticationResponseJSON }`
- Creates session
- Returns `{ token: string, username: string }`

#### `POST /auth/logout`
- Clear session
- Requires: `Authorization: Bearer {token}`
- Returns `{ success: true }`

### IndieAuth Endpoints

#### `GET /auth/authorize`
Authorization request from client app

**Query Parameters:**
- `response_type=code` (required)
- `client_id` (required) - App's URL
- `redirect_uri` (required) - Callback URL
- `state` (required) - CSRF protection
- `code_challenge` (required) - PKCE challenge
- `code_challenge_method=S256` (required)
- `scope` (optional) - Space-separated scopes (default: "profile")
- `me` (optional) - User's URL (hint)

**Flow:**
1. Validate parameters
2. Auto-register app if not exists
3. If no session → redirect to `/login`
4. If session exists → show consent screen
5. Check if user previously approved this app
   - If yes → auto-approve (skip consent)
   - If no → show consent screen

**Response:**
- HTML consent screen
- Shows: app name, requested scopes
- Buttons: "Allow" / "Deny"

#### `POST /auth/authorize`
Consent form submission (CSRF protected)

**Body:**
- `client_id` (required)
- `redirect_uri` (required)
- `state` (required)
- `code_challenge` (required)
- `scopes` (required)
- `action` (required) - "allow" | "deny"

**Flow:**
1. Validate CSRF token
2. Validate session
3. If denied → redirect with error
4. If allowed:
   - Create authorization code
   - Store permission grant
   - Update app last_used
   - Redirect to redirect_uri with code & state

**Success Response:**
```
HTTP/1.1 302 Found
Location: {redirect_uri}?code={authcode}&state={state}
```

**Error Response:**
```
HTTP/1.1 302 Found
Location: {redirect_uri}?error=access_denied&state={state}
```

#### `POST /auth/token`
Exchange authorization code for user identity (NOT CSRF protected)

**Headers:**
- `Content-Type: application/json`

**Body:**
```json
{
  "grant_type": "authorization_code",
  "code": "authcode123",
  "client_id": "https://blog.kierank.dev",
  "redirect_uri": "https://blog.kierank.dev/auth/callback",
  "code_verifier": "pkce_verifier_string"
}
```

**Flow:**
1. Validate authorization code exists
2. Verify code not expired
3. Verify code not already used
4. Verify client_id matches
5. Verify redirect_uri matches
6. Verify PKCE code_verifier
7. Mark code as used
8. Return user identity + profile

**Success Response:**
```json
{
  "me": "https://indiko.yourdomain.com/u/kieran",
  "profile": {
    "name": "Kieran Klukas",
    "email": "kieran@example.com",
    "photo": "https://...",
    "url": "https://kierank.dev"
  }
}
```

**Error Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired"
}
```

#### `GET /auth/userinfo` (Optional)
Get current user profile with bearer token

**Headers:**
- `Authorization: Bearer {access_token}`

**Response:**
```json
{
  "sub": "https://indiko.yourdomain.com/u/kieran",
  "name": "Kieran Klukas",
  "email": "kieran@example.com",
  "picture": "https://...",
  "website": "https://kierank.dev"
}
```

#### `POST /auth/device` (RFC 8628)
Device Authorization Request for CLI tools and headless devices

**Body:**
```
client_id=https://myapp.example.com&scope=profile email
```

**Response:**
```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://indiko.yourdomain.com/device",
  "verification_uri_complete": "https://indiko.yourdomain.com/device?code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

#### `GET /device`
User-facing verification page (requires session)

**Query Parameters:**
- `code` (optional) - Pre-fill the user code

**Flow:**
1. If no session, redirect to `/login`
2. Show code input form (or confirmation if code provided)
3. On submit, show app name + scopes with Allow/Deny buttons

#### `POST /device`
User approves or denies the device authorization

**Body:**
- `code` (required) - The user code
- `action` (required) - "allow" | "deny"

#### Device Code Polling (Token Endpoint)
The device polls `POST /auth/token` with grant type `urn:ietf:params:oauth:grant-type:device_code`

**Body:**
```
grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
&client_id=https://myapp.example.com
```

**Polling Responses:**

| Error | Meaning |
|-------|---------|
| `authorization_pending` | User hasn't acted yet; keep polling |
| `slow_down` | Polling too fast; interval increased by 5s |
| `access_denied` | User denied the request; stop polling |
| `expired_token` | Code expired (10 min TTL); restart |

**Notes:**
- No PKCE required (device code is high-entropy proof)
- Device code is single-use; deleted after successful exchange
- User codes use unambiguous consonants (no vowels, no 0/O, 1/l/I)
- Rate limited via `interval` + `last_polled_at` tracking

### User Profile & Settings

#### `GET /settings`
User settings page (requires session)

**Shows:**
- Profile form (name, email, photo, URL)
- Connected apps list
- Revoke access buttons
- (Admin only) Invite generation

#### `POST /settings/profile`
Update user profile

**Body:**
```json
{
  "name": "Kieran Klukas",
  "email": "kieran@example.com",
  "photo": "https://...",
  "url": "https://kierank.dev"
}
```

**Response:**
```json
{
  "success": true,
  "profile": { ... }
}
```

#### `POST /settings/apps/:client_id/revoke`
Revoke app access

**Response:**
```json
{
  "success": true
}
```

#### `GET /u/:username`
Public user profile page (h-card)

**Response:**
HTML page with microformats h-card:
```html
<div class="h-card">
  <img class="u-photo" src="...">
  <a class="p-name u-url" href="...">Kieran Klukas</a>
  <a class="u-email" href="mailto:...">email</a>
</div>
```

### Admin Endpoints

#### `POST /api/invites/create`
Create invite link (admin only)

**Headers:**
- `Authorization: Bearer {token}`

**Response:**
```json
{
  "inviteCode": "abc123xyz"
}
```

Usage: `https://indiko.yourdomain.com/login?invite=abc123xyz`

### Dashboard

#### `GET /`
Main dashboard (requires session)

**Shows:**
- User info
- Test API button
- (Admin only) Admin controls section
  - Generate invite link button
  - Invite display

#### `GET /api/hello`
Test endpoint (requires session)

**Headers:**
- `Authorization: Bearer {token}`

**Response:**
```json
{
  "message": "Hello kieran! You're authenticated with passkeys.",
  "username": "kieran",
  "isAdmin": true
}
```

## Session Behavior

### Single Sign-On
- Once logged into indiko (valid session), subsequent app authorization requests:
  - Skip passkey authentication
  - Show consent screen directly
  - If app previously approved, auto-approve
- Session duration: 24 hours
- Passkey required only when session expires

### Security
- PKCE required for all authorization flows
- Authorization codes:
  - Single-use only
  - 60-second expiration
  - Bound to client_id and redirect_uri
- State parameter required for CSRF protection

## Client Integration Example

### 1. Initiate Authorization
```javascript
const params = new URLSearchParams({
  response_type: 'code',
  client_id: 'https://blog.kierank.dev',
  redirect_uri: 'https://blog.kierank.dev/auth/callback',
  state: generateRandomState(),
  code_challenge: generatePKCEChallenge(verifier),
  code_challenge_method: 'S256',
  scope: 'profile email'
});

window.location.href = `https://indiko.yourdomain.com/auth/authorize?${params}`;
```

### 2. Handle Callback
```javascript
// At https://blog.kierank.dev/auth/callback?code=...&state=...
const code = new URLSearchParams(window.location.search).get('code');
const state = new URLSearchParams(window.location.search).get('state');

// Verify state matches

// Exchange code for profile
const response = await fetch('https://indiko.yourdomain.com/auth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code,
    client_id: 'https://blog.kierank.dev',
    redirect_uri: 'https://blog.kierank.dev/auth/callback',
    code_verifier: storedVerifier
  })
});

const { me, profile } = await response.json();
// me: "https://indiko.yourdomain.com/u/kieran"
// profile: { name, email, photo, url }

// Create session for user
```

## OpenID Connect (OIDC) Support

Indiko implements OpenID Connect Core 1.0 as an identity layer on top of OAuth 2.0, enabling "Sign in with Indiko" for any OIDC-compatible application.

### Overview

OIDC extends the existing OAuth 2.0 authorization flow by:
- Adding the `openid` scope to request identity information
- Returning an **ID Token** (signed JWT) alongside the authorization code exchange
- Providing a standardized `/userinfo` endpoint
- Publishing discovery metadata at `/.well-known/openid-configuration`

### Supported Scopes

| Scope | Claims Returned |
|-------|-----------------|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time` |
| `profile` | `name`, `picture`, `website` |
| `email` | `email` |

### OIDC Endpoints

#### `GET /.well-known/openid-configuration`
Discovery document for OIDC clients.

**Response:**
```json
{
  "issuer": "https://indiko.yourdomain.com",
  "authorization_endpoint": "https://indiko.yourdomain.com/auth/authorize",
  "token_endpoint": "https://indiko.yourdomain.com/auth/token",
  "userinfo_endpoint": "https://indiko.yourdomain.com/auth/userinfo",
  "jwks_uri": "https://indiko.yourdomain.com/jwks",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "name", "email", "picture", "website"],
  "code_challenge_methods_supported": ["S256"]
}
```

#### `GET /jwks`
JSON Web Key Set containing the public key for ID Token verification.

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "indiko-oidc-key-1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### ID Token

When the `openid` scope is requested, the token endpoint returns an `id_token` JWT:

**Token Endpoint Response (with openid scope):**
```json
{
  "me": "https://indiko.yourdomain.com/u/kieran",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImluZGlrby1vaWRjLWtleS0xIn0...",
  "profile": {
    "name": "Kieran Klukas",
    "email": "kieran@example.com",
    "photo": "https://...",
    "url": "https://kierank.dev"
  }
}
```

**ID Token Claims:**
```json
{
  "iss": "https://indiko.yourdomain.com",
  "sub": "https://indiko.yourdomain.com/u/kieran",
  "aud": "https://blog.kierank.dev",
  "exp": 1234567890,
  "iat": 1234567800,
  "auth_time": 1234567700,
  "nonce": "abc123",
  "name": "Kieran Klukas",
  "email": "kieran@example.com",
  "picture": "https://...",
  "website": "https://kierank.dev"
}
```

### OIDC Authorization Flow

1. Client initiates authorization with `scope=openid profile email`
2. User authenticates and consents (same as IndieAuth)
3. Client receives authorization code
4. Client exchanges code at `/auth/token` with `code_verifier`
5. Token endpoint returns `id_token` JWT + profile data
6. Client verifies `id_token` signature using keys from `/jwks`

### Key Management

- RSA 2048-bit key pair generated on first OIDC request
- Private key stored in database (`oidc_keys` table)
- Key rotation: manual via admin interface (future)
- Key ID format: `indiko-oidc-key-{version}`

### Data Structures

#### OIDC Keys
```
oidc_keys -> {
  id: number,
  kid: string,              // e.g. "indiko-oidc-key-1"
  private_key: string,      // PEM-encoded RSA private key
  public_key: string,       // PEM-encoded RSA public key
  created_at: timestamp,
  is_active: boolean
}
```

#### Authorization Code (Extended)
```
authcode:{code} -> {
  ...existing fields...,
  nonce?: string,           // OIDC nonce for replay protection
  auth_time: timestamp      // when user authenticated
}
```

## Future Enhancements

- Token endpoint for longer-lived access tokens
- Refresh tokens
- Client metadata endpoint discovery
- Micropub support
- WebSub notifications
- Multiple passkey support per user
- Email notifications for new logins
- Audit log for admin
- Rate limiting
- Account recovery flow
- OIDC key rotation via admin interface

## Standards Compliance

- [IndieAuth Specification](https://indieauth.spec.indieweb.org/)
- [WebAuthn/FIDO2](https://www.w3.org/TR/webauthn-2/)
- [OAuth 2.0 PKCE](https://tools.ietf.org/html/rfc7636)
- [Microformats h-card](http://microformats.org/wiki/h-card)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
