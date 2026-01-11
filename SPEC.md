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

## Standards Compliance

- [IndieAuth Specification](https://indieauth.spec.indieweb.org/)
- [WebAuthn/FIDO2](https://www.w3.org/TR/webauthn-2/)
- [OAuth 2.0 PKCE](https://tools.ietf.org/html/rfc7636)
- [Microformats h-card](http://microformats.org/wiki/h-card)
