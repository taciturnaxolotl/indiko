---
title: indiko documentation
subtitle: IndieAuth/OAuth 2.0 server with passkey authentication
---

## openid connect (oidc)

Indiko supports OpenID Connect (OIDC) for modern authentication flows, enabling "Sign in with Indiko" for any OIDC-compatible application.

### oidc endpoints

| Endpoint | Description |
| --- | --- |
| `/.well-known/openid-configuration` | OIDC discovery document |
| `/jwks` | JSON Web Key Set for ID token verification |
| `/auth/authorize` | Authorization endpoint (same as OAuth 2.0) |
| `/auth/token` | Token endpoint (returns ID token when `openid` scope requested) |
| `/userinfo` | OIDC userinfo endpoint |

### key features

- Authorization Code Flow with PKCE
- ID Token with RS256 signing
- Support for `openid`, `profile`, and `email` scopes
- Automatic key generation and management
- Standards-compliant discovery document

### id token claims

When the `openid` scope is requested, the token endpoint returns an ID token (JWT) containing:

- `iss` - Issuer (Indiko server URL)
- `sub` - Subject (user identifier)
- `aud` - Audience (client ID)
- `exp` - Expiration time
- `iat` - Issued at time
- `auth_time` - Authentication time
- `nonce` - Nonce (if provided in authorization request)
- `name`, `email`, `picture`, `website` - User claims (based on granted scopes)

> **Testing:** You can test your OIDC setup using the [OIDC Debugger](https://oidcdebugger.com/). Set the discovery endpoint and use PKCE with SHA-256.

## getting started

### for app developers

To integrate with Indiko as an OAuth client, you'll need:

1. A **client ID** (any valid URL, e.g., `https://myapp.example.com`)
2. A **redirect URI** (where users return after authorization)
3. Support for PKCE (code challenge/verifier)

> **Auto-registration:** Apps are automatically registered on first use. You don't need admin approval to get started. During registration, Indiko fetches your client metadata from your `client_id` URL to validate redirect URIs and display your app name/logo. For advanced features like client secrets and role assignment, contact your Indiko admin to pre-register your app.

### publishing client metadata (recommended)

To help Indiko verify your app and display proper branding, publish client metadata as JSON at your `client_id` URL:

```json
{
  "client_id": "https://myapp.example.com/",
  "client_name": "My App",
  "logo_uri": "https://myapp.example.com/logo.png",
  "redirect_uris": [
    "https://myapp.example.com/callback",
    "https://myapp.example.com/auth/callback"
  ]
}
```

Alternatively, you can publish redirect URIs as HTML `<link>` tags:

```html
<link rel="redirect_uri" href="https://myapp.example.com/callback" />
```

> **Security:** If your `redirect_uri` uses a different host than your `client_id`, you MUST publish `redirect_uris` in your client metadata. This prevents unauthorized apps from hijacking your client_id.

> **Client ID Metadata Document (CIMD):** This URL-published metadata follows the OAuth Client ID Metadata Document draft. A few rules apply: the `client_id` in the document must exactly match the URL it's fetched from, the document must be under 5 KB, and it must not request a shared-secret `token_endpoint_auth_method` (like `client_secret_post`) — public URL-based clients have no secret. If you need a client secret, use [dynamic registration](#dynamic-client-registration-rfc-7591) instead.

### for users

You'll need an invite code to create an account. Once registered:

- Set up your passkey (fingerprint, face ID, or security key), and add more later from your dashboard
- Complete your profile (name, photo, website)
- Authorize apps to access your profile
- Manage app permissions from your dashboard

## sign in button

Copy this themed button for your app's login page. It matches Indiko's visual style:

:::demo-button

### HTML + CSS

:::button-code

> **Customization:** Replace `YOUR_OAUTH_URL_HERE` with your authorization URL (see [authorization flow](#authorization) below). You can also change the button text or adjust colors to match your app's theme.

## API endpoints

### authorization endpoints

| Endpoint | Method | Description |
| --- | --- | --- |
| `/.well-known/oauth-authorization-server` | GET | IndieAuth server metadata (discovery endpoint) |
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/.well-known/oauth-client?client_id=…` | GET | Look up a registered client's metadata |
| `/jwks` | GET | JSON Web Key Set for ID token verification |
| `/auth/authorize` | GET | Start OAuth authorization flow |
| `/auth/authorize` | POST | Submit consent/scope approval |
| `/auth/token` | POST | Exchange code for access token and refresh token |
| `/auth/token/introspect` | POST | Verify access token validity |
| `/auth/token/revoke` | POST | Revoke access or refresh token |
| `/userinfo` | GET | Get user profile data with bearer token |
| `/auth/device` | POST | Request device and user codes (RFC 8628) |
| `/device` | GET | User verification page (enter code, approve/deny) |
| `/oauth/register` | POST | Dynamic client registration (RFC 7591) |
| `/u/:username` | GET | Public user profile (h-card with discovery links) |

### authentication endpoints

| Endpoint | Method | Description |
| --- | --- | --- |
| `/auth/can-register` | POST | Check if invite code is valid |
| `/auth/register/options` | POST | Get WebAuthn registration options |
| `/auth/register/verify` | POST | Complete passkey registration |
| `/auth/login/options` | POST | Get WebAuthn login options |
| `/auth/login/verify` | POST | Complete passkey login |
| `/auth/logout` | POST | End current session |

## authorization flow

### 0. discovery (recommended)

Before starting authorization, clients should discover the authorization server's endpoints from the user's profile URL:

1. Fetch the user's profile URL (e.g., `{{origin}}/u/username`)
2. Look for `<link rel="indieauth-metadata">` tag or HTTP `Link:` header
3. Fetch the metadata endpoint to get `authorization_endpoint` and `token_endpoint`

The metadata endpoint returns:

```json
{
  "issuer": "{{origin}}",
  "authorization_endpoint": "{{origin}}/auth/authorize",
  "token_endpoint": "{{origin}}/auth/token",
  "introspection_endpoint": "{{origin}}/auth/token/introspect",
  "revocation_endpoint": "{{origin}}/auth/token/revoke",
  "userinfo_endpoint": "{{origin}}/userinfo",
  "jwks_uri": "{{origin}}/jwks",
  "device_authorization_endpoint": "{{origin}}/auth/device",
  "registration_endpoint": "{{origin}}/oauth/register",
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "client_id_metadata_document_supported": true,
  "authorization_response_iss_parameter_supported": true,
  "service_documentation": "{{origin}}/docs"
}
```

> **OIDC clients:** `/.well-known/openid-configuration` serves the same server under OIDC discovery, including the `openid` scope and ID token signing algorithms.

### 1. redirect to authorization endpoint

```http
GET {{origin}}/auth/authorize?response_type=code
  &client_id=https://myapp.example.com
  &redirect_uri=https://myapp.example.com/callback
  &state=random_state_string
  &code_challenge=base64url_encoded_challenge
  &code_challenge_method=S256
  &scope=profile email
```

> **PKCE is required:** Generate a random `code_verifier` (43-128 characters), then create `code_challenge` by hashing it with SHA-256 and base64url encoding.

### 2. user authenticates and approves

Indiko will:

- Check if user has an active session (if not, prompt for passkey login)
- Show consent screen with requested scopes
- Auto-approve if user previously authorized this app

### 3. redirect back with code

```http
https://myapp.example.com/callback?code=short_lived_authorization_code
  &state=random_state_string
  &iss={{origin}}
```

> **Security:** The `iss` (issuer) parameter allows you to verify the response came from the expected authorization server. Compare it to the `issuer` from the metadata endpoint.

### 4. exchange code for token

```http
POST {{origin}}/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=authorization_code
&client_id=https://myapp.example.com
&redirect_uri=https://myapp.example.com/callback
&code_verifier=original_code_verifier
&client_secret=your_client_secret (if pre-registered)
```

> **Client authentication:** All clients MUST use PKCE (code_verifier) per the IndieAuth specification. Pre-registered confidential clients should also include `client_secret` in the token request for additional security.

### 5. receive tokens and user profile

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "RT_abc123xyz...",
  "me": "{{origin}}/u/username",
  "profile": {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "photo": "https://example.com/photo.jpg",
    "url": "https://jane.example.com"
  },
  "scope": "profile email",
  "iss": "{{origin}}",
  "role": "admin"
}
```

> **Token types:**
>
> - `access_token` - Short-lived token (1 hour) for API access
> - `refresh_token` - Long-lived token (30 days) for getting new access tokens

> **Roles:** If an admin has assigned a role to this user for your app, it will be included in the response. Roles are arbitrary strings that you can use for role-based access control (RBAC) in your application.

## token management

Indiko provides a complete OAuth 2.0 token management system with access tokens, refresh tokens, introspection, and revocation.

### refresh tokens

A refresh token is only issued when your app requests the `offline_access` scope at authorization time. If you don't request it, the grant is one-shot: you get an access token (1 hour) and nothing more. See [scopes](#scopes).

Exchange a refresh token for a new access token (and a new rotated refresh token):

```http
POST {{origin}}/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=RT_abc123xyz...
&client_id=https://myapp.example.com
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "RT_new_rotated_token...",
  "me": "{{origin}}/u/username",
  "scope": "profile email offline_access",
  "iss": "{{origin}}"
}
```

> **Token rotation:** Refresh tokens are rotated on every use. The old refresh token is invalidated when a new one is issued. Always store and use the latest refresh token from the response.

> **Reuse detection (RFC 9700):** If a refresh token that was already rotated is presented again, Indiko treats it as a possible token leak and **revokes the entire token family** — the current access and refresh tokens in that chain stop working immediately. This means a stolen refresh token can't be replayed without killing the session it came from. Well-behaved clients never replay an old token, so this only fires on a race or a leak; if it fires for you, re-authorize and check how the token was stored.

### token introspection

Verify an access token and get its metadata:

```http
POST {{origin}}/auth/token/introspect
Content-Type: application/x-www-form-urlencoded

token=access_token_here
```

Active token response:

```json
{
  "active": true,
  "sub": "{{origin}}/u/username",
  "me": "{{origin}}/u/username",
  "client_id": "https://myapp.example.com",
  "scope": "profile email",
  "exp": 1735689600,
  "iat": 1735686000,
  "username": "username"
}
```

An `aud` field also appears when the token was bound to a [resource indicator](#resource-indicators-rfc-8707).

Inactive or expired tokens return:

```json
{
  "active": false
}
```

### token revocation

Revoke an access token or refresh token:

```http
POST {{origin}}/auth/token/revoke
Content-Type: application/x-www-form-urlencoded

token=token_to_revoke
```

> **Cascade revocation:** Revoking a refresh token also revokes its associated access tokens, and vice versa. The endpoint returns `200 OK` even if the token doesn't exist (per RFC 7009).

### userinfo endpoint

Get the authenticated user's profile using their access token:

```http
GET {{origin}}/userinfo
Authorization: Bearer access_token_here
```

Response (claims depend on granted scopes):

```json
{
  "sub": "{{origin}}/u/username",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "picture": "https://example.com/photo.jpg",
  "website": "https://jane.example.com"
}
```

> **OIDC claims:** The userinfo endpoint returns OIDC-standard claim names (`picture` instead of `photo`, `website` instead of `url`). The `sub` claim always uses the canonical profile URL for stability.

### device flow (RFC 8628)

For CLI tools and headless devices that can't open a browser. The device displays a code, the user approves it on another device, and the device polls for tokens.

**Step 1:** Device requests codes:

```http
POST {{origin}}/auth/device
Content-Type: application/x-www-form-urlencoded

client_id=https://myapp.example.com
&scope=profile email
&resource=https://api.example.com
```

The `resource` parameter is optional and takes a single value here. See [resource indicators](#resource-indicators-rfc-8707).

Response:

```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "{{origin}}/device",
  "verification_uri_complete": "{{origin}}/device?code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

**Step 2:** Show the user the `user_code` and `verification_uri`. The user visits the URL on their phone or laptop, enters the code, and approves.

**Step 3:** Device polls the token endpoint:

```http
POST {{origin}}/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
&client_id=https://myapp.example.com
```

Polling responses:

| Error | Meaning | Action |
| --- | --- | --- |
| `authorization_pending` | User hasn't acted yet | Keep polling at `interval` |
| `slow_down` | Polling too fast | Increase interval by 5s |
| `access_denied` | User denied the request | Stop polling |
| `expired_token` | Code expired (10 min TTL) | Stop polling, restart |

Success response (same as authorization_code grant):

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "me": "{{origin}}/u/username",
  "scope": "profile email",
  "iss": "{{origin}}"
}
```

> **Notes:**
>
> - Codes expire after 10 minutes
> - The device code is single-use — deleted after successful token exchange
> - No PKCE required (the device code itself is high-entropy proof)
> - Confidential clients (anything with a `client_secret`) must send it on **both** `/auth/device` and the token poll
> - User codes use unambiguous characters (no 0/O, 1/l/I confusion)
> - The `verification_uri_complete` can be shown as a QR code

## rate limits

Indiko rate limits the endpoints an anonymous caller can reach, per client IP. Over the limit you get `429` with an `invalid_request` (or `invalid_client_metadata`) OAuth error body.

| Endpoint | Limit |
| --- | --- |
| `/auth/token` | 30 requests / minute |
| `/auth/device` | 10 requests / minute |
| `/oauth/register` | 5 registrations / minute |
| `/device` code entry | 10 failed code lookups / 15 minutes, per signed-in user |

> **Polling devices:** the device flow `interval` (5s) keeps you well inside the token endpoint limit. Honor `slow_down` and you will never see a `429`.

## resource indicators (RFC 8707)

Scopes say *what* a token may do. A **resource indicator** says *where* it may be used. If your app talks to more than one API, ask for a token per API and each one becomes useless if it leaks to the other.

Pass `resource` on the authorization request. It may repeat:

```http
GET {{origin}}/auth/authorize?response_type=code
  &client_id=https://myapp.example.com
  &redirect_uri=https://myapp.example.com/callback
  &state=random_state_string
  &code_challenge=base64url_encoded_challenge
  &code_challenge_method=S256
  &scope=profile
  &resource=https://api.example.com
  &resource=https://files.example.com
```

Each value must be an absolute `https` (or `http`) URI with **no fragment**. Indiko normalizes it to origin plus path with any trailing slash removed, so `https://api.example.com/` and `https://api.example.com` are the same audience. Duplicates collapse. A malformed value fails the request with `invalid_target`.

The consent screen names the resources it is about to hand out. Indiko fetches each one's [Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728) at `{resource}/.well-known/oauth-protected-resource` and shows the `resource_name` and `logo_uri` it finds there. This is best-effort: a resource with no metadata just shows as its hostname, and the fetch is SSRF-guarded.

The audience rides along the rest of the way:

- **Authorization code** → the token minted from it carries the audience
- **Refresh** → a refreshed token keeps the audience of the token it replaced. You cannot widen it later.
- **Device flow** → pass `resource` on the `POST /auth/device` request (single value), and the polled tokens carry it

To check the audience, introspect the token and read `aud`. One resource comes back as a string, several as an array, and a token with no resource indicator omits the field entirely:

```json
{
  "active": true,
  "sub": "{{origin}}/u/username",
  "client_id": "https://myapp.example.com",
  "scope": "profile",
  "aud": "https://api.example.com",
  "exp": 1735689600
}
```

> **For resource servers:** compare `aud` byte-for-byte against your own resource identifier, using the same normalized form the client sent. If `aud` is absent, the token was issued without an audience and is not scoped to you. Reject it or accept it deliberately, but decide.

> **Consent is per-audience:** Indiko remembers which resources a user approved for your app. Asking for a resource they haven't approved shows the consent screen again, even when the scopes are unchanged. Request the audiences you need up front rather than adding them one at a time.

> **Optional by design:** clients that ignore `resource` behave exactly as before. Adding it is a hardening step, not a migration.

## scopes

Scopes control what data your app can access:

| Scope | Description |
| --- | --- |
| `profile` | Access to user profile (name, photo, URL) — **always required** |
| `email` | Access to user email address |
| `openid` | Request an OIDC ID token |
| `offline_access` | Request a refresh token for long-lived access |

Users can uncheck optional scopes during authorization. The `profile` scope is always granted.

> **offline_access:** Request this only if your app needs to act on the user's behalf after the access token expires. Without it you get a 1-hour access token and no refresh token. Users see it on the consent screen as a distinct "keep you signed in long-term" permission.

> **Scope handling:** Requested scopes appear as checkboxes on the consent screen. Users can deny optional scopes, and your app receives only the approved subset in the token response.

## roles

Indiko supports role-based access control (RBAC) through app-specific roles. Roles are arbitrary strings assigned to users on a per-app basis.

### how roles work

1. An admin defines available roles for a pre-registered app
2. An admin assigns roles to users for that app
3. When the user authorizes your app, their role is included in the token response
4. Your app uses the role for access control decisions

```json
{
  "access_token": "...",
  "me": "{{origin}}/u/username",
  "role": "editor"
}
```

### defining app roles

Admins define roles when creating or editing a pre-registered client. Roles are app-specific; each app defines its own set (e.g., `admin`, `editor`, `viewer`).

### assigning roles

Roles can be assigned two ways:

- **Manually** — Admins assign roles to specific users via the admin panel
- **Via invites** — Invite links can pre-assign roles; users who register through the link get those roles automatically

> **Default roles:** Pre-registered apps can define a default role. New users who authorize the app get this role automatically unless they've been assigned a different one.

## client types

### auto-registered clients

Apps that use a URL as their `client_id` are automatically registered on first authorization. No approval needed.

- Must publish metadata at the `client_id` URL (JSON or `<link rel="redirect_uri">` tags)
- No client secret (public client)
- Use PKCE for security

### pre-registered clients

Apps that an admin registers manually get additional features:

- Opaque client ID (e.g., `ikc_abc123...`)
- Client secret for confidential clients
- Role management (define and assign roles)
- Custom name, logo, and description
- No metadata publishing required

> **Choosing a type:** Use auto-registration for most apps. Pre-register when you need a client secret, role-based access control, or custom branding on the consent screen.

## dynamic client registration (RFC 7591)

Register a confidential client programmatically instead of asking an admin. Returns an opaque `client_id` and `client_secret` for use with the authorization code flow.

```http
POST {{origin}}/oauth/register
Content-Type: application/json

{
  "redirect_uris": ["https://myapp.example.com/callback"],
  "client_name": "My App",
  "logo_uri": "https://myapp.example.com/logo.png"
}
```

`grant_types` is optional and defaults to `["authorization_code", "refresh_token"]`. Supported values are `authorization_code`, `refresh_token`, and `urn:ietf:params:oauth:grant-type:device_code`. Indiko stores what you register and refuses any other grant at the token endpoint, so ask for what you'll actually use.

`redirect_uris` is required only when you register `authorization_code`. A device-only client has nowhere to redirect, so it can leave the field out entirely rather than inventing a placeholder:

```json
{
  "client_name": "My CLI",
  "token_endpoint_auth_method": "none",
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"]
}
```

### confidential or public?

`token_endpoint_auth_method` decides whether you get a `client_secret` at all. It defaults to `client_secret_post`; pass `"none"` to register a public client and no secret is issued.

Pick by asking where the secret would live:

| Situation | Register as |
| --- | --- |
| Server-side app, secret in its own environment | `client_secret_post` |
| CLI or desktop app that registers **once per install** and stores its own credentials | `client_secret_post` |
| CLI shipping one shared secret compiled into the binary | `none` |
| Anything a user can extract with `strings` | `none` |

A secret distributed to every user isn't a secret, and registering as confidential with one is worse than registering public: it tells Indiko to treat requests as authenticated when they aren't. Per-install dynamic registration is the way to have real credentials in a CLI, since each copy gets its own.

Public clients aren't unprotected. The authorization code flow still requires PKCE from everyone, and the device flow's `device_code` is high-entropy proof of possession on its own.

> **Confidential clients and the device flow:** if you did register with a secret, send it on **both** `POST /auth/device` and every token poll. RFC 8628 applies the same client authentication rules as the token endpoint, so a secret that only shows up at one of the two will be rejected at the other.

Response `201 Created`:

```json
{
  "client_id": "ikc_abc123...",
  "client_secret": "iks_xyz789...",
  "client_id_issued_at": 1735686000,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://myapp.example.com/callback"],
  "client_name": "My App",
  "token_endpoint_auth_method": "client_secret_post",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

> **Store the secret now:** `client_secret` is returned in plaintext **only once**, in this response. It is stored hashed and never shown again. Use it as `client_secret` in the [token exchange](#4-exchange-code-for-token). If you lose it, an admin must regenerate it.

> **When to use DCR vs auto-registration:** DCR gives you a confidential client with a secret (better for server-side apps that can keep one). Auto-registration (using a URL as your `client_id`) is simpler for public clients and needs no secret.
