# Indiko

No that was not a typo the project's name actually is `indiko`! This is a small implementation of [IndieAuth](https://indieweb.org/How_to_set_up_web_sign-in_on_your_own_domain) running on bun with sqlite and serving as the authentication provider for my homelab / side projects it also supports custom clients with roles over the OAuth 2.0 spec.

The canonical repo for this is hosted on tangled over at [`dunkirk.sh/indiko`](https://tangled.org/@dunkirk.sh/indiko)

## Quick Start

### Prerequisites

- [Bun](https://bun.sh) v1.0 or higher
- A domain with HTTPS (required for WebAuthn)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/taciturnaxolotl/indiko.git
cd indiko
```

2. Install dependencies:

```bash
bun install
```

3. Create a `.env` file:

```bash
cp .env.example .env
```

Configure the following environment variables:

```env
ORIGIN=https://your-indiko-domain.com
RP_ID=your-indiko-domain.com
PORT=3000
NODE_ENV=production
```

- `ORIGIN` - Full URL where Indiko is hosted (must match RP_ID)
- `RP_ID` - Domain for WebAuthn (no protocol, matches ORIGIN domain)
- `PORT` - Port to run the server on
- `NODE_ENV` - Environment (dev/production)

The database will be automatically created at `./indiko.db` on first run.

4. Start the server:

```bash
# Development (with hot reload)
bun run dev

# Production
bun run start
```

### First User Setup

On first run, you'll need to create an admin user:

1. Visit `https://your-indiko-domain.com/login?invite=bootstrap`
2. Register with a passkey
3. This first user will automatically be an admin

After the first user is created, the bootstrap invite is disabled. Subsequent users must be invited by an admin.

## Usage

### Creating OAuth Apps

1. Go to `/admin/clients`
2. Click "Create OAuth Client"
3. Fill in:

   - **Name** - Display name for your app
   - **Logo URL** - (Optional) URL to app logo
   - **Description** - (Optional) Brief description
   - **Redirect URIs** - One or more OAuth callback URLs
   - **Available Roles** - (Optional) Define roles users can be assigned
   - **Default Role** - (Optional) Auto-assign this role on first auth

4. Save and copy the generated credentials:

   - **Client ID** - Format: `ikc_xxxxxxxxxxxxxxxxxxxxx`
   - **Client Secret** - Format: `iks_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

   > [!IMPORTANT]
   > The client secret is only shown once! Save it securely.

### Using as an IndieAuth Provider

Add these tags to your website's `<head>`:

```html
<link
  rel="authorization_endpoint"
  href="https://your-indiko-domain.com/auth/authorize"
/>
<link rel="token_endpoint" href="https://your-indiko-domain.com/auth/token" />
<link rel="me" href="https://your-indiko-domain.com/u/your-username" />
```

Now you can sign in to IndieAuth-compatible sites using `https://your-domain.com/` as your identity.

## API Reference

### OAuth 2.0 Endpoints

- `GET /auth/authorize` - Authorization endpoint
- `POST /auth/token` - Token exchange endpoint
- `POST /auth/logout` - Session logout

### User Profile

- `GET /u/:username` - Public h-card profile

### Admin API (requires admin token)

- `GET /api/admin/users` - List all users
- `POST /api/admin/invites` - Create invite
- `GET /api/admin/invites` - List invites
- `GET /api/admin/clients` - List OAuth clients
- `POST /api/admin/clients` - Create OAuth client
- `GET /api/admin/clients/:clientId` - Get client details
- `PUT /api/admin/clients/:clientId` - Update client
- `DELETE /api/admin/clients/:clientId` - Delete client

## Development

```bash
# Run with hot reload
bun run dev

# Format code
bun run format

# Type check (handled by Bun)
bun run src/index.ts
```

<p align="center">
    <img src="https://raw.githubusercontent.com/taciturnaxolotl/carriage/main/.github/images/line-break.svg" />
</p>

<p align="center">
    <i><code>&copy 2025-present <a href="https://dunkirk.sh">Kieran Klukas</a></code></i>
</p>

<p align="center">
    <a href="https://tangled.org/dunkirk.sh/indiko/blob/main/LICENSE.md"><img src="https://img.shields.io/static/v1.svg?style=for-the-badge&label=License&message=O'Saasy&logoColor=d9e0ee&colorA=363a4f&colorB=b7bdf8"/></a>
</p>
