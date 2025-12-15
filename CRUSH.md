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

### Project Structure
```
src/
├── db.ts              # Database setup and exports
├── index.ts           # Main server entry point
├── routes/            # Route handlers (server-side)
│   └── auth.ts        # Authentication routes
├── client/            # Client-side TypeScript modules
│   └── login.ts       # Login page logic
├── html/              # HTML templates (Bun bundles them with script imports)
└── migrations/        # SQL migrations
```

### Client-Side Code
- Extract JavaScript from HTML into separate TypeScript modules in `src/client/`
- Import client modules into HTML with `<script type="module" src="../client/file.ts"></script>`
- Bun will bundle the imports automatically
- Static assets (images, favicons) in `public/` are served at root path
- In HTML files: use paths relative to server root (e.g., `/logo.svg`, `/favicon.svg`) since Bun bundles HTML and resolves paths from server context

## Commands

(Add test/lint/build commands here as discovered)

## Code Style

- Use tabs for indentation
- TypeScript with Bun runtime
- Use SQLite with WAL mode
- Route handlers: `(req: Request) => Response`
