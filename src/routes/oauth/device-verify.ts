import { db } from "../../db";
import {
	BASE_STYLES,
	escapeHtml,
	FRAME_DENY_HEADERS,
} from "../../lib/oauth/pages";
import { getCsrfToken, getUserFromCookie } from "../../lib/session";

const DEVICE_STYLES = `
	body { padding: 2rem 1rem; }
	.device {
		max-width: 30rem;
		width: 100%;
		background: rgba(188, 141, 160, 0.05);
		border: 1px solid var(--old-rose);
		padding: 2.5rem;
	}
	.code-input {
		width: 100%;
		padding: 1rem;
		font-family: "Space Grotesk", monospace;
		font-size: 1.5rem;
		font-weight: 700;
		text-align: center;
		letter-spacing: 0.3rem;
		text-transform: uppercase;
		background: rgba(12, 23, 19, 0.6);
		border: 2px solid var(--old-rose);
		color: var(--lavender);
		margin-bottom: 1.5rem;
		outline: none;
		transition: border-color 0.2s;
	}
	.code-input:focus {
		border-color: var(--berry-crush);
	}
	.code-input::placeholder {
		color: rgba(188, 141, 160, 0.3);
		letter-spacing: 0.15rem;
	}
	.app-info {
		padding: 1.25rem;
		background: rgba(12, 23, 19, 0.4);
		border: 1px solid var(--old-rose);
		margin-bottom: 1.5rem;
	}
	.app-info .name {
		font-size: 1.125rem;
		font-weight: 700;
		color: var(--lavender);
		margin-bottom: 0.25rem;
	}
	.app-info .scopes {
		font-size: 0.875rem;
		color: var(--old-rose);
	}
	.app-info .scopes code {
		font-size: 0.8125rem;
	}
	.error-msg {
		padding: 1rem;
		background: rgba(160, 70, 104, 0.15);
		border: 1px solid var(--rosewood);
		color: var(--lavender);
		margin-bottom: 1.5rem;
		font-size: 0.875rem;
	}
	.success-msg {
		padding: 1rem;
		background: rgba(74, 124, 89, 0.15);
		border: 1px solid #4a7c59;
		color: var(--lavender);
		margin-bottom: 1.5rem;
		font-size: 0.875rem;
	}
	.buttons {
		display: flex;
		gap: 1rem;
		margin-top: 1.5rem;
	}
	.buttons button { flex: 1; }
	.allow {
		background: var(--berry-crush);
		color: var(--lavender);
	}
	.allow::before { border-color: var(--rosewood); }
	.deny {
		background: transparent;
		color: var(--old-rose);
	}
	.deny::before { border-color: var(--old-rose); }
	.who {
		margin-top: 1.5rem;
		text-align: center;
		font-size: 0.8125rem;
		color: var(--old-rose);
	}
	.who strong { color: var(--lavender); font-weight: 600; }
	.submit-btn {
		width: 100%;
		background: var(--berry-crush);
		color: var(--lavender);
	}
	.submit-btn::before { border-color: var(--rosewood); }
`;

function devicePage(title: string, body: string, status = 200): Response {
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>${escapeHtml(title)} • Indiko</title>
	<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
	<style>${BASE_STYLES}${DEVICE_STYLES}</style>
</head>
<body>
	<main class="device">
		<h1>${escapeHtml(title)}</h1>
		${body}
	</main>
</body>
</html>`;

	return new Response(html, {
		status,
		headers: {
			"Content-Type": "text/html",
			...FRAME_DENY_HEADERS,
		},
	});
}

function normalizeUserCode(input: string): string {
	return input.toUpperCase().replace(/[^A-Z]/g, "");
}

// Rate limiting for device code verification (RFC 8628 §5.2).
// Track failed lookups per user; lock out after MAX_FAILURES within WINDOW.
const MAX_FAILURES = 10;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const failedAttempts = new Map<number, { count: number; firstAt: number }>();

function isRateLimited(userId: number): boolean {
	// Skip rate limiting in tests
	if (process.env.NODE_ENV === "test") return false;

	const entry = failedAttempts.get(userId);
	if (!entry) return false;
	if (Date.now() - entry.firstAt > WINDOW_MS) {
		failedAttempts.delete(userId);
		return false;
	}
	return entry.count >= MAX_FAILURES;
}

function recordFailure(userId: number): void {
	const entry = failedAttempts.get(userId);
	if (!entry || Date.now() - entry.firstAt > WINDOW_MS) {
		failedAttempts.set(userId, { count: 1, firstAt: Date.now() });
	} else {
		entry.count++;
	}
}

function clearFailures(userId: number): void {
	failedAttempts.delete(userId);
}

function lookupDeviceCode(userCode: string) {
	const normalized = normalizeUserCode(userCode);
	// Try with and without the dash
	const withDash =
		normalized.length === 8
			? `${normalized.slice(0, 4)}-${normalized.slice(4)}`
			: normalized;

	return db
		.query(
			`SELECT dc.id, dc.client_id, dc.scope, dc.expires_at, dc.status, dc.user_id,
			        a.name as app_name, a.logo_url as app_logo
			 FROM device_codes dc
			 LEFT JOIN apps a ON dc.client_id = a.client_id
			 WHERE dc.user_code = ? OR dc.user_code = ?`,
		)
		.get(withDash, normalized) as
		| {
				id: number;
				client_id: string;
				scope: string;
				expires_at: number;
				status: string;
				user_id: number | null;
				app_name: string | null;
				app_logo: string | null;
		  }
		| undefined;
}

// GET /device - User verification page
export function deviceGet(req: Request): Response {
	const user = getUserFromCookie(req);
	if (!user) {
		const url = new URL(req.url);
		const returnUrl = `/device${url.search}`;
		return Response.redirect(`/login?return=${encodeURIComponent(returnUrl)}`);
	}

	const url = new URL(req.url);
	const code = url.searchParams.get("code") || "";

	const inputHtml = `
		<p>enter the code shown on your device</p>
		<form method="GET" action="/device">
			<input
				type="text"
				name="code"
				class="code-input"
				placeholder="XXXX-XXXX"
				value="${escapeHtml(code)}"
				maxlength="9"
				autocomplete="off"
				autofocus
			/>
			<button type="submit" class="submit-btn">verify</button>
		</form>
		<div class="who">signed in as <strong>${escapeHtml(user.username)}</strong></div>
	`;

	if (!code) {
		return devicePage("authorize device", inputHtml);
	}

	if (isRateLimited(user.userId)) {
		return devicePage(
			"authorize device",
			`<div class="error-msg">Too many failed attempts. Please wait before trying again.</div>`,
			429,
		);
	}

	const deviceCode = lookupDeviceCode(code);

	if (!deviceCode) {
		recordFailure(user.userId);
		return devicePage(
			"authorize device",
			`<div class="error-msg">Invalid code. Check the code on your device and try again.</div>${inputHtml}`,
		);
	}

	clearFailures(user.userId);

	const now = Math.floor(Date.now() / 1000);
	if (deviceCode.expires_at < now) {
		return devicePage(
			"authorize device",
			`<div class="error-msg">This code has expired. Restart the login process on your device.</div>${inputHtml}`,
		);
	}

	if (deviceCode.status !== "pending") {
		const msg =
			deviceCode.status === "approved"
				? "This device has already been authorized."
				: "This device authorization was denied.";
		return devicePage(
			"authorize device",
			`<div class="error-msg">${msg}</div>${inputHtml}`,
		);
	}

	// Show the confirmation screen
	const appName = deviceCode.app_name || deviceCode.client_id;
	const scopes = deviceCode.scope;

	const confirmHtml = `
		<p>a device is requesting access to your account</p>
		<div class="app-info">
			<div class="name">${escapeHtml(appName)}</div>
			<div class="scopes">scopes: <code>${escapeHtml(scopes)}</code></div>
		</div>
		<p>make sure you initiated this on your device. only approve if you recognize the request.</p>
		<form method="POST" action="/device">
			<input type="hidden" name="csrf_token" value="${escapeHtml(getCsrfToken(req) || "")}" />
			<input type="hidden" name="code" value="${escapeHtml(code)}" />
			<div class="buttons">
				<button type="submit" name="action" value="deny" class="deny">deny</button>
				<button type="submit" name="action" value="allow" class="allow">allow</button>
			</div>
		</form>
		<div class="who">signed in as <strong>${escapeHtml(user.username)}</strong></div>
	`;

	return devicePage("authorize device", confirmHtml);
}

// POST /device - User approves or denies
export async function devicePost(req: Request): Promise<Response> {
	const user = getUserFromCookie(req);
	if (!user) {
		return new Response("Unauthorized", { status: 401 });
	}

	const formData = await req.formData();
	const code = formData.get("code") as string;
	const action = formData.get("action") as string;

	if (!code || !action) {
		return new Response("Missing parameters", { status: 400 });
	}

	// Validate CSRF token from form field against cookie
	const formCsrf = formData.get("csrf_token") as string;
	const cookieCsrf = getCsrfToken(req);
	if (!formCsrf || !cookieCsrf || formCsrf !== cookieCsrf) {
		return new Response("CSRF token mismatch", { status: 403 });
	}

	if (isRateLimited(user.userId)) {
		return devicePage(
			"authorize device",
			`<div class="error-msg">Too many failed attempts. Please wait before trying again.</div>`,
			429,
		);
	}

	const deviceCode = lookupDeviceCode(code);

	if (!deviceCode) {
		recordFailure(user.userId);
		return devicePage(
			"authorize device",
			`<div class="error-msg">Invalid code.</div>`,
			400,
		);
	}

	clearFailures(user.userId);

	const now = Math.floor(Date.now() / 1000);
	if (deviceCode.expires_at < now) {
		return devicePage(
			"authorize device",
			`<div class="error-msg">This code has expired.</div>`,
			400,
		);
	}

	if (deviceCode.status !== "pending") {
		return devicePage(
			"authorize device",
			`<div class="error-msg">This code has already been used.</div>`,
			400,
		);
	}

	if (action === "deny") {
		db.query("UPDATE device_codes SET status = 'denied' WHERE id = ?").run(
			deviceCode.id,
		);
		return devicePage(
			"device denied",
			`<div class="success-msg">The device has been denied access. You can close this page.</div>`,
		);
	}

	// Approve
	db.query(
		"UPDATE device_codes SET status = 'approved', user_id = ? WHERE id = ?",
	).run(user.userId, deviceCode.id);

	return devicePage(
		"device authorized",
		`<div class="success-msg">Device authorized! You can close this page and return to your device.</div>`,
	);
}
