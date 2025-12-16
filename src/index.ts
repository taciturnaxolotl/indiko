import { env } from "bun";
import { db } from "./db";
import indexHTML from "./html/index.html";
import adminHTML from "./html/admin.html";
import adminAppsHTML from "./html/admin-apps.html";
import loginHTML from "./html/login.html";
import profileHTML from "./html/profile.html";
import oauthTestHTML from "./html/oauth-test.html";
import appsHTML from "./html/apps.html";
import { canRegister, registerOptions, registerVerify, loginOptions, loginVerify } from "./routes/auth";
import { hello, listUsers, getProfile, updateProfile, getAuthorizedApps, revokeApp, listAllApps, getAppDetails, revokeAppForUser } from "./routes/api";
import { authorizeGet, authorizePost, token, logout, userProfile, createInvite, listInvites } from "./routes/indieauth";

(() => {
	const required = ["ORIGIN", "RP_ID"];

	const missing = required.filter((key) => !process.env[key]);

	if (missing.length > 0) {
		console.warn(
			`[Startup] Missing required envivonment variables: ${missing.join(", ")}`,
		);
		process.exit(1);
	}
})();

const server = Bun.serve({
	port: env.PORT ? Number.parseInt(env.PORT, 10) : 3000,
	routes: {
		"/": indexHTML,
		"/admin": adminHTML,
		"/admin/apps": adminAppsHTML,
		"/login": loginHTML,
		"/profile": profileHTML,
		"/oauth-test": oauthTestHTML,
		"/apps": appsHTML,
		// API endpoints
		"/api/hello": hello,
		"/api/users": listUsers,
		"/api/profile": (req: Request) => {
			if (req.method === "GET") return getProfile(req);
			if (req.method === "PUT") return updateProfile(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/apps": (req: Request) => {
			if (req.method === "GET") return getAuthorizedApps(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/apps": (req: Request) => {
			if (req.method === "GET") return listAllApps(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/invites/create": (req: Request) => {
			if (req.method === "POST") return createInvite(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/invites": (req: Request) => {
			if (req.method === "GET") return listInvites(req);
			return new Response("Method not allowed", { status: 405 });
		},
		// IndieAuth/OAuth 2.0 endpoints
		"/auth/authorize": async (req: Request) => {
			if (req.method === "GET") return authorizeGet(req);
			if (req.method === "POST") return await authorizePost(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/token": async (req: Request) => {
			if (req.method === "POST") return await token(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/logout": (req: Request) => {
			if (req.method === "POST") return logout(req);
			return new Response("Method not allowed", { status: 405 });
		},
		// Passkey auth endpoints
		"/auth/can-register": canRegister,
		"/auth/register/options": registerOptions,
		"/auth/register/verify": registerVerify,
		"/auth/login/options": loginOptions,
		"/auth/login/verify": loginVerify,
	},
	development: process.env.NODE_ENV === "dev",
	fetch(req) {
		// Handle dynamic routes like /u/:username
		const url = new URL(req.url);
		
		// /u/:username - user profiles
		const userMatch = url.pathname.match(/^\/u\/([^\/]+)$/);
		if (userMatch) {
			const username = userMatch[1];
			return userProfile(req, username);
		}
		
		// /api/apps/:clientId - revoke app access
		const appMatch = url.pathname.match(/^\/api\/apps\/([^\/]+)$/);
		if (appMatch) {
			if (req.method === "DELETE") {
				const clientId = decodeURIComponent(appMatch[1]);
				return revokeApp(req, clientId);
			}
			return new Response("Method not allowed", { status: 405 });
		}
		
		// /api/admin/apps/:clientId - get app details (admin)
		const adminAppMatch = url.pathname.match(/^\/api\/admin\/apps\/([^\/]+)$/);
		if (adminAppMatch) {
			if (req.method === "GET") {
				const clientId = decodeURIComponent(adminAppMatch[1]);
				return getAppDetails(req, clientId);
			}
			return new Response("Method not allowed", { status: 405 });
		}
		
		// /api/admin/apps/:clientId/users/:username - revoke app access for user (admin)
		const adminAppUserMatch = url.pathname.match(/^\/api\/admin\/apps\/([^\/]+)\/users\/([^\/]+)$/);
		if (adminAppUserMatch) {
			if (req.method === "DELETE") {
				const clientId = decodeURIComponent(adminAppUserMatch[1]);
				const username = decodeURIComponent(adminAppUserMatch[2]);
				return revokeAppForUser(req, clientId, username);
			}
			return new Response("Method not allowed", { status: 405 });
		}
		
		// Let Bun handle static routes
		return undefined as never;
	},
});

console.log("[Indiko] running on", env.ORIGIN);

let is_shutting_down = false;
function shutdown(sig: string) {
	if (is_shutting_down) return;
	is_shutting_down = true;

	console.log(`[Shutdown] triggering shutdown due to ${sig}`);

	server.stop();
	console.log("[Shutdown] stopped server");

	db.close();
	console.log("[Shutdown] closed db");

	process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
