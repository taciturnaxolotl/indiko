import { env } from "bun";
import { db } from "./db";
import indexHTML from "./html/index.html";
import adminHTML from "./html/admin.html";
import adminInvitesHTML from "./html/admin-invites.html";
import adminClientsHTML from "./html/admin-clients.html";
import loginHTML from "./html/login.html";
import docsHTML from "./html/docs.html";
import appsHTML from "./html/apps.html";
import {
	canRegister,
	registerOptions,
	registerVerify,
	loginOptions,
	loginVerify,
} from "./routes/auth";
import {
	hello,
	listUsers,
	getProfile,
	updateProfile,
	getAuthorizedApps,
	revokeApp,
	listAllApps,
	getAppDetails,
	revokeAppForUser,
	disableUser,
	enableUser,
	deleteUser,
	deleteSelfAccount,
} from "./routes/api";
import {
	authorizeGet,
	authorizePost,
	token,
	logout,
	userProfile,
	createInvite,
	listInvites,
	updateInvite,
	deleteInvite,
} from "./routes/indieauth";
import {
	listClients,
	createClient,
	getClient,
	updateClient,
	deleteClient,
	setUserRole,
	regenerateClientSecret,
} from "./routes/clients";

(() => {
	const required = ["ORIGIN", "RP_ID"];

	const missing = required.filter((key) => !process.env[key]);

	if (missing.length > 0) {
		console.warn(
			`[Startup] Missing required environment variables: ${missing.join(", ")}`,
		);
		process.exit(1);
	}

	// Validate ORIGIN is HTTPS in production
	const origin = process.env.ORIGIN!;
	const rpId = process.env.RP_ID!;
	const nodeEnv = process.env.NODE_ENV || "development";

	if (nodeEnv === "production" && !origin.startsWith("https://")) {
		console.error(
			`[Startup] ORIGIN must use HTTPS in production (got: ${origin})`,
		);
		process.exit(1);
	}

	// Validate RP_ID matches ORIGIN domain
	try {
		const originUrl = new URL(origin);
		if (originUrl.hostname !== rpId) {
			console.error(
				`[Startup] RP_ID must match ORIGIN domain (ORIGIN: ${originUrl.hostname}, RP_ID: ${rpId})`,
			);
			process.exit(1);
		}
	} catch {
		console.error(`[Startup] Invalid ORIGIN URL format: ${origin}`);
		process.exit(1);
	}

	console.log(`[Startup] Environment validated (${nodeEnv} mode)`);
})();

const server = Bun.serve({
	port: env.PORT ? Number.parseInt(env.PORT, 10) : 3000,
	routes: {
		"/": indexHTML,
		"/health": () => {
			try {
				// Verify database is accessible
				db.query("SELECT 1").get();
				return Response.json({ status: "ok", timestamp: new Date().toISOString() });
			} catch {
				return Response.json(
					{ status: "error", error: "Database unavailable" },
					{ status: 503 }
				);
			}
		},
		"/admin": adminHTML,
		"/admin/invites": adminInvitesHTML,
		"/admin/apps": () => Response.redirect("/admin/clients", 302),
		"/admin/clients": adminClientsHTML,
		"/login": loginHTML,
		"/docs": docsHTML,
		"/apps": appsHTML,
		// Well-known endpoints
		"/.well-known/security.txt": () =>
			new Response(
				`# Security Contact Information for Indiko
# See: https://securitytxt.org/

Contact: mailto:security@dunkirk.sh
Expires: 2026-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: ${env.ORIGIN}/.well-known/security.txt

# Reporting Security Vulnerabilities
# 
# If you discover a security vulnerability in Indiko, please report it 
# responsibly by emailing security@dunkirk.sh with:
# 
# - Description of the vulnerability
# - Steps to reproduce
# - Potential impact assessment
# - Any suggested fixes (optional)
#
# Please do not open public issues for security vulnerabilities.
# You will receive a response within 48 hours.
#
# We appreciate responsible disclosure and will credit researchers 
# who report vulnerabilities (unless you prefer to remain anonymous).

Policy: https://github.com/taciturnaxolotl/indiko/blob/main/SECURITY.md
Acknowledgments: https://github.com/taciturnaxolotl/indiko/blob/main/SECURITY.md#security-audit-history
`,
				{
					headers: {
						"Content-Type": "text/plain; charset=utf-8",
					},
				},
			),
		// API endpoints
		"/api/hello": hello,
		"/api/users": listUsers,
		"/api/profile": (req: Request) => {
			if (req.method === "GET") return getProfile(req);
			if (req.method === "PUT") return updateProfile(req);
			if (req.method === "DELETE") return deleteSelfAccount(req);
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
		"/api/admin/clients": (req: Request) => {
			if (req.method === "GET") return listClients(req);
			if (req.method === "POST") return createClient(req);
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
		"/api/invites/:id": (req: Request) => {
			if (req.method === "PATCH") return updateInvite(req);
			if (req.method === "DELETE") return deleteInvite(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/disable": (req: Request) => {
			if (req.method === "POST") {
				const url = new URL(req.url);
				const userId = url.pathname.split("/")[4];
				return disableUser(req, userId);
			}
			return new Response("Method not allowed", { status: 405 });
		},
	"/api/admin/users/:id/enable": (req: Request) => {
		if (req.method === "POST") {
			const url = new URL(req.url);
			const userId = url.pathname.split("/")[4];
			return enableUser(req, userId);
		}
		return new Response("Method not allowed", { status: 405 });
	},
		"/api/admin/users/:id/delete": (req: Request) => {
			if (req.method === "DELETE") {
				const url = new URL(req.url);
				const userId = url.pathname.split("/")[4];
				return deleteUser(req, userId);
			}
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
		// Dynamic routes with Bun's :param syntax
		"/u/:username": userProfile,
		"/api/apps/:clientId": (req) => {
			if (req.method === "DELETE") return revokeApp(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/apps/:clientId": (req) => {
			if (req.method === "GET") return getAppDetails(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/apps/:clientId/users/:username": (req) => {
			if (req.method === "DELETE")
				return revokeAppForUser(req, req.params.clientId, req.params.username);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/clients/:clientId": (req) => {
			if (req.method === "GET") return getClient(req, req.params.clientId);
			if (req.method === "PUT") return updateClient(req, req.params.clientId);
			if (req.method === "DELETE") return deleteClient(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/clients/:clientId/users/:username/role": (req) => {
			if (req.method === "POST")
				return setUserRole(req, req.params.clientId, req.params.username);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/clients/:clientId/secret": (req) => {
			if (req.method === "POST")
				return regenerateClientSecret(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
	},
	development: process.env.NODE_ENV === "dev",
});

console.log("[Indiko] running on", env.ORIGIN);

// Cleanup job: runs every hour to remove expired data
const cleanupJob = setInterval(() => {
	const now = Math.floor(Date.now() / 1000);
	
	const sessionsDeleted = db.query("DELETE FROM sessions WHERE expires_at < ?").run(now);
	const challengesDeleted = db.query("DELETE FROM challenges WHERE expires_at < ?").run(now);
	const authcodesDeleted = db.query("DELETE FROM authcodes WHERE expires_at < ?").run(now);
	
	const total = sessionsDeleted.changes + challengesDeleted.changes + authcodesDeleted.changes;
	
	if (total > 0) {
		console.log(`[Cleanup] Removed ${total} expired records (sessions: ${sessionsDeleted.changes}, challenges: ${challengesDeleted.changes}, authcodes: ${authcodesDeleted.changes})`);
	}
}, 3600000); // 1 hour in milliseconds

let is_shutting_down = false;
function shutdown(sig: string) {
	if (is_shutting_down) return;
	is_shutting_down = true;

	console.log(`[Shutdown] triggering shutdown due to ${sig}`);

	clearInterval(cleanupJob);
	console.log("[Shutdown] stopped cleanup job");

	server.stop();
	console.log("[Shutdown] stopped server");

	db.close();
	console.log("[Shutdown] closed db");

	process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
