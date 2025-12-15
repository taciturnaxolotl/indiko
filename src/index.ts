import { env } from "bun";
import { db } from "./db";
import indexHTML from "./html/index.html";
import loginHTML from "./html/login.html";
import profileHTML from "./html/profile.html";
import { canRegister, registerOptions, registerVerify, loginOptions, loginVerify } from "./routes/auth";
import { hello, listUsers, getProfile, updateProfile } from "./routes/api";

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
		"/login": loginHTML,
		"/profile": profileHTML,
		// API endpoints
		"/api/hello": hello,
		"/api/users": listUsers,
		"/api/profile": (req: Request) => {
			if (req.method === "GET") return getProfile(req);
			if (req.method === "PUT") return updateProfile(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/can-register": canRegister,
		"/auth/register/options": registerOptions,
		"/auth/register/verify": registerVerify,
		"/auth/login/options": loginOptions,
		"/auth/login/verify": loginVerify,
	},
	development: process.env.NODE_ENV === "dev",
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
