import { Elena, html, nothing } from "@elenajs/core";
import {
	cachedSession,
	forgetSession,
	type Session,
	session,
} from "../session";

/**
 * <i-nav> — shared top navigation for authenticated pages.
 *
 * Attributes: active (dashboard|apps|docs|admin)
 * Renders logo, primary links, and the signed-in user chip. Paints the
 * remembered session immediately, then confirms it against the server.
 *
 * Usage: <i-nav active="apps"></i-nav>
 */
export default class INav extends Elena(HTMLElement) {
	static override tagName = "i-nav";
	static override props = ["active"];

	active = "";

	private user: Session | null = cachedSession();

	override async firstUpdated() {
		const confirmed = await session().catch(() => this.user);
		if (
			confirmed?.username !== this.user?.username ||
			confirmed?.isAdmin !== this.user?.isAdmin
		) {
			this.user = confirmed;
			this.requestUpdate();
		}
	}

	private link(href: string, key: string, label: string) {
		const current = this.active === key;
		return html`<a href="${href}" class="${current ? "active" : ""}" ${current ? 'aria-current="page"' : ""}>${label}</a>`;
	}

	override render() {
		const user = this.user;
		return html`
			<nav class="nav">
				<a href="/" class="brand">
					<img src="/logo.svg" alt="indiko" />
				</a>
				<div class="links">
					${this.link("/dashboard", "dashboard", "dashboard")}
					${this.link("/apps", "apps", "apps")}
					${this.link("/docs", "docs", "docs")}
					${user?.isAdmin ? this.link("/admin", "admin", "admin") : nothing}
				</div>
				<div class="who">
					${
						user
							? html`
							<a href="/u/${user.username}" class="user">${user.username}</a>
							<button type="button" class="signout" id="signout">sign out</button>
						`
							: nothing
					}
				</div>
			</nav>
		`;
	}

	override updated() {
		const btn = this.querySelector<HTMLButtonElement>("#signout");
		if (btn && !btn.dataset.bound) {
			btn.dataset.bound = "1";
			btn.addEventListener("click", () => this.signOut());
		}
	}

	private async signOut() {
		forgetSession();
		try {
			const csrf = document.cookie.match(/indiko_csrf=([^;]+)/)?.[1];
			await fetch("/auth/logout", {
				method: "POST",
				headers: csrf ? { "X-CSRF-Token": csrf } : {},
			});
		} catch {
			// Ignore
		}
		window.location.href = "/login";
	}
}
INav.define();

// Prefetch a same-origin page once the pointer settles on its link (Chromium; ignored elsewhere).
if (HTMLScriptElement.supports?.("speculationrules")) {
	const rules = document.createElement("script");
	rules.type = "speculationrules";
	rules.textContent = JSON.stringify({
		prefetch: [
			{
				where: {
					and: [
						{ href_matches: "/*" },
						{ not: { href_matches: ["/auth/*", "/api/*", "/device*"] } },
					],
				},
				eagerness: "moderate",
			},
		],
	});
	document.head.append(rules);
}
