import { Elena, html, nothing } from "@elenajs/core";

interface SessionInfo {
	username: string;
	isAdmin: boolean;
}

/**
 * <i-nav> — shared top navigation for authenticated pages.
 *
 * Attributes: active (dashboard|apps|docs|admin)
 * Renders logo, primary links, and the signed-in user chip. Fetches the
 * current session itself so every page behaves identically. Stays minimal
 * (logo + links) until the session resolves.
 *
 * Usage: <i-nav active="apps"></i-nav>
 */
export default class INav extends Elena(HTMLElement) {
	static override tagName = "i-nav";
	static override props = ["active"];

	active = "";

	private session: SessionInfo | null = null;

	override async firstUpdated() {
		try {
			const res = await fetch("/api/hello");
			if (!res.ok) return;
			const data = await res.json();
			this.session = { username: data.username, isAdmin: !!data.isAdmin };
			this.requestUpdate();
		} catch {
			// Stay logged-out-looking on error
		}
	}

	private link(href: string, key: string, label: string) {
		const current = this.active === key;
		return html`<a href="${href}" class="${current ? "active" : ""}" ${current ? 'aria-current="page"' : ""}>${label}</a>`;
	}

	override render() {
		const user = this.session;
		return html`
			<nav class="nav">
				<a href="/" class="brand">
					<img src="/logo.svg" alt="indiko" />
				</a>
				<div class="links">
					${this.link("/", "dashboard", "dashboard")}
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
		try {
			await fetch("/auth/logout", { method: "POST" });
		} catch {
			// Ignore
		}
		window.location.href = "/login";
	}
}
INav.define();
