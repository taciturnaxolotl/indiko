import "./ds";
import { apiFetch } from "./api";
import type IToast from "./ds/toast";

interface App {
	clientId: string;
	name: string;
	scopes: string[];
	grantedAt: number;
	lastUsed: number;
}

function $(id: string): HTMLElement {
	const el = document.getElementById(id);
	if (!el) throw new Error(`#${id} missing from page`);
	return el;
}

let appsList: HTMLElement;
let toast: IToast;

import { escapeHtml } from "./escape";

async function loadApps() {
	try {
		const response = await apiFetch("/api/apps");

		if (response.status === 401 || response.status === 403) {
			window.location.href = "/login";
			return;
		}

		if (!response.ok) throw new Error("Failed to load apps");

		const data = await response.json();
		displayApps(data.apps);
	} catch (error) {
		console.error("Failed to load apps:", error);
		appsList.innerHTML =
			'<div class="error">Failed to load authorized apps</div>';
	}
}

function displayApps(apps: App[]) {
	if (apps.length === 0) {
		appsList.innerHTML =
			'<div class="empty">No authorized apps yet. Apps will appear here after you grant them access.</div>';
		return;
	}

	appsList.innerHTML = apps
		.map((app) => {
			const lastUsedDate = new Date(app.lastUsed * 1000).toLocaleDateString();
			const grantedDate = new Date(app.grantedAt * 1000).toLocaleDateString();
			const badges = app.scopes
				.map((s) => `<span class="scope-badge">${escapeHtml(s)}</span>`)
				.join("");

			return `
			<i-card class="app-card" data-client-id="${escapeHtml(app.clientId)}">
				<div class="app-head">
					<div>
						<div class="app-name">${escapeHtml(app.name)}</div>
						<div class="app-meta">granted ${grantedDate} • last used ${lastUsedDate}</div>
					</div>
					<button type="button" class="revoke-btn" data-client-id="${escapeHtml(app.clientId)}">revoke</button>
				</div>
				<div class="scopes">
					<div class="scope-title">permissions</div>
					<div class="scope-list">${badges}</div>
				</div>
			</i-card>
		`;
		})
		.join("");
}

async function handleRevoke(btn: HTMLButtonElement) {
	const clientId = btn.dataset.clientId;
	if (!clientId) return;

	// Two-step confirm: first click arms, second click revokes
	if (btn.dataset.confirmState !== "pending") {
		btn.dataset.confirmState = "pending";
		btn.textContent = "you sure?";
		setTimeout(() => {
			if (btn.dataset.confirmState === "pending") {
				delete btn.dataset.confirmState;
				btn.textContent = "revoke";
			}
		}, 3000);
		return;
	}

	delete btn.dataset.confirmState;
	btn.disabled = true;
	btn.textContent = "revoking...";

	try {
		const response = await apiFetch(
			`/api/apps/${encodeURIComponent(clientId)}`,
			{ method: "DELETE" },
		);

		if (!response.ok) throw new Error("Failed to revoke app");

		document.querySelector(`[data-client-id="${clientId}"]`)?.remove();
		toast.show("App access revoked", "success");

		if (document.querySelectorAll(".app-card").length === 0) {
			appsList.innerHTML =
				'<div class="empty">No authorized apps yet. Apps will appear here after you grant them access.</div>';
		}
	} catch (error) {
		console.error("Failed to revoke app:", error);
		toast.show("Failed to revoke app access. Please try again.", "error");
		btn.disabled = false;
		btn.textContent = "revoke";
	}
}

function init() {
	appsList = $("appsList");
	toast = $("toast") as unknown as IToast;

	appsList.addEventListener("click", (e) => {
		const btn = (e.target as HTMLElement).closest(
			".revoke-btn",
		) as HTMLButtonElement | null;
		if (btn) handleRevoke(btn);
	});

	loadApps();
}

if (document.readyState === "complete") {
	init();
} else {
	document.addEventListener("DOMContentLoaded", init);
}
