import "./ds";
import { apiFetch } from "./api";
import { escapeHtml } from "./escape";
import { requirePage } from "./session";

const usersList = document.getElementById("usersList") as HTMLElement;
const toast = document.getElementById("toast") as HTMLElement & {
	show(message: string, kind?: "success" | "error"): void;
};
let currentUserId: number;

const ACTIONS: Record<string, { path: string; method: string }> = {
	enable: { path: "enable", method: "POST" },
	disable: { path: "disable", method: "POST" },
	reset: { path: "passkeys/reset", method: "POST" },
	delete: { path: "delete", method: "DELETE" },
};

interface PasskeyReset {
	username: string;
	passkeys: number;
	url: string;
	expiresAt: number;
}

async function loadUsers() {
	try {
		const [me, response] = await Promise.all([
			requirePage({ admin: true }),
			apiFetch("/api/users", {}),
		]);
		currentUserId = me.id;

		if (!response.ok) {
			throw new Error("Failed to load users");
		}

		const data = await response.json();

		if (data.users.length === 0) {
			usersList.innerHTML = '<div class="loading">No users found</div>';
			return;
		}

		usersList.innerHTML = data.users
			.map(
				(user: {
					id: number;
					username: string;
					name: string;
					email: string | null;
					photo: string | null;
					status: string;
					role: string;
					isAdmin: boolean;
					createdAt: number;
					credentialCount: number;
				}) => {
					const createdDate = new Date(
						user.createdAt * 1000,
					).toLocaleDateString();
					const initials = user.username.substring(0, 2).toUpperCase();
					const avatarContent = user.photo
						? `<img src="${escapeHtml(user.photo)}" alt="${escapeHtml(user.username)}" />`
						: initials;
					const isSelf = user.id === currentUserId;

					return `
				<div class="user-card ${user.status === "suspended" ? "user-suspended" : ""}" data-user-id="${user.id}">
					<div class="user-avatar">${avatarContent}</div>
					<div class="user-info">
						<div class="user-name">${escapeHtml(user.username)}${isSelf ? " (you)" : ""}</div>
						<div class="user-meta">
							<span class="user-meta-item">${user.credentialCount} passkey${user.credentialCount !== 1 ? "s" : ""}</span>
							<span class="user-meta-item">joined ${createdDate}</span>
							${user.email ? `<span class="user-meta-item">${escapeHtml(user.email)}</span>` : ""}
						</div>
					</div>
					<div class="user-badges">
						<span class="user-badge badge-status ${escapeHtml(user.status)}">${escapeHtml(user.status)}</span>
						<span class="user-badge badge-role">${escapeHtml(user.role)}</span>
					</div>
					<div class="user-actions">
						${
							!isSelf
								? user.status === "suspended"
									? `<button class="btn-edit" data-action="enable" data-user-id="${user.id}">enable</button>`
									: `<button class="btn-disable" data-action="disable" data-user-id="${user.id}">disable</button>`
								: ""
						}
						${!isSelf ? `<button class="btn-edit" data-action="reset" data-user-id="${user.id}">reset passkeys</button>` : ""}
						${!isSelf ? `<button class="btn-delete" data-action="delete" data-user-id="${user.id}">delete</button>` : ""}
					</div>
				</div>
			`;
				},
			)
			.join("");

		// Add event listeners for action buttons
		document.querySelectorAll("button[data-action]").forEach((btn) => {
			btn.addEventListener("click", handleUserAction);
		});
	} catch (error) {
		console.error("Failed to load users:", error);
		usersList.innerHTML = '<div class="error">Failed to load users</div>';
	}
}

async function handleUserAction(e: Event) {
	const btn = e.target as HTMLButtonElement;
	const action = btn.dataset.action;
	const userId = btn.dataset.userId;

	if (!userId || !action) return;

	// Check if already in confirmation state
	if (btn.dataset.confirmState === "pending") {
		// Second click - perform action
		btn.dataset.confirmState = "";
		btn.disabled = true;

		try {
			const target = ACTIONS[action];
			if (!target) return;
			const response = await apiFetch(
				`/api/admin/users/${userId}/${target.path}`,
				{
					method: target.method,
					headers: {},
				},
			);

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.error || "Failed to perform action");
			}

			await loadUsers();
			if (action === "reset")
				showResetLink(userId, (await response.json()) as PasskeyReset);
		} catch (error) {
			console.error(`Failed to ${action} user:`, error);
			alert(
				`Failed to ${action} user: ${error instanceof Error ? error.message : "Unknown error"}`,
			);
			btn.disabled = false;
		}
	} else {
		// First click - set confirmation state
		const originalText = btn.textContent;
		btn.dataset.confirmState = "pending";
		btn.dataset.originalText = originalText || "";
		btn.textContent = "you sure?";

		// Reset after 3 seconds if not clicked again
		setTimeout(() => {
			if (btn.dataset.confirmState === "pending") {
				btn.dataset.confirmState = "";
				btn.textContent = btn.dataset.originalText || originalText;
			}
		}, 3000);
	}
}

/** The link exists only in this response, so it stays on screen until the admin dismisses it. */
function showResetLink(userId: string, reset: PasskeyReset) {
	const card = usersList.querySelector(`.user-card[data-user-id="${userId}"]`);
	if (!card) return;
	const expires = new Date(reset.expiresAt * 1000).toLocaleString();
	const panel = document.createElement("div");
	panel.className = "reset-link";
	panel.innerHTML = `
		<p>Removed ${reset.passkeys} passkey${reset.passkeys !== 1 ? "s" : ""} and signed ${escapeHtml(reset.username)} out.
		Send them this link to register a new one. It works once, until ${escapeHtml(expires)}.</p>
		<div class="reset-link-row">
			<input type="text" readonly value="${escapeHtml(reset.url)}" aria-label="reset link" />
			<button class="btn-edit" data-copy>copy</button>
			<button class="btn-edit" data-dismiss>done</button>
		</div>`;
	const input = panel.querySelector("input") as HTMLInputElement;
	const copy = async () => {
		try {
			await navigator.clipboard.writeText(reset.url);
			toast.show("Reset link copied");
		} catch {
			input.select();
			toast.show("Couldn't copy; select the link and copy it by hand", "error");
		}
	};
	panel.querySelector("[data-copy]")?.addEventListener("click", copy);
	panel
		.querySelector("[data-dismiss]")
		?.addEventListener("click", () => panel.remove());
	input.addEventListener("focus", () => input.select());
	card.after(panel);
	copy();
}

loadUsers();
