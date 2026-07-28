import "./ds";
import { escapeHtml } from "./escape";

declare global {
	interface Window {
		submitCreateInvite: () => Promise<void>;
		closeCreateInviteModal: () => void;
		editInvite: (inviteId: number) => Promise<void>;
		submitEditInvite: () => Promise<void>;
		closeEditInviteModal: () => void;
		deleteInvite: (inviteId: number, event?: Event) => Promise<void>;
	}
}
const token = localStorage.getItem("indiko_session");
const invitesList = document.getElementById("invitesList") as HTMLElement;
const createInviteBtn = document.getElementById(
	"createInviteBtn",
) as HTMLButtonElement;

// Check auth and display user
async function checkAuth() {
	if (!token) {
		window.location.href = "/login";
		return;
	}

	try {
		const response = await fetch("/api/hello", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (response.status === 401 || response.status === 403) {
			localStorage.removeItem("indiko_session");
			window.location.href = "/login";
			return;
		}

		const data = await response.json();

		// Check if admin
		if (!data.isAdmin) {
			window.location.href = "/";
			return;
		}

		// Load invites
		loadInvites();
	} catch (error) {
		console.error("Auth check failed:", error);
		invitesList.innerHTML = '<div class="error">Failed to load invites</div>';
	}
}

async function createInvite() {
	// Show the create invite modal
	const modal = document.getElementById("createInviteModal");
	if (modal) {
		modal.style.display = "flex";
		// Load apps for role assignment
		await loadAppsForInvite();
	}
}

async function loadAppsForInvite() {
	try {
		const response = await fetch("/api/admin/clients", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error("Failed to load apps");
		}

		const data = await response.json();
		const appRolesContainer = document.getElementById("appRolesContainer");

		if (!appRolesContainer) return;

		if (data.clients.length === 0) {
			appRolesContainer.innerHTML =
				'<p style="color: var(--old-rose); font-size: 0.875rem;">No pre-registered apps available</p>';
			return;
		}

		appRolesContainer.innerHTML = data.clients
			.filter((app: { isPreregistered: boolean }) => app.isPreregistered)
			.map(
				(app: {
					id: number;
					clientId: string;
					name: string;
					roles: string[];
				}) => {
					const roleOptions =
						app.roles.length > 0
							? app.roles
									.map((role) => `<option value="${role}">${role}</option>`)
									.join("")
							: '<option value="" disabled>No roles defined yet</option>';

					const displayName = app.name || app.clientId;

					return `
				<div class="app-role-item">
					<label>
						<input type="checkbox" name="appRole" value="${app.id}" data-client-id="${app.clientId}">
						<span>${displayName}</span>
					</label>
					<select class="role-select" data-app-id="${app.id}" disabled>
						<option value="">Select role...</option>
						${roleOptions}
					</select>
				</div>
			`;
				},
			)
			.join("");

		// Enable/disable role select when checkbox changes
		const checkboxes = appRolesContainer.querySelectorAll(
			'input[name="appRole"]',
		);
		checkboxes.forEach((checkbox) => {
			checkbox.addEventListener("change", (e) => {
				const target = e.target as HTMLInputElement;
				const appId = target.value;
				const roleSelect = appRolesContainer.querySelector(
					`select.role-select[data-app-id="${appId}"]`,
				) as HTMLSelectElement;

				if (roleSelect) {
					roleSelect.disabled = !target.checked;
					if (!target.checked) {
						roleSelect.value = "";
					}
				}
			});
		});
	} catch (error) {
		console.error("Failed to load apps:", error);
	}
}

async function submitCreateInvite() {
	const maxUsesInput = document.getElementById("maxUses") as HTMLInputElement;
	const expiresAtInput = document.getElementById(
		"expiresAt",
	) as HTMLInputElement;
	const noteInput = document.getElementById(
		"inviteNote",
	) as HTMLTextAreaElement;
	const messageInput = document.getElementById(
		"inviteMessage",
	) as HTMLTextAreaElement;
	const submitBtn = document.getElementById(
		"submitInviteBtn",
	) as HTMLButtonElement;

	const maxUses = maxUsesInput.value ? parseInt(maxUsesInput.value, 10) : 1;
	const expiresAt = expiresAtInput.value
		? Math.floor(new Date(expiresAtInput.value).getTime() / 1000)
		: null;
	const note = noteInput.value.trim() || null;
	const message = messageInput.value.trim() || null;

	// Collect app roles
	const appRolesContainer = document.getElementById("appRolesContainer");
	const appRoles: Array<{ appId: number; role: string }> = [];

	if (appRolesContainer) {
		const checkedBoxes = appRolesContainer.querySelectorAll(
			'input[name="appRole"]:checked',
		);
		checkedBoxes.forEach((checkbox) => {
			const appId = parseInt((checkbox as HTMLInputElement).value, 10);
			const roleSelect = appRolesContainer.querySelector(
				`select.role-select[data-app-id="${appId}"]`,
			) as HTMLSelectElement;

			let role = "";
			if (roleSelect?.value) {
				role = roleSelect.value;
			}

			if (role) {
				appRoles.push({
					appId,
					role,
				});
			}
		});
	}

	submitBtn.disabled = true;
	submitBtn.textContent = "creating...";

	try {
		const response = await fetch("/api/invites/create", {
			method: "POST",
			headers: {
				Authorization: `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				maxUses,
				expiresAt,
				note,
				message,
				appRoles: appRoles.length > 0 ? appRoles : undefined,
			}),
		});

		if (!response.ok) {
			throw new Error("Failed to create invite");
		}

		await loadInvites();
		closeCreateInviteModal();
	} catch (error) {
		console.error("Failed to create invite:", error);
		alert("Failed to create invite");
	} finally {
		submitBtn.disabled = false;
		submitBtn.textContent = "create invite";
	}
}

function closeCreateInviteModal() {
	const modal = document.getElementById("createInviteModal");
	if (modal) {
		modal.style.display = "none";
		// Reset form
		(document.getElementById("maxUses") as HTMLInputElement).value = "1";
		(document.getElementById("expiresAt") as HTMLInputElement).value = "";
		(document.getElementById("inviteNote") as HTMLTextAreaElement).value = "";
		(document.getElementById("inviteMessage") as HTMLTextAreaElement).value =
			"";
		const appRolesContainer = document.getElementById("appRolesContainer");
		if (appRolesContainer) {
			appRolesContainer
				.querySelectorAll('input[type="checkbox"]')
				.forEach((input) => {
					(input as HTMLInputElement).checked = false;
				});
			appRolesContainer.querySelectorAll("select").forEach((select) => {
				(select as HTMLSelectElement).value = "";
				(select as HTMLSelectElement).disabled = true;
			});
		}
	}
}

// Expose functions to global scope for HTML onclick handlers
window.submitCreateInvite = submitCreateInvite;
window.closeCreateInviteModal = closeCreateInviteModal;

async function loadInvites() {
	try {
		const response = await fetch("/api/invites", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error("Failed to load invites");
		}

		const data = await response.json();

		if (data.invites.length === 0) {
			invitesList.innerHTML =
				'<div class="loading">No invites created yet</div>';
			return;
		}

		invitesList.innerHTML = data.invites
			.map(
				(invite: {
					id: number;
					code: string;
					maxUses: number;
					currentUses: number;
					isExpired: boolean;
					isFullyUsed: boolean;
					expiresAt: number | null;
					note: string | null;
					message: string | null;
					createdAt: number;
					createdBy: string;
					inviteUrl: string;
					appRoles: Array<{
						clientId: string;
						name: string | null;
						role: string;
					}>;
					usedBy: Array<{ username: string; usedAt: number }>;
				}) => {
					const createdDate = new Date(
						invite.createdAt * 1000,
					).toLocaleDateString();

					let status = `${invite.currentUses}/${invite.maxUses} used`;
					if (invite.isExpired) {
						status += " (expired)";
					} else if (invite.isFullyUsed) {
						status += " (fully used)";
					}

					const expiryInfo = invite.expiresAt
						? `Expires: ${new Date(invite.expiresAt * 1000).toLocaleString()}`
						: "No expiry";

				const roleInfo =
						invite.appRoles.length > 0
							? `<div class="invite-meta-item">
							<div class="invite-meta-label">app roles</div>
							<div class="invite-roles">${invite.appRoles
								.map((r) => {
									const appName = r.name || r.clientId;
									return `<span class="invite-role">${escapeHtml(appName)} • ${escapeHtml(r.role)}</span>`;
								})
								.join("")}</div>
						</div>`
							: "";

					const usedByInfo =
						invite.usedBy.length > 0
							? `<div class="invite-meta-item">
							<div class="invite-meta-label">used by</div>
							<div class="invite-meta-value">${invite.usedBy.map((u) => `${escapeHtml(u.username)} (${new Date(u.usedAt * 1000).toLocaleDateString()})`).join(", ")}</div>
						</div>`
							: "";

					const noteInfo = invite.note
						? `<div class="invite-extra-item"><span class="invite-extra-label">Internal note:</span> ${escapeHtml(invite.note)}</div>`
						: "";

					const messageInfo = invite.message
						? `<div class="invite-extra-item"><span class="invite-extra-label">Message to invitees:</span> ${escapeHtml(invite.message)}</div>`
						: "";

					const isActive = !invite.isExpired && !invite.isFullyUsed;
					const statusBadgeClass = isActive ? "badge-active" : "badge-inactive";
					const statusText = isActive ? "active" : status;

					return `
				<div class="invite-item ${isActive ? "" : "invite-inactive"}">
					<div class="invite-primary">
						<span class="invite-code">${escapeHtml(invite.code)}</span>
						<div class="invite-status">
							<span class="badge ${statusBadgeClass}">${statusText}</span>
						</div>
						<div class="invite-meta-grid">
							<div class="invite-meta-item">
								<div class="invite-meta-label">created by</div>
								<div class="invite-meta-value">${escapeHtml(invite.createdBy)}</div>
							</div>
							<div class="invite-meta-item">
								<div class="invite-meta-label">created</div>
								<div class="invite-meta-value">${createdDate}</div>
							</div>
							<div class="invite-meta-item">
								<div class="invite-meta-label">expires</div>
								<div class="invite-meta-value">${expiryInfo}</div>
							</div>
							<div class="invite-meta-item">
								<div class="invite-meta-label">link</div>
								<div class="invite-meta-value invite-url">${escapeHtml(invite.inviteUrl)}</div>
							</div>
						</div>
						<div class="invite-extra">
							${noteInfo}
							${messageInfo}
							${roleInfo}
							${usedByInfo}
						</div>
					</div>
					<div class="invite-actions-btns">
						<button class="btn-copy" data-invite-id="${invite.id}" data-invite-url="${escapeHtml(invite.inviteUrl)}" ${isActive ? "" : "disabled"}>copy link</button>
						<button class="btn-edit" data-action="edit" data-invite-id="${invite.id}" ${isActive ? "" : "disabled"}>edit</button>
						<button class="btn-delete" data-action="delete" data-invite-id="${invite.id}">delete</button>
					</div>
				</div>
			`;
				},
			)
			.join("");

		// Add copy button handlers
		const copyButtons = invitesList.querySelectorAll(".btn-copy");
		copyButtons.forEach((btn) => {
			btn.addEventListener("click", async (e) => {
				const button = e.target as HTMLButtonElement;
				const url = button.dataset.inviteUrl;
				if (!url) return;

				try {
					await navigator.clipboard.writeText(url);
					const originalText = button.textContent;
					button.textContent = "copied!";
					setTimeout(() => {
						button.textContent = originalText;
					}, 2000);
				} catch (error) {
					console.error("Failed to copy:", error);
				}
			});
		});
	} catch (error) {
		console.error("Failed to load invites:", error);
		invitesList.innerHTML = '<div class="error">Failed to load invites</div>';
	}
}

// Event delegation for edit/delete invite buttons
invitesList.addEventListener("click", (e) => {
	const target = e.target as HTMLElement;
	const actionEl = target.closest("[data-action]") as HTMLElement;
	if (!actionEl) return;

	const action = actionEl.dataset.action;
	const inviteId = Number(actionEl.dataset.inviteId);
	if (!inviteId) return;

	if (action === "edit") {
		window.editInvite(inviteId);
	} else if (action === "delete") {
		window.deleteInvite(inviteId, e);
	}
});

checkAuth();

createInviteBtn.addEventListener("click", createInvite);

// Close modals on escape key
document.addEventListener("keydown", (e) => {
	if (e.key === "Escape") {
		closeCreateInviteModal();
		window.closeEditInviteModal();
	}
});

// Close modals on outside click
document.getElementById("createInviteModal")?.addEventListener("click", (e) => {
	if (e.target === e.currentTarget) {
		closeCreateInviteModal();
	}
});

document.getElementById("editInviteModal")?.addEventListener("click", (e) => {
	if (e.target === e.currentTarget) {
		window.closeEditInviteModal();
	}
});

let currentEditInviteId: number | null = null;

// Make editInvite globally available for onclick handler
window.editInvite = async (inviteId: number) => {
	try {
		const response = await fetch("/api/invites", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error("Failed to load invite");
		}

		const data = await response.json();
		const invite = data.invites.find(
			(inv: { id: number }) => inv.id === inviteId,
		);

		if (!invite) {
			throw new Error("Invite not found");
		}

		currentEditInviteId = inviteId;

		// Populate form
		(document.getElementById("editMaxUses") as HTMLInputElement).value = String(
			invite.maxUses,
		);
		(document.getElementById("editInviteNote") as HTMLTextAreaElement).value =
			invite.note || "";
		(
			document.getElementById("editInviteMessage") as HTMLTextAreaElement
		).value = invite.message || "";

		// Handle expiration date
		const expiresAtInput = document.getElementById(
			"editExpiresAt",
		) as HTMLInputElement;
		if (invite.expiresAt) {
			const date = new Date(invite.expiresAt * 1000);
			const localDatetime = new Date(
				date.getTime() - date.getTimezoneOffset() * 60000,
			)
				.toISOString()
				.slice(0, 16);
			expiresAtInput.value = localDatetime;
		} else {
			expiresAtInput.value = "";
		}

		// Show modal
		const modal = document.getElementById("editInviteModal");
		if (modal) {
			modal.style.display = "flex";
		}
	} catch (error) {
		console.error("Failed to load invite:", error);
		alert("Failed to load invite");
	}
};

window.submitEditInvite = async () => {
	if (currentEditInviteId === null) return;

	const maxUsesInput = document.getElementById(
		"editMaxUses",
	) as HTMLInputElement;
	const expiresAtInput = document.getElementById(
		"editExpiresAt",
	) as HTMLInputElement;
	const noteInput = document.getElementById(
		"editInviteNote",
	) as HTMLTextAreaElement;
	const messageInput = document.getElementById(
		"editInviteMessage",
	) as HTMLTextAreaElement;
	const submitBtn = document.getElementById(
		"submitEditInviteBtn",
	) as HTMLButtonElement;

	const maxUses = maxUsesInput.value ? parseInt(maxUsesInput.value, 10) : null;
	const expiresAt = expiresAtInput.value
		? Math.floor(new Date(expiresAtInput.value).getTime() / 1000)
		: null;
	const note = noteInput.value.trim() || null;
	const message = messageInput.value.trim() || null;

	submitBtn.disabled = true;
	submitBtn.textContent = "saving...";

	try {
		const response = await fetch(`/api/invites/${currentEditInviteId}`, {
			method: "PATCH",
			headers: {
				Authorization: `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ maxUses, expiresAt, note, message }),
		});

		if (!response.ok) {
			throw new Error("Failed to update invite");
		}

		await loadInvites();
		window.closeEditInviteModal();
	} catch (error) {
		console.error("Failed to update invite:", error);
		alert("Failed to update invite");
	} finally {
		submitBtn.disabled = false;
		submitBtn.textContent = "save changes";
	}
};

window.closeEditInviteModal = () => {
	const modal = document.getElementById("editInviteModal");
	if (modal) {
		modal.style.display = "none";
		currentEditInviteId = null;
		(document.getElementById("editMaxUses") as HTMLInputElement).value = "";
		(document.getElementById("editExpiresAt") as HTMLInputElement).value = "";
		(document.getElementById("editInviteNote") as HTMLTextAreaElement).value =
			"";
		(
			document.getElementById("editInviteMessage") as HTMLTextAreaElement
		).value = "";
	}
};

window.deleteInvite = async (inviteId: number, event?: Event) => {
	const btn = event?.target as HTMLButtonElement | undefined;

	// Double-click confirmation pattern
	if (btn?.dataset.confirmState === "pending") {
		// Second click - execute delete
		delete btn.dataset.confirmState;
		btn.textContent = "deleting...";
		btn.disabled = true;

		try {
			const response = await fetch(`/api/invites/${inviteId}`, {
				method: "DELETE",
				headers: {
					Authorization: `Bearer ${token}`,
				},
			});

			if (!response.ok) {
				throw new Error("Failed to delete invite");
			}

			await loadInvites();
		} catch (error) {
			console.error("Failed to delete invite:", error);
			alert("Failed to delete invite");
			btn.textContent = "delete";
			btn.disabled = false;
		}
	} else {
		// First click - set pending state
		if (btn) {
			const originalText = btn.textContent;
			btn.dataset.confirmState = "pending";
			btn.textContent = "you sure?";

			// Reset after 3 seconds if not confirmed
			setTimeout(() => {
				if (btn.dataset.confirmState === "pending") {
					delete btn.dataset.confirmState;
					btn.textContent = originalText;
				}
			}, 3000);
		}
	}
};
