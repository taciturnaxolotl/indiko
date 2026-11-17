import "./ds";
import { apiFetch } from "./api";
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
const invitesList = document.getElementById("invitesList") as HTMLElement;
const createInviteBtn = document.getElementById(
	"createInviteBtn",
) as HTMLButtonElement;

// Check auth and display user
async function checkAuth() {
	try {
		const response = await apiFetch("/api/hello", {});

		if (response.status === 401 || response.status === 403) {
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
		await loadResourcesForInvite();
	}
}

interface ResourceOption {
	id: number;
	name: string;
	availableRoles: string[] | null;
}

async function loadResourcesForInvite() {
	const container = document.getElementById("appRolesContainer");
	if (!container) return;
	const response = await apiFetch("/api/admin/resources", {});
	if (!response.ok) {
		container.innerHTML = '<div class="error">Failed to load resources</div>';
		return;
	}
	const { resources } = (await response.json()) as {
		resources: ResourceOption[];
	};
	if (resources.length === 0) {
		container.innerHTML =
			'<p style="color: var(--old-rose); font-size: 0.875rem;">No resources yet. Register one on the <a href="/admin/resources" style="color: inherit;">resources page</a> to hand out roles with invites.</p>';
		return;
	}
	container.innerHTML = resources
		.map((r) => {
			const field = r.availableRoles
				? `<select class="role-select" data-resource-id="${r.id}"><option value="">no role</option>${r.availableRoles
						.map(
							(role) =>
								`<option value="${escapeHtml(role)}">${escapeHtml(role)}</option>`,
						)
						.join("")}</select>`
				: `<input class="role-input-custom" data-resource-id="${r.id}" placeholder="no role">`;
			return `<div class="app-role-item"><label>${escapeHtml(r.name)}</label>${field}</div>`;
		})
		.join("");
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

	const resourceRoles = Array.from(
		document.querySelectorAll<HTMLInputElement | HTMLSelectElement>(
			"#appRolesContainer [data-resource-id]",
		),
	)
		.filter((field) => field.value.trim())
		.map((field) => ({
			resourceId: Number(field.dataset.resourceId),
			role: field.value.trim(),
		}));

	submitBtn.disabled = true;
	submitBtn.textContent = "creating...";

	try {
		const response = await apiFetch("/api/invites/create", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				maxUses,
				expiresAt,
				note,
				message,
				resourceRoles,
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
		for (const field of document.querySelectorAll<
			HTMLInputElement | HTMLSelectElement
		>("#appRolesContainer [data-resource-id]")) {
			field.value = "";
		}
	}
}

// Expose functions to global scope for HTML onclick handlers
window.submitCreateInvite = submitCreateInvite;
window.closeCreateInviteModal = closeCreateInviteModal;

async function loadInvites() {
	try {
		const response = await apiFetch("/api/invites", {});

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
					resourceRoles: Array<{ name: string; role: string }>;
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
						invite.resourceRoles.length > 0
							? `<div class="invite-meta-item">
							<div class="invite-meta-label">roles</div>
							<div class="invite-roles">${invite.resourceRoles
								.map(
									(r) =>
										`<span class="invite-role">${escapeHtml(r.name)} • ${escapeHtml(r.role)}</span>`,
								)
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
		const response = await apiFetch("/api/invites", {});

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
		const response = await apiFetch(`/api/invites/${currentEditInviteId}`, {
			method: "PATCH",
			headers: {
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
			const response = await apiFetch(`/api/invites/${inviteId}`, {
				method: "DELETE",
				headers: {},
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
