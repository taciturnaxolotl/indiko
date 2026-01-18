import { startRegistration } from "@simplewebauthn/browser";

const token = localStorage.getItem("indiko_session");
const footer = document.getElementById("footer") as HTMLElement;
const welcome = document.getElementById("welcome") as HTMLElement;
const subtitle = document.getElementById("subtitle") as HTMLElement;
const recentApps = document.getElementById("recentApps") as HTMLElement;
const passkeysList = document.getElementById("passkeysList") as HTMLElement;
const addPasskeyBtn = document.getElementById(
	"addPasskeyBtn",
) as HTMLButtonElement;
const toast = document.getElementById("toast") as HTMLElement;

// Profile form elements
const profileForm = document.getElementById("profileForm") as HTMLFormElement;
const avatarPreview = document.getElementById("avatarPreview") as HTMLElement;
const usernameInput = document.getElementById("username") as HTMLInputElement;
const nameInput = document.getElementById("name") as HTMLInputElement;
const emailInput = document.getElementById("email") as HTMLInputElement;
const photoInput = document.getElementById("photo") as HTMLInputElement;
const urlInput = document.getElementById("url") as HTMLInputElement;
const saveBtn = document.getElementById("saveBtn") as HTMLButtonElement;
const deleteAccountBtn = document.getElementById(
	"deleteAccountBtn",
) as HTMLButtonElement;
const dangerZone = document.getElementById("dangerZone") as HTMLElement;

let isAdmin = false;

if (!token) {
	window.location.href = "/login";
}

interface App {
	clientId: string;
	name: string;
	scopes: string[];
	grantedAt: number;
	lastUsed: number;
}

interface Profile {
	username: string;
	name: string;
	email: string | null;
	photo: string | null;
	url: string | null;
	isAdmin?: boolean;
}

interface Passkey {
	id: number;
	name: string;
	created_at: number;
}

function showToast(message: string, type: "success" | "error" = "success") {
	toast.textContent = message;
	toast.className = `toast ${type} show`;

	setTimeout(() => {
		toast.classList.remove("show");
	}, 3000);
}

function updateAvatarPreview(photo: string | null, username: string) {
	if (photo) {
		avatarPreview.innerHTML = `<img src="${photo}" alt="${username}" style="width: 100%; height: 100%; object-fit: cover; border-radius: 50%;" />`;
	} else {
		const initials = username.substring(0, 2).toUpperCase();
		avatarPreview.textContent = initials;
	}
}

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

		// Update welcome message
		welcome.textContent = `welcome, ${data.username}`;
		subtitle.textContent = "your identity dashboard";

		// Build footer with conditional admin link
		const adminLink = data.isAdmin ? ' • <a href="/admin">admin</a>' : "";
		footer.innerHTML = `signed in as <strong><a href="/u/${data.username}">${data.username}</a></strong> • <a href="/apps">apps</a> • <a href="/docs">docs</a>${adminLink} • <a href="/login" id="logoutLink">sign out</a>`;

		// Handle logout
		document
			.getElementById("logoutLink")
			?.addEventListener("click", async (e) => {
				e.preventDefault();
				try {
					await fetch("/auth/logout", {
						method: "POST",
						headers: {
							Authorization: `Bearer ${token}`,
						},
					});
				} catch {
					// Ignore logout errors
				}
				localStorage.removeItem("indiko_session");
				window.location.href = "/login";
			});

		// Load profile and apps
		loadProfile();
		loadRecentApps();
		loadPasskeys();
	} catch (error) {
		console.error("Auth check failed:", error);
		footer.textContent = "error loading user info";
	}
}

async function loadProfile() {
	try {
		const response = await fetch("/api/profile", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error("Failed to load profile");
		}

		const profile = (await response.json()) as Profile;

		// Track admin status to hide delete button for admins
		isAdmin = profile.isAdmin || false;
		if (!isAdmin) {
			dangerZone.style.display = "block";
		}

		// Populate form
		usernameInput.value = profile.username;
		nameInput.value = profile.name || "";
		emailInput.value = profile.email || "";
		photoInput.value = profile.photo || "";
		urlInput.value = profile.url || "";

		updateAvatarPreview(profile.photo, profile.username);

		// Update avatar preview when photo URL changes
		photoInput.addEventListener("input", () => {
			updateAvatarPreview(photoInput.value || null, profile.username);
		});
	} catch (error) {
		console.error("Failed to load profile:", error);
		showToast("Failed to load profile", "error");
	}
}

async function loadRecentApps() {
	try {
		const response = await fetch("/api/apps", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error("Failed to load apps");
		}

		const data = await response.json();
		const apps = data.apps as App[];

		if (apps.length === 0) {
			recentApps.innerHTML = '<div class="empty">No authorized apps yet</div>';
			return;
		}

		// Show top 7 most recent
		const recent = apps.slice(0, 7);

		recentApps.innerHTML = recent
			.map((app) => {
				const lastUsedDate = new Date(app.lastUsed * 1000).toLocaleDateString();

				return `
				<div class="app-item">
					<div class="app-name">${app.name}</div>
					<div class="app-date">${lastUsedDate}</div>
				</div>
			`;
			})
			.join("");

		if (apps.length > 7) {
			recentApps.innerHTML +=
				'<a href="/apps" class="view-all">view all apps →</a>';
		}
	} catch (error) {
		console.error("Failed to load apps:", error);
		recentApps.innerHTML = '<div class="empty">Failed to load apps</div>';
	}
}

// Profile form submission
profileForm.addEventListener("submit", async (e) => {
	e.preventDefault();

	saveBtn.disabled = true;
	saveBtn.textContent = "saving...";

	try {
		const response = await fetch("/api/profile", {
			method: "PUT",
			headers: {
				Authorization: `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				name: nameInput.value,
				email: emailInput.value || null,
				photo: photoInput.value || null,
				url: urlInput.value || null,
			}),
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || "Failed to update profile");
		}

		showToast("Profile updated successfully!", "success");
	} catch (error) {
		showToast((error as Error).message || "Failed to update profile", "error");
	} finally {
		saveBtn.disabled = false;
		saveBtn.textContent = "save changes";
	}
});

// Delete account handler
deleteAccountBtn.addEventListener("click", async () => {
	const confirmMessage =
		"Are you absolutely sure you want to delete your account?\n\n" +
		"This will permanently delete:\n" +
		"• Your profile and credentials\n" +
		"• All authorized apps\n" +
		"• All active sessions\n\n" +
		"This action CANNOT be undone.\n\n" +
		'Type "DELETE" to confirm:';

	const confirmation = prompt(confirmMessage);

	if (confirmation !== "DELETE") {
		if (confirmation !== null) {
			showToast(
				'Account deletion cancelled. You must type "DELETE" exactly.',
				"error",
			);
		}
		return;
	}

	deleteAccountBtn.disabled = true;
	deleteAccountBtn.textContent = "deleting...";

	try {
		const response = await fetch("/api/profile", {
			method: "DELETE",
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || "Failed to delete account");
		}

		// Clear session and redirect
		localStorage.removeItem("indiko_session");
		showToast("Account deleted successfully. Redirecting...", "success");
		setTimeout(() => {
			window.location.href = "/login";
		}, 2000);
	} catch (error) {
		showToast((error as Error).message || "Failed to delete account", "error");
		deleteAccountBtn.disabled = false;
		deleteAccountBtn.textContent = "delete my account";
	}
});

async function loadPasskeys() {
	try {
		const response = await fetch("/api/passkeys", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error("Failed to load passkeys");
		}

		const data = await response.json();
		const passkeys = data.passkeys as Passkey[];

		if (passkeys.length === 0) {
			passkeysList.innerHTML =
				'<div class="empty">No passkeys registered</div>';
			return;
		}

		passkeysList.innerHTML = passkeys
			.map((passkey) => {
				const createdDate = new Date(
					passkey.created_at * 1000,
				).toLocaleDateString();

				return `
				<div class="passkey-item" data-passkey-id="${passkey.id}">
					<div class="passkey-info">
						<div class="passkey-name">${passkey.name}</div>
						<div class="passkey-date">added ${createdDate}</div>
					</div>
					<div class="passkey-actions">
						<button type="button" class="rename-passkey-btn" data-passkey-id="${passkey.id}">rename</button>
						${passkeys.length > 1 ? `<button type="button" class="delete-passkey-btn" data-passkey-id="${passkey.id}">delete</button>` : ""}
					</div>
				</div>
			`;
			})
			.join("");

		// Add event listeners for rename buttons
		document.querySelectorAll(".rename-passkey-btn").forEach((btn) => {
			btn.addEventListener("click", () => {
				const passkeyId = btn.getAttribute("data-passkey-id");
				showRenameForm(Number(passkeyId));
			});
		});

		// Add event listeners for delete buttons
		document.querySelectorAll(".delete-passkey-btn").forEach((btn) => {
			btn.addEventListener("click", async () => {
				const passkeyId = btn.getAttribute("data-passkey-id");
				await deletePasskeyHandler(Number(passkeyId));
			});
		});
	} catch (error) {
		console.error("Failed to load passkeys:", error);
		passkeysList.innerHTML = '<div class="empty">Failed to load passkeys</div>';
	}
}

function showRenameForm(passkeyId: number) {
	const passkeyItem = document.querySelector(
		`[data-passkey-id="${passkeyId}"]`,
	);
	if (!passkeyItem) return;

	const infoDiv = passkeyItem.querySelector(".passkey-info");
	const nameDiv = infoDiv?.querySelector(".passkey-name");
	if (!nameDiv) return;

	const currentName = nameDiv.textContent || "";

	// Replace the info div with a rename form
	if (infoDiv) {
		infoDiv.innerHTML = `
			<div class="rename-form">
				<input type="text" value="${currentName}" class="rename-input" data-passkey-id="${passkeyId}" />
				<button type="button" class="save-rename-btn" data-passkey-id="${passkeyId}">save</button>
				<button type="button" class="cancel-rename-btn" data-passkey-id="${passkeyId}">cancel</button>
			</div>
		`;

		const input = infoDiv.querySelector(".rename-input") as HTMLInputElement;
		input.focus();
		input.select();

		// Save button
		infoDiv
			.querySelector(".save-rename-btn")
			?.addEventListener("click", async () => {
				await renamePasskeyHandler(passkeyId, input.value);
			});

		// Cancel button
		infoDiv
			.querySelector(".cancel-rename-btn")
			?.addEventListener("click", () => {
				loadPasskeys();
			});

		// Enter to save
		input.addEventListener("keypress", async (e) => {
			if (e.key === "Enter") {
				await renamePasskeyHandler(passkeyId, input.value);
			}
		});

		// Escape to cancel
		input.addEventListener("keydown", (e) => {
			if (e.key === "Escape") {
				loadPasskeys();
			}
		});
	}
}

async function renamePasskeyHandler(passkeyId: number, newName: string) {
	if (!newName.trim()) {
		showToast("Passkey name cannot be empty", "error");
		return;
	}

	try {
		const response = await fetch(`/api/passkeys/${passkeyId}`, {
			method: "PATCH",
			headers: {
				Authorization: `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ name: newName }),
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || "Failed to rename passkey");
		}

		showToast("Passkey renamed successfully!", "success");
		loadPasskeys();
	} catch (error) {
		showToast((error as Error).message || "Failed to rename passkey", "error");
	}
}

async function deletePasskeyHandler(passkeyId: number) {
	if (
		!confirm(
			"Are you sure you want to delete this passkey? You will no longer be able to use it to sign in.",
		)
	) {
		return;
	}

	try {
		const response = await fetch(`/api/passkeys/${passkeyId}`, {
			method: "DELETE",
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || "Failed to delete passkey");
		}

		showToast("Passkey deleted successfully!", "success");
		loadPasskeys();
	} catch (error) {
		showToast((error as Error).message || "Failed to delete passkey", "error");
	}
}

// Add passkey button handler
addPasskeyBtn.addEventListener("click", async () => {
	addPasskeyBtn.disabled = true;
	addPasskeyBtn.textContent = "preparing...";

	try {
		// Get registration options
		const optionsRes = await fetch("/api/passkeys/add/options", {
			method: "POST",
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (!optionsRes.ok) {
			const error = await optionsRes.json();
			throw new Error(error.error || "Failed to get passkey options");
		}

		const options = await optionsRes.json();

		addPasskeyBtn.textContent = "create your passkey...";

		// Start registration
		const regResponse = await startRegistration(options);

		addPasskeyBtn.textContent = "verifying...";

		// Ask for a name
		const name = prompt(
			"Give this passkey a name (e.g., 'iPhone', 'Work Laptop'):",
		);

		// Verify registration
		const verifyRes = await fetch("/api/passkeys/add/verify", {
			method: "POST",
			headers: {
				Authorization: `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				response: regResponse,
				challenge: options.challenge,
				name: name || undefined,
			}),
		});

		if (!verifyRes.ok) {
			const error = await verifyRes.json();
			throw new Error(error.error || "Failed to add passkey");
		}

		showToast("Passkey added successfully!", "success");
		loadPasskeys();
	} catch (error) {
		showToast((error as Error).message || "Failed to add passkey", "error");
	} finally {
		addPasskeyBtn.disabled = false;
		addPasskeyBtn.textContent = "add new passkey";
	}
});

checkAuth();
