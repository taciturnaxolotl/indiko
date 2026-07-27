import { startRegistration } from "@simplewebauthn/browser";
import "./ds";
import type IButton from "./ds/button";
import type IToast from "./ds/toast";

const token = localStorage.getItem("indiko_session");

let welcome!: HTMLElement;
let subtitle!: HTMLElement;
let recentApps!: HTMLElement;
let passkeysList!: HTMLElement;
let addPasskeyBtn!: IButton;
let toast!: IToast;
let profileForm!: HTMLFormElement;
let avatarPreview!: HTMLElement;
let usernameInput!: HTMLInputElement;
let nameInput!: HTMLInputElement;
let emailInput!: HTMLInputElement;
let photoInput!: HTMLInputElement;
let urlInput!: HTMLInputElement;
let saveBtn!: HTMLButtonElement;
let deleteAccountBtn!: HTMLButtonElement;
let addPasskeyNativeBtn!: HTMLButtonElement;
let dangerZone!: HTMLElement;

let isAdmin = false;

if (!token) {
	window.location.href = "/login";
}

function $(id: string): HTMLElement {
	const el = document.getElementById(id);
	if (!el) {
		console.error(
			`[indiko] #${id} missing from page. ` +
				`readyState=${document.readyState} url=${location.href} ` +
				`html-has-id=${document.documentElement.innerHTML.includes(`id="${id}"`)}`,
		);
		throw new Error(`#${id} missing from page`);
	}
	return el;
}

function init() {
	welcome = $("welcome");
	subtitle = $("subtitle");
	recentApps = $("recentApps");
	passkeysList = $("passkeysList");
	addPasskeyBtn = $("addPasskeyBtn") as IButton;
	toast = $("toast") as unknown as IToast;
	profileForm = $("profileForm") as HTMLFormElement;
	avatarPreview = $("avatarPreview");
	usernameInput = $("username") as HTMLInputElement;
	nameInput = $("name") as HTMLInputElement;
	emailInput = $("email") as HTMLInputElement;
	photoInput = $("photo") as HTMLInputElement;
	urlInput = $("url") as HTMLInputElement;
	saveBtn = $("saveBtn").querySelector("button") as HTMLButtonElement;
	deleteAccountBtn = $("deleteAccountBtn").querySelector(
		"button",
	) as HTMLButtonElement;
	addPasskeyNativeBtn = $("addPasskeyBtn").querySelector(
		"button",
	) as HTMLButtonElement;
	dangerZone = $("dangerZone");

	profileForm.addEventListener("submit", onProfileSubmit);
	deleteAccountBtn.addEventListener("click", onDeleteAccount);
	passkeysList.addEventListener(
		"rename",
		onPasskeyRename as unknown as EventListener,
	);
	passkeysList.addEventListener(
		"remove",
		onPasskeyRemove as unknown as EventListener,
	);
	addPasskeyBtn.addEventListener("click", onAddPasskey);

	checkAuth();
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
	toast.show(message, type);
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

		// Load profile and apps
		loadProfile();
		loadRecentApps();
		loadPasskeys();
	} catch (error) {
		console.error("Auth check failed:", error);
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
async function onProfileSubmit(e: SubmitEvent) {
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
}

// Delete account handler
async function onDeleteAccount() {
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
}

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

		passkeysList.replaceChildren();
		for (const passkey of passkeys) {
			const row = document.createElement("i-passkey-row");
			row.setAttribute("pid", String(passkey.id));
			row.setAttribute("name", passkey.name);
			row.setAttribute("created", String(passkey.created_at));
			passkeysList.appendChild(row);
		}
	} catch (error) {
		console.error("Failed to load passkeys:", error);
		passkeysList.innerHTML = '<div class="empty">Failed to load passkeys</div>';
	}
}

// Component events bubble up from <i-passkey-row>
async function onPasskeyRename(e: CustomEvent<{ id: string; name: string }>) {
	const { id, name } = e.detail;
	if (!name.trim()) {
		showToast("Passkey name cannot be empty", "error");
		return;
	}

	try {
		const response = await fetch(`/api/passkeys/${id}`, {
			method: "PATCH",
			headers: {
				Authorization: `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ name }),
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || "Failed to rename passkey");
		}

		showToast("Passkey renamed successfully!", "success");
	} catch (error) {
		showToast((error as Error).message || "Failed to rename passkey", "error");
		loadPasskeys();
	}
}

async function onPasskeyRemove(e: CustomEvent<{ id: string }>) {
	const { id } = e.detail;

	if (
		!confirm(
			"Are you sure you want to delete this passkey? You will no longer be able to use it to sign in.",
		)
	) {
		return;
	}

	try {
		const response = await fetch(`/api/passkeys/${id}`, {
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

// Passkey naming modal — returns a promise that resolves with the name (or empty string on cancel)
function promptPasskeyName(): Promise<string> {
	return new Promise((resolve) => {
		const modal = document.getElementById("passkeyNameModal") as HTMLElement;
		const input = document.getElementById("passkeyName") as HTMLInputElement;
		const confirmBtn = document.getElementById(
			"passkeyNameConfirm",
		) as HTMLButtonElement;
		const cancelBtn = document.getElementById(
			"passkeyNameCancel",
		) as HTMLButtonElement;

		input.value = "";
		modal.style.display = "flex";
		input.focus();

		function cleanup() {
			modal.style.display = "none";
			confirmBtn.removeEventListener("click", onConfirm);
			cancelBtn.removeEventListener("click", onCancel);
			input.removeEventListener("keydown", onKeydown);
		}

		function onConfirm() {
			const val = input.value.trim();
			cleanup();
			resolve(val);
		}

		function onCancel() {
			cleanup();
			resolve("");
		}

		function onKeydown(e: KeyboardEvent) {
			if (e.key === "Enter") onConfirm();
			if (e.key === "Escape") onCancel();
		}

		confirmBtn.addEventListener("click", onConfirm);
		cancelBtn.addEventListener("click", onCancel);
		input.addEventListener("keydown", onKeydown);
	});
}

// Add passkey button handler
async function onAddPasskey() {
	addPasskeyNativeBtn.disabled = true;
	addPasskeyNativeBtn.textContent = "preparing...";

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

		addPasskeyNativeBtn.textContent = "create your passkey...";

		// Start registration
		const regResponse = await startRegistration(options);

		addPasskeyNativeBtn.textContent = "verifying...";

		// Ask for a name via modal
		const name = await promptPasskeyName();

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
		addPasskeyNativeBtn.disabled = false;
		addPasskeyNativeBtn.textContent = "add new passkey";
	}
}

if (document.readyState === "complete") {
	init();
} else {
	document.addEventListener("DOMContentLoaded", init);
}
