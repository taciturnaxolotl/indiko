const token = localStorage.getItem("indiko_session");
const footer = document.getElementById("footer") as HTMLElement;
const welcome = document.getElementById("welcome") as HTMLElement;
const subtitle = document.getElementById("subtitle") as HTMLElement;
const recentApps = document.getElementById("recentApps") as HTMLElement;
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

checkAuth();
