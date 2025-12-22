const token = localStorage.getItem("indiko_session");
const appsList = document.getElementById("appsList") as HTMLElement;

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

async function loadApps() {
	try {
		const response = await fetch("/api/apps", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});

		if (response.status === 401 || response.status === 403) {
			localStorage.removeItem("indiko_session");
			window.location.href = "/login";
			return;
		}

		if (!response.ok) {
			throw new Error("Failed to load apps");
		}

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

			return `
			<div class="app-card" data-client-id="${app.clientId}">
				<div class="app-header">
					<div>
						<div class="app-name">${app.name}</div>
						<div class="app-meta">Granted ${grantedDate} • Last used ${lastUsedDate}</div>
					</div>
					<button class="revoke-btn" onclick="revokeApp('${app.clientId}', event)">revoke</button>
				</div>
				<div class="scopes">
					<div class="scope-title">permissions</div>
					<div class="scope-list">
						${app.scopes.map((scope) => `<span class="scope-badge">${scope}</span>`).join("")}
					</div>
				</div>
			</div>
		`;
		})
		.join("");
}

(window as any).revokeApp = async (clientId: string, event?: Event) => {
	const btn = event?.target as HTMLButtonElement | undefined;

	// Double-click confirmation pattern
	if (btn?.dataset.confirmState === "pending") {
		// Second click - execute revoke
		delete btn.dataset.confirmState;
		btn.disabled = true;
		btn.textContent = "revoking...";

		const card = document.querySelector(`[data-client-id="${clientId}"]`);

		try {
			const response = await fetch(
				`/api/apps/${encodeURIComponent(clientId)}`,
				{
					method: "DELETE",
					headers: {
						Authorization: `Bearer ${token}`,
					},
				},
			);

			if (!response.ok) {
				throw new Error("Failed to revoke app");
			}

			// Remove from UI
			card?.remove();

			// Check if list is now empty
			const remaining = document.querySelectorAll(".app-card");
			if (remaining.length === 0) {
				appsList.innerHTML =
					'<div class="empty">No authorized apps yet. Apps will appear here after you grant them access.</div>';
			}
		} catch (error) {
			console.error("Failed to revoke app:", error);
			alert("Failed to revoke app access. Please try again.");
			if (btn) {
				btn.disabled = false;
				btn.textContent = "revoke";
			}
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

loadApps();
