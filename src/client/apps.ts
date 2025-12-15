const token = localStorage.getItem('indiko_session');
const appsList = document.getElementById('appsList') as HTMLElement;

if (!token) {
	window.location.href = '/login';
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
		const response = await fetch('/api/apps', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (response.status === 401) {
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
			return;
		}

		if (!response.ok) {
			throw new Error('Failed to load apps');
		}

		const data = await response.json();
		displayApps(data.apps);
	} catch (error) {
		console.error('Failed to load apps:', error);
		appsList.innerHTML = '<div class="error">Failed to load authorized apps</div>';
	}
}

function displayApps(apps: App[]) {
	if (apps.length === 0) {
		appsList.innerHTML = '<div class="empty">No authorized apps yet. Apps will appear here after you grant them access.</div>';
		return;
	}

	appsList.innerHTML = apps.map((app) => {
		const lastUsedDate = new Date(app.lastUsed * 1000).toLocaleDateString();
		const grantedDate = new Date(app.grantedAt * 1000).toLocaleDateString();
		
		return `
			<div class="app-card" data-client-id="${app.clientId}">
				<div class="app-header">
					<div>
						<div class="app-name">${app.name}</div>
						<div class="app-meta">Granted ${grantedDate} • Last used ${lastUsedDate}</div>
					</div>
					<button class="revoke-btn" onclick="revokeApp('${app.clientId}')">revoke</button>
				</div>
				<div class="scopes">
					<div class="scope-title">permissions</div>
					<div class="scope-list">
						${app.scopes.map(scope => `<span class="scope-badge">${scope}</span>`).join('')}
					</div>
				</div>
			</div>
		`;
	}).join('');
}

(window as any).revokeApp = async function(clientId: string) {
	if (!confirm('Are you sure you want to revoke access for this app? You will need to authorize it again next time.')) {
		return;
	}

	const card = document.querySelector(`[data-client-id="${clientId}"]`);
	const btn = card?.querySelector('.revoke-btn') as HTMLButtonElement;
	
	if (btn) {
		btn.disabled = true;
		btn.textContent = 'revoking...';
	}

	try {
		const response = await fetch(`/api/apps/${encodeURIComponent(clientId)}`, {
			method: 'DELETE',
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to revoke app');
		}

		// Remove from UI
		card?.remove();

		// Check if list is now empty
		const remaining = document.querySelectorAll('.app-card');
		if (remaining.length === 0) {
			appsList.innerHTML = '<div class="empty">No authorized apps yet. Apps will appear here after you grant them access.</div>';
		}
	} catch (error) {
		console.error('Failed to revoke app:', error);
		alert('Failed to revoke app access. Please try again.');
		if (btn) {
			btn.disabled = false;
			btn.textContent = 'revoke';
		}
	}
};

loadApps();
