const token = localStorage.getItem('indiko_session');
const footer = document.getElementById('footer') as HTMLElement;
const appsList = document.getElementById('appsList') as HTMLElement;

async function checkAuth() {
	if (!token) {
		window.location.href = '/login';
		return;
	}

	try {
		const response = await fetch('/api/hello', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (response.status === 401) {
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
			return;
		}

		const data = await response.json();

		footer.innerHTML = `admin • signed in as <strong><a href="/u/${data.username}">${data.username}</a></strong> • <a href="/login" id="logoutLink">sign out</a>
		<div class="back-link"><a href="/">← back to dashboard</a></div>`;

		document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
			e.preventDefault();
			try {
				await fetch('/auth/logout', {
					method: 'POST',
					headers: {
						'Authorization': `Bearer ${token}`,
					},
				});
			} catch {
				// Ignore logout errors
			}
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
		});

		if (!data.isAdmin) {
			window.location.href = '/';
			return;
		}

		loadApps();
	} catch (error) {
		console.error('Auth check failed:', error);
		footer.textContent = 'error loading user info';
		appsList.innerHTML = '<div class="error">Failed to load apps</div>';
	}
}

interface App {
	clientId: string;
	name: string;
	firstSeen: number;
	lastUsed: number;
	userCount: number;
}

interface AppPermission {
	username: string;
	name: string;
	scopes: string[];
	grantedAt: number;
	lastUsed: number;
}

interface AppDetails {
	app: {
		clientId: string;
		name: string;
		firstSeen: number;
		lastUsed: number;
	};
	permissions: AppPermission[];
}

async function loadApps() {
	try {
		const response = await fetch('/api/admin/apps', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load apps');
		}

		const data = await response.json();
		displayApps(data.apps);
	} catch (error) {
		console.error('Failed to load apps:', error);
		appsList.innerHTML = '<div class="error">Failed to load apps</div>';
	}
}

function displayApps(apps: App[]) {
	if (apps.length === 0) {
		appsList.innerHTML = '<div class="empty">No apps registered yet. Apps will appear here after users grant them access.</div>';
		return;
	}

	appsList.innerHTML = apps.map((app) => {
		const lastUsedDate = new Date(app.lastUsed * 1000).toLocaleDateString();
		const firstSeenDate = new Date(app.firstSeen * 1000).toLocaleDateString();
		
		return `
			<div class="app-card" data-client-id="${app.clientId}" onclick="toggleApp('${app.clientId}')">
				<div class="app-header">
					<div class="app-info">
						<div class="app-name">${app.name}</div>
						<div class="app-meta">
							<span>First seen ${firstSeenDate}</span>
							<span>Last used ${lastUsedDate}</span>
						</div>
					</div>
					<div class="app-stats">
						<span class="stat-badge">${app.userCount} user${app.userCount !== 1 ? 's' : ''}</span>
						<span class="expand-indicator">details</span>
					</div>
				</div>
				<div class="app-details" id="details-${encodeURIComponent(app.clientId)}">
					<div class="loading">loading permissions...</div>
				</div>
			</div>
		`;
	}).join('');
}

(window as any).toggleApp = async function(clientId: string) {
	const card = document.querySelector(`[data-client-id="${clientId}"]`) as HTMLElement;
	if (!card) return;

	const isExpanded = card.classList.contains('expanded');
	
	if (isExpanded) {
		card.classList.remove('expanded');
		return;
	}

	card.classList.add('expanded');
	
	const detailsDiv = document.getElementById(`details-${encodeURIComponent(clientId)}`);
	if (!detailsDiv) return;

	if (detailsDiv.dataset.loaded === 'true') {
		return;
	}

	try {
		const response = await fetch(`/api/admin/apps/${encodeURIComponent(clientId)}`, {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load app details');
		}

		const data: AppDetails = await response.json();
		
		if (data.permissions.length === 0) {
			detailsDiv.innerHTML = '<div class="empty">No users have granted access to this app</div>';
		} else {
			detailsDiv.innerHTML = `
				<div class="permissions-list">
					${data.permissions.map((perm) => {
						const grantedDate = new Date(perm.grantedAt * 1000).toLocaleDateString();
						const lastUsedDate = new Date(perm.lastUsed * 1000).toLocaleDateString();
						
						return `
							<div class="permission-item">
								<div class="permission-user">
									<div class="permission-username">${perm.name} (@${perm.username})</div>
									<div class="permission-scopes">
										${perm.scopes.map(scope => `<span class="scope-badge">${scope}</span>`).join('')}
									</div>
									<div class="permission-meta">
										<span>Granted ${grantedDate}</span>
										<span>Last used ${lastUsedDate}</span>
									</div>
								</div>
								<button class="revoke-btn" onclick="event.stopPropagation(); revokePermission('${clientId}', '${perm.username}')">revoke</button>
							</div>
						`;
					}).join('')}
				</div>
			`;
		}
		
		detailsDiv.dataset.loaded = 'true';
	} catch (error) {
		console.error('Failed to load app details:', error);
		detailsDiv.innerHTML = '<div class="error">Failed to load permissions</div>';
	}
};

(window as any).revokePermission = async function(clientId: string, username: string) {
	if (!confirm(`Are you sure you want to revoke access for ${username}? They will need to authorize this app again.`)) {
		return;
	}

	try {
		const response = await fetch(`/api/admin/apps/${encodeURIComponent(clientId)}/users/${encodeURIComponent(username)}`, {
			method: 'DELETE',
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to revoke permission');
		}

		const detailsDiv = document.getElementById(`details-${encodeURIComponent(clientId)}`);
		if (detailsDiv) {
			detailsDiv.dataset.loaded = 'false';
		}

		const card = document.querySelector(`[data-client-id="${clientId}"]`) as HTMLElement;
		if (card) {
			card.classList.remove('expanded');
		}

		await loadApps();
	} catch (error) {
		console.error('Failed to revoke permission:', error);
		alert('Failed to revoke permission. Please try again.');
	}
};

checkAuth();
