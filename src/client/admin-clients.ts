const token = localStorage.getItem('indiko_session');
const footer = document.getElementById('footer') as HTMLElement;
const clientsList = document.getElementById('clientsList') as HTMLElement;
const createClientBtn = document.getElementById('createClientBtn') as HTMLButtonElement;
const clientModal = document.getElementById('clientModal') as HTMLElement;
const modalClose = document.getElementById('modalClose') as HTMLButtonElement;
const cancelBtn = document.getElementById('cancelBtn') as HTMLButtonElement;
const clientForm = document.getElementById('clientForm') as HTMLFormElement;
const modalTitle = document.getElementById('modalTitle') as HTMLElement;
const addRedirectUriBtn = document.getElementById('addRedirectUriBtn') as HTMLButtonElement;
const redirectUrisList = document.getElementById('redirectUrisList') as HTMLElement;
const toast = document.getElementById('toast') as HTMLElement;

function showToast(message: string, type: 'success' | 'error' = 'success') {
	toast.textContent = message;
	toast.className = `toast ${type} show`;
	
	setTimeout(() => {
		toast.classList.remove('show');
	}, 3000);
}

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

		loadClients();
	} catch (error) {
		console.error('Auth check failed:', error);
		footer.textContent = 'error loading user info';
		clientsList.innerHTML = '<div class="error">Failed to load clients</div>';
	}
}

interface Client {
	id: number;
	clientId: string;
	name: string;
	logoUrl: string | null;
	description: string | null;
	redirectUris: string[];
	isPreregistered: boolean;
	availableRoles: string[] | null;
	defaultRole: string | null;
	firstSeen: number;
	lastUsed: number;
}

interface ClientUser {
	username: string;
	name: string;
	scopes: string[];
	role: string | null;
	grantedAt: number;
	lastUsed: number;
}

interface AppPermission {
	username: string;
	name: string;
	scopes: string[];
	grantedAt: number;
	lastUsed: number;
}

async function loadClients() {
	try {
		const response = await fetch('/api/admin/clients', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load clients');
		}

		const data = await response.json();
		displayClients(data.clients);
	} catch (error) {
		console.error('Failed to load clients:', error);
		clientsList.innerHTML = '<div class="error">Failed to load clients</div>';
	}
}

function displayClients(clients: Client[]) {
	if (clients.length === 0) {
		clientsList.innerHTML = '<div class="empty">No OAuth clients registered yet.</div>';
		return;
	}

	clientsList.innerHTML = clients.map((client) => {
		const lastUsedDate = new Date(client.lastUsed * 1000).toLocaleDateString();
		const firstSeenDate = new Date(client.firstSeen * 1000).toLocaleDateString();
		
		return `
			<div class="client-card" data-client-id="${client.clientId}">
				<div class="client-header" onclick="toggleClient('${client.clientId}')">
					<div class="client-logo">
						${client.logoUrl 
							? `<img src="${client.logoUrl}" alt="${client.name}" />`
							: `<div class="client-logo-placeholder">🔐</div>`
						}
					</div>
					<div class="client-info">
						<div class="client-name">${client.name}</div>
						<div class="client-id">${client.clientId}</div>
						${client.description ? `<div class="client-description">${client.description}</div>` : ''}
						<div class="client-badges">
							<span class="badge ${client.isPreregistered ? 'badge-preregistered' : 'badge-auto'}">
								${client.isPreregistered ? 'pre-registered' : 'auto-registered'}
							</span>
							<span class="badge badge-auto">first seen ${firstSeenDate}</span>
							<span class="badge badge-auto">last used ${lastUsedDate}</span>
						</div>
					</div>
					<div class="client-actions" style="display: flex; gap: 0.5rem; align-items: center;">
						${client.isPreregistered ? `
							<button class="btn-edit" onclick="event.stopPropagation(); editClient('${client.clientId}')">edit</button>
							<button class="btn-delete" onclick="event.stopPropagation(); deleteClient('${client.clientId}', event)">delete</button>
						` : ''}
						<span class="expand-indicator">details <span class="arrow">▼</span></span>
					</div>
				</div>
				<div class="client-details" id="details-${encodeURIComponent(client.clientId)}">
					<div class="loading">loading details...</div>
				</div>
			</div>
		`;
	}).join('');
}

(window as any).toggleClient = async function(clientId: string) {
	const card = document.querySelector(`[data-client-id="${clientId}"]`) as HTMLElement;
	if (!card) return;

	const isExpanded = card.classList.contains('expanded');
	const arrow = card.querySelector('.arrow') as HTMLElement;
	
	if (isExpanded) {
		card.classList.remove('expanded');
		if (arrow) arrow.textContent = '▼';
		return;
	}

	card.classList.add('expanded');
	if (arrow) arrow.textContent = '▲';
	
	const detailsDiv = document.getElementById(`details-${encodeURIComponent(clientId)}`);
	if (!detailsDiv) return;

	if (detailsDiv.dataset.loaded === 'true') {
		return;
	}

	try {
		const response = await fetch(`/api/admin/clients/${encodeURIComponent(clientId)}`, {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load client details');
		}

		const data = await response.json();
		
		detailsDiv.innerHTML = `
			${data.client.isPreregistered ? `
				<div class="detail-section">
					<div class="detail-title">client secret</div>
					<div class="secret-section">
						<input type="password" value="••••••••••••••••••••••••" readonly style="background: rgba(0, 0, 0, 0.3); border: 1px solid var(--old-rose); color: var(--lavender); padding: 0.5rem; font-family: monospace; width: 100%; margin-bottom: 0.5rem;" id="secret-${encodeURIComponent(clientId)}" />
						<button class="btn-edit" onclick="event.stopPropagation(); regenerateSecret('${clientId}')">regenerate secret</button>
					</div>
				</div>
			` : ''}
			<div class="detail-section">
				<div class="detail-title">redirect uris</div>
				<div class="redirect-uris">
					${data.client.redirectUris.map((uri: string) => `<div class="redirect-uri">${uri}</div>`).join('')}
				</div>
			</div>
			<div class="detail-section">
				<div class="detail-title">authorized users (${data.users.length})</div>
				${data.users.length === 0 
					? '<div class="empty">No users have authorized this client yet</div>'
					: `<div class="users-list">
						${data.users.map((user: ClientUser) => {
							const grantedDate = new Date(user.grantedAt * 1000).toLocaleDateString();
							const lastUsedDate = new Date(user.lastUsed * 1000).toLocaleDateString();
							
							return `
								<div class="user-item">
									<div class="user-info">
										<div class="user-name"><a href="/u/${user.username}" onclick="event.stopPropagation();" style="color: var(--lavender); text-decoration: none;">${user.name}</a> (<a href="/u/${user.username}" onclick="event.stopPropagation();" style="color: var(--old-rose); text-decoration: none;">@${user.username}</a>)</div>
										${data.client.isPreregistered && data.client.availableRoles !== null ? `
											<div class="user-role-input">
												<label style="color: var(--old-rose); font-size: 0.75rem;">ROLE${data.client.availableRoles.length > 0 ? '' : ' (OPTIONAL)'}:</label>
												${data.client.availableRoles.length > 0 
													? `<select data-username="${user.username}" data-client-id="${clientId}" style="padding: 0.5rem; background: rgba(0, 0, 0, 0.3); border: 1px solid var(--old-rose); color: var(--lavender); font-family: inherit; font-size: 0.875rem;">
														<option value="">No role</option>
														${data.client.availableRoles.map((role: string) => `
															<option value="${role}" ${user.role === role ? 'selected' : ''}>${role}</option>
														`).join('')}
													</select>`
													: `<input type="text" value="${user.role || ''}" placeholder="e.g. admin, editor, viewer" data-username="${user.username}" data-client-id="${clientId}" />`
												}
												<button onclick="event.stopPropagation(); setUserRole('${clientId}', '${user.username}', this.previousElementSibling.value)">update</button>
											</div>
										` : ''}
										<div class="user-meta">
											Granted ${grantedDate} • Last used ${lastUsedDate} • Scopes: ${user.scopes.join(', ')}
										</div>
									</div>
									<button class="revoke-btn" onclick="event.stopPropagation(); revokeUserPermission('${clientId}', '${user.username}')">revoke</button>
								</div>
							`;
						}).join('')}
					</div>`
				}
			</div>
		`;
		
		detailsDiv.dataset.loaded = 'true';
	} catch (error) {
		console.error('Failed to load client details:', error);
		detailsDiv.innerHTML = '<div class="error">Failed to load details</div>';
	}
};

(window as any).setUserRole = async function(clientId: string, username: string, role: string) {
	try {
		const response = await fetch(`/api/admin/clients/${encodeURIComponent(clientId)}/users/${encodeURIComponent(username)}/role`, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${token}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ role: role || null }),
		});

		if (!response.ok) {
			throw new Error('Failed to set user role');
		}

		showToast('User role updated successfully');
	} catch (error) {
		console.error('Failed to set user role:', error);
		showToast('Failed to update user role. Please try again.', 'error');
	}
};

(window as any).editClient = async function(clientId: string) {
	try {
		const response = await fetch(`/api/admin/clients/${encodeURIComponent(clientId)}`, {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load client');
		}

		const data = await response.json();
		const client = data.client;

		modalTitle.textContent = 'Edit OAuth Client';
		(document.getElementById('editClientId') as HTMLInputElement).value = clientId;
		(document.getElementById('clientId') as HTMLInputElement).value = client.clientId;
		(document.getElementById('clientId') as HTMLInputElement).disabled = true;
		(document.getElementById('clientName') as HTMLInputElement).value = client.name || '';
		(document.getElementById('logoUrl') as HTMLInputElement).value = client.logoUrl || '';
		(document.getElementById('description') as HTMLTextAreaElement).value = client.description || '';
		(document.getElementById('availableRoles') as HTMLTextAreaElement).value = client.availableRoles ? client.availableRoles.join('\n') : '';
		(document.getElementById('defaultRole') as HTMLInputElement).value = client.defaultRole || '';

		redirectUrisList.innerHTML = client.redirectUris.map((uri: string) => `
			<div class="redirect-uri-item">
				<input type="url" class="form-input redirect-uri-input" value="${uri}" required />
				<button type="button" class="btn-remove" onclick="removeRedirectUri(this)">remove</button>
			</div>
		`).join('');

		clientModal.classList.add('active');
	} catch (error) {
		console.error('Failed to load client:', error);
		showToast('Failed to load client details', 'error');
	}
};

(window as any).deleteClient = async function(clientId: string, event?: Event) {
	const btn = event?.target as HTMLButtonElement | undefined;
	
	// Double-click confirmation pattern
	if (btn?.dataset.confirmState === 'pending') {
		// Second click - execute delete
		delete btn.dataset.confirmState;
		btn.disabled = true;
		btn.textContent = 'deleting...';
		
		try {
			const response = await fetch(`/api/admin/clients/${encodeURIComponent(clientId)}`, {
				method: 'DELETE',
				headers: {
					'Authorization': `Bearer ${token}`,
				},
			});

			if (!response.ok) {
				throw new Error('Failed to delete client');
			}

			await loadClients();
		} catch (error) {
			console.error('Failed to delete client:', error);
			showToast('Failed to delete client. Please try again.', 'error');
			btn.disabled = false;
			btn.textContent = 'delete';
		}
	} else {
		// First click - set pending state
		if (btn) {
			const originalText = btn.textContent;
			btn.dataset.confirmState = 'pending';
			btn.textContent = 'you sure?';
			
			// Reset after 3 seconds if not confirmed
			setTimeout(() => {
				if (btn.dataset.confirmState === 'pending') {
					delete btn.dataset.confirmState;
					btn.textContent = originalText;
				}
			}, 3000);
		}
	}
};

createClientBtn.addEventListener('click', () => {
	modalTitle.textContent = 'Create OAuth Client';
	clientForm.reset();
	(document.getElementById('editClientId') as HTMLInputElement).value = '';
	(document.getElementById('clientId') as HTMLInputElement).disabled = false;
	redirectUrisList.innerHTML = `
		<div class="redirect-uri-item">
			<input type="url" class="form-input redirect-uri-input" placeholder="https://example.com/auth/callback" required />
			<button type="button" class="btn-remove" onclick="removeRedirectUri(this)">remove</button>
		</div>
	`;
	clientModal.classList.add('active');
});

modalClose.addEventListener('click', () => {
	clientModal.classList.remove('active');
});

cancelBtn.addEventListener('click', () => {
	clientModal.classList.remove('active');
});

addRedirectUriBtn.addEventListener('click', () => {
	const newItem = document.createElement('div');
	newItem.className = 'redirect-uri-item';
	newItem.innerHTML = `
		<input type="url" class="form-input redirect-uri-input" placeholder="https://example.com/auth/callback" required />
		<button type="button" class="btn-remove" onclick="removeRedirectUri(this)">remove</button>
	`;
	redirectUrisList.appendChild(newItem);
});

(window as any).removeRedirectUri = function(btn: HTMLButtonElement) {
	const items = redirectUrisList.querySelectorAll('.redirect-uri-item');
	if (items.length > 1) {
		btn.parentElement?.remove();
	} else {
		showToast('At least one redirect URI is required', 'error');
	}
};

clientForm.addEventListener('submit', async (e) => {
	e.preventDefault();

	const editClientId = (document.getElementById('editClientId') as HTMLInputElement).value;
	const clientId = (document.getElementById('clientId') as HTMLInputElement).value;
	const name = (document.getElementById('clientName') as HTMLInputElement).value;
	const logoUrl = (document.getElementById('logoUrl') as HTMLInputElement).value;
	const description = (document.getElementById('description') as HTMLTextAreaElement).value;
	const availableRolesText = (document.getElementById('availableRoles') as HTMLTextAreaElement).value;
	const defaultRole = (document.getElementById('defaultRole') as HTMLInputElement).value;
	
	const redirectUriInputs = Array.from(redirectUrisList.querySelectorAll('.redirect-uri-input')) as HTMLInputElement[];
	const redirectUris = redirectUriInputs.map(input => input.value).filter(uri => uri.trim());

	// Parse available roles from textarea (one per line)
	const availableRoles = availableRolesText
		.split('\n')
		.map(r => r.trim())
		.filter(r => r);

	// Validate default role is in available roles
	if (defaultRole && availableRoles.length > 0 && !availableRoles.includes(defaultRole)) {
		showToast('Default role must be one of the available roles', 'error');
		return;
	}

	if (redirectUris.length === 0) {
		showToast('At least one redirect URI is required', 'error');
		return;
	}

	const isEdit = !!editClientId;
	const url = isEdit 
		? `/api/admin/clients/${encodeURIComponent(editClientId)}`
		: '/api/admin/clients';
	const method = isEdit ? 'PUT' : 'POST';

	try {
		const response = await fetch(url, {
			method,
			headers: {
				'Authorization': `Bearer ${token}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				clientId: isEdit ? undefined : clientId,
				name,
				logoUrl,
				description,
				redirectUris,
				availableRoles: availableRolesText.trim() ? availableRoles : null,
				defaultRole: defaultRole || undefined,
			}),
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || 'Failed to save client');
		}

		clientModal.classList.remove('active');
		
		// If creating a new client, show the secret in modal
		if (!isEdit) {
			const result = await response.json();
			if (result.client && result.client.clientSecret) {
				const secretModal = document.getElementById('secretModal') as HTMLElement;
				const generatedSecret = document.getElementById('generatedSecret') as HTMLElement;
				
				if (generatedSecret && secretModal) {
					generatedSecret.textContent = result.client.clientSecret;
					secretModal.classList.add('active');
				}
			}
		} else {
			showToast('Client updated successfully');
		}
		
		await loadClients();
	} catch (error) {
		console.error('Failed to save client:', error);
		showToast(`Failed to ${isEdit ? 'update' : 'create'} client: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
	}
});

(window as any).regenerateSecret = async function(clientId: string) {
	if (!confirm('Are you sure you want to regenerate the client secret? This will invalidate the old secret and any apps using it will need to be updated.')) {
		return;
	}

	try {
		const response = await fetch(`/api/admin/clients/${encodeURIComponent(clientId)}/secret`, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to regenerate secret');
		}

		const data = await response.json();
		
		// Show the secret in modal
		const secretModal = document.getElementById('secretModal') as HTMLElement;
		const generatedSecret = document.getElementById('generatedSecret') as HTMLElement;
		
		if (generatedSecret && secretModal) {
			generatedSecret.textContent = data.clientSecret;
			secretModal.classList.add('active');
		}
	} catch (error) {
		console.error('Failed to regenerate secret:', error);
		showToast('Failed to regenerate client secret. Please try again.', 'error');
	}
};

(window as any).revokeUserPermission = async function(clientId: string, username: string) {
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

		// Reload the client details
		const detailsDiv = document.getElementById(`details-${encodeURIComponent(clientId)}`);
		if (detailsDiv) {
			detailsDiv.dataset.loaded = 'false';
		}

		const card = document.querySelector(`[data-client-id="${clientId}"]`) as HTMLElement;
		if (card) {
			card.classList.remove('expanded');
		}

		await loadClients();
	} catch (error) {
		console.error('Failed to revoke permission:', error);
		showToast('Failed to revoke permission. Please try again.', 'error');
	}
};

// Secret modal handlers
const secretModal = document.getElementById('secretModal') as HTMLElement;
const secretModalClose = document.getElementById('secretModalClose') as HTMLButtonElement;
const copySecretBtn = document.getElementById('copySecretBtn') as HTMLButtonElement;

secretModalClose?.addEventListener('click', () => {
	secretModal?.classList.remove('active');
});

copySecretBtn?.addEventListener('click', async () => {
	const generatedSecret = document.getElementById('generatedSecret') as HTMLElement;
	if (generatedSecret) {
		try {
			await navigator.clipboard.writeText(generatedSecret.textContent || '');
			copySecretBtn.textContent = 'copied! ✓';
			setTimeout(() => {
				copySecretBtn.textContent = 'copy to clipboard';
			}, 2000);
		} catch (error) {
			console.error('Failed to copy:', error);
			showToast('Failed to copy to clipboard', 'error');
		}
	}
});

// Close modals on escape key
document.addEventListener('keydown', (e) => {
	if (e.key === 'Escape') {
		clientModal?.classList.remove('active');
		secretModal?.classList.remove('active');
	}
});

// Close modals on outside click
clientModal?.addEventListener('click', (e) => {
	if (e.target === clientModal) {
		clientModal.classList.remove('active');
	}
});

secretModal?.addEventListener('click', (e) => {
	if (e.target === secretModal) {
		secretModal.classList.remove('active');
	}
});

checkAuth();
