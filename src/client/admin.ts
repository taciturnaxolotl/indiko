const token = localStorage.getItem('indiko_session');
const footer = document.getElementById('footer') as HTMLElement;
const usersList = document.getElementById('usersList') as HTMLElement;
const invitesList = document.getElementById('invitesList') as HTMLElement;
const createInviteBtn = document.getElementById('createInviteBtn') as HTMLButtonElement;

// Check auth and display user
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

		// Handle logout
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

		// Check if admin
		if (!data.isAdmin) {
			window.location.href = '/';
			return;
		}

		// Load users if admin
		loadUsers();
		loadInvites();
	} catch (error) {
		console.error('Auth check failed:', error);
		footer.textContent = 'error loading user info';
		usersList.innerHTML = '<div class="error">Failed to load users</div>';
	}
}

async function createInvite() {
	// Show the create invite modal
	const modal = document.getElementById('createInviteModal');
	if (modal) {
		modal.style.display = 'flex';
		// Load apps for role assignment
		await loadAppsForInvite();
	}
}

async function loadAppsForInvite() {
	try {
		const response = await fetch('/api/admin/clients', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load apps');
		}

		const data = await response.json();
		const appRolesContainer = document.getElementById('appRolesContainer');
		
		if (!appRolesContainer) return;
		
		if (data.clients.length === 0) {
			appRolesContainer.innerHTML = '<p style="color: var(--old-rose); font-size: 0.875rem;">No pre-registered apps available</p>';
			return;
		}

		appRolesContainer.innerHTML = data.clients
			.filter((app: { isPreregistered: boolean }) => app.isPreregistered)
			.map((app: { id: number; clientId: string; roles: string[] }) => {
				const roleOptions = app.roles.length > 0
					? app.roles.map(role => `<option value="${role}">${role}</option>`).join('')
					: '<option value="" disabled>No roles defined yet</option>';
				
				return `
				<div class="app-role-item">
					<label>
						<input type="checkbox" name="appRole" value="${app.id}" data-client-id="${app.clientId}">
						<span>${app.clientId}</span>
					</label>
					<select class="role-select" data-app-id="${app.id}" disabled>
						<option value="">Select role...</option>
						${roleOptions}
						<option value="__custom__">Custom...</option>
					</select>
					<input type="text" class="role-input-custom" placeholder="Enter custom role" data-app-id="${app.id}" style="display: none;" disabled>
				</div>
			`}).join('');

		// Enable/disable role select and handle custom input
		const checkboxes = appRolesContainer.querySelectorAll('input[name="appRole"]');
		checkboxes.forEach((checkbox) => {
			checkbox.addEventListener('change', (e) => {
				const target = e.target as HTMLInputElement;
				const appId = target.value;
				const roleSelect = appRolesContainer.querySelector(`select.role-select[data-app-id="${appId}"]`) as HTMLSelectElement;
				const customInput = appRolesContainer.querySelector(`input.role-input-custom[data-app-id="${appId}"]`) as HTMLInputElement;
				
				if (roleSelect) {
					roleSelect.disabled = !target.checked;
					if (!target.checked) {
						roleSelect.value = '';
						if (customInput) {
							customInput.style.display = 'none';
							customInput.disabled = true;
							customInput.value = '';
						}
					}
				}
			});
		});

		// Handle custom role input toggle
		const roleSelects = appRolesContainer.querySelectorAll('select.role-select');
		roleSelects.forEach((select) => {
			select.addEventListener('change', (e) => {
				const target = e.target as HTMLSelectElement;
				const appId = target.dataset.appId;
				const customInput = appRolesContainer.querySelector(`input.role-input-custom[data-app-id="${appId}"]`) as HTMLInputElement;
				
				if (customInput) {
					if (target.value === '__custom__') {
						customInput.style.display = 'block';
						customInput.disabled = false;
						customInput.focus();
					} else {
						customInput.style.display = 'none';
						customInput.disabled = true;
						customInput.value = '';
					}
				}
			});
		});
	} catch (error) {
		console.error('Failed to load apps:', error);
	}
}

async function submitCreateInvite() {
	const maxUsesInput = document.getElementById('maxUses') as HTMLInputElement;
	const expiresInInput = document.getElementById('expiresIn') as HTMLInputElement;
	const noteInput = document.getElementById('inviteNote') as HTMLTextAreaElement;
	const submitBtn = document.getElementById('submitInviteBtn') as HTMLButtonElement;

	const maxUses = maxUsesInput.value ? parseInt(maxUsesInput.value) : 1;
	const expiresIn = expiresInInput.value ? parseInt(expiresInInput.value) : null;
	const note = noteInput.value.trim() || null;

	// Collect app roles
	const appRolesContainer = document.getElementById('appRolesContainer');
	const appRoles: Array<{ appId: number; role: string }> = [];
	
	if (appRolesContainer) {
		const checkedBoxes = appRolesContainer.querySelectorAll('input[name="appRole"]:checked');
		checkedBoxes.forEach((checkbox) => {
			const appId = parseInt((checkbox as HTMLInputElement).value, 10);
			const roleSelect = appRolesContainer.querySelector(`select.role-select[data-app-id="${appId}"]`) as HTMLSelectElement;
			const customInput = appRolesContainer.querySelector(`input.role-input-custom[data-app-id="${appId}"]`) as HTMLInputElement;
			
			let role = '';
			if (roleSelect && roleSelect.value) {
				if (roleSelect.value === '__custom__' && customInput && customInput.value.trim()) {
					role = customInput.value.trim();
				} else if (roleSelect.value !== '__custom__') {
					role = roleSelect.value;
				}
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
	submitBtn.textContent = 'creating...';

	try {
		const response = await fetch('/api/invites/create', {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${token}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				maxUses,
				expiresIn,
				note,
				appRoles: appRoles.length > 0 ? appRoles : undefined,
			}),
		});

		if (!response.ok) {
			throw new Error('Failed to create invite');
		}

		await loadInvites();
		closeCreateInviteModal();
	} catch (error) {
		console.error('Failed to create invite:', error);
		alert('Failed to create invite');
	} finally {
		submitBtn.disabled = false;
		submitBtn.textContent = 'create invite';
	}
}

function closeCreateInviteModal() {
	const modal = document.getElementById('createInviteModal');
	if (modal) {
		modal.style.display = 'none';
		// Reset form
		(document.getElementById('maxUses') as HTMLInputElement).value = '1';
		(document.getElementById('expiresIn') as HTMLInputElement).value = '';
		(document.getElementById('inviteNote') as HTMLTextAreaElement).value = '';
		const appRolesContainer = document.getElementById('appRolesContainer');
		if (appRolesContainer) {
			appRolesContainer.querySelectorAll('input').forEach((input) => {
				if (input.type === 'checkbox') {
					(input as HTMLInputElement).checked = false;
				} else {
					(input as HTMLInputElement).value = '';
					(input as HTMLInputElement).disabled = true;
				}
			});
		}
	}
}

// Expose functions to global scope for HTML onclick handlers
(window as any).submitCreateInvite = submitCreateInvite;
(window as any).closeCreateInviteModal = closeCreateInviteModal;

async function loadInvites() {
	try {
		const response = await fetch('/api/invites', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load invites');
		}

		const data = await response.json();
		
		if (data.invites.length === 0) {
			invitesList.innerHTML = '<div class="loading">No invites created yet</div>';
			return;
		}

		invitesList.innerHTML = data.invites.map((invite: {
			id: number;
			code: string;
			maxUses: number;
			currentUses: number;
			isExpired: boolean;
			isFullyUsed: boolean;
			expiresAt: number | null;
			note: string | null;
			createdAt: number;
			createdBy: string;
			inviteUrl: string;
			appRoles: Array<{ clientId: string; role: string }>;
			usedBy: Array<{ username: string; usedAt: number }>;
		}) => {
			const createdDate = new Date(invite.createdAt * 1000).toLocaleDateString();
			
			let status = `${invite.currentUses}/${invite.maxUses} used`;
			if (invite.isExpired) {
				status += ' (expired)';
			} else if (invite.isFullyUsed) {
				status += ' (fully used)';
			}
			
			const expiryInfo = invite.expiresAt 
				? `Expires: ${new Date(invite.expiresAt * 1000).toLocaleString()}` 
				: 'No expiry';
			
			const roleInfo = invite.appRoles.length > 0
				? `<div class="invite-roles">Roles: ${invite.appRoles.map(r => `${r.clientId}: ${r.role}`).join(', ')}</div>`
				: '';
			
			const usedByInfo = invite.usedBy.length > 0
				? `<div class="invite-used-by">Used by: ${invite.usedBy.map(u => `${u.username} (${new Date(u.usedAt * 1000).toLocaleDateString()})`).join(', ')}</div>`
				: '';
			
			const noteInfo = invite.note
				? `<div class="invite-note">Note: ${invite.note}</div>`
				: '';
			
			const isActive = !invite.isExpired && !invite.isFullyUsed;
			
			return `
				<div class="invite-item ${isActive ? '' : 'invite-inactive'}">
					<div>
						<div class="invite-code">${invite.code}</div>
						<div class="invite-meta">Created by ${invite.createdBy} on ${createdDate} • ${status}</div>
						<div class="invite-meta">${expiryInfo}</div>
						${noteInfo}
						${roleInfo}
						${usedByInfo}
						<div class="invite-url">${invite.inviteUrl}</div>
					</div>
					<div class="invite-actions-btns">
						<button class="copy-btn" onclick="navigator.clipboard.writeText('${invite.inviteUrl}')" ${isActive ? '' : 'disabled'}>copy link</button>
					</div>
				</div>
			`;
		}).join('');
	} catch (error) {
		console.error('Failed to load invites:', error);
		invitesList.innerHTML = '<div class="error">Failed to load invites</div>';
	}
}

async function loadUsers() {
	try {
		const response = await fetch('/api/users', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load users');
		}

		const data = await response.json();
		
		if (data.users.length === 0) {
			usersList.innerHTML = '<div class="loading">No users found</div>';
			return;
		}

		usersList.innerHTML = data.users.map((user: {
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
			const createdDate = new Date(user.createdAt * 1000).toLocaleDateString();
			const initials = user.username.substring(0, 2).toUpperCase();
			const avatarContent = user.photo 
				? `<img src="${user.photo}" alt="${user.username}" />`
				: initials;
			
			return `
				<div class="user-card">
					<div class="user-avatar">${avatarContent}</div>
					<div class="user-info">
						<div class="user-name">${user.username}</div>
						<div class="user-meta">
							<span class="user-meta-item">${user.credentialCount} passkey${user.credentialCount !== 1 ? 's' : ''}</span>
							<span class="user-meta-item">joined ${createdDate}</span>
							${user.email ? `<span class="user-meta-item">${user.email}</span>` : ''}
						</div>
					</div>
					<div class="user-badges">
						<span class="user-badge badge-status ${user.status}">${user.status}</span>
						<span class="user-badge badge-role">${user.role}</span>
					</div>
				</div>
			`;
		}).join('');
	} catch (error) {
		console.error('Failed to load users:', error);
		usersList.innerHTML = '<div class="error">Failed to load users</div>';
	}
}

checkAuth();

createInviteBtn.addEventListener('click', createInvite);
