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
	createInviteBtn.disabled = true;
	createInviteBtn.textContent = 'creating...';

	try {
		const response = await fetch('/api/invites/create', {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to create invite');
		}

		await loadInvites();
	} catch (error) {
		console.error('Failed to create invite:', error);
		alert('Failed to create invite');
	} finally {
		createInviteBtn.disabled = false;
		createInviteBtn.textContent = 'create invite link';
	}
}

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
			used: boolean;
			createdAt: number;
			usedAt: number | null;
			createdBy: string;
			usedBy: string | null;
			inviteUrl: string;
		}) => {
			const createdDate = new Date(invite.createdAt * 1000).toLocaleDateString();
			const status = invite.used 
				? `Used by ${invite.usedBy} on ${new Date(invite.usedAt! * 1000).toLocaleDateString()}`
				: 'Unused';
			
			return `
				<div class="invite-item">
					<div>
						<div class="invite-code">${invite.code}</div>
						<div class="invite-meta">Created by ${invite.createdBy} on ${createdDate} • ${status}</div>
						<div class="invite-url">${invite.inviteUrl}</div>
					</div>
					<div class="invite-actions-btns">
						<button class="copy-btn" onclick="navigator.clipboard.writeText('${invite.inviteUrl}')">copy link</button>
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
