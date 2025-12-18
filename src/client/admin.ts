const token = localStorage.getItem('indiko_session');
const footer = document.getElementById('footer') as HTMLElement;
const usersList = document.getElementById('usersList') as HTMLElement;
let currentUserId: number;

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

		if (response.status === 401 || response.status === 403) {
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
			return;
		}

		const data = await response.json();
		currentUserId = data.id;

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
	} catch (error) {
		console.error('Auth check failed:', error);
		footer.textContent = 'error loading user info';
		usersList.innerHTML = '<div class="error">Failed to load users</div>';
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
			const isSelf = user.id === currentUserId;
			
			return `
				<div class="user-card ${user.status === 'suspended' ? 'user-suspended' : ''}" data-user-id="${user.id}">
					<div class="user-avatar">${avatarContent}</div>
					<div class="user-info">
						<div class="user-name">${user.username}${isSelf ? ' (you)' : ''}</div>
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
					<div class="user-actions">
						${!isSelf ? (user.status === 'suspended' 
							? `<button class="btn-edit" data-action="enable" data-user-id="${user.id}">enable</button>` 
							: `<button class="btn-disable" data-action="disable" data-user-id="${user.id}">disable</button>`
						) : ''}
						${!isSelf ? `<button class="btn-delete" data-action="delete" data-user-id="${user.id}">delete</button>` : ''}
					</div>
				</div>
			`;
		}).join('');

		// Add event listeners for action buttons
		document.querySelectorAll('button[data-action]').forEach(btn => {
			btn.addEventListener('click', handleUserAction);
		});
	} catch (error) {
		console.error('Failed to load users:', error);
		usersList.innerHTML = '<div class="error">Failed to load users</div>';
	}
}

async function handleUserAction(e: Event) {
	const btn = e.target as HTMLButtonElement;
	const action = btn.dataset.action;
	const userId = btn.dataset.userId;
	
	if (!userId || !action) return;

	// Check if already in confirmation state
	if (btn.dataset.confirmState === 'pending') {
		// Second click - perform action
		btn.dataset.confirmState = '';
		btn.disabled = true;
		
		try {
			let endpoint = '';
			let method = 'POST';
			
			if (action === 'delete') {
				endpoint = `/api/admin/users/${userId}/delete`;
				method = 'DELETE';
			} else if (action === 'disable') {
				endpoint = `/api/admin/users/${userId}/disable`;
			} else if (action === 'enable') {
				endpoint = `/api/admin/users/${userId}/enable`;
			}

			const response = await fetch(endpoint, {
				method,
				headers: {
					'Authorization': `Bearer ${token}`,
				},
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.error || 'Failed to perform action');
			}

			// Reload users list
			loadUsers();
		} catch (error) {
			console.error(`Failed to ${action} user:`, error);
			alert(`Failed to ${action} user: ${error instanceof Error ? error.message : 'Unknown error'}`);
			btn.disabled = false;
		}
	} else {
		// First click - set confirmation state
		const originalText = btn.textContent;
		btn.dataset.confirmState = 'pending';
		btn.dataset.originalText = originalText || '';
		btn.textContent = 'you sure?';
		
		// Reset after 3 seconds if not clicked again
		setTimeout(() => {
			if (btn.dataset.confirmState === 'pending') {
				btn.dataset.confirmState = '';
				btn.textContent = btn.dataset.originalText || originalText;
			}
		}, 3000);
	}
}

checkAuth();
