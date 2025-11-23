// Caddy Manager - Complete UI JavaScript
// Save this as: CaddyMAN_ui.js

let currentUser = null;
let allGroups = [];
let editingProxyId = null;
let editingWebsiteId = null;
let editingUserId = null;
let editingGroupId = null;
let currentProxyMode = 'simple';
let currentWebsiteMode = 'simple';
let csrfToken = null; // CSRF token for secure requests
let inactivityTimer = null; // Auto-logout timer
const INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes in milliseconds

// Mobile Menu Functions
function toggleMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('mobile-overlay');
    sidebar.classList.toggle('mobile-open');
    overlay.classList.toggle('active');
}

function closeMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('mobile-overlay');
    sidebar.classList.remove('mobile-open');
    overlay.classList.remove('active');
}

// Inactivity Timer Functions
function startInactivityTimer() {
    clearInactivityTimer();
    inactivityTimer = setTimeout(() => {
        showAlert('You have been logged out due to inactivity', 'warning');
        logout();
    }, INACTIVITY_TIMEOUT);
}

function resetInactivityTimer() {
    if (currentUser) {
        startInactivityTimer();
    }
}

function clearInactivityTimer() {
    if (inactivityTimer) {
        clearTimeout(inactivityTimer);
        inactivityTimer = null;
    }
}

// Utility Functions
function showAlert(message, type = 'success') {
    const container = document.getElementById('alert-container');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    container.appendChild(alert);
    setTimeout(() => alert.remove(), 16000);
}

async function apiCall(url, options = {}, showErrors = true) {
    try {
        // Add CSRF token header for state-changing requests
        if (csrfToken && options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
            options.headers = {
                ...options.headers,
                'X-CSRF-Token': csrfToken
            };
        }
        const response = await fetch(url, {
            ...options,
            credentials: 'include'
        });
        if (response.status === 401) {
            showLogin();
            throw new Error('Not authenticated');
        }
        if (!response.ok) {
            let errorMsg = 'Request failed';
            try {
                const error = await response.json();
                // Handle Pydantic validation errors
                if (error.detail && Array.isArray(error.detail)) {
                    // Format validation errors nicely
                    errorMsg = error.detail.map(err => {
                        // Skip "body" in the field path for cleaner error messages
                        const field = err.loc ? err.loc.slice(1).join('.') : 'unknown';
                        const msg = err.msg || 'Validation error';
                        return `${field}: ${msg}`;
                    }).join('\n');
                } else if (typeof error.detail === 'string') {
                    errorMsg = error.detail;
                } else if (error.detail && typeof error.detail === 'object') {
                    errorMsg = JSON.stringify(error.detail);
                } else {
                    errorMsg = error.detail || JSON.stringify(error);
                }
            } catch (e) {
                console.error('Failed to parse error:', e);
                errorMsg = `Request failed with status ${response.status}`;
            }
            throw new Error(errorMsg);
        }
        return await response.json();
    } catch (err) {
        console.error('API Call Error:', err);
        if (showErrors) {
            showAlert(err.message, 'error');
        }
        throw err;
    }
}

// Authentication
function showLogin() {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('main-app').classList.add('hidden');
}

function showApp() {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('main-app').classList.remove('hidden');
    startInactivityTimer(); // Start inactivity timer when user logs in
}

async function login() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const totpToken = document.getElementById('login-2fa-token').value.trim();

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({
                username,
                password,
                totp_token: totpToken || undefined
            })
        });

        if (!response.ok) {
            let error;
            try {
                error = await response.json();
            } catch (e) {
                // If response is not JSON, create error object
                error = { detail: 'Login failed' };
            }

            // Check if 2FA is required
            if (response.status === 403) {
                if (error.detail === '2FA token required' || error.detail.includes('2FA')) {
                    document.getElementById('login-2fa-group').classList.remove('hidden');
                    document.getElementById('login-2fa-token').value = '';
                    document.getElementById('login-2fa-token').focus();
                    document.getElementById('login-alert').innerHTML =
                        '<div class="alert alert-warning">Please enter your 2FA code from your authenticator app</div>';
                    return;
                }
            }

            throw new Error(error.detail || 'Login failed');
        }

        const data = await response.json();
        currentUser = data.user;
        csrfToken = data.csrf_token; // Store CSRF token for subsequent requests
        sessionStorage.setItem('csrf_token', csrfToken); // Persist for page refreshes and mobile tab suspension

        // Hide 2FA field for next login and clear alert
        document.getElementById('login-2fa-group').classList.add('hidden');
        document.getElementById('login-2fa-token').value = '';
        document.getElementById('login-alert').innerHTML = '';

        // Check if password change is required
        if (data.needs_password_change) {
            showAlert('Please change your default password for security reasons', 'warning');
            // Could redirect to settings or show password change modal here
        }

        showApp();
        await checkForUpdates();
        await loadDashboard();
    } catch (err) {
        console.error('Login error:', err);
        document.getElementById('login-alert').innerHTML =
            '<div class="alert alert-error">' + (err.message || 'Invalid credentials') + '</div>';
    }
}

async function logout() {
    await fetch('/api/auth/logout', {method: 'POST', credentials: 'include'});
    currentUser = null;
    csrfToken = null; // Clear CSRF token on logout
    sessionStorage.removeItem('csrf_token'); // Clear stored CSRF token
    clearInactivityTimer(); // Clear inactivity timer on logout
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
    showLogin();
}

async function checkAuth() {
    try {
        const data = await apiCall('/api/auth/me', {}, false);
        currentUser = data;
        // Restore CSRF token from sessionStorage if available (for page refreshes and mobile tab restoration)
        const storedToken = sessionStorage.getItem('csrf_token');
        if (storedToken) {
            csrfToken = storedToken;
        }
        showApp();
        await loadDashboard();
        startAutoRefresh(); // NEW LINE
    } catch {
        showLogin();
    }
}

// Updates
async function checkForUpdates() {
    try {
        const data = await apiCall('/api/update/check', {}, false);
        if (data.update_available) {
            document.getElementById('update-banner').classList.remove('hidden');
        } else {
            document.getElementById('update-banner').classList.add('hidden');  // ADD THIS LINE
        }
    } catch {}
}

async function installUpdate() {
    if (confirm('Install update and restart? This will take a few moments.')) {
        showAlert('Downloading update...', 'success');
        await apiCall('/api/update/install', {method: 'POST'});
    }
}

// Navigation
function showPage(page, sourceEvent = null) {
    document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById(page + '-page').classList.remove('hidden');

    // Only try to update active nav item if we have a source event
    if (sourceEvent && sourceEvent.target) {
        const navItem = sourceEvent.target.closest('.nav-item');
        if (navItem) {
            navItem.classList.add('active');
        }
    } else {
        // Fallback: find and activate the nav item manually
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            if (item.textContent.toLowerCase().includes(page)) {
                item.classList.add('active');
            }
        });
    }

    // Close mobile menu after navigation
    closeMobileMenu();

    if (page === 'dashboard') loadDashboard();
    if (page === 'proxies') loadProxies();
    if (page === 'websites') loadWebsites();
    if (page === 'users') loadUsers();
    if (page === 'groups') loadGroups();
    if (page === 'settings') loadSettings();
    if (page === 'help') loadRuntimeInfo();
}

function setTheme(theme, sourceEvent = null) {
    document.body.className = theme;
    // Save theme to localStorage
    localStorage.setItem('caddy-manager-theme', theme);
    document.querySelectorAll('#theme-toggle .toggle-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    if (sourceEvent && sourceEvent.target) {
        sourceEvent.target.classList.add('active');
    } else {
        // If no source event, find the button for this theme and mark it active
        document.querySelectorAll('#theme-toggle .toggle-btn').forEach(btn => {
            if (btn.textContent.toLowerCase().includes(theme)) {
                btn.classList.add('active');
            }
        });
    }
}

// Dashboard
async function loadDashboard() {
    try {
        // Load groups first so they're available for rendering throughout the app
        if (allGroups.length === 0) {
            const groups = await apiCall('/api/groups');
            allGroups = groups;
        }

        const status = await apiCall('/api/caddy/status');
        let statusText = status.status === 'running' ? '✅ Running (PID: ' + status.pid + ')' : '❌ Stopped';
        if (status.status === 'stopped' && status.reason) {
            statusText += ' - ' + status.reason;
        }
        document.getElementById('caddy-status').textContent = statusText;
        const versionData = await apiCall('/api/version');
        document.getElementById('app-version').textContent = versionData.version;

        const proxies = await apiCall('/api/proxies');
        const websites = await apiCall('/api/websites');
        const users = await apiCall('/api/users');

        document.getElementById('proxy-count').textContent = proxies.length;
        document.getElementById('website-count').textContent = websites.length;
        document.getElementById('user-count').textContent = users.length;

        await loadSecurityWarnings();
        await loadActivity();
        await loadNotifications();
    } catch {}
}

async function loadSecurityWarnings() {
    try {
        const settings = await apiCall('/api/settings');
        const warningsCard = document.getElementById('security-warnings-card');
        const warningsList = document.getElementById('security-warnings-list');

        // Only show warnings if Enhanced Security is enabled
        if (!settings.enhanced_security) {
            warningsCard.classList.add('hidden');
            return;
        }

        const warnings = await apiCall('/api/security/warnings');

        if (warnings.warnings.length === 0) {
            warningsCard.classList.add('hidden');
            return;
        }

        warningsCard.classList.remove('hidden');
        warningsList.innerHTML = warnings.warnings.map(w => {
            return `<div class="alert alert-warning" style="margin-bottom: 10px;">
                <strong>${w.username}</strong>: ${w.message}
            </div>`;
        }).join('');
    } catch (err) {
        console.error('Failed to load security warnings:', err);
    }
}

async function loadActivity() {
    try {
        const data = await apiCall('/api/activity');
        const log = document.getElementById('activity-log');
        
        if (data.activities.length === 0) {
            log.innerHTML = '<p style="color: var(--text-secondary);">No recent activity</p>';
            return;
        }
        
        log.innerHTML = data.activities.map(activity => {
            const time = new Date(activity.timestamp).toLocaleString();
            const actionColor = activity.action.includes('FAILED') || activity.action.includes('DENIED') 
                ? 'var(--danger)' 
                : activity.action.includes('SUCCESS') || activity.action.includes('LOGIN')
                ? 'var(--success)'
                : 'var(--text-primary)';
            
            return `
                <div style="padding: 8px; border-bottom: 1px solid var(--border); line-height: 1.6;">
                    <div style="color: var(--text-secondary);">${time}</div>
                    <div>
                        <strong style="color: var(--accent);">${activity.username}</strong> 
                        <span style="color: ${actionColor}; font-weight: 500;">${activity.action}</span>
                    </div>
                    ${activity.details ? `<div style="color: var(--text-secondary); font-size: 11px;">${activity.details}</div>` : ''}
                    <div style="color: var(--text-secondary); font-size: 11px;">IP: ${activity.ip}</div>
                </div>
            `;
        }).join('');
    } catch {}
}

async function loadNotifications() {
    try {
        const data = await apiCall('/api/notifications');
        const log = document.getElementById('notification-log');

        if (data.notifications.length === 0) {
            log.innerHTML = '<p style="color: var(--text-secondary);">No notifications sent yet</p>';
            return;
        }

        log.innerHTML = data.notifications.map(notif => {
            const time = new Date(notif.timestamp).toLocaleString();
            const typeColors = {
                'info': 'var(--accent)',
                'success': 'var(--success)',
                'warning': '#ff9800',
                'critical': 'var(--danger)',
                'alert': '#ff5722'
            };
            const typeColor = typeColors[notif.type] || 'var(--text-primary)';

            return `
                <div style="padding: 8px; border-bottom: 1px solid var(--border); line-height: 1.6;">
                    <div style="color: var(--text-secondary);">${time}</div>
                    <div>
                        <strong style="color: ${typeColor};">${notif.title}</strong>
                    </div>
                    <div style="color: var(--text-secondary); font-size: 11px; white-space: pre-wrap;">${notif.message}</div>
                </div>
            `;
        }).join('');
    } catch {}
}

// Load runtime info and update help page dynamically
let runtimeInfo = null;
async function loadRuntimeInfo() {
    if (runtimeInfo) return; // Only load once
    try {
        runtimeInfo = await apiCall('/api/runtime-info');
        updateHelpPage();
        updateSettingsPlaceholder();
    } catch (err) {
        console.error('Failed to load runtime info:', err);
    }
}

function updateHelpPage() {
    if (!runtimeInfo) return;

    const { platform, is_executable, executable_name, php_cgi_name } = runtimeInfo;

    // Update PHP-CGI references
    const phpCgiElements = ['help-php-cgi', 'help-php-cgi-troubleshoot'];
    phpCgiElements.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = php_cgi_name;
    });

    // Update process check command
    const processCmdEl = document.getElementById('help-process-cmd');
    if (processCmdEl) {
        if (platform === 'windows') {
            if (is_executable) {
                processCmdEl.textContent = `tasklist | findstr ${executable_name}`;
            } else {
                processCmdEl.textContent = 'tasklist | findstr python';
            }
        } else {
            // Linux/Mac
            if (is_executable) {
                processCmdEl.textContent = `ps aux | grep ${executable_name}`;
            } else {
                processCmdEl.textContent = 'ps aux | grep CaddyMAN.py';
            }
        }
    }

    // Update command line start instruction
    const startCmdEl = document.getElementById('help-start-cmd');
    if (startCmdEl) {
        if (is_executable) {
            startCmdEl.textContent = `./${executable_name}`;
        } else {
            startCmdEl.textContent = 'python CaddyMAN.py';
        }
    }

    // Update Python requirement visibility
    const pythonReqEl = document.getElementById('help-python-req');
    if (pythonReqEl) {
        if (is_executable) {
            pythonReqEl.style.display = 'none';
        } else {
            pythonReqEl.style.display = 'list-item';
        }
    }

    // Update OS support text
    const osListEl = document.getElementById('help-os-list');
    if (osListEl) {
        const platformName = platform === 'windows' ? 'Windows' :
                            platform === 'linux' ? 'Linux' :
                            platform === 'darwin' ? 'macOS' : platform;
        osListEl.textContent = `${platformName} (other platforms supported)`;
    }
}

function updateSettingsPlaceholder() {
    if (!runtimeInfo) return;

    const phpPathInput = document.getElementById('php-path');
    const phpCgiNameSpan = document.getElementById('php-cgi-name');

    if (phpPathInput && runtimeInfo.platform === 'windows') {
        phpPathInput.placeholder = `C:\\php\\${runtimeInfo.php_cgi_name}`;
    } else if (phpPathInput) {
        phpPathInput.placeholder = `/usr/bin/${runtimeInfo.php_cgi_name}`;
    }

    if (phpCgiNameSpan) {
        phpCgiNameSpan.textContent = runtimeInfo.php_cgi_name;
    }
}

// Settings
async function loadSettings() {
    await loadRuntimeInfo(); // Ensure runtime info is loaded
    const data = await apiCall('/api/settings');
    document.getElementById('health-check-enabled').checked = data.health_check_enabled;
    document.getElementById('health-check-domain').value = data.health_check_domain;
    document.getElementById('health-check-interval').value = data.health_check_interval;
    document.getElementById('restart-after-failures').value = data.restart_after_failures;
    document.getElementById('notification-service').value = data.notification_service;
    document.getElementById('notification-url').value = data.notification_url;
    document.getElementById('notification-token').value = data.notification_token;
    document.getElementById('php-enabled').checked = data.php_enabled || false;
    document.getElementById('php-path').value = data.php_path || '';
    document.getElementById('manager-port').value = data.manager_port || 8000;
    document.getElementById('caddy-admin-port').value = data.caddy_admin_port || 12999;
    document.getElementById('enhanced-security').checked = data.enhanced_security || false;
    document.getElementById('caddy-log-level').value = data.caddy_log_level || 'WARN';
    document.body.className = data.theme;
    document.querySelectorAll('#theme-toggle .toggle-btn').forEach((btn, idx) => {
        const themes = ['light', 'dark', 'black'];
        btn.classList.toggle('active', themes[idx] === data.theme);
    });

    // Load notification events and show/hide container based on service selection
    const notificationEventsContainer = document.getElementById('notification-events-container');
    if (data.notification_service && data.notification_service !== '') {
        notificationEventsContainer.style.display = 'block';
    } else {
        notificationEventsContainer.style.display = 'none';
    }

    // Load notification event checkboxes
    if (data.notification_events) {
        Object.keys(data.notification_events).forEach(eventType => {
            const checkbox = document.getElementById(`notif-${eventType}`);
            if (checkbox) {
                checkbox.checked = data.notification_events[eventType].enabled || false;
            }
        });
    }
}

// Toggle notification events visibility when service changes
document.getElementById('notification-service')?.addEventListener('change', function() {
    const container = document.getElementById('notification-events-container');
    container.style.display = (this.value && this.value !== '') ? 'block' : 'none';
});

async function saveSettings() {
    const currentSettings = await apiCall('/api/settings');
    const wasEnhancedSecurityOff = !currentSettings.enhanced_security;

    // Collect notification events from checkboxes
    const notificationEvents = {};
    const eventCheckboxes = document.querySelectorAll('[id^="notif-"]');
    eventCheckboxes.forEach(checkbox => {
        const eventType = checkbox.id.replace('notif-', '');
        // Preserve severity from current settings, only update enabled state
        const currentEvent = currentSettings.notification_events?.[eventType] || {};
        notificationEvents[eventType] = {
            enabled: checkbox.checked,
            severity: currentEvent.severity || 'info'
        };
    });

    const settings = {
        theme: document.body.className,
        health_check_enabled: document.getElementById('health-check-enabled').checked,
        health_check_domain: document.getElementById('health-check-domain').value,
        health_check_interval: parseInt(document.getElementById('health-check-interval').value),
        restart_after_failures: parseInt(document.getElementById('restart-after-failures').value),
        notification_service: document.getElementById('notification-service').value,
        notification_url: document.getElementById('notification-url').value,
        notification_token: document.getElementById('notification-token').value,
        notification_events: notificationEvents,
        php_enabled: document.getElementById('php-enabled').checked,
        php_path: document.getElementById('php-path').value,
        manager_port: parseInt(document.getElementById('manager-port').value),
        caddy_admin_port: parseInt(document.getElementById('caddy-admin-port').value),
        enhanced_security: document.getElementById('enhanced-security').checked,
        caddy_log_level: document.getElementById('caddy-log-level').value
    };
    await apiCall('/api/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(settings)
    });

    // Check if Enhanced Security was just enabled
    if (wasEnhancedSecurityOff && settings.enhanced_security) {
        const users = await apiCall('/api/users');
        const usersWithout2FA = users.filter(u => !u.totp_enabled);

        if (usersWithout2FA.length > 0) {
            const userList = usersWithout2FA.map(u => u.username).join(', ');
            showAlert(`Enhanced Security enabled! Warning: ${usersWithout2FA.length} user(s) without 2FA: ${userList}. Please enable 2FA for these users and have them set strong passwords.`, 'warning');
        } else {
            showAlert('Enhanced Security enabled! All users have 2FA enabled.');
        }
        // Reload dashboard to show security warnings
        await loadDashboard();
    } else if (settings.manager_port !== 8000) {
        showAlert('Settings saved! Note: Manager port change requires restart to take effect.');
    } else {
        showAlert('Settings saved! Caddy reloaded.');
    }
}

// Groups
async function loadGroups() {
    const groups = await apiCall('/api/groups');
    allGroups = groups;
    const list = document.getElementById('group-list');
    list.innerHTML = groups.map(g => `
        <div class="item">
            <div class="item-info">
                <h3>${g.name}</h3>
                <p>${g.description || 'No description'}</p>
            </div>
            <div class="item-actions">
                <button class="btn btn-primary" onclick="editGroup('${g.id}')">Edit</button>
                ${g.system ? '<span class="status-badge status-active">System</span>' : 
                `<button class="btn btn-danger" onclick="deleteGroup('${g.id}')">Delete</button>`}
            </div>
        </div>
    `).join('');
}

function openGroupModal() {
    editingGroupId = null;
    document.getElementById('group-modal-title').textContent = 'Add Group';
    document.getElementById('group-name').value = '';
    document.getElementById('group-description').value = '';
    document.getElementById('group-modal').classList.add('active');
}

function closeGroupModal() {
    document.getElementById('group-modal').classList.remove('active');
}

async function saveGroup() {
    try {
        const group = {
            id: editingGroupId || 'group_' + Date.now(),
            name: document.getElementById('group-name').value,
            description: document.getElementById('group-description').value
        };
        
        await apiCall('/api/groups', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(group)
        });
        
        showAlert('Group saved!');
        closeGroupModal();
        loadGroups();
    } catch (err) {
        showAlert('Failed to save group: ' + err.message, 'error');
    }
}

async function editGroup(id) {
    const groups = await apiCall('/api/groups');
    const group = groups.find(g => g.id === id);
    
    editingGroupId = id;
    document.getElementById('group-modal-title').textContent = 'Edit Group';
    document.getElementById('group-name').value = group.name;
    document.getElementById('group-description').value = group.description;
    document.getElementById('group-modal').classList.add('active');
}

async function deleteGroup(id) {
    if (confirm('Delete this group?')) {
        await apiCall(`/api/groups/${id}`, {method: 'DELETE'});
        showAlert('Group deleted');
        loadGroups();
    }
}

// Users
async function loadUsers() {
    const users = await apiCall('/api/users');
    const list = document.getElementById('user-list');
    list.innerHTML = users.map(u => {
        // Map group IDs to group names
        const groupNames = u.groups.map(gid => {
            const group = allGroups.find(g => g.id === gid);
            return group ? group.name : gid;
        }).join(', ');

        // Check if user has 2FA enabled
        const has2FA = u.totp_enabled ? ' <span class="status-badge status-active" style="font-size: 11px; padding: 3px 8px;">🔐 2FA</span>' : '';

        return `
        <div class="item">
            <div class="item-info">
                <h3>${u.username}</h3>
                <p>Groups: ${groupNames || 'None'}${has2FA}</p>
            </div>
            <div class="item-actions">
<button class="btn btn-primary" onclick="editUser('${u.id}')">Edit</button>
${u.groups.includes('admin_group') && users.filter(user => user.groups.includes('admin_group')).length === 1
    ? '<span class="status-badge status-active">Last Admin</span>'
    : `<button class="btn btn-danger" onclick="deleteUser('${u.id}')">Delete</button>`}
            </div>
        </div>
        `;
    }).join('');
}

function openUserModal() {
    editingUserId = null;
    document.getElementById('user-modal-title').textContent = 'Add User';
    document.getElementById('user-username').value = '';
    document.getElementById('user-password').value = '';
    renderGroupSelector('user-groups', []);
    document.getElementById('user-2fa-section').classList.add('hidden');
    document.getElementById('user-modal').classList.add('active');
}

function closeUserModal() {
    document.getElementById('user-modal').classList.remove('active');
}

function renderGroupSelector(elementId, selectedGroups) {
    const container = document.getElementById(elementId);
    container.innerHTML = `
        <div class="multi-select" id="${elementId}-display">
            ${selectedGroups.map(g => `
                <div class="multi-select-tag">
                    ${allGroups.find(gr => gr.id === g)?.name || g}
                    <button onclick="removeGroupFromUser('${elementId}', '${g}')">×</button>
                </div>
            `).join('')}
        </div>
        <select id="${elementId}-select" onchange="addGroupToUser('${elementId}')">
            <option value="">+ Add group</option>
            ${allGroups.filter(g => !selectedGroups.includes(g.id)).map(g => 
                `<option value="${g.id}">${g.name}</option>`
            ).join('')}
        </select>
    `;
    container.dataset.groups = JSON.stringify(selectedGroups);
}

function addGroupToUser(elementId) {
    const select = document.getElementById(elementId + '-select');
    const groupId = select.value;
    if (!groupId) return;
    
    const container = document.getElementById(elementId);
    const current = JSON.parse(container.dataset.groups || '[]');
    current.push(groupId);
    renderGroupSelector(elementId, current);
}

function removeGroupFromUser(elementId, groupId) {
    const container = document.getElementById(elementId);
    const current = JSON.parse(container.dataset.groups || '[]');
    const updated = current.filter(g => g !== groupId);
    renderGroupSelector(elementId, updated);
}

async function saveUser() {
    try {
        const userId = editingUserId;
        const container = document.getElementById('user-groups');
        const groups = JSON.parse(container.dataset.groups || '[]');
        
        // Check if removing admin group
        if (userId) {
            const users = await apiCall('/api/users');
            const existingUser = users.find(u => u.id === userId);
            
            if (existingUser && existingUser.groups.includes('admin_group') && !groups.includes('admin_group')) {
                const adminCount = users.filter(u => u.groups.includes('admin_group')).length;
                
                if (adminCount <= 1) {
                    showAlert('Cannot remove admin group from the last admin user!', 'error');
                    return;
                }
                
                if (!confirm('⚠️ Warning: You are removing admin privileges from this user. Continue?')) {
                    return;
                }
            }
        }
        
        // FIX: Check if editing existing user
        if (editingUserId) {
            // Use PUT to update existing user
            const user = {
                id: editingUserId,
                username: document.getElementById('user-username').value,
                password: document.getElementById('user-password').value,
                groups: groups
            };
            
            await apiCall(`/api/users/${editingUserId}`, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(user)
            });
        } else {
            // Use POST to create new user
            const user = {
                username: document.getElementById('user-username').value,
                password: document.getElementById('user-password').value,
                groups: groups
            };
            
            await apiCall('/api/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(user)
            });
        }
        
        showAlert('User saved!');
        closeUserModal();
        loadUsers();
    } catch (err) {
        showAlert('Failed to save user: ' + err.message, 'error');
    }
}

async function editUser(id) {
    const users = await apiCall('/api/users');
    const user = users.find(u => u.id === id);

    editingUserId = id;
    document.getElementById('user-modal-title').textContent = 'Edit User';
    document.getElementById('user-username').value = user.username;
    document.getElementById('user-password').value = '';
    document.getElementById('user-password').placeholder = 'Leave empty to keep current';
    renderGroupSelector('user-groups', user.groups);
    await update2FASection(user);
    document.getElementById('user-modal').classList.add('active');
}

async function deleteUser(id) {
    const users = await apiCall('/api/users');
    const user = users.find(u => u.id === id);
    
    // Extra warning for admin users
    if (user && user.groups.includes('admin_group')) {
        const adminCount = users.filter(u => u.groups.includes('admin_group')).length;
        
        if (adminCount <= 1) {
            showAlert('Cannot delete the last admin user!', 'error');
            return;
        }
        
        if (!confirm(`⚠️ Warning: "${user.username}" is an admin. Are you sure you want to delete this user?`)) {
            return;
        }
    } else {
        if (!confirm('Delete this user?')) {
            return;
        }
    }
    
    try {
        await apiCall(`/api/users/${id}`, {method: 'DELETE'});
        showAlert('User deleted');
        loadUsers();
    } catch (err) {
        // Error already shown by apiCall
    }
}

// 2FA Functions
async function update2FASection(user) {
    const settings = await apiCall('/api/settings');
    const section = document.getElementById('user-2fa-section');
    const enableSection = document.getElementById('user-2fa-enable-section');
    const qrSection = document.getElementById('user-2fa-qr-section');
    const disableSection = document.getElementById('user-2fa-disable-section');
    const statusText = document.getElementById('user-2fa-enabled-text');

    // Only show 2FA section when editing existing user and Enhanced Security is enabled
    if (editingUserId && settings.enhanced_security) {
        section.classList.remove('hidden');

        if (user.totp_enabled) {
            // 2FA is enabled
            statusText.textContent = 'Enabled';
            statusText.style.color = 'var(--success)';
            enableSection.classList.add('hidden');
            qrSection.classList.add('hidden');
            disableSection.classList.remove('hidden');
        } else {
            // 2FA is disabled
            statusText.textContent = 'Disabled';
            statusText.style.color = 'var(--text-secondary)';
            enableSection.classList.remove('hidden');
            qrSection.classList.add('hidden');
            disableSection.classList.add('hidden');
        }
    } else {
        section.classList.add('hidden');
    }
}

async function enable2FA() {
    try {
        const data = await apiCall(`/api/users/${editingUserId}/2fa/enable`, {
            method: 'POST'
        });

        // Show QR code section
        document.getElementById('user-2fa-enable-section').classList.add('hidden');
        document.getElementById('user-2fa-qr-section').classList.remove('hidden');
        document.getElementById('user-2fa-qr-code').src = data.qr_code;
        document.getElementById('user-2fa-token').value = '';
        document.getElementById('user-2fa-token').focus();
    } catch (err) {
        showAlert(err.message, 'error');
    }
}

async function verify2FA() {
    const token = document.getElementById('user-2fa-token').value.trim();

    if (!token || token.length !== 6) {
        showAlert('Please enter a valid 6-digit code', 'error');
        return;
    }

    try {
        await apiCall(`/api/users/${editingUserId}/2fa/verify`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({token})
        });

        showAlert('2FA enabled successfully!', 'success');

        // Reload user data and update UI
        const users = await apiCall('/api/users');
        const user = users.find(u => u.id === editingUserId);
        await update2FASection(user);
        await loadUsers();
    } catch (err) {
        showAlert(err.message, 'error');
    }
}

async function disable2FA() {
    if (!confirm('Are you sure you want to disable 2FA for this user?')) {
        return;
    }

    try {
        await apiCall(`/api/users/${editingUserId}/2fa/disable`, {
            method: 'POST'
        });

        showAlert('2FA disabled successfully!', 'success');

        // Reload user data and update UI
        const users = await apiCall('/api/users');
        const user = users.find(u => u.id === editingUserId);
        await update2FASection(user);
        await loadUsers();
    } catch (err) {
        showAlert(err.message, 'error');
    }
}

function cancel2FASetup() {
    document.getElementById('user-2fa-qr-section').classList.add('hidden');
    document.getElementById('user-2fa-enable-section').classList.remove('hidden');
    document.getElementById('user-2fa-token').value = '';
}

// Proxies
async function loadProxies() {
    const proxies = await apiCall('/api/proxies');
    const list = document.getElementById('proxy-list');
    list.innerHTML = proxies.map(p => {
        const features = [];
        const displayDomain = (p.domains && p.domains.length) ? p.domains.join(', ') : 'All domains';

        // Handle port display - support both new and legacy format
        let http_ports, https_ports;
        if (p.http_ports || p.https_ports) {
            // New format
            http_ports = p.http_ports || [];
            https_ports = p.https_ports || [];
        } else if (p.listen_port !== undefined) {
            // Legacy format
            if (p.tls) {
                http_ports = [];
                https_ports = [p.listen_port];
            } else {
                http_ports = [p.listen_port];
                https_ports = [];
            }
        } else {
            http_ports = [80];
            https_ports = [];
        }

        // Add port info to features
        if (http_ports.length > 0 && !(http_ports.length === 1 && http_ports[0] === 80)) {
            features.push(`HTTP: ${http_ports.join(', ')}`);
        }
        if (https_ports.length > 0) {
            features.push(`🔒 HTTPS: ${https_ports.join(', ')}`);
        }

        if (p.auto_https) features.push('↗️ Auto HTTPS');
        if (p.websocket) features.push('🔌 WebSocket');
        if (p.load_balance) features.push(`⚖️ ${p.load_balance}`);
        if (p.access_groups && p.access_groups.length) {
            const groupNames = p.access_groups.map(gid => {
                const group = allGroups.find(g => g.id === gid);
                return group ? group.name : gid;
            }).join(', ');
            features.push(`🔐 ${groupNames}`);
        }

        return `
            <div class="item">
                <div class="item-info">
                    <h3>${displayDomain}</h3>
                    <p>→ ${p.upstream}</p>
                    ${features.length ? `<p style="font-size: 12px; margin-top: 5px;">${features.join(' • ')}</p>` : ''}
                </div>
                <div class="item-actions">
                    <span class="status-badge ${p.enabled ? 'status-active' : 'status-inactive'}">
                        ${p.enabled ? 'Active' : 'Disabled'}
                    </span>
                    <button class="btn btn-primary" onclick="editProxy('${p.id}')">Edit</button>
                    <button class="btn btn-danger" onclick="deleteProxy('${p.id}')">Delete</button>
                </div>
            </div>
        `;
    }).join('');
}

function toggleLoadBalancingVisibility() {
    const upstreamInput = document.getElementById('proxy-upstream');
    const loadBalanceGroup = document.getElementById('proxy-load-balance-group');

    if (!upstreamInput || !loadBalanceGroup) return;

    const upstreamValue = upstreamInput.value.trim();
    // Check if there are multiple upstreams (contains comma)
    const hasMultipleUpstreams = upstreamValue.includes(',');

    if (hasMultipleUpstreams) {
        loadBalanceGroup.classList.remove('hidden');
    } else {
        loadBalanceGroup.classList.add('hidden');
    }
}

function openProxyModal() {
    editingProxyId = null;
    document.getElementById('proxy-modal-title').textContent = 'Add Reverse Proxy';
    document.getElementById('proxy-domain').value = '';
    document.getElementById('proxy-http-ports').value = '80';
    document.getElementById('proxy-https-ports').value = '';
    document.getElementById('proxy-upstream').value = '';
    document.getElementById('proxy-load-balance').value = '';
    document.getElementById('proxy-header-host').value = '';
    document.getElementById('proxy-websocket').checked = false;
    document.getElementById('proxy-remove-origin').checked = false;
    document.getElementById('proxy-remove-referer').checked = false;
    document.getElementById('proxy-custom-headers').value = '';
    document.getElementById('proxy-auto-https').checked = false;
    document.getElementById('proxy-enabled').checked = true;
    document.getElementById('proxy-additional-directives').value = '';
    renderGroupSelector('proxy-access-groups', []);

    // Hide load balancing initially (no upstream entered yet)
    document.getElementById('proxy-load-balance-group').classList.add('hidden');

    // Add event listener to upstream input
    const upstreamInput = document.getElementById('proxy-upstream');
    upstreamInput.removeEventListener('input', toggleLoadBalancingVisibility); // Remove old listener if exists
    upstreamInput.addEventListener('input', toggleLoadBalancingVisibility);

    document.getElementById('proxy-modal').classList.add('active');
}

function closeProxyModal() {
    document.getElementById('proxy-modal').classList.remove('active');
}

function toggleProxyMode(mode, event) {
    currentProxyMode = mode;
    document.querySelectorAll('#proxy-modal .toggle-btn').forEach(btn => btn.classList.remove('active'));

    // If called programmatically without event, find and activate the correct button
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        const buttonToActivate = document.querySelector(`#proxy-modal .toggle-btn[onclick*="${mode}"]`);
        if (buttonToActivate) {
            buttonToActivate.classList.add('active');
        }
    }

    if (mode === 'simple') {
        document.getElementById('proxy-simple-form').classList.remove('hidden');
        document.getElementById('proxy-advanced-form').classList.add('hidden');
    } else {
        document.getElementById('proxy-simple-form').classList.add('hidden');
        document.getElementById('proxy-advanced-form').classList.remove('hidden');
    }
}

async function saveProxy() {
    try {
        let proxy;
        if (currentProxyMode === 'simple') {
            const domainInput = document.getElementById('proxy-domain').value.trim();
            if (!domainInput) {
                showAlert('Domain(s) are required for reverse proxy', 'error');
                return;
            }
            const domains = domainInput.split(',').map(d => d.trim()).filter(d => d);

            if (domains.length === 0) {
                showAlert('At least one valid domain is required', 'error');
                return;
            }

            // Parse port strings into arrays
            const httpPortsInput = document.getElementById('proxy-http-ports').value.trim();
            const httpsPortsInput = document.getElementById('proxy-https-ports').value.trim();

            const http_ports = httpPortsInput ? httpPortsInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p)) : [];
            const https_ports = httpsPortsInput ? httpsPortsInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p)) : [];

            const accessGroups = JSON.parse(document.getElementById('proxy-access-groups').dataset.groups || '[]');

            // Parse custom_headers JSON
            let custom_headers = null;
            const customHeadersInput = document.getElementById('proxy-custom-headers').value.trim();
            if (customHeadersInput) {
                try {
                    custom_headers = JSON.parse(customHeadersInput);
                } catch (e) {
                    showAlert('Invalid JSON in Custom Headers: ' + e.message, 'error');
                    return;
                }
            }

            proxy = {
                id: editingProxyId || 'proxy_' + Date.now(),
                domains: domains,
                http_ports: http_ports.length > 0 ? http_ports : [80],
                https_ports: https_ports,
                upstream: document.getElementById('proxy-upstream').value,
                load_balance: document.getElementById('proxy-load-balance').value || null,
                header_up_host: document.getElementById('proxy-header-host').value || null,
                websocket: document.getElementById('proxy-websocket').checked,
                remove_origin: document.getElementById('proxy-remove-origin').checked,
                remove_referer: document.getElementById('proxy-remove-referer').checked,
                custom_headers: custom_headers,
                auto_https: document.getElementById('proxy-auto-https').checked,
                enabled: document.getElementById('proxy-enabled').checked,
                additional_directives: document.getElementById('proxy-additional-directives').value.trim(),
                access_groups: accessGroups
            };
        } else {
            // Advanced mode - all config is in the JSON
            const advancedJson = document.getElementById('proxy-advanced').value.trim();
            if (!advancedJson) {
                showAlert('Caddy JSON configuration is required in advanced mode', 'error');
                return;
            }

            let advancedConfig;
            try {
                advancedConfig = JSON.parse(advancedJson);
            } catch (e) {
                showAlert('Invalid JSON in advanced configuration: ' + e.message, 'error');
                return;
            }

            proxy = {
                id: editingProxyId || 'proxy_' + Date.now(),
                domains: [],  // Defined in JSON
                http_ports: [],  // Defined in JSON
                https_ports: [],  // Defined in JSON
                upstream: '',  // Defined in JSON
                enabled: document.getElementById('proxy-enabled-adv').checked,
                advanced: advancedConfig,
                access_groups: []
            };
        }

        await apiCall('/api/proxies', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(proxy)
        });

        showAlert('Proxy saved!');
        closeProxyModal();
        loadProxies();
    } catch (err) {
        showAlert('Failed to save proxy: ' + err.message, 'error');
    }
}

async function editProxy(id) {
    const proxies = await apiCall('/api/proxies');
    const proxy = proxies.find(p => p.id === id);

    editingProxyId = id;
    document.getElementById('proxy-modal-title').textContent = 'Edit Reverse Proxy';

    if (proxy.advanced) {
        toggleProxyMode('advanced');
        // Advanced mode - all config is in the JSON, just load it
        document.getElementById('proxy-advanced').value = JSON.stringify(proxy.advanced, null, 2);
        document.getElementById('proxy-enabled-adv').checked = proxy.enabled;
    } else {
        document.getElementById('proxy-domain').value = (proxy.domains || []).join(', ');

        // Handle port arrays - check for new format first, then fall back to legacy
        let http_ports, https_ports;
        if (proxy.http_ports || proxy.https_ports) {
            // New format
            http_ports = proxy.http_ports || [];
            https_ports = proxy.https_ports || [];
        } else if (proxy.listen_port !== undefined) {
            // Legacy format
            if (proxy.tls) {
                http_ports = [];
                https_ports = [proxy.listen_port];
            } else {
                http_ports = [proxy.listen_port];
                https_ports = [];
            }
        } else {
            http_ports = [80];
            https_ports = [];
        }

        document.getElementById('proxy-http-ports').value = http_ports.join(', ');
        document.getElementById('proxy-https-ports').value = https_ports.join(', ');
        document.getElementById('proxy-upstream').value = proxy.upstream;
        document.getElementById('proxy-load-balance').value = proxy.load_balance || '';
        document.getElementById('proxy-header-host').value = proxy.header_up_host || '';
        document.getElementById('proxy-websocket').checked = proxy.websocket || false;
        document.getElementById('proxy-remove-origin').checked = proxy.remove_origin || false;
        document.getElementById('proxy-remove-referer').checked = proxy.remove_referer || false;
        document.getElementById('proxy-custom-headers').value = proxy.custom_headers ? JSON.stringify(proxy.custom_headers, null, 2) : '';
        document.getElementById('proxy-auto-https').checked = proxy.auto_https || false;
        document.getElementById('proxy-enabled').checked = proxy.enabled;
        document.getElementById('proxy-additional-directives').value = proxy.additional_directives || '';
        renderGroupSelector('proxy-access-groups', proxy.access_groups || []);

        // Add event listener to upstream input and toggle visibility
        const upstreamInput = document.getElementById('proxy-upstream');
        upstreamInput.removeEventListener('input', toggleLoadBalancingVisibility);
        upstreamInput.addEventListener('input', toggleLoadBalancingVisibility);
        toggleLoadBalancingVisibility(); // Check initial state
    }

    document.getElementById('proxy-modal').classList.add('active');
}

async function deleteProxy(id) {
    if (confirm('Delete this proxy?')) {
        await apiCall(`/api/proxies/${id}`, {method: 'DELETE'});
        showAlert('Proxy deleted');
        loadProxies();
    }
}

// Websites
async function loadWebsites() {
    const websites = await apiCall('/api/websites');
    const list = document.getElementById('website-list');
    list.innerHTML = websites.map(w => {
        const features = [];
        const displayDomain = (w.domains && w.domains.length) ? w.domains.join(', ') : 'All domains';

        // Handle port display - support both new and legacy format
        let http_ports, https_ports;
        if (w.http_ports || w.https_ports) {
            // New format
            http_ports = w.http_ports || [];
            https_ports = w.https_ports || [];
        } else if (w.listen_port !== undefined) {
            // Legacy format
            if (w.tls) {
                http_ports = [];
                https_ports = [w.listen_port];
            } else {
                http_ports = [w.listen_port];
                https_ports = [];
            }
        } else {
            http_ports = [80];
            https_ports = [];
        }

        // Add port info to features
        if (http_ports.length > 0 && !(http_ports.length === 1 && http_ports[0] === 80)) {
            features.push(`HTTP: ${http_ports.join(', ')}`);
        }
        if (https_ports.length > 0) {
            features.push(`🔒 HTTPS: ${https_ports.join(', ')}`);
        }

        if (w.auto_https) features.push('↗️ Auto HTTPS');
        if (w.php_enabled) features.push('🐘 PHP');
        if (w.access_groups && w.access_groups.length) {
            const groupNames = w.access_groups.map(gid => {
                const group = allGroups.find(g => g.id === gid);
                return group ? group.name : gid;
            }).join(', ');
            features.push(`🔐 ${groupNames}`);
        }

        return `
            <div class="item">
                <div class="item-info">
                    <h3>${displayDomain}</h3>
                    <p>📁 ${w.root}</p>
                    ${features.length ? `<p style="font-size: 12px; margin-top: 5px;">${features.join(' • ')}</p>` : ''}
                </div>
                <div class="item-actions">
                    <span class="status-badge ${w.enabled ? 'status-active' : 'status-inactive'}">
                        ${w.enabled ? 'Active' : 'Disabled'}
                    </span>
                    <button class="btn btn-primary" onclick="editWebsite('${w.id}')">Edit</button>
                    <button class="btn btn-danger" onclick="deleteWebsite('${w.id}')">Delete</button>
                </div>
            </div>
        `;
    }).join('');
}

function openWebsiteModal() {
    editingWebsiteId = null;
    document.getElementById('website-modal-title').textContent = 'Add Website';
    document.getElementById('website-domain').value = '';
    document.getElementById('website-http-ports').value = '80';
    document.getElementById('website-https-ports').value = '';
    document.getElementById('website-root').value = '';
    document.getElementById('website-index').value = 'index.html';
    document.getElementById('website-auto-https').checked = false;
    document.getElementById('website-php-enabled').checked = false;
    document.getElementById('website-enabled').checked = true;
    renderGroupSelector('website-access-groups', []);
    document.getElementById('website-modal').classList.add('active');
}

function closeWebsiteModal() {
    document.getElementById('website-modal').classList.remove('active');
}

function toggleWebsiteMode(mode, event) {
    currentWebsiteMode = mode;
    document.querySelectorAll('#website-modal .toggle-btn').forEach(btn => btn.classList.remove('active'));

    // If called programmatically without event, find and activate the correct button
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        const buttonToActivate = document.querySelector(`#website-modal .toggle-btn[onclick*="${mode}"]`);
        if (buttonToActivate) {
            buttonToActivate.classList.add('active');
        }
    }

    if (mode === 'simple') {
        document.getElementById('website-simple-form').classList.remove('hidden');
        document.getElementById('website-advanced-form').classList.add('hidden');
    } else {
        document.getElementById('website-simple-form').classList.add('hidden');
        document.getElementById('website-advanced-form').classList.remove('hidden');
    }
}

async function saveWebsite() {
    try {
        let website;
        if (currentWebsiteMode === 'simple') {
            const domainInput = document.getElementById('website-domain').value.trim();
            const domains = domainInput ? domainInput.split(',').map(d => d.trim()).filter(d => d) : [];

            // Parse port strings into arrays
            const httpPortsInput = document.getElementById('website-http-ports').value.trim();
            const httpsPortsInput = document.getElementById('website-https-ports').value.trim();

            const http_ports = httpPortsInput ? httpPortsInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p)) : [];
            const https_ports = httpsPortsInput ? httpsPortsInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p)) : [];

            // Safely get access groups
            const accessGroupsElement = document.getElementById('website-access-groups');
            const accessGroups = accessGroupsElement ? JSON.parse(accessGroupsElement.dataset.groups || '[]') : [];

            website = {
                id: editingWebsiteId || 'website_' + Date.now(),
                domains: domains,
                http_ports: http_ports.length > 0 ? http_ports : [80],
                https_ports: https_ports,
                root: document.getElementById('website-root').value || '',
                index_files: document.getElementById('website-index').value.split(',').map(s => s.trim()).filter(s => s) || ['index.html'],
                auto_https: document.getElementById('website-auto-https').checked,
                php_enabled: document.getElementById('website-php-enabled').checked,
                enabled: document.getElementById('website-enabled').checked,
                access_groups: accessGroups
            };
        } else {
            // Advanced mode - all config is in the JSON
            const advancedJson = document.getElementById('website-advanced').value.trim();
            if (!advancedJson) {
                showAlert('Caddy JSON configuration is required in advanced mode', 'error');
                return;
            }

            let advancedConfig;
            try {
                advancedConfig = JSON.parse(advancedJson);
            } catch (e) {
                showAlert('Invalid JSON in advanced configuration: ' + e.message, 'error');
                return;
            }

            website = {
                id: editingWebsiteId || 'website_' + Date.now(),
                domains: [],  // Defined in JSON
                http_ports: [],  // Defined in JSON
                https_ports: [],  // Defined in JSON
                root: '',
                enabled: document.getElementById('website-enabled-adv').checked,
                advanced: advancedConfig,
                access_groups: []
            };
        }

        console.log('Saving website:', website);

        await apiCall('/api/websites', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(website)
        });

        showAlert('Website saved!');
        closeWebsiteModal();
        loadWebsites();
    } catch (err) {
        console.error('Save website error:', err);
        showAlert('Failed to save website: ' + err.message, 'error');
    }
}

async function editWebsite(id) {
    const websites = await apiCall('/api/websites');
    const website = websites.find(w => w.id === id);

    editingWebsiteId = id;
    document.getElementById('website-modal-title').textContent = 'Edit Website';

    if (website.advanced) {
        toggleWebsiteMode('advanced');
        // Advanced mode - all config is in the JSON, just load it
        document.getElementById('website-advanced').value = JSON.stringify(website.advanced, null, 2);
        document.getElementById('website-enabled-adv').checked = website.enabled;
    } else {
        toggleWebsiteMode('simple');
        // Clear advanced textarea to prevent showing old data
        document.getElementById('website-advanced').value = '';
        document.getElementById('website-domain').value = (website.domains || []).join(', ');

        // Handle port arrays - check for new format first, then fall back to legacy
        let http_ports, https_ports;
        if (website.http_ports || website.https_ports) {
            // New format
            http_ports = website.http_ports || [];
            https_ports = website.https_ports || [];
        } else if (website.listen_port !== undefined) {
            // Legacy format
            if (website.tls) {
                http_ports = [];
                https_ports = [website.listen_port];
            } else {
                http_ports = [website.listen_port];
                https_ports = [];
            }
        } else {
            http_ports = [80];
            https_ports = [];
        }

        document.getElementById('website-http-ports').value = http_ports.join(', ');
        document.getElementById('website-https-ports').value = https_ports.join(', ');
        document.getElementById('website-root').value = website.root;
        document.getElementById('website-index').value = website.index_files.join(', ');
        document.getElementById('website-auto-https').checked = website.auto_https || false;
        document.getElementById('website-php-enabled').checked = website.php_enabled || false;
        document.getElementById('website-enabled').checked = website.enabled;
        renderGroupSelector('website-access-groups', website.access_groups || []);
    }

    document.getElementById('website-modal').classList.add('active');
}

async function deleteWebsite(id) {
    if (confirm('Delete this website?')) {
        await apiCall(`/api/websites/${id}`, {method: 'DELETE'});
        showAlert('Website deleted');
        loadWebsites();
    }
}
// Auto-refresh for live updates
let refreshInterval = null;

function startAutoRefresh() {
    // Clear any existing interval
    if (refreshInterval) clearInterval(refreshInterval);
    
    // Check every 30 seconds
    refreshInterval = setInterval(async () => {
        try {
            // Update banner
            await checkForUpdates();
            
// Update caddy status and activity if on dashboard
            const dashboardPage = document.getElementById('dashboard-page');
            if (!dashboardPage.classList.contains('hidden')) {
                const status = await apiCall('/api/caddy/status');
                let statusText = status.status === 'running' ? '✅ Running (PID: ' + status.pid + ')' : '❌ Stopped';
                if (status.status === 'stopped' && status.reason) {
                    statusText += ' - ' + status.reason;
                }
                document.getElementById('caddy-status').textContent = statusText;
                
                // Refresh activity log
                await loadActivity();
            }
        } catch {}
    }, 30000);
}
// Initialize theme from localStorage (default to dark)
const savedTheme = localStorage.getItem('caddy-manager-theme') || 'dark';
setTheme(savedTheme);

// Initialize
checkAuth();

// Setup inactivity detection - reset timer on any user activity
const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'];
activityEvents.forEach(event => {
    document.addEventListener(event, resetInactivityTimer, true);
});