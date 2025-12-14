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

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Secure way to set HTML content - sanitizes by default
function setContent(element, content, allowHtml = false) {
    if (!element) return;
    if (allowHtml) {
        // For trusted HTML content only (from our own template strings, not user input)
        element.innerHTML = content;
    } else {
        // Default: treat as plain text to prevent XSS
        element.textContent = content;
    }
}

// Secure way to create HTML from template with escaped values
function createSecureHtml(template, values = {}) {
    let result = template;
    for (const [key, value] of Object.entries(values)) {
        const escaped = escapeHtml(String(value));
        result = result.replace(new RegExp(`{{${key}}}`, 'g'), escaped);
    }
    return result;
}

// Toggle password visibility for password fields
function togglePasswordVisibility(fieldId, button) {
    const field = document.getElementById(fieldId);
    if (!field) return;

    if (field.type === 'password') {
        field.type = 'text';
        button.textContent = '🙈'; // Eye closed emoji
        button.title = 'Hide';
    } else {
        field.type = 'password';
        button.textContent = '👁️'; // Eye open emoji
        button.title = 'Show';
    }
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
        if (response.status === 401 || response.status === 403) {
            showLogin();
            throw new Error('Session expired or not authenticated');
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
        // Only log errors to console if showErrors is true (suppress on login page)
        if (showErrors) {
            console.error('API Call Error:', err);
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
                    setContent(document.getElementById('login-alert'),
                        '<div class="alert alert-warning">Please enter your 2FA code from your authenticator app</div>', true);
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
        setContent(document.getElementById('login-alert'), '');

        // Check if password change is required
        if (data.needs_password_change) {
            showAlert('Please change your default password for security reasons', 'warning');
            // Could redirect to settings or show password change modal here
        }

        // Check if there's a return URL from OAuth flow
        const returnTo = sessionStorage.getItem('returnTo');
        if (returnTo) {
            sessionStorage.removeItem('returnTo');
            window.location.href = returnTo;
            return;
        }

        showApp();
        await checkForUpdates();
        await loadDashboard();
        // Update authentication nav visibility after successful login
        await initAuthNav();
    } catch (err) {
        console.error('Login error:', err);
        const errorMsg = escapeHtml(err.message || 'Invalid credentials');
        setContent(document.getElementById('login-alert'),
            '<div class="alert alert-error">' + errorMsg + '</div>', true);
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

// Auto-install removed in v1.3.11 - use caddyman-update.exe instead

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
    if (page === 'authentication') loadAuthenticationPage();
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
        await loadPendingInvites();
        await updateAuthServicesStatus();
        await checkForUpdates();
    } catch {}
}

async function checkForUpdates() {
    try {
        const updateData = await apiCall('/api/update/check');
        const updateStatus = document.getElementById('update-status');
        const updateVersion = document.getElementById('update-version');
        const updateButton = document.getElementById('update-button-text');

        if (updateData.update_available) {
            updateVersion.textContent = `v${updateData.update_available.version}`;
            updateStatus.style.display = 'block';

            // Check if running as executable or script
            if (!runtimeInfo) {
                await loadRuntimeInfo();
            }

            if (runtimeInfo && runtimeInfo.is_executable) {
                // EXE mode: Can auto-update
                updateButton.textContent = '⬇️ Download & Install Update';
            } else {
                // Script mode: Show download link
                updateButton.textContent = '🔗 View Download Page';
            }
        } else {
            updateStatus.style.display = 'none';
        }
    } catch (err) {
        console.error('Failed to check for updates:', err);
    }
}

async function handleUpdate() {
    // Always show download link - use caddyman-update.exe for auto-install
    const updateData = await apiCall('/api/update/check');
    if (updateData.update_available && updateData.update_available.download_url) {
        window.open(updateData.update_available.download_url, '_blank');
        showAlert('Download started. Use caddyman-update.exe to automatically install updates.', 'info');
    }
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
        setContent(warningsList, warnings.warnings.map(w => {
            const username = escapeHtml(w.username);
            const message = escapeHtml(w.message);
            return `<div class="alert alert-warning" style="margin-bottom: 10px;">
                <strong>${username}</strong>: ${message}
            </div>`;
        }).join(''), true);
    } catch (err) {
        console.error('Failed to load security warnings:', err);
    }
}

async function loadActivity() {
    try {
        const data = await apiCall('/api/activity');
        const log = document.getElementById('activity-log');
        
        if (data.activities.length === 0) {
            setContent(log, '<p style="color: var(--text-secondary);">No recent activity</p>', true);
            return;
        }

        setContent(log, data.activities.map(activity => {
            const time = escapeHtml(new Date(activity.timestamp).toLocaleString());
            const username = escapeHtml(activity.username);
            const action = escapeHtml(activity.action);
            const details = activity.details ? escapeHtml(activity.details) : '';
            const ip = escapeHtml(activity.ip);
            const actionColor = activity.action.includes('FAILED') || activity.action.includes('DENIED')
                ? 'var(--danger)'
                : activity.action.includes('SUCCESS') || activity.action.includes('LOGIN')
                ? 'var(--success)'
                : 'var(--text-primary)';

            return `
                <div style="padding: 8px; border-bottom: 1px solid var(--border); line-height: 1.6;">
                    <div style="color: var(--text-secondary);">${time}</div>
                    <div>
                        <strong style="color: var(--accent);">${username}</strong>
                        <span style="color: ${actionColor}; font-weight: 500;">${action}</span>
                    </div>
                    ${details ? `<div style="color: var(--text-secondary); font-size: 11px;">${details}</div>` : ''}
                    <div style="color: var(--text-secondary); font-size: 11px;">IP: ${ip}</div>
                </div>
            `;
        }).join(''), true);
    } catch {}
}

async function loadNotifications() {
    try {
        const data = await apiCall('/api/notifications');
        const log = document.getElementById('notification-log');

        if (data.notifications.length === 0) {
            setContent(log, '<p style="color: var(--text-secondary);">No notifications sent yet</p>', true);
            return;
        }

        setContent(log, data.notifications.map(notif => {
            const time = escapeHtml(new Date(notif.timestamp).toLocaleString());
            const title = escapeHtml(notif.title);
            const message = escapeHtml(notif.message);
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
                        <strong style="color: ${typeColor};">${title}</strong>
                    </div>
                    <div style="color: var(--text-secondary); font-size: 11px; white-space: pre-wrap;">${message}</div>
                </div>
            `;
        }).join(''), true);
    } catch {}
}

async function loadPendingInvites() {
    try {
        const invites = await apiCall('/api/users/pending-invites');
        const card = document.getElementById('pending-invites-card');
        const list = document.getElementById('pending-invites-list');

        if (invites.length === 0) {
            card.style.display = 'none';
            return;
        }

        card.style.display = 'block';
        setContent(list, invites.map(invite => {
            const createdTime = escapeHtml(new Date(invite.created_at * 1000).toLocaleString());
            const username = escapeHtml(invite.username);
            const email = escapeHtml(invite.email);
            const timeRemaining = escapeHtml(invite.time_remaining);
            const createdBy = escapeHtml(invite.created_by);
            const groupNames = invite.groups.map(gid => {
                const group = allGroups.find(g => g.id === gid);
                return group ? escapeHtml(group.name) : escapeHtml(gid);
            }).join(', ');

            return `
                <div style="padding: 12px; border-bottom: 1px solid var(--border); line-height: 1.6;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                        <strong style="color: var(--accent);">${username}</strong>
                        <span style="color: var(--warning); font-weight: 500;">⏳ ${timeRemaining}</span>
                    </div>
                    <div style="color: var(--text-secondary); font-size: 13px;">📧 ${email}</div>
                    ${groupNames ? `<div style="color: var(--text-secondary); font-size: 12px;">Groups: ${groupNames}</div>` : ''}
                    <div style="color: var(--text-secondary); font-size: 11px; margin-top: 3px;">Created by ${createdBy} on ${createdTime}</div>
                </div>
            `;
        }).join(''), true);
    } catch (err) {
        console.error('Failed to load pending invites:', err);
    }
}

async function updateAuthServicesStatus() {
    try {
        const settings = await apiCall('/api/settings', {}, false);
        const authCard = document.getElementById('auth-services-card');

        // Check if authentication protocols are enabled
        if (!settings.auth_protocols_enabled) {
            authCard.style.display = 'none';
            return;
        }

        // Track if any service is enabled
        let anyServiceEnabled = false;

        // OIDC Provider
        const oidcStatus = document.getElementById('oidc-service-status');
        if (settings.oidc_enabled) {
            oidcStatus.style.display = 'block';
            anyServiceEnabled = true;
        } else {
            oidcStatus.style.display = 'none';
        }

        // LDAP Server
        const ldapStatus = document.getElementById('ldap-service-status');
        const ldapPortInfo = document.getElementById('ldap-port-info');
        if (settings.ldap_enabled) {
            const port = settings.ldap_port || 389;
            ldapPortInfo.textContent = `✅ Running on port ${port}`;
            ldapStatus.style.display = 'block';
            anyServiceEnabled = true;
        } else {
            ldapStatus.style.display = 'none';
        }

        // RADIUS Server
        const radiusStatus = document.getElementById('radius-service-status');
        const radiusPortInfo = document.getElementById('radius-port-info');
        if (settings.radius_enabled) {
            const port = settings.radius_auth_port || 1812;
            radiusPortInfo.textContent = `✅ Running on port ${port}`;
            radiusStatus.style.display = 'block';
            anyServiceEnabled = true;
        } else {
            radiusStatus.style.display = 'none';
        }

        // SMTP/Email
        const smtpStatus = document.getElementById('smtp-service-status');
        if (settings.smtp_enabled) {
            smtpStatus.style.display = 'block';
            anyServiceEnabled = true;
        } else {
            smtpStatus.style.display = 'none';
        }

        // Show card only if at least one service is enabled
        if (anyServiceEnabled) {
            authCard.style.display = 'block';
        } else {
            authCard.style.display = 'none';
        }
    } catch (err) {
        // Hide card on error (user not authenticated yet, etc.)
        const authCard = document.getElementById('auth-services-card');
        if (authCard) {
            authCard.style.display = 'none';
        }
    }
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
    document.getElementById('auth-protocols-enabled').checked = data.auth_protocols_enabled || false;
    document.getElementById('caddy-log-level').value = data.caddy_log_level || 'WARN';

    // Load branding & domain settings
    document.getElementById('organization-name').value = data.organization_name || 'CaddyMAN';
    document.getElementById('domain-url').value = data.domain_url || 'http://localhost:8000';
    document.getElementById('admin-path-mode').checked = data.admin_path_mode || false;

    // Show/hide Authentication nav item based on setting
    updateAuthenticationNavVisibility(data.auth_protocols_enabled || false);

    // Theme: browser-only via localStorage (not synced to backend)
    const savedTheme = localStorage.getItem('caddy-manager-theme') || 'dark';
    document.body.className = savedTheme;
    document.querySelectorAll('#theme-toggle .toggle-btn').forEach((btn, idx) => {
        const themes = ['light', 'dark', 'black'];
        btn.classList.toggle('active', themes[idx] === savedTheme);
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

    // Start with current settings to preserve authentication settings
    const settings = {...currentSettings};

    // Update only the fields from this page
    settings.health_check_enabled = document.getElementById('health-check-enabled').checked;
    settings.health_check_domain = document.getElementById('health-check-domain').value;
    settings.health_check_interval = parseInt(document.getElementById('health-check-interval').value);
    settings.restart_after_failures = parseInt(document.getElementById('restart-after-failures').value);
    settings.notification_service = document.getElementById('notification-service').value;
    settings.notification_url = document.getElementById('notification-url').value;
    settings.notification_token = document.getElementById('notification-token').value;
    settings.notification_events = notificationEvents;
    settings.php_enabled = document.getElementById('php-enabled').checked;
    settings.php_path = document.getElementById('php-path').value;
    settings.manager_port = parseInt(document.getElementById('manager-port').value);
    settings.caddy_admin_port = parseInt(document.getElementById('caddy-admin-port').value);
    settings.enhanced_security = document.getElementById('enhanced-security').checked;
    settings.auth_protocols_enabled = document.getElementById('auth-protocols-enabled').checked;
    settings.caddy_log_level = document.getElementById('caddy-log-level').value;
    settings.organization_name = document.getElementById('organization-name').value;
    settings.domain_url = document.getElementById('domain-url').value;
    settings.admin_path_mode = document.getElementById('admin-path-mode').checked;
    await apiCall('/api/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(settings)
    });

    // Update Authentication nav visibility after saving
    updateAuthenticationNavVisibility(settings.auth_protocols_enabled);

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
    setContent(list, groups.map(g => {
        const name = escapeHtml(g.name);
        const description = escapeHtml(g.description || 'No description');
        const id = escapeHtml(g.id);
        return `
        <div class="item">
            <div class="item-info">
                <h3>${name}</h3>
                <p>${description}</p>
            </div>
            <div class="item-actions">
                <button class="btn btn-primary" onclick="editGroup('${id}')">Edit</button>
                ${g.system ? '<span class="status-badge status-active">System</span>' :
                `<button class="btn btn-danger" onclick="deleteGroup('${id}')">Delete</button>`}
            </div>
        </div>
    `;
    }).join(''), true);
}

async function openGroupModal() {
    editingGroupId = null;
    document.getElementById('group-modal-title').textContent = 'Add Group';
    document.getElementById('group-name').value = '';
    document.getElementById('group-description').value = '';
    document.getElementById('group-force-2fa').checked = false;
    document.getElementById('group-oidc-claims').value = '';

    // Show/hide OIDC claims field based on settings
    try {
        const settings = await apiCall('/api/settings', {}, false);
        const oidcEnabled = settings?.oidc_enabled || false;
        const claimsSection = document.getElementById('group-oidc-claims-section');
        if (claimsSection) {
            claimsSection.style.display = oidcEnabled ? 'block' : 'none';
        }
    } catch (err) {
        console.error('Failed to load settings:', err);
    }

    document.getElementById('group-modal').classList.add('active');
}

function closeGroupModal() {
    document.getElementById('group-modal').classList.remove('active');
}

async function saveGroup() {
    try {
        const oidcClaims = document.getElementById('group-oidc-claims').value.trim();

        // Validate JSON if provided
        if (oidcClaims) {
            try {
                JSON.parse(oidcClaims);
            } catch (e) {
                showAlert('Invalid JSON in OIDC Claims field', 'error');
                return;
            }
        }

        const group = {
            id: editingGroupId || 'group_' + Date.now(),
            name: document.getElementById('group-name').value,
            description: document.getElementById('group-description').value,
            force_2fa: document.getElementById('group-force-2fa').checked,
            oidc_claims: oidcClaims || null
        };

        // Use PUT for editing, POST for creating
        const method = editingGroupId ? 'PUT' : 'POST';
        const url = editingGroupId ? `/api/groups/${editingGroupId}` : '/api/groups';

        await apiCall(url, {
            method: method,
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
    document.getElementById('group-description').value = group.description || '';
    document.getElementById('group-force-2fa').checked = group.force_2fa || false;
    document.getElementById('group-oidc-claims').value = group.oidc_claims || '';

    // Show/hide OIDC claims field based on settings
    try {
        const settings = await apiCall('/api/settings', {}, false);
        const oidcEnabled = settings?.oidc_enabled || false;
        const claimsSection = document.getElementById('group-oidc-claims-section');
        if (claimsSection) {
            claimsSection.style.display = oidcEnabled ? 'block' : 'none';
        }
    } catch (err) {
        console.error('Failed to load settings:', err);
    }

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

    // Check if SMTP is enabled to show invite link button
    const settings = await apiCall('/api/settings', {}, false);
    const inviteBtn = document.getElementById('invite-link-btn');
    if (settings && settings.smtp_enabled) {
        inviteBtn.style.display = 'inline-block';
    } else {
        inviteBtn.style.display = 'none';
    }

    const list = document.getElementById('user-list');
    setContent(list, users.map(u => {
        // Map group IDs to group names
        const groupNames = u.groups.map(gid => {
            const group = allGroups.find(g => g.id === gid);
            return group ? escapeHtml(group.name) : escapeHtml(gid);
        }).join(', ');

        // Check if user has 2FA enabled
        const has2FA = u.totp_enabled ? ' <span class="status-badge status-active" style="font-size: 11px; padding: 3px 8px;">🔐 2FA</span>' : '';

        const username = escapeHtml(u.username);
        const userId = escapeHtml(u.id);

        return `
        <div class="item">
            <div class="item-info">
                <h3>${username}</h3>
                <p>Groups: ${groupNames || 'None'}${has2FA}</p>
            </div>
            <div class="item-actions">
<button class="btn btn-primary" onclick="editUser('${userId}')">Edit</button>
${u.groups.includes('admin_group') && users.filter(user => user.groups.includes('admin_group')).length === 1
    ? '<span class="status-badge status-active">Last Admin</span>'
    : `<button class="btn btn-danger" onclick="deleteUser('${userId}')">Delete</button>`}
            </div>
        </div>
        `;
    }).join(''), true);
}

function openUserModal() {
    editingUserId = null;
    document.getElementById('user-modal-title').textContent = 'Add User';
    document.getElementById('user-username').value = '';
    document.getElementById('user-password').value = '';
    document.getElementById('user-email').value = '';
    renderGroupSelector('user-groups', []);
    document.getElementById('user-2fa-section').classList.add('hidden');
    document.getElementById('user-modal').classList.add('active');
}

function closeUserModal() {
    document.getElementById('user-modal').classList.remove('active');
}

function renderGroupSelector(elementId, selectedGroups) {
    const container = document.getElementById(elementId);
    const escapedElementId = escapeHtml(elementId);

    setContent(container, `
        <div class="multi-select" id="${escapedElementId}-display">
            ${selectedGroups.map(g => {
                const groupName = escapeHtml(allGroups.find(gr => gr.id === g)?.name || g);
                const groupId = escapeHtml(g);
                const escapedElemId = escapeHtml(elementId);
                return `
                <div class="multi-select-tag">
                    ${groupName}
                    <button onclick="removeGroupFromUser('${escapedElemId}', '${groupId}')">×</button>
                </div>
            `;
            }).join('')}
        </div>
        <select id="${escapedElementId}-select" onchange="addGroupToUser('${escapedElementId}')" style="width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; margin-top: 8px; cursor: pointer;">
            <option value="">+ Add group</option>
            ${allGroups.filter(g => !selectedGroups.includes(g.id)).map(g => {
                const groupId = escapeHtml(g.id);
                const groupName = escapeHtml(g.name);
                return `<option value="${groupId}">${groupName}</option>`;
            }).join('')}
        </select>
    `, true);
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

function getSelectedGroups(elementId) {
    const container = document.getElementById(elementId);
    return JSON.parse(container.dataset.groups || '[]');
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
                email: document.getElementById('user-email').value || '',
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
                email: document.getElementById('user-email').value || '',
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

    if (!user) {
        showAlert('User not found', 'error');
        return;
    }

    editingUserId = id;
    document.getElementById('user-modal-title').textContent = 'Edit User';
    document.getElementById('user-username').value = user.username;
    document.getElementById('user-password').value = '';
    document.getElementById('user-password').placeholder = 'Leave empty to keep current';
    // Explicitly set email value (ensure it clears if no email exists)
    const emailInput = document.getElementById('user-email');
    emailInput.value = user.email || '';
    console.log(`Editing user ${user.username}, email: ${user.email || '(empty)'}`);
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

// Invite Link Functions
function openInviteLinkModal() {
    document.getElementById('invite-username').value = '';
    document.getElementById('invite-email').value = '';
    renderGroupSelector('invite-groups', []);
    document.getElementById('invite-expiry').value = '24';
    document.getElementById('invite-link-result').classList.add('hidden');
    document.getElementById('invite-link-modal').classList.add('active');
}

function closeInviteLinkModal() {
    document.getElementById('invite-link-modal').classList.remove('active');
}

async function generateInviteLink() {
    try {
        const container = document.getElementById('invite-groups');
        const groups = JSON.parse(container.dataset.groups || '[]');

        const inviteData = {
            username: document.getElementById('invite-username').value.trim(),
            email: document.getElementById('invite-email').value.trim(),
            groups: groups,
            expiry_hours: parseInt(document.getElementById('invite-expiry').value)
        };

        const result = await apiCall('/api/users/invite-link', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(inviteData)
        });

        // Show the generated link
        document.getElementById('invite-link-url').value = result.invite_url;
        document.getElementById('invite-link-result').classList.remove('hidden');

        showAlert('Invite link generated and sent!', 'success');
    } catch (err) {
        showAlert('Failed to generate invite link: ' + err.message, 'error');
    }
}

async function copyInviteLink() {
    const linkInput = document.getElementById('invite-link-url');
    try {
        await navigator.clipboard.writeText(linkInput.value);
        showAlert('Invite link copied to clipboard!', 'success');
    } catch (err) {
        // Fallback for older browsers
        linkInput.select();
        showAlert('Please copy the link manually (Ctrl+C)', 'info');
    }
}

// Proxies
async function loadProxies() {
    const proxies = await apiCall('/api/proxies');
    const list = document.getElementById('proxy-list');
    setContent(list, proxies.map(p => {
        const features = [];
        const displayDomain = (p.domains && p.domains.length) ? p.domains.map(d => escapeHtml(d)).join(', ') : 'All domains';

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
        if (p.load_balance) features.push(`⚖️ ${escapeHtml(p.load_balance)}`);
        if (p.access_groups && p.access_groups.length) {
            const groupNames = p.access_groups.map(gid => {
                const group = allGroups.find(g => g.id === gid);
                return group ? escapeHtml(group.name) : escapeHtml(gid);
            }).join(', ');
            features.push(`🔐 ${groupNames}`);
        }

        const upstream = escapeHtml(p.upstream);
        const proxyId = escapeHtml(p.id);

        return `
            <div class="item">
                <div class="item-info">
                    <h3>${displayDomain}</h3>
                    <p>→ ${upstream}</p>
                    ${features.length ? `<p style="font-size: 12px; margin-top: 5px;">${features.join(' • ')}</p>` : ''}
                </div>
                <div class="item-actions">
                    <span class="status-badge ${p.enabled ? 'status-active' : 'status-inactive'}">
                        ${p.enabled ? 'Active' : 'Disabled'}
                    </span>
                    <button class="btn btn-primary" onclick="editProxy('${proxyId}')">Edit</button>
                    <button class="btn btn-danger" onclick="deleteProxy('${proxyId}')">Delete</button>
                </div>
            </div>
        `;
    }).join(''), true);
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
    setContent(list, websites.map(w => {
        const features = [];
        const displayDomain = (w.domains && w.domains.length) ? w.domains.map(d => escapeHtml(d)).join(', ') : 'All domains';

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
                return group ? escapeHtml(group.name) : escapeHtml(gid);
            }).join(', ');
            features.push(`🔐 ${groupNames}`);
        }

        const root = escapeHtml(w.root);
        const websiteId = escapeHtml(w.id);

        return `
            <div class="item">
                <div class="item-info">
                    <h3>${displayDomain}</h3>
                    <p>📁 ${root}</p>
                    ${features.length ? `<p style="font-size: 12px; margin-top: 5px;">${features.join(' • ')}</p>` : ''}
                </div>
                <div class="item-actions">
                    <span class="status-badge ${w.enabled ? 'status-active' : 'status-inactive'}">
                        ${w.enabled ? 'Active' : 'Disabled'}
                    </span>
                    <button class="btn btn-primary" onclick="editWebsite('${websiteId}')">Edit</button>
                    <button class="btn btn-danger" onclick="deleteWebsite('${websiteId}')">Delete</button>
                </div>
            </div>
        `;
    }).join(''), true);
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

// Initialize authentication nav visibility from settings
async function initAuthNav() {
    try {
        // Suppress error alerts for unauthenticated users on login page
        const settings = await apiCall('/api/settings', {}, false);
        updateAuthenticationNavVisibility(settings.auth_protocols_enabled || false);
    } catch (e) {
        // If settings can't be loaded yet (not authenticated), hide by default
        updateAuthenticationNavVisibility(false);
    }
}
initAuthNav();

// Initialize
checkAuth();

// Setup inactivity detection - reset timer on any user activity
const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'];
activityEvents.forEach(event => {
    document.addEventListener(event, resetInactivityTimer, true);
});

// ========================================
// Authentication Page Functions
// ========================================

async function loadAuthenticationPage() {
    // Load groups if not already loaded
    if (allGroups.length === 0) {
        try {
            const groups = await apiCall('/api/groups');
            allGroups = groups;
        } catch (error) {
            console.error('Failed to load groups:', error);
        }
    }

    // Load OAuth clients
    await loadOAuthClients();

    // Load settings and populate form
    const settings = await apiCall('/api/settings');

    // Update protocol status indicators
    updateProtocolStatus('oidc', settings.oidc_enabled);
    updateProtocolStatus('ldap', settings.ldap_enabled);
    updateProtocolStatus('radius', settings.radius_enabled);
    updateProtocolStatus('smtp', settings.smtp_enabled);

    // Populate OIDC settings
    document.getElementById('oidc_enabled').checked = settings.oidc_enabled || false;
    document.getElementById('oidc_issuer').value = settings.oidc_issuer || '';

    // Populate LDAP settings
    document.getElementById('ldap_enabled').checked = settings.ldap_enabled || false;
    document.getElementById('ldap_port').value = settings.ldap_port || 389;
    document.getElementById('ldap_base_dn').value = settings.ldap_base_dn || '';
    document.getElementById('ldap_bind_dn').value = settings.ldap_bind_dn || '';
    renderGroupSelector('ldap-allowed-groups', settings.ldap_allowed_groups || []);

    // Update LDAP client configuration display
    updateLDAPConfigDisplay();

    // Populate RADIUS settings
    document.getElementById('radius_enabled').checked = settings.radius_enabled || false;
    document.getElementById('radius_auth_port').value = settings.radius_auth_port || 1812;
    document.getElementById('radius_acct_port').value = settings.radius_acct_port || 1813;
    document.getElementById('radius_secret').value = settings.radius_secret || '';
    document.getElementById('radius_vlan_assignment').checked = settings.radius_vlan_assignment || false;
    document.getElementById('radius_eap_method').value = settings.radius_eap_method || 'PAP';
    renderGroupSelector('radius-allowed-groups', settings.radius_allowed_groups || []);

    // Populate SMTP settings
    document.getElementById('smtp_enabled').checked = settings.smtp_enabled || false;
    document.getElementById('smtp_server').value = settings.smtp_server || '';
    document.getElementById('smtp_port').value = settings.smtp_port || 587;
    document.getElementById('smtp_use_tls').checked = settings.smtp_use_tls !== false;
    document.getElementById('smtp_username').value = settings.smtp_username || '';
    document.getElementById('smtp_password').value = settings.smtp_password || '';
    document.getElementById('smtp_from_address').value = settings.smtp_from_address || '';
    document.getElementById('smtp_from_name').value = settings.smtp_from_name || 'CaddyIAM';
}

function updateProtocolStatus(protocol, enabled) {
    const statusEl = document.getElementById(`${protocol}-status`);
    if (enabled) {
        setContent(statusEl, '<span style="color: var(--success);">● Enabled</span>', true);
    } else {
        setContent(statusEl, '<span style="color: var(--danger);">● Disabled</span>', true);
    }
}

async function saveAuthenticationSettings() {
    try {
        const settings = await apiCall('/api/settings');

        // Update authentication settings
        settings.oidc_enabled = document.getElementById('oidc_enabled').checked;
        settings.oidc_issuer = document.getElementById('oidc_issuer').value;

        settings.ldap_enabled = document.getElementById('ldap_enabled').checked;
        settings.ldap_port = parseInt(document.getElementById('ldap_port').value);
        settings.ldap_base_dn = document.getElementById('ldap_base_dn').value;
        settings.ldap_bind_dn = document.getElementById('ldap_bind_dn').value;
        settings.ldap_allowed_groups = getSelectedGroups('ldap-allowed-groups');

        settings.radius_enabled = document.getElementById('radius_enabled').checked;
        settings.radius_auth_port = parseInt(document.getElementById('radius_auth_port').value);
        settings.radius_acct_port = parseInt(document.getElementById('radius_acct_port').value);
        settings.radius_secret = document.getElementById('radius_secret').value;
        settings.radius_vlan_assignment = document.getElementById('radius_vlan_assignment').checked;
        settings.radius_eap_method = document.getElementById('radius_eap_method').value;
        settings.radius_allowed_groups = getSelectedGroups('radius-allowed-groups');

        settings.smtp_enabled = document.getElementById('smtp_enabled').checked;
        settings.smtp_server = document.getElementById('smtp_server').value;
        settings.smtp_port = parseInt(document.getElementById('smtp_port').value);
        settings.smtp_use_tls = document.getElementById('smtp_use_tls').checked;
        settings.smtp_username = document.getElementById('smtp_username').value;
        settings.smtp_password = document.getElementById('smtp_password').value;
        settings.smtp_from_address = document.getElementById('smtp_from_address').value;
        settings.smtp_from_name = document.getElementById('smtp_from_name').value;

        await apiCall('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        alert('Authentication settings saved successfully');
        await loadAuthenticationPage(); // Reload to update status
    } catch (error) {
        alert(`Failed to save settings: ${error.message}`);
    }
}

async function sendTestEmail(event) {
    const button = event.target;
    const originalText = button.textContent;

    try {
        // Check if any admin has an email address
        const users = await apiCall('/api/users');
        const adminWithEmail = users.find(u => u.groups.includes('admin_group') && u.email);

        if (!adminWithEmail) {
            alert('No admin users have email addresses configured. Please add an email address to at least one admin user before testing.');
            return;
        }

        // Confirm action
        if (!confirm('Send a test email to all admin users?')) {
            return;
        }

        // Show loading state
        button.disabled = true;
        button.textContent = 'Sending...';

        await apiCall('/api/smtp/test-email', {
            method: 'POST'
        });

        button.textContent = originalText;
        button.disabled = false;

        alert('Test email sent successfully! Check admin inboxes.');
    } catch (error) {
        button.textContent = originalText;
        button.disabled = false;
        alert(`Failed to send test email: ${error.message}`);
    }
}

async function loadOAuthClients() {
    try {
        // Load groups first if not already loaded
        if (allGroups.length === 0) {
            try {
                const groups = await apiCall('/api/groups');
                allGroups = groups;
            } catch (error) {
                console.error('Failed to load groups:', error);
            }
        }

        const clients = await apiCall('/api/oauth/clients');
        const container = document.getElementById('oauth-clients-list');

        if (clients.length === 0) {
            setContent(container, '<p style="color: var(--text-muted); text-align: center; padding: 20px;">No OAuth clients configured</p>', true);
            return;
        }

        setContent(container, clients.map(client => {
            // Get group names for display
            const groupNames = (client.allowed_groups || []).map(groupId => {
                const group = allGroups.find(g => g.id === groupId);
                return group ? group.name : groupId;
            });
            const groupsDisplay = groupNames.length > 0
                ? groupNames.map(name => `<span style="background: var(--primary); color: white; padding: 2px 8px; border-radius: 3px; display: inline-block; margin: 2px; font-size: 0.85em;">${escapeHtml(name)}</span>`).join('')
                : '<span style="color: var(--text-muted); font-style: italic;">All groups</span>';

            const clientId = escapeHtml(client.client_id);

            return `
            <div style="padding: 15px; background: var(--bg-secondary); border-radius: 6px; margin-bottom: 15px; border: 1px solid var(--border);">
                <!-- Header row: Name, Client ID, and Action Buttons -->
                <div class="oauth-client-card">
                    <div style="flex: 1; min-width: 0;">
                        <h4 style="margin: 0 0 5px 0;">${escapeHtml(client.name)}</h4>
                        <p style="margin: 0; font-size: 0.85em; color: var(--text-muted); word-wrap: break-word;">
                            <strong>Client ID:</strong> <code style="background: var(--bg-primary); padding: 2px 6px; border-radius: 3px; word-break: break-all;">${clientId}</code>
                        </p>
                    </div>
                    <div class="oauth-client-actions">
                        <button class="btn btn-secondary" onclick="editOAuthClient('${clientId}')">Edit</button>
                        <button class="btn btn-danger" onclick="deleteOAuthClient('${clientId}')">Delete</button>
                    </div>
                </div>

                <!-- Full-width details section -->
                <div style="margin-top: 12px;">
                    <p style="margin: 0 0 10px 0; font-size: 0.9em; color: var(--text-muted);">
                        <strong>Redirect URIs:</strong><br>
                        ${client.redirect_uris.map(uri => `<code style="background: var(--bg-primary); padding: 2px 6px; border-radius: 3px; display: inline-block; margin: 2px; word-break: break-all; max-width: 100%;">${escapeHtml(uri)}</code>`).join('')}
                    </p>
                    <p style="margin: 10px 0 0 0; font-size: 0.9em; color: var(--text-muted);">
                        <strong>Allowed Groups:</strong><br>
                        ${groupsDisplay}
                    </p>
                </div>
            </div>
            `;
        }).join(''), true);
    } catch (error) {
        alert(`Failed to load OAuth clients: ${error.message}`);
    }
}

async function openOAuthClientModal() {
    // Load groups if not already loaded
    if (allGroups.length === 0) {
        try {
            const groups = await apiCall('/api/groups');
            allGroups = groups;
        } catch (error) {
            console.error('Failed to load groups:', error);
        }
    }

    document.getElementById('oauth-client-name').value = '';
    document.getElementById('oauth-redirect-uris').value = '';

    // Render group selector for OAuth client
    renderGroupSelector('oauth-client-groups', []);

    // Reset modal title for creating new client
    document.querySelector('#oauth-client-modal .modal-header h2').textContent = 'Add OAuth/OIDC Client';

    // Clear any editing state
    document.getElementById('oauth-client-modal').dataset.editingClientId = '';

    // Show the custom Client ID field for creation (hidden in edit mode)
    document.getElementById('oauth-custom-client-id-group').style.display = 'block';
    document.getElementById('oauth-custom-client-id').value = '';

    document.getElementById('oauth-client-modal').classList.add('active');
}

function closeOAuthClientModal() {
    document.getElementById('oauth-client-modal').classList.remove('active');
    // Clear the editing client ID
    document.getElementById('oauth-client-modal').dataset.editingClientId = '';
}

async function editOAuthClient(clientId) {
    try {
        // Load groups if not already loaded
        if (allGroups.length === 0) {
            try {
                const groups = await apiCall('/api/groups');
                allGroups = groups;
            } catch (error) {
                console.error('Failed to load groups:', error);
            }
        }

        // Fetch the existing client data
        const client = await apiCall(`/api/oauth/clients/${clientId}`);

        // Populate the modal with existing data
        document.getElementById('oauth-client-name').value = client.name;
        document.getElementById('oauth-redirect-uris').value = client.redirect_uris.join('\n');

        // Select the allowed groups - this will now properly render with the loaded groups
        renderGroupSelector('oauth-client-groups', client.allowed_groups || []);

        // Hide the custom Client ID field (only shown during creation)
        document.getElementById('oauth-custom-client-id-group').style.display = 'none';

        // Store the client ID in the modal so saveOAuthClient knows we're editing
        document.getElementById('oauth-client-modal').dataset.editingClientId = clientId;

        // Change the modal title
        document.querySelector('#oauth-client-modal .modal-header h2').textContent = 'Edit OAuth Client';

        // Open the modal
        document.getElementById('oauth-client-modal').classList.add('active');
    } catch (error) {
        alert(`Failed to load OAuth client: ${error.message}`);
    }
}

async function saveOAuthClient() {
    try {
        const name = document.getElementById('oauth-client-name').value.trim();
        const redirectUrisText = document.getElementById('oauth-redirect-uris').value.trim();

        if (!name) {
            alert('Client name is required');
            return;
        }

        if (!redirectUrisText) {
            alert('At least one redirect URI is required');
            return;
        }

        const redirect_uris = redirectUrisText.split('\n').map(uri => uri.trim()).filter(uri => uri);

        // Get selected groups
        const allowed_groups = getSelectedGroups('oauth-client-groups');

        // Check if we're editing an existing client
        const editingClientId = document.getElementById('oauth-client-modal').dataset.editingClientId;

        if (editingClientId) {
            // Edit mode - update existing client (Client ID cannot be changed)
            await apiCall(`/api/oauth/clients/${editingClientId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, redirect_uris, allowed_groups })
            });

            showAlert('OAuth client updated successfully!', 'success');
            closeOAuthClientModal();
            await loadOAuthClients();
        } else {
            // Create mode - get custom Client ID if provided
            const customClientId = document.getElementById('oauth-custom-client-id').value.trim();

            const requestBody = {
                name,
                redirect_uris,
                allowed_groups
            };

            // Include custom_client_id only if provided
            if (customClientId) {
                requestBody.custom_client_id = customClientId;
            }

            const result = await apiCall('/api/oauth/clients', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            // Show credentials modal with copy buttons
            document.getElementById('oauth-client-id-display').value = result.client_id;
            document.getElementById('oauth-client-secret-display').value = result.client_secret;

            closeOAuthClientModal();
            document.getElementById('oauth-credentials-modal').classList.add('active');

            await loadOAuthClients();
        }
    } catch (error) {
        alert(`Failed to save OAuth client: ${error.message}`);
    }
}

function closeOAuthCredentialsModal() {
    document.getElementById('oauth-credentials-modal').classList.remove('active');
    document.getElementById('oauth-client-id-display').value = '';
    document.getElementById('oauth-client-secret-display').value = '';
}

async function copyOAuthClientId() {
    const clientId = document.getElementById('oauth-client-id-display').value;
    try {
        await navigator.clipboard.writeText(clientId);
        showAlert('Client ID copied to clipboard!', 'success');
    } catch (err) {
        // Fallback for older browsers
        document.getElementById('oauth-client-id-display').select();
        showAlert('Please copy the Client ID manually (Ctrl+C)', 'info');
    }
}

async function copyOAuthClientSecret() {
    const clientSecret = document.getElementById('oauth-client-secret-display').value;
    try {
        await navigator.clipboard.writeText(clientSecret);
        showAlert('Client Secret copied to clipboard!', 'success');
    } catch (err) {
        // Fallback for older browsers
        document.getElementById('oauth-client-secret-display').select();
        showAlert('Please copy the Client Secret manually (Ctrl+C)', 'info');
    }
}

async function deleteOAuthClient(clientId) {
    if (!confirm('Are you sure you want to delete this OAuth client? This will revoke access for all applications using this client.')) {
        return;
    }

    try {
        await apiCall(`/api/oauth/clients/${clientId}`, {
            method: 'DELETE'
        });

        await loadOAuthClients();
        alert('OAuth client deleted');
    } catch (error) {
        alert(`Failed to delete OAuth client: ${error.message}`);
    }
}

async function updateLDAPConfigDisplay() {
    // Update the LDAP client configuration display
    const port = document.getElementById('ldap_port').value || '389';
    const baseDN = document.getElementById('ldap_base_dn').value || 'dc=example,dc=com';
    const bindDN = document.getElementById('ldap_bind_dn').value || '-';

    document.getElementById('ldap-port-display').textContent = port;
    document.getElementById('ldap-bind-dn-display').textContent = bindDN;
    document.getElementById('ldap-search-base-display').textContent = baseDN;

    // Get server IP addresses
    try {
        const response = await apiCall('/api/system/network-info', {}, false);
        if (response && response.addresses && response.addresses.length > 0) {
            document.getElementById('ldap-server-display').textContent = response.addresses.join(', ');
        }
    } catch (e) {
        // Fallback to localhost if we can't get network info
        document.getElementById('ldap-server-display').textContent = 'localhost';
    }
}

function generateRadiusSecret() {
    // Generate a cryptographically secure 512-bit (64 bytes) random secret
    const array = new Uint8Array(64);
    crypto.getRandomValues(array);

    // Convert to base64 for easier copy/paste
    const secret = btoa(String.fromCharCode.apply(null, array));

    // Set the value in the input field and change type to text temporarily to show it
    const secretInput = document.getElementById('radius_secret');
    secretInput.value = secret;
    secretInput.type = 'text';
    secretInput.select();

    // Copy to clipboard
    navigator.clipboard.writeText(secret).then(() => {
        showAlert('✅ RADIUS secret generated and copied to clipboard!', 'success');
    }).catch(() => {
        showAlert('✅ RADIUS secret generated! (Copy failed - please copy manually)', 'success');
    });

    // Change back to password type after 3 seconds
    setTimeout(() => {
        secretInput.type = 'password';
    }, 3000);
}

function updateAuthSettings() {
    // Real-time status update when checkboxes change
    const oidcEnabled = document.getElementById('oidc_enabled').checked;
    const ldapEnabled = document.getElementById('ldap_enabled').checked;
    const radiusEnabled = document.getElementById('radius_enabled').checked;
    const smtpEnabled = document.getElementById('smtp_enabled').checked;

    // Update LDAP config display
    updateLDAPConfigDisplay();

    updateProtocolStatus('oidc', oidcEnabled);
    updateProtocolStatus('ldap', ldapEnabled);
    updateProtocolStatus('radius', radiusEnabled);
    updateProtocolStatus('smtp', smtpEnabled);
}

function updateAuthenticationNavVisibility(enabled) {
    // Find the Authentication nav item
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        if (item.textContent.includes('Authentication')) {
            if (enabled) {
                item.style.display = 'flex';
                // Add a subtle highlight animation to draw attention
                item.style.transition = 'background-color 0.5s';
                item.style.backgroundColor = 'rgba(76, 175, 80, 0.2)';
                setTimeout(() => {
                    item.style.backgroundColor = '';
                }, 2000);
            } else {
                item.style.display = 'none';
            }
        }
    });
}