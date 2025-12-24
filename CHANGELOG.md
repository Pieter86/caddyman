# CaddyMAN Changelog

## v1.3.17 (2025-12-22)
🧹 **Major Code Cleanup & Modernization**
- User passwords now exclusively use Argon2id with DPAPI-encrypted pepper (slow but secure for weak passwords)
- OAuth client secrets remain on bcrypt permanently (fast verification needed for frequent API calls, already high-entropy)
- **RADIUS PAP security fix:** PAP now uses WiFi password instead of main account password (limits damage if PAP traffic intercepted)
- **Smart WiFi password UI:** User Portal only shows WiFi password section when RADIUS uses PAP or PEAP (hidden for secure EAP-TTLS)
- Fixed `default_backend()` deprecation warnings from cryptography library (removed from 7 locations)
- Fixed Unicode encoding issues on Windows (replaced → with -> in log messages)
- Removed ~100+ lines of dead code and outdated migrations
- Removed legacy `website_session` cookie system (unified SSO with `session_id`)
- Fixed `_use_argon2id` undefined variable error
- Version checking now allows downgrades (with minimum version enforcement)
- SSE client now stops reconnecting when session expires (prevents endless 401 log spam)
- Improved brute force notification messaging - less alarming for intentional public-facing deployments
- Updated blocked IP status endpoint to fix dictionary error
- Enhanced root directory validation - prevents exposing sensitive files (requires at least one subfolder deep)
- JavaScript version bumped to v1.3.17 for cache busting

## v1.3.16 (2025-12-21)
🔒 **Security & Real-time Updates**
- Implemented server-side SSE monitoring for pending invites with adaptive push intervals (60s when >1min remaining, 1s when <1min)
- Added comprehensive Blocked IPs security feature with automatic escalation to permanent block after 3 violations
- Manual status control (permanent/temporary/monitoring) for blocked IPs
- External IP detection with configurable notifications
- Enabled FastAPI documentation endpoints (/docs, /redoc, /openapi.json) when log level set to DEBUG with warning banner
- Added automatic system-managed proxy for Domain URL setting
- Creates/updates/deletes proxy configuration automatically when domain URL changes
- Replaces user-created duplicates on startup, locks proxy at top of list with optimal settings
- Fixed Python syntax error with nested f-strings in brute force logging
- Fixed background health check logging for proxies without upstreams (changed from WARNING to INFO)
- Enhanced mobile-friendly responsive design for all new features

## v1.3.15 (2025-12-20)
🔒 **UX & Accessibility Improvements**
- Fixed HTML accessibility issues (added form label associations, lang attributes, charset declarations)
- Updated HTTP security headers to modern standards (Content-Security-Policy with frame-ancestors)
- Removed deprecated X-Frame-Options and X-XSS-Protection headers
- Fixed advanced proxy health checks to properly detect routes array format
- Fixed WiFi password section to work with all RADIUS authentication methods (PAP, PEAP, EAP-TTLS) instead of only PEAP
- Removed health check status badges for static websites (only reverse proxies show them now)
- Disabled website health check background loop entirely to reduce unnecessary HTTP requests and log spam
- Fixed mobile alert positioning to not cover menu button
- Enhanced SSE reconnection with heartbeat monitoring and exponential backoff
- Advanced proxy example updated to use generic domain names
- Added debug logging for health check troubleshooting

## v1.3.14 (2025-12-19)
🔒 **CRITICAL Security Hardening - LDAP/RADIUS Network Security Overhaul**
- Removed bind address configuration (now automatically binds to 0.0.0.0 for all network interfaces)
- Added automatic external/public IP blocking with security notifications for LDAP and RADIUS servers
- Only private networks allowed (10.x, 172.16-31.x, 192.168.x, localhost) - external connections rejected immediately
- Fixed JWT kid header for audiobookshelf browser authentication compatibility
- Enhanced notification system with 3-attempt retry logic and 15-second delays
- Non-blocking notifications prevent application startup delays
- Added brute force protection with rate limiting (20 req/min) and 30-minute IP blocks
- Website path security prevents hosting from CaddyMAN directory
- Improved mobile responsive design for RADIUS settings
- All security events trigger configurable notifications

## v1.3.13 (2025-12-18)
🐛 **Critical Bug Fixes & Enhancements**
- Fixed settings page overwriting authentication settings (LDAP/RADIUS/OIDC were being disabled when saving general settings)
- Settings page now preserves all authentication settings when saving
- Fixed update notifications not being sent
- Added configurable log level for both CaddyMAN and Caddy (DEBUG/INFO/WARN/ERROR)
- Log levels apply immediately for CaddyMAN (Caddy requires restart)
- Reduced console log spam from health checks
- Created caddyman-update.exe standalone updater with --auto mode for Windows Task Scheduler
- Update banner button now properly opens download page
- Better error handling for frozen executable logging

## v1.3.12 (2025-12-17)
🐛 **Bug Fixes**
- Removed noisy migration messages that appeared on every startup
- Suppressed httpx INFO logs to reduce console spam while keeping important application logs visible
- Added automatic update system with SHA256 hash verification for security
- Added build-release.py script for automated build/release process

## v1.3.11 (2025-12-16)
🔒 **CRITICAL Security Hardening**
- All sensitive settings now encrypted with pepper-based encryption (SMTP password, RADIUS secret, notification tokens)
- Fixed critical bug where LDAP and RADIUS servers wouldn't start due to boolean settings stored as strings
- Added wifi_password_hash column for separate WiFi RADIUS authentication
- Migrated WiFi password encryption from insecure DB-stored key to DPAPI-protected pepper
- Auto-migration on startup transparently encrypts existing plaintext secrets
- Moving database to new PC now invalidates ALL secrets (not just passwords) for defense-in-depth
- Settings cache now automatically decrypts encrypted values
- Comprehensive startup migration handles both type fixes and encryption

## v1.3.10 (2025-12-15)
🔐 **Auth & UX Fixes**
- Fixed Caddy config generation bug where /api/auth/* routes were being applied to all proxies
- Prevents services like Mealie from using their own /api/auth/login endpoints
- Fixed user portal & OAuth login 2FA flow to properly show 2FA input field
- Backend now returns requires_2fa response instead of 403 error
- Added support for two_factor_token field in LoginRequest
- Enhanced 2FA input styling across all login pages for better UX consistency with admin panel

## v1.3.9 (2025-12-14)
🔒 **Major Security Hardening & UX Improvements**
- Fixed XSS vulnerabilities across all admin interface JavaScript (14+ innerHTML usages now properly escaped)
- Added password visibility toggles (👁️/🙈) for RADIUS secret, SMTP password, and notification token fields
- Disabled FastAPI documentation endpoints (/docs, /redoc, /openapi.json) to prevent API schema exposure
- Mobile responsive fixes for OIDC settings and OAuth client cards
- OAuth client cards redesigned with cleaner layout
- Improved invite link system - creating new invite for existing username now automatically replaces old invite
- Enhanced HTML security helper functions (escapeHtml, setContent) across script.js and user-portal-script.js
- Fixed settings API to use password-type fields with show/hide buttons

## v1.3.8 (2025-12-13)
🔐 **Auth Routing Fix for Protected Sites**
- Fixed /auth/* route bypass logic to properly differentiate between CaddyMAN-protected sites and self-authenticating services
- Protected reverse proxies and file servers now work correctly alongside services with their own authentication

## v1.3.7 (2025-12-12)
🔧 **LDAP Search Filter Fix & Pending Invitations Dashboard**
- Fixed critical LDAP search filter parsing bug (was returning all users instead of filtering by username)
- Emby, Jellyfin, and other LDAP clients now correctly authenticate specific users
- Added Pending Invitations card to dashboard showing active invite links with time remaining
- Displays username, email, assigned groups, creator, and expiry countdown
- Auto-cleanup of expired invitations from database when dashboard loads
- Invitation persistence across reboots (stored in SQLite database)

## v1.3.6 (2025-12-11)
🔐 **Argon2id Password Hashing & OIDC Custom Claims**
- Gradual migration from bcrypt to Argon2id with interactive prompt
- Fresh installations automatically use Argon2id by default
- 512 MB memory-hard hashing resistant to GPU/ASIC attacks
- DPAPI-encrypted pepper on Windows for additional security
- 20-second timeout migration prompt (defaults to bcrypt if no input)
- OIDC Custom Claims support - configure application-specific permissions per group
- Fixed authentication settings persistence (OIDC issuer, SMTP, allowed groups)
- Fixed group edit duplicate name validation

## v1.3.5 (2025-12-10)
📶 **WiFi Password & PEAP Support**
- Separate WiFi password for RADIUS/PEAP authentication in user portal
- PEAP-MSCHAPv2 support for Windows/Android/iOS WiFi clients
- Encrypted NT hash storage using Fernet (AES-128)
- WiFi password must differ from account password (8 char minimum)
- Full MSCHAPv2 challenge-response per RFC 2759
- User portal shows WiFi section only for RADIUS-eligible users
- Enhanced RADIUS logging for PEAP/TTLS authentication events

## v1.3.4 (2025-12-09)
🔒 **Security & Features Update**
- Fixed email field loading in user edit form
- Implemented hierarchical LDAP search (support for searching base DN or specific group OUs)
- Fixed OAuth/OIDC client group display
- Marked unimplemented EAP methods as "not done" in UI
- Added DEBUG_MODE flag (env: CADDYMAN_DEBUG) to control TLS keylog files
- Set secure=True on session cookies
- Added return_to URL validation to prevent open redirect attacks
- Improved IPv4 validation using ipaddress module

## v1.3.3 (2025-12-08)
🔐 **OAuth/OIDC Improvements**
- Fixed admin-only access enforcement for admin panel
- Created separate OAuth login page at /login with clean design
- Added /api/user endpoint for user portal
- Fixed user portal CSS/JS loading
- Implemented proper OIDC logout flow with redirect support
- Fixed ID token generation with username as subject claim
- Enhanced OAuth token endpoint with form data and HTTP Basic Auth support
- Improved session management for OAuth clients

## v1.3.1 (2025-12-06)
🎉 **User Self-Service Portal**
- User Self-Service Portal at /user-portal (change password, update email, manage 2FA)
- Password Reset via email with 2FA verification
- Invite Link System for user onboarding (admin-generated, email-delivered, time-limited)
- Force 2FA at Group Level (require 2FA for admin panel, LDAP, OIDC access)
- Email field added to user profiles
- Password minimum changed to 4 characters (always enforced)
- Modern Clipboard API
- Comprehensive security enhancements

## v1.3.0 (2025-12-05)
🎉 **MAJOR RELEASE - Identity & Access Management (IAM)**
- OIDC/OAuth2 Provider for modern apps (Audiobookshelf, etc.)
- LDAP Server for legacy apps (Emby, Jellyfin, etc.)
- RADIUS Server for WiFi WPA2-Enterprise authentication
- SMTP/Email system with invite & password reset
- Enhanced user model with email/name fields
- Full authentication management UI
- Group-based access control
- 2FA support (TOTP)

## v1.2.24 (2025-12-04)
**Advanced Proxy & Update System**
- Fixed Advanced proxy mode validation (domains no longer required when using full Caddy JSON)
- Added dynamic help page that adapts to platform (Windows/Linux/macOS) and execution mode (script/executable)
- Improved update system with dashboard UI showing platform-appropriate update buttons
- GitHub integration for updates
- Platform-aware PHP-CGI paths

## v1.2.23 (2025-12-03)
**CRITICAL FIX - Notification Events Persistence**
- Fixed notification_events settings persistence bug
- Added Custom Headers (JSON) UI for reverse proxies
- Enhanced notification system with 26 granular event types
- Recent Notifications dashboard widget
- Linux compatibility improvements
- Removed unused http_port/https_port settings

## v1.2.22 (2025-12-02)
**CRITICAL FIX - Settings Persistence**
- Fixed settings persistence for WebSocket support, Custom Host Headers, Remove Origin/Referer, Custom Headers, Load Balancing
- Fixed CSRF token on mobile browsers (tab suspension)

## v1.2.21 (2025-12-01)
**Session Management**
- Fixed CSRF token handling on logout
- Added auto-logout after 30 minutes of inactivity

## v1.2.20 (2025-11-30)
**Performance Optimization**
- Settings caching - reduced disk I/O by keeping settings in memory
- Only reads from database on startup and when settings are saved

## v1.2.19 (2025-11-29)
**Major Security Update**
- CSRF protection for all state-changing requests
- Rate limiting with account lockout (5 failed attempts = 15-minute lockout)
- Secure session IDs with SameSite cookie flags
- Open redirect prevention
- Forced password change for default admin on first login
- Enhanced password validation

## v1.2.18 (2025-11-28)
**Bug Fixes**
- Fixed header parsing in reverse proxies
- Fixed upstream dial addresses
- Fixed ACME challenge bypass
- Fixed default index files for websites
- Mobile responsive UI improvements

## v1.2.17 (2025-11-27)
**Port Configuration**
- Added configurable Caddy admin port
- Fixed import port defaults
- Fixed auto_https redirects

## v1.2.16 (2025-11-26)
**Website Modal Fixes**
- Fixed website edit modal bugs
- Improved mode toggle handling

## v1.2.13 (2025-11-25)
**Advanced Directives**
- Added additional directives support for Simple mode
- Cleaned up advanced forms

## v1.2.11 (2025-11-24)
**Rebranding**
- Application rebranded from Caddy Manager to CaddyMAN
- Comprehensive help menu added
- Updated branding across all pages

## v1.2.10 (2025-11-23)
**Critical Settings Fix**
- Fixed critical settings persistence bug
- Settings now properly saved across restarts

## v1.2.9 (2025-11-22)
**SQLite Migration**
- Complete SQLite migration for all configuration data
- Improved data persistence and reliability

## v1.2.8 (2025-11-21)
**Enhanced Security Mode & 2FA**
- Enhanced Security Mode implementation
- Two-Factor Authentication (2FA) support with TOTP
- QR code generation for 2FA setup
- Help page added with comprehensive documentation and changelog
