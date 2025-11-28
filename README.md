# CaddyMAN

**A web-based management interface for Caddy web server with integrated IAM, OAuth/OIDC, and reverse proxy management.**

> This project was born out of pure laziness - maintaining multiple services, authentication systems, and reverse proxies in my homelab became tedious. CaddyMAN is my all-in-one solution to manage everything from a single web interface. If you're running a homelab and tired of juggling config files, this might be for you.

## What is CaddyMAN?

CaddyMAN is a management platform that wraps around the Caddy web server, adding a web UI, user management, OAuth/OIDC provider capabilities, and more. 
### Key Features

- **Web-Based Management Interface**: Manage your entire Caddy configuration through a clean, modern web UI
- **Identity & Access Management (IAM)**: Full user and group management with role-based access control
- **OAuth 2.0 / OpenID Connect Provider**: Use CaddyMAN as your SSO provider for other applications
- **Reverse Proxy Management**: Configure and manage reverse proxy rules with automatic SSL/TLS
- **User Self-Service Portal**: Let users manage their own passwords, 2FA, and profile settings
- **Two-Factor Authentication (TOTP)**: Secure accounts with time-based one-time passwords
- **Automated Updates**: Built-in update system with one-click updates
- **Activity Logging**: Track all administrative actions and user logins
- **Email Notifications**: Get notified of important events via SMTP integration
- **Webhook Support**: Integrate with Discord, Slack, and other platforms
- **Auto-Generated Caddyfile**: Your configuration is automatically generated - no manual editing needed

## Why CaddyMAN?

I got tired of:
- Editing Caddyfile manually for every config change
- Managing users across multiple services
- Setting up separate OAuth providers
- Remembering which port maps to which service
- SSH-ing into servers just to add a reverse proxy rule

CaddyMAN consolidates all of this into one place. It's opinionated, it's specific to my homelab needs, but it might work for yours too.


## Installation

### Windows (Recommended)

1. Download the latest `CaddyMAN.exe` from [Releases](https://github.com/Pieter86/caddyman/releases)
2. Place it in a dedicated folder (e.g., `C:\CaddyMAN\`)
3. Download `caddy.exe` from [caddyserver.com](https://caddyserver.com/download) and place it in the same folder
4. Run `CaddyMAN.exe`
5. Open your browser to `http://localhost:12888`
6. Follow the first-time setup wizard

### Python (Cross-Platform)

```bash
# Clone the repository
git clone https://github.com/Pieter86/caddyman.git
cd caddyman

# Install dependencies
pip install -r requirements.txt

# Download Caddy binary for your platform
# Place it in the same directory

# Run CaddyMAN
python CaddyMAN.py
```

First-time login: `admin` / `changeme` (you'll be prompted to change this immediately)

## Configuration

CaddyMAN is designed to work out of the box with minimal configuration. Everything is managed through the web interface:

1. **Initial Setup**: Configure your domain, SSL/TLS settings, and admin credentials
2. **Add Users**: Create user accounts or send invite links
3. **Configure Reverse Proxies**: Point domains/subdomains to your internal services
4. **Enable OAuth/OIDC**: Set up SSO for compatible applications
5. **Set Up Notifications**: Configure email/webhook notifications for events

## OAuth/OIDC Integration

CaddyMAN can act as an OpenID Connect provider for your applications. Tested with:

- **Audiobookshelf**: Full SSO integration
- **Any OIDC-compatible application**: Standard endpoints available

### OIDC Endpoints

- **Authorization**: `http://your-server:12888/oauth/authorize`
- **Token**: `http://your-server:12888/oauth/token`
- **UserInfo**: `http://your-server:12888/oauth/userinfo`
- **Logout**: `http://your-server:12888/oauth/revoke`
- **Discovery**: `http://your-server:12888/.well-known/openid-configuration`

## User Portal

Non-admin users get access to a self-service portal at `/user-portal` where they can:

- Change their password
- Update email address
- Enable/disable 2FA
- View their group memberships
- Log out

## Technology Stack

- **Backend**: FastAPI (Python)
- **Web Server**: Caddy v2
- **Database**: SQLite
- **Frontend**: Vanilla JavaScript (no frameworks - keeping it simple)
- **Authentication**: Session-based with CSRF protection
- **OAuth/OIDC**: Custom implementation using PyJWT

## Security Features

- Session-based authentication with secure cookies
- CSRF token protection on all state-changing operations
- Password hashing with bcrypt
- TOTP-based two-factor authentication
- Admin-only access controls
- Activity logging for audit trails
- Automatic HTTPS with Caddy's ACME integration

## Requirements

- **Windows**: Windows 10/11 or Windows Server 2019+
- **Linux**: Any modern distribution with Python 3.8+
- **Caddy**: v2.6.0 or newer (included in releases)
- **Python**: 3.8 or newer (for script mode)
- **RAM**: 256MB minimum, 512MB recommended
- **Disk**: 100MB for application + space for logs

## Updates

CaddyMAN includes an automatic update system:

1. Checks GitHub for new releases every 12 hours
2. Displays update notification in the web UI
3. One-click download and installation (EXE mode)
4. Automatic backup of previous version

Updates are published at: [https://github.com/Pieter86/caddyman/releases](https://github.com/Pieter86/caddyman/releases)

## Contributing

This is primarily a personal homelab project, but PRs are welcome! If you find bugs or have feature requests, open an issue.

## License

This project is provided as-is for personal and homelab use. No warranty, use at your own risk.

## Credits

- Built with [Caddy](https://caddyserver.com/) - the amazing web server
- Powered by [FastAPI](https://fastapi.tiangolo.com/)
- Claude.ai for lots of help. lol

## FAQ

**Q: Is this production-ready?**
A: It's homelab-ready. I use it daily. Your mileage may vary.

**Q: Why not use [existing solution]?**
A: Because I wanted everything in one place, and I enjoy building stuff.

**Q: Can I use this commercially?**
A: It's designed for homelab/personal use. For commercial use, please review the license and consider contributing back.

**Q: Where's the documentation?**
A: The web UI has a built-in help section. The code is reasonably well-commented. That's all you get for now.

**Q: Something broke!**
A: Check `logs/app.log` first. Then open an issue on GitHub with details.

## Support

- **Issues**: [GitHub Issues](https://github.com/Pieter86/caddyman/issues)
- **Documentation**: Built-in help page at `/` (Help tab)
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md) or the help page


