from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response as StarletteResponse
from fastapi import FastAPI, HTTPException, Request, Response, Cookie, Header, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from packaging import version
from pydantic import BaseModel, Field, field_validator, model_validator, ValidationInfo
from typing import Optional, Dict, Any, List
import httpx
import subprocess
import atexit
import asyncio
import os
import json
import tempfile
import shutil
import secrets
import logging
import hashlib
import uuid
import time
import copy
from pathlib import Path
from datetime import datetime, timezone
import platform
from contextlib import asynccontextmanager
import sys
import pyotp
import qrcode
import io
import base64
import re
import sqlite3
from contextlib import closing
from jose import jwt, jwk
from jose.constants import ALGORITHMS
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlencode, parse_qs, urlparse
import ssl
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding
from email.message import EmailMessage
import aiosmtplib
from datetime import timedelta
from cryptography.fernet import Fernet
from passlib.hash import nthash
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
import bcrypt  # Permanent: OAuth client secrets use bcrypt for speed (high-entropy, frequent verification)

VERSION = "1.3.23"

# ============================================================================
# DEBUG mode - enables sensitive TLS secret logging and keylog files
# WARNING: Never enable in production! Only for development/debugging
DEBUG_MODE = os.getenv('CADDYMAN_DEBUG', 'false').lower() == 'true'

def validate_return_url(url: str) -> bool:
    """
    Validate return_to URL to prevent open redirect attacks.
    Only allows relative paths or same-origin URLs.

    Security: Prevents attackers from redirecting users to malicious external sites
    """
    if not url:
        return False

    # Allow relative paths (starting with /)
    if url.startswith('/'):
        # Ensure it's not a protocol-relative URL (//example.com)
        if url.startswith('//'):
            return False
        return True

    # Reject all absolute URLs (http://, https://, etc.)
    # For a homelab/internal tool, we only allow relative redirects
    return False

def is_local_request(request) -> bool:
    """
    Check if request is from a local/private IP address.
    Returns True for localhost, private IPs (10.x, 192.168.x, 172.16-31.x)
    Returns False for public/external IPs (should use HTTPS with secure cookies)
    """
    import ipaddress

    # Get client IP (handle x-forwarded-for)
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "127.0.0.1")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    try:
        addr = ipaddress.ip_address(client_ip)
        # Check if it's a private/local IP
        return addr.is_loopback or addr.is_private
    except ValueError:
        # If we can't parse the IP, assume it's not local (safer default)
        return False

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller (including auto-py-to-exe)

    auto-py-to-exe uses PyInstaller under the hood, so this function automatically
    detects and works correctly with executables created by auto-py-to-exe.
    """
    try:
        # PyInstaller (and auto-py-to-exe) stores files in _MEIPASS temporary folder
        base_path = sys._MEIPASS
    except AttributeError:
        # Running as normal Python script
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def get_permanent_caddy_path():
    """Copy caddy.exe to a permanent location to avoid firewall issues with PyInstaller's temp folders

    Works with both PyInstaller and auto-py-to-exe executables. On Linux/Mac, uses system caddy binary.
    """
    if platform.system() != "Windows":
        return "caddy"  # On Linux/Mac, use system caddy from PATH

    # Define permanent location in the same directory as the database
    permanent_caddy = os.path.join(os.path.abspath("."), "caddy.exe")

    # If running from PyInstaller bundle (or auto-py-to-exe), copy caddy.exe to permanent location
    try:
        bundled_caddy = resource_path("caddy.exe")
        # Only copy if source is different (i.e., we're in a PyInstaller/auto-py-to-exe bundle)
        if bundled_caddy != permanent_caddy and os.path.exists(bundled_caddy):
            import shutil
            shutil.copy2(bundled_caddy, permanent_caddy)
            logger.info(f"Copied caddy.exe to permanent location: {permanent_caddy}")
    except Exception as e:
        logger.warning(f"Could not copy caddy.exe to permanent location: {e}")

    # Return permanent path if it exists, otherwise fall back to bundled
    if os.path.exists(permanent_caddy):
        return permanent_caddy
    return resource_path("caddy.exe")

def get_permanent_app_path():
    """Copy the 'app' folder to a permanent location to avoid missing static files when PyInstaller temp is cleared.
    """
    # Define permanent location in the same directory as the database
    permanent_app = os.path.join(os.path.abspath("."), "app")
    
    # If running from PyInstaller bundle, copy app dir to permanent location
    try:
        bundled_app = resource_path("app")
        # Ensure we are in a bundle (app exists and is not the permanent location)
        if bundled_app != permanent_app and os.path.isdir(bundled_app):
            # We copy everything, replacing the existing permanent files so they update with app upgrades
            if os.path.exists(permanent_app):
                shutil.rmtree(permanent_app, ignore_errors=True)
            shutil.copytree(bundled_app, permanent_app)
            logger.info(f"Copied app folder to permanent location: {permanent_app}")
    except Exception as e:
        logger.warning(f"Could not copy app folder to permanent location: {e}")
        
    if os.path.exists(permanent_app):
        return permanent_app
    return resource_path("app")

def get_php_cgi_executable():
    """Get the platform-specific PHP-CGI executable name"""
    return "php-cgi.exe" if platform.system() == "Windows" else "php-cgi"

UPDATE_CHECK_URL = "https://raw.githubusercontent.com/Pieter86/updates/refs/heads/main/caddyman/caddyman.json"

# Ensure logs directory exists before setting up logging
LOG_DIR = "logs"
Path(LOG_DIR).mkdir(exist_ok=True)

# Custom logging filter to suppress httpx INFO logs (primarily health check spam)
class HttpxInfoFilter(logging.Filter):
    """Suppress httpx INFO logs to prevent console spam from health checks

    Health checks run every 60 seconds and generate:
    "HTTP Request: GET https://domain.com HTTP/1.1 200 OK"

    Important application logs are still visible:
    - "Update available: x.x.x" (from check_for_updates)
    - "Notification sent: {title}" (from send_notification)
    - httpx WARNING/ERROR logs still shown
    """
    def filter(self, record):
        # Suppress httpx INFO logs (health checks dominate these)
        if record.name == "httpx" and record.levelno == logging.INFO:
            return False
        return True

# Configure logging to write to logs/app.log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'app.log')),
        logging.StreamHandler()  # Also output to console
    ]
)
logger = logging.getLogger(__name__)

# Apply filter to suppress httpx INFO spam (health checks every 60s)
for handler in logging.root.handlers:
    handler.addFilter(HttpxInfoFilter())

# Log DEBUG_MODE status after logger is configured
if DEBUG_MODE:
    logger.info("[STARTUP] DEBUG_MODE enabled - TLS keylog files will be created")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global health_check_task, caddy_monitor_task
    logger.info(f"Starting CaddyMAN v{VERSION}")
    load_last_restart_time()  # Load restart tracking from database
    settings = get_settings_from_db()  # Initialize settings cache on startup
    apply_log_level(settings)  # Apply log level from settings to CaddyMAN logger
    # Migration removed - root cause fixed in script.js saveSettings() function
    # The Settings page now preserves all settings instead of sending partial updates
    await start_caddy()
    await start_php_cgi()
    await start_ldap_server()  # Start LDAP server if enabled
    await start_radius_server()  # Start RADIUS server if enabled
    await asyncio.sleep(2)
    try:
        await reload_caddy()
    except:
        pass
    health_check_task = asyncio.create_task(health_check_loop())
    status_monitor_task = asyncio.create_task(status_monitor_loop())
    caddy_monitor_task = asyncio.create_task(monitor_caddy())
    asyncio.create_task(periodic_update_check())
    asyncio.create_task(cleanup_expired_sessions())
    asyncio.create_task(monitor_invites())
    await check_for_updates()

    yield

    # Shutdown
    if health_check_task:
        health_check_task.cancel()
    if caddy_monitor_task:
        caddy_monitor_task.cancel()
    await stop_ldap_server()  # Stop LDAP server
    await stop_radius_server()  # Stop RADIUS server
    await stop_php_cgi()
    await stop_caddy()
    sessions.clear()
app = FastAPI(
    title="CaddyMAN",
    version=VERSION,
    lifespan=lifespan,
    docs_url="/docs",  # Always enable, access controlled by middleware
    redoc_url="/redoc",  # Always enable, access controlled by middleware
    openapi_url="/openapi.json"  # Always enable, access controlled by middleware
)

# Custom CORS middleware for OAuth endpoints that allows subdomains
class OAuthCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin")

        # Only apply CORS to OAuth endpoints
        if request.url.path.startswith("/oauth/") or request.url.path.startswith("/.well-known/"):
            # Get domain from settings to allow all subdomains
            try:
                settings = get_settings_from_db()
                domain_url = settings.get('domain_url', '')
                if domain_url:
                    parsed = urlparse(domain_url)
                    base_domain = parsed.netloc
                    # Extract base domain (e.g., jvr.nz from users.jvr.nz)
                    parts = base_domain.split('.')
                    if len(parts) >= 2:
                        base_domain = '.'.join(parts[-2:])  # Get last two parts (e.g., jvr.nz)

                    # Check if origin matches the base domain or any subdomain
                    if origin:
                        origin_parsed = urlparse(origin)
                        origin_host = origin_parsed.netloc

                        # Allow if origin is the base domain or any subdomain
                        if origin_host == base_domain or origin_host.endswith('.' + base_domain):
                            if request.method == "OPTIONS":
                                # Preflight request
                                return Response(
                                    status_code=200,
                                    headers={
                                        "Access-Control-Allow-Origin": origin,
                                        "Access-Control-Allow-Credentials": "true",
                                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                                        "Access-Control-Allow-Headers": "*",
                                    }
                                )
                            else:
                                # Actual request
                                response = await call_next(request)
                                response.headers["Access-Control-Allow-Origin"] = origin
                                response.headers["Access-Control-Allow-Credentials"] = "true"
                                return response
            except Exception as e:
                logger.warning(f"CORS middleware error: {e}")

        # For non-OAuth endpoints or if CORS check fails, proceed normally
        return await call_next(request)

app.add_middleware(OAuthCORSMiddleware)


class ProxyFixMiddleware(BaseHTTPMiddleware):
    """
    Fix client IP address from proxy headers (X-Forwarded-For)
    This ensures uvicorn access logs show the real client IP, not the proxy IP

    Security: Only trusts X-Forwarded-For when request comes from Caddy proxy (localhost/same machine)
    """
    async def dispatch(self, request: Request, call_next):
        # Only trust X-Forwarded-For if the request is from our Caddy reverse proxy
        # Caddy runs on the same machine, so request.client.host will be 127.0.0.1 or ::1 or local IP
        if request.client:
            proxy_ip = request.client.host

            # Trust X-Forwarded-For only from localhost or local network (10.x, 192.168.x, 172.16-31.x)
            is_trusted_proxy = (
                proxy_ip == "127.0.0.1" or
                proxy_ip == "::1" or
                proxy_ip.startswith("10.") or
                proxy_ip.startswith("192.168.") or
                any(proxy_ip.startswith(f"172.{i}.") for i in range(16, 32))
            )

            if is_trusted_proxy:
                # Get the real client IP from X-Forwarded-For header (set by Caddy reverse proxy)
                forwarded_for = request.headers.get("x-forwarded-for")
                if forwarded_for:
                    # Take the first IP from the chain (original client)
                    client_ip = forwarded_for.split(",")[0].strip()
                    # Override the client host for logging purposes
                    # This affects uvicorn's access logs
                    request.scope["client"] = (client_ip, request.client.port)

        response = await call_next(request)
        return response

app.add_middleware(ProxyFixMiddleware)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Add security headers (ZAP scan recommendations - v1.3.17)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Content Security Policy (Option B - Pragmatic)
        # Allows inline scripts/styles (required for current implementation)
        # Protects against external script injection and most XSS attacks
        # TODO v1.3.18+: Refactor inline scripts/styles to use strict CSP (Option A)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "object-src 'none';"
        )

        # Cross-Origin headers for Spectre vulnerability mitigation
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # Permissions Policy - disable unnecessary browser features
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Add cache control for HTML responses
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Cache-Control"] = "no-store"
            # Ensure charset is set for HTML
            if "charset" not in response.headers.get("content-type", ""):
                response.headers["Content-Type"] = "text/html; charset=utf-8"

        # Ensure charset is set for JSON responses
        if response.headers.get("content-type", "").startswith("application/json"):
            if "charset" not in response.headers.get("content-type", ""):
                response.headers["Content-Type"] = "application/json; charset=utf-8"

        return response

app.add_middleware(SecurityHeadersMiddleware)


class DebugDocsMiddleware(BaseHTTPMiddleware):
    """Middleware to control access to FastAPI docs based on log level setting"""
    async def dispatch(self, request: Request, call_next):
        # Check if accessing docs endpoints
        if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
            # Check both environment variable and log level setting
            settings = get_settings_from_db()
            debug_enabled = DEBUG_MODE or settings.get("caddy_log_level", "WARN") == "DEBUG"

            if not debug_enabled:
                # Get client IP
                client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
                if "," in client_ip:
                    client_ip = client_ip.split(",")[0].strip()

                # Try to get username if authenticated
                session_id = request.cookies.get("session_id")
                user = get_session_user(session_id)
                username = user.get("username", "anonymous") if user else "anonymous"

                # Log the attempt
                logger.warning(f"Unauthorized access attempt to {request.url.path} from {client_ip} (user: {username}) - Debug mode is disabled")

                # Send notification if configured
                await send_notification(
                    "security_alert",
                    "Unauthorized Debug Endpoint Access",
                    f"Attempted access to debug endpoint {request.url.path}\n\n"
                    f"User: {username}\n"
                    f"IP Address: {client_ip}\n"
                    f"Status: Blocked (Debug mode disabled)\n\n"
                    f"Enable DEBUG log level in Settings to allow access to API documentation.",
                    source_ip=client_ip,
                    username=username
                )

                # Debug mode not enabled, return 404
                return StarletteResponse(
                    content='{"detail":"Not found"}',
                    status_code=404,
                    media_type="application/json"
                )

        return await call_next(request)

app.add_middleware(DebugDocsMiddleware)


class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        # Allow login page, OAuth, user portal, auth endpoints, and admin page
        if (request.url.path in ["/", "/admin", "/login", "/api/auth/login", "/api/auth/logout", "/api/auth/verify", "/api/login", "/api/user"] or
            request.url.path.startswith("/static/") or
            request.url.path.startswith("/api/website-auth/") or
            request.url.path.startswith("/auth/") or
            request.url.path.startswith("/oauth/") or
            request.url.path.startswith("/user-portal") or
            request.url.path.startswith("/api/user-portal/") or
            request.url.path.startswith("/api/user-portal/branding")):
            return await call_next(request)

        # All other pages require admin group membership
        if request.url.path.startswith("/api/"):
            session_id = request.cookies.get("session_id")
            user = get_session_user(session_id)
            
            if not user:
                return StarletteResponse(
                    content='{"detail":"Not authenticated"}',
                    status_code=401,
                    media_type="application/json"
                )
            
            # Check if user is in admin group
            if "admin_group" not in user.get("groups", []):
                await log_activity(
                    user.get("username", "unknown"),
                    "ACCESS_DENIED",
                    f"Attempted to access {request.url.path}",
                    client_ip
                )
                return StarletteResponse(
                    content='{"detail":"Access denied - admin privileges required"}',
                    status_code=403,
                    media_type="application/json"
                )
            
            # Log API access (skip noisy endpoints)
            if request.url.path not in ["/api/auth/me", "/api/caddy/status", "/api/activity"]:
                action = request.method + " " + request.url.path.split("/")[-1]
                await log_activity(user.get("username", "unknown"), action, request.url.path, client_ip)
        
        return await call_next(request)

app.add_middleware(AdminAuthMiddleware)


class Admin403TrackingMiddleware(BaseHTTPMiddleware):
    """Middleware to track and auto-block IPs that repeatedly get 403 errors on admin endpoints"""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Only track 403 errors on /api/ endpoints
        if response.status_code == 403 and request.url.path.startswith("/api/"):
            # Get client IP
            client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
            if "," in client_ip:
                client_ip = client_ip.split(",")[0].strip()

            # Check if external IP
            is_external = is_external_ip(client_ip)

            # Track this 403 attempt (async call in background)
            try:
                await track_admin_403_attempt(client_ip, request.url.path, is_external)
            except Exception as e:
                logger.error(f"Error tracking 403 attempt for {client_ip}: {e}")

        return response

app.add_middleware(Admin403TrackingMiddleware)


# Custom exception handlers for better user experience
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Custom 404 handler that shows a nice error page instead of JSON"""
    # Return HTML for browser requests
    if "text/html" in request.headers.get("accept", ""):
        # Get settings to determine user portal link
        settings = get_settings_from_db()
        user_portal_link = "/" if settings.get('admin_path_mode', False) else "/user-portal"

        return HTMLResponse(content=f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .error-container {{
            background: white;
            border-radius: 12px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{
            font-size: 72px;
            margin: 0;
            color: #667eea;
        }}
        h2 {{
            font-size: 24px;
            margin: 20px 0;
            color: #333;
        }}
        p {{
            color: #666;
            line-height: 1.6;
        }}
        .btn {{
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: background 0.2s;
        }}
        .btn:hover {{
            background: #5568d3;
        }}
        .path {{
            background: #f5f5f5;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            margin-top: 20px;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you're looking for doesn't exist or has been moved.</p>
        <div class="path">{request.url.path}</div>
        <a href="javascript:history.back()" class="btn" style="background: #555;">Go Back</a>
        <a href="{user_portal_link}" class="btn" style="background: #764ba2;">User Portal</a>
    </div>
</body>
</html>
        """, status_code=404)
    # Return JSON for API requests
    return JSONResponse(
        status_code=404,
        content={"detail": "Not Found"}
    )

@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    """Custom 500 handler for internal server errors"""
    if "text/html" in request.headers.get("accept", ""):
        return HTMLResponse(content=f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Server Error</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .error-container {{
            background: white;
            border-radius: 12px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{
            font-size: 72px;
            margin: 0;
            color: #f5576c;
        }}
        h2 {{
            font-size: 24px;
            margin: 20px 0;
            color: #333;
        }}
        p {{
            color: #666;
            line-height: 1.6;
        }}
        .btn {{
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background: #f5576c;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: background 0.2s;
        }}
        .btn:hover {{
            background: #e04857;
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <h1>500</h1>
        <h2>Internal Server Error</h2>
        <p>Something went wrong on our end. Please try again later.</p>
        <a href="/" class="btn">Go to Dashboard</a>
    </div>
</body>
</html>
        """, status_code=500)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

# Get absolute path for reliability - works with PyInstaller
# and copies `app` folder to permanent path to avoid cleanup issues
static_dir = get_permanent_app_path()

# Mount /static to serve CSS/JS/etc
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# CADDY_ADMIN_URL is now dynamic based on settings, see get_caddy_admin_url()
# Use get_permanent_caddy_path() to avoid Windows Firewall issues with PyInstaller temp folders
CADDY_BIN = os.getenv("CADDY_BIN", get_permanent_caddy_path())
DB_FILE = "CaddyMAN.db"

caddy_process = None
php_cgi_process = None
config_lock = asyncio.Lock()
sessions = {}  # {session_id: {user_id, expires_at, csrf_token}} - Unified SSO for both admin and protected websites
csrf_tokens = {}  # {session_id: csrf_token}
health_check_task = None
caddy_monitor_task = None
last_restart_time = 0
caddy_stop_reason = ""  # Track why Caddy stopped
update_available = None
activity_log = []  # Store recent activity
MAX_ACTIVITY_LOG = 100  # Keep last 100 activities
notification_log = []  # Store recent notifications
MAX_NOTIFICATION_LOG = 100  # Keep last 100 notifications
failed_login_attempts = {}  # Track failed login attempts by IP
pending_2fa_challenges = {}  # Track pending 2FA challenges {challenge_id: {username, expires, original_url}}
auth_verify_attempts = {}  # Track /api/auth/verify attempts by IP: {ip: [timestamps]} (rapid attacks)
auth_verify_401_attempts = {}  # Track 401 errors on auth endpoints by IP: {ip: [timestamps]} (slow attacks over 24h)
admin_403_attempts = {}  # Track 403 errors on admin endpoints by IP: {ip: [timestamps]}

# Status monitoring - track online/offline state of proxies and websites
status_cache = {}  # {proxy_id: online_status, website_id: online_status}
status_details = {}  # { 'proxy_<id>': {'online': bool, 'status': int, 'protected': bool}, 'website_<id>': {...} }
status_sse_clients = []  # List of SSE clients for real-time status updates

# Security constants
MAX_LOGIN_ATTEMPTS = 5  # Lock account after this many failures
LOCKOUT_DURATION = 900  # 15 minutes lockout in seconds

# Rapid attack detection - instant permanent ban
MAX_AUTH_VERIFY_ATTEMPTS = 60  # Max auth verify requests before permanent ban
AUTH_VERIFY_WINDOW = 120  # Check attempts in last 120 seconds (2 minutes)

# 403 rate limiting - auto-block IPs that repeatedly hit admin endpoints without auth
ADMIN_403_MAX_ATTEMPTS = 60  # Max 403 errors before permanent ban
ADMIN_403_WINDOW = 120  # Check attempts in last 120 seconds (2 minutes)

# Slow brute force detection - catches distributed/slow attacks over longer periods
# DISABLED: Commented out to avoid blocking legitimate monitoring tools (e.g., Uptime Kuma)
# TODO: Re-enable when custom monitoring with authentication handshake is implemented
# SLOW_BRUTE_FORCE_MAX_401S = 280  # Max 401 errors in 24 hours before permanent ban
# SLOW_BRUTE_FORCE_WINDOW = 86400  # Check 401s in last 24 hours (86400 seconds)

# Settings cache - reduces disk I/O by keeping settings in memory
_cached_settings = None

# Load last restart time from database (persists across reboots)
def load_last_restart_time():
    """Load the last restart timestamp from database"""
    global last_restart_time

    # Load from database
    try:
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM settings WHERE key = ?', ('last_restart_time',))
            row = cursor.fetchone()
            if row and row['value']:
                last_restart_time = float(row['value'])
                logger.info(f"Loaded last restart time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_restart_time))}")
            else:
                last_restart_time = 0
    except Exception as e:
        logger.warning(f"Could not load last restart time: {e}")
        last_restart_time = 0

def save_last_restart_time():
    """Save the last restart timestamp to database"""
    try:
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value)
                VALUES (?, ?)
            ''', ('last_restart_time', str(last_restart_time)))
            conn.commit()
        logger.info(f"Saved last restart time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_restart_time))}")
    except Exception as e:
        logger.error(f"Could not save last restart time: {e}")

# Load restart time on startup (after database is initialized)
# This will be called after init_db() in the lifespan function

default_settings = {
    "health_check_enabled": False, "health_check_domain": "",
    "health_check_interval": 60, "restart_after_failures": 3,
    "notification_service": "", "notification_url": "", "notification_token": "",
    "php_enabled": False, "php_path": "",
    "manager_port": 8000, "enhanced_security": False,
    "caddy_log_level": "WARN", "caddy_admin_port": 12999,
    "caddy_use_path_prefix": False,  # Use path_prefix instead of path for ACME challenges

    # Branding & Domain Settings (v1.3.5)
    "organization_name": "CaddyMAN",
    "domain_url": "http://localhost:8000",
    "admin_path_mode": False,  # If true, admin is at /admin and / shows user portal login
    "notification_events": {
        # Security Events
        "admin_login": {"enabled": True, "severity": "info"},
        "failed_login": {"enabled": True, "severity": "alert"},
        "account_lockout": {"enabled": True, "severity": "critical"},
        "user_created": {"enabled": True, "severity": "info"},
        "user_deleted": {"enabled": True, "severity": "warning"},
        "password_changed": {"enabled": False, "severity": "info"},
        # User Portal
        "user_portal_login_success": {"enabled": False, "severity": "info"},
        "user_portal_login_failed": {"enabled": True, "severity": "warning"},
        # Website Authentication
        "website_login_success": {"enabled": False, "severity": "info"},
        "website_login_failed": {"enabled": True, "severity": "warning"},
        # Authentication Protocols (LDAP/RADIUS/OIDC)
        "ldap_auth_success": {"enabled": False, "severity": "info"},
        "ldap_auth_failed": {"enabled": True, "severity": "warning"},
        "ldap_auth_denied": {"enabled": True, "severity": "warning"},
        "ldap_external_connection": {"enabled": True, "severity": "critical"},
        "radius_auth_success": {"enabled": False, "severity": "info"},
        "radius_auth_failed": {"enabled": True, "severity": "warning"},
        "radius_auth_denied": {"enabled": True, "severity": "warning"},
        "radius_external_connection": {"enabled": True, "severity": "critical"},
        "oidc_auth_success": {"enabled": False, "severity": "info"},
        "oidc_auth_denied": {"enabled": True, "severity": "warning"},
        # Security Threats
        "insecure_bind_detected": {"enabled": True, "severity": "critical"},
        "suspicious_activity": {"enabled": True, "severity": "alert"},
        "security_alert": {"enabled": True, "severity": "warning"},
        # User Management
        "invite_created": {"enabled": False, "severity": "info"},
        "invite_used": {"enabled": True, "severity": "info"},
        "password_reset_requested": {"enabled": True, "severity": "warning"},
        "password_reset_completed": {"enabled": False, "severity": "info"},
        "2fa_enabled": {"enabled": False, "severity": "info"},
        "2fa_disabled": {"enabled": True, "severity": "warning"},
        "wifi_password_set": {"enabled": False, "severity": "info"},
        "wifi_password_deleted": {"enabled": False, "severity": "info"},
        # Group & OAuth Management
        "group_created": {"enabled": False, "severity": "info"},
        "group_modified": {"enabled": False, "severity": "info"},
        "group_deleted": {"enabled": True, "severity": "warning"},
        "oauth_client_created": {"enabled": False, "severity": "info"},
        "oauth_client_modified": {"enabled": False, "severity": "info"},
        "oauth_client_deleted": {"enabled": True, "severity": "warning"},
        # System Events
        "caddy_started": {"enabled": True, "severity": "success"},
        "caddy_stopped": {"enabled": True, "severity": "warning"},
        "caddy_crashed": {"enabled": True, "severity": "critical"},
        "caddy_reloaded": {"enabled": False, "severity": "info"},
        "php_started": {"enabled": False, "severity": "info"},
        "php_stopped": {"enabled": False, "severity": "warning"},
        "health_check_failed": {"enabled": True, "severity": "warning"},
        "proxy_down": {"enabled": True, "severity": "critical"},
        "proxy_back_online": {"enabled": True, "severity": "success"},
        "website_down": {"enabled": True, "severity": "critical"},
        "website_back_online": {"enabled": True, "severity": "success"},
        "system_restart": {"enabled": True, "severity": "critical"},
        # Configuration Changes
        "website_added": {"enabled": False, "severity": "info"},
        "website_modified": {"enabled": False, "severity": "info"},
        "website_deleted": {"enabled": True, "severity": "warning"},
        "proxy_added": {"enabled": False, "severity": "info"},
        "proxy_modified": {"enabled": False, "severity": "info"},
        "proxy_deleted": {"enabled": True, "severity": "warning"},
        "settings_changed": {"enabled": False, "severity": "info"},
        # Updates
        "update_available": {"enabled": True, "severity": "info"},
        "update_installed": {"enabled": True, "severity": "success"},
        # Logs (sampled to avoid spam)
        "error_log": {"enabled": True, "severity": "critical"},
        "warning_log": {"enabled": False, "severity": "warning"}
    },

    # Authentication Protocols (Experimental - v1.3.0)
    "auth_protocols_enabled": False,

    # OIDC Provider Settings
    "oidc_enabled": False,
    "oidc_issuer": "",  # e.g., https://sso.jvrensburg.cc
    "oidc_signing_key_private": "",  # RSA private key (PEM format)
    "oidc_signing_key_public": "",   # RSA public key (PEM format)

    # LDAP Server Settings
    "ldap_enabled": False,
    "ldap_port": 3389,
    "ldap_base_dn": "dc=example,dc=com",
    "ldap_bind_dn": "cn=admin,dc=example,dc=com",
    "ldap_username_attribute": "both",  # "cn", "uid", or "both"
    "ldap_allowed_groups": [],

    # RADIUS Server Settings
    "radius_enabled": False,
    "radius_auth_port": 1812,
    "radius_acct_port": 1813,
    "radius_secret": "",  # Shared secret
    "radius_vlan_assignment": False,
    "radius_eap_method": "PAP",
    "radius_auth_method": "pap",  # For WiFi password requirement check (pap, peap, eap-ttls)
    "radius_allowed_groups": [],

    # Version Tracking (v1.3.16)
    "last_version": VERSION,
    "minimum_version": "1.3.16",  # v1.3.17 requires upgrade from v1.3.16

    # Email/SMTP Settings
    "smtp_enabled": False,
    "smtp_server": "",
    "smtp_port": 587,
    "smtp_use_tls": True,
    "smtp_username": "",
    "smtp_password": "",
    "smtp_from_address": "noreply@example.com",
    "smtp_from_name": "CaddyIAM"
}

# Models
class Settings(BaseModel):
    theme: Optional[str] = None  # Deprecated (frontend uses localStorage) - kept for DB compatibility
    health_check_enabled: bool = False
    health_check_domain: str = ""
    health_check_interval: int = 60
    restart_after_failures: int = 3
    notification_service: str = ""
    notification_url: str = ""
    notification_token: str = ""
    php_enabled: bool = False
    php_path: str = ""
    manager_port: int = Field(default=8000, ge=1, le=65535)
    enhanced_security: bool = False
    caddy_log_level: str = "WARN"
    caddy_admin_port: int = Field(default=12999, ge=1, le=65535)
    notification_events: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Authentication Protocols (v1.3.0)
    auth_protocols_enabled: bool = False
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_signing_key_private: str = ""
    oidc_signing_key_public: str = ""
    ldap_enabled: bool = False
    ldap_port: int = 3389
    ldap_base_dn: str = ""
    ldap_bind_dn: str = ""
    ldap_username_attribute: str = "both"
    ldap_allowed_groups: List[str] = []
    radius_enabled: bool = False
    radius_auth_port: int = 1812
    radius_acct_port: int = 1813
    radius_secret: str = ""
    radius_vlan_assignment: bool = False
    radius_eap_method: str = "PAP"
    radius_allowed_groups: List[str] = []

    # Version Tracking (v1.3.16)
    last_version: str = VERSION  # Last CaddyMAN version that modified this database
    minimum_version: str = "1.3.16"  # Minimum version allowed - v1.3.17 requires upgrade from v1.3.16

    smtp_enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_address: str = ""
    smtp_from_name: str = "CaddyIAM"

    # Branding & Domain Settings (v1.3.5)
    organization_name: str = "CaddyMAN"
    domain_url: str = "http://localhost:8000"
    admin_path_mode: bool = False

    @field_validator('php_path')
    @classmethod
    def validate_php_path(cls, v, info: ValidationInfo):
        # Only validate if PHP is enabled
        if info.data.get('php_enabled', False) and v:
            php_path = v
            # If path is a directory, append platform-specific php-cgi executable
            if os.path.isdir(php_path):
                php_path = os.path.join(php_path, get_php_cgi_executable())

            # Check if php-cgi executable exists
            if not os.path.exists(php_path):
                raise ValueError(f"PHP-CGI executable not found at path: {php_path}")
        return v

class User(BaseModel):
    id: str
    username: str
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    password_hash: str
    groups: List[str] = Field(default_factory=list)
    totp_secret: Optional[str] = None
    totp_enabled: bool = False
    email_verified: bool = False
    password_reset_token: Optional[str] = None
    password_reset_expires: Optional[str] = None  # ISO format datetime string

class Group(BaseModel):
    id: str
    name: str
    description: str = ""
    system: bool = False  # System groups cannot be deleted
    radius_vlan: Optional[int] = None  # VLAN assignment for RADIUS
    force_2fa: bool = False  # Require 2FA for users in this group
    oidc_claims: Optional[str] = None  # JSON string with custom OIDC claims for this group

class OAuthClient(BaseModel):
    client_id: str
    client_secret_hash: str  # Hashed client secret
    name: str  # Display name (e.g., "Audiobookshelf")
    redirect_uris: List[str]  # Allowed redirect URIs
    allowed_scopes: List[str] = Field(default_factory=lambda: ["openid", "profile", "email", "groups"])
    grant_types: List[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])
    require_pkce: bool = True
    created_at: str  # ISO format datetime
    enabled: bool = True

class OAuthAuthorizationCode(BaseModel):
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scopes: List[str]
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    expires_at: str  # ISO format datetime
    used: bool = False

class OAuthToken(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    client_id: str
    user_id: str
    scopes: List[str]
    expires_at: str  # ISO format datetime
    created_at: str  # ISO format datetime

class ReverseProxy(BaseModel):
    id: str
    domains: List[str] = Field(default_factory=list)
    upstream: str
    http_ports: List[int] = Field(default_factory=lambda: [80])  # HTTP ports (no TLS)
    https_ports: List[int] = Field(default_factory=list)  # HTTPS ports (with TLS)
    auto_https: bool = False
    enabled: bool = True
    websocket: bool = False
    header_up_host: Optional[str] = None
    remove_origin: bool = False
    remove_referer: bool = False
    custom_headers: Optional[Dict[str, str]] = None
    load_balance: Optional[str] = None
    additional_directives: str = ""  # Additional Caddyfile directives for the reverse_proxy block
    access_groups: List[str] = Field(default_factory=list)
    advanced: Optional[Dict[str, Any]] = None
    # Legacy fields for backward compatibility
    listen_port: Optional[int] = None
    tls: Optional[bool] = None

    @model_validator(mode='after')
    def validate_domains_required(self):
        # In advanced mode, domains are defined in the JSON config, not required here
        if self.advanced:
            return self
        # In simple mode, at least one domain is required
        if not self.domains or len(self.domains) == 0:
            raise ValueError('At least one domain is required for reverse proxy')
        return self

class Website(BaseModel):
    id: str
    domains: List[str] = Field(default_factory=list)
    root: str
    http_ports: List[int] = Field(default_factory=lambda: [80])  # HTTP ports (no TLS)
    https_ports: List[int] = Field(default_factory=list)  # HTTPS ports (with TLS)
    auto_https: bool = False
    enabled: bool = True
    index_files: List[str] = Field(default_factory=lambda: ["index.html"])
    access_groups: List[str] = Field(default_factory=list)
    php_enabled: bool = False
    advanced: Optional[Dict[str, Any]] = None
    # Legacy fields for backward compatibility
    listen_port: Optional[int] = None
    tls: Optional[bool] = None

class UserCreate(BaseModel):
    username: str
    password: str
    groups: List[str] = Field(default_factory=list)
    email: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_token: Optional[str] = None
    two_factor_token: Optional[str] = None  # User portal sends this instead of totp_token

# ====================================================================
# Argon2id Password Hashing with DPAPI-Encrypted Pepper
# ====================================================================

# Path for DPAPI-encrypted pepper file
PEPPER_FILE = Path("pepper.enc")

def _get_dpapi_pepper() -> bytes:
    """
    Get or create DPAPI-encrypted pepper for Argon2id.
    On Windows, uses DPAPI to encrypt pepper bound to local machine/user.
    On other platforms, uses basic file encryption (less secure).
    """
    if platform.system() == 'Windows':
        try:
            import win32crypt
        except ImportError:
            logger.warning("pywin32 not installed - falling back to basic pepper encryption")
            return _get_fallback_pepper()

        if PEPPER_FILE.exists():
            # Read existing encrypted pepper
            try:
                encrypted_pepper = PEPPER_FILE.read_bytes()
                pepper = win32crypt.CryptUnprotectData(encrypted_pepper, None, None, None, 0)[1]
                logger.debug("DPAPI pepper loaded successfully")
                return pepper
            except Exception as e:
                logger.error(f"Failed to decrypt pepper with DPAPI: {e}")
                raise RuntimeError("Failed to decrypt pepper - data may be corrupted or bound to different user/machine")
        else:
            # Generate new pepper and encrypt with DPAPI
            pepper = secrets.token_bytes(32)
            try:
                encrypted_pepper = win32crypt.CryptProtectData(pepper, "CaddyMAN Argon2id Pepper", None, None, None, 0)
                PEPPER_FILE.write_bytes(encrypted_pepper)
                logger.info("Generated new DPAPI-encrypted pepper")
                return pepper
            except Exception as e:
                logger.error(f"Failed to encrypt pepper with DPAPI: {e}")
                raise RuntimeError(f"Failed to create DPAPI-encrypted pepper: {e}")
    else:
        # Non-Windows fallback (less secure - just uses file permissions)
        return _get_fallback_pepper()

def _get_fallback_pepper() -> bytes:
    """Fallback pepper storage for non-Windows platforms (less secure)"""
    if PEPPER_FILE.exists():
        return PEPPER_FILE.read_bytes()
    else:
        pepper = secrets.token_bytes(32)
        PEPPER_FILE.write_bytes(pepper)
        # Set restrictive permissions on Unix-like systems
        if hasattr(os, 'chmod'):
            os.chmod(PEPPER_FILE, 0o600)
        logger.warning("Using fallback pepper storage (not DPAPI-protected)")
        return pepper

# Initialize Argon2id hasher with strong security parameters
# time_cost=2 (iterations), memory_cost=524288 (512 MiB), parallelism=4
_argon2_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=524288,  # 512 MiB (512 * 1024)
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID  # Argon2id
)

def _add_pepper(password: str) -> str:
    """
    Add DPAPI-encrypted pepper to password before hashing.
    v1.3.17+: Always uses pepper with Argon2id.
    """
    pepper = _get_dpapi_pepper()
    # Use HMAC to combine password and pepper securely
    h = hmac.HMAC(pepper, hashes.SHA256())
    h.update(password.encode('utf-8'))
    peppered = h.finalize()
    # Return base64 encoded to use as password input for Argon2
    return base64.b64encode(peppered).decode('ascii')

def hash_password(password: str) -> str:
    """
    Hash password using Argon2id with DPAPI-encrypted pepper.
    v1.3.17+ only supports Argon2id (bcrypt removed).
    """
    # Use Argon2id with DPAPI-encrypted pepper
    peppered_password = _add_pepper(password)
    hashed = _argon2_hasher.hash(peppered_password)
    logger.debug("Password hashed with Argon2id")
    return hashed

def _get_pepper_fernet_key() -> bytes:
    """
    Get Fernet encryption key derived from DPAPI-protected pepper.
    Uses the same pepper as password hashing for consistent security.
    """
    pepper = _get_dpapi_pepper()
    # Derive a Fernet-compatible key from the pepper using HKDF
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'caddyman-settings-encryption',
        info=b'fernet-key-derivation'
    )
    key = hkdf.derive(pepper)
    return base64.urlsafe_b64encode(key)

def encrypt_setting(plaintext: str) -> str:
    """
    Encrypt a setting value using pepper-based Fernet encryption.
    Returns encrypted value with 'enc:' prefix to mark it as encrypted.
    """
    if not plaintext:
        return plaintext
    fernet_key = _get_pepper_fernet_key()
    f = Fernet(fernet_key)
    encrypted = f.encrypt(plaintext.encode('utf-8'))
    return 'enc:' + encrypted.decode('utf-8')

def decrypt_setting(encrypted_or_plain: str) -> str:
    """
    Decrypt a setting value encrypted with pepper-based Fernet.
    If value doesn't start with 'enc:', returns it as-is (plaintext).
    """
    if not encrypted_or_plain or not encrypted_or_plain.startswith('enc:'):
        return encrypted_or_plain
    try:
        encrypted_value = encrypted_or_plain[4:]  # Remove 'enc:' prefix
        fernet_key = _get_pepper_fernet_key()
        f = Fernet(fernet_key)
        decrypted = f.decrypt(encrypted_value.encode('utf-8'))
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to decrypt setting: {e}")
        raise RuntimeError("Failed to decrypt setting - pepper may be incorrect")

def verify_password(password: str, hashed: str) -> bool:
    """
    Verify password against Argon2id or bcrypt hash.

    Strategy:
    - User passwords: Argon2id with pepper (slow is acceptable, infrequent login, weak passwords)
    - OAuth client secrets: bcrypt (fast needed for frequent API calls, already high-entropy)

    v1.3.17+: All user passwords are Argon2id (enforced by v1.3.16 minimum version).
    OAuth client secrets remain bcrypt permanently for performance.
    """
    try:
        # Check if it's a bcrypt hash (OAuth client secrets)
        if hashed.startswith('$2b$') or hashed.startswith('$2a$') or hashed.startswith('$2y$'):
            try:
                # Bcrypt hash - no pepper, fast verification (~50ms)
                result = bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
                if result:
                    logger.debug("Password verified with bcrypt (OAuth client secret)")
                return result
            except Exception as e:
                logger.debug(f"Bcrypt verification failed: {e}")
                return False

        # Argon2id hash - use peppered password, slow verification (~500ms)
        peppered_password = _add_pepper(password)
        try:
            _argon2_hasher.verify(hashed, peppered_password)
            logger.debug("Password verified with Argon2id")
            return True
        except (VerifyMismatchError, VerificationError, InvalidHash):
            logger.debug("Argon2id verification failed")
            return False
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def user_requires_2fa(user: dict) -> bool:
    """Check if user is required to have 2FA based on their group memberships"""
    user_groups = user.get('groups', [])
    all_groups = get_all_groups_from_db()

    for group in all_groups:
        if group['id'] in user_groups and group.get('force_2fa', False):
            return True
    return False

async def check_password_pwned(password: str) -> bool:
    """Check if password appears in Have I Been Pwned database"""
    try:
        # Hash the password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query HIBP API
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
                timeout=5.0
            )

            if response.status_code == 200:
                # Check if our suffix appears in the results
                hashes = response.text.split('\n')
                for hash_line in hashes:
                    if hash_line.startswith(suffix):
                        return True
        return False
    except Exception as e:
        logger.warning(f"Failed to check password against HIBP: {e}")
        # If check fails, allow password (don't block users due to API issues)
        return False

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength based on complexity and length requirements.
    Returns (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"

    # Check character types
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    # Count how many character types are present
    complexity_count = sum([has_lower, has_upper, has_digit, has_symbol])

    # Determine minimum length based on complexity
    if complexity_count >= 4:
        min_length = 8
        complexity_desc = "lowercase, uppercase, numbers, and symbols"
    elif complexity_count == 3:
        min_length = 10
        complexity_desc = "at least 3 of: lowercase, uppercase, numbers, symbols"
    elif complexity_count == 2:
        min_length = 14
        complexity_desc = "at least 2 of: lowercase, uppercase, numbers, symbols"
    else:  # complexity_count == 1
        min_length = 20
        complexity_desc = "only one character type"

    # Check length requirement
    if len(password) < min_length:
        return False, f"Password with {complexity_desc} must be at least {min_length} characters long (current: {len(password)})"

    return True, ""

def generate_totp_secret() -> str:
    """Generate a new TOTP secret"""
    return pyotp.random_base32()

def generate_totp_qr_code(username: str, secret: str) -> str:
    """Generate QR code for TOTP setup, returns base64 encoded PNG"""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="CaddyMAN")

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, 'PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()

    return f"data:image/png;base64,{img_base64}"

def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 1 time step tolerance
    except:
        return False

# SQLite Database Functions
def init_database():
    """Initialize SQLite database with tables for users, settings, websites, proxies, and groups"""
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                groups TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled INTEGER DEFAULT 0,
                email TEXT,
                email_verified INTEGER DEFAULT 0,
                first_name TEXT,
                last_name TEXT,
                wifi_password_hash TEXT,
                is_admin INTEGER DEFAULT 0,
                password_reset_token TEXT,
                password_reset_expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration: Add missing columns to existing users table
        for col_def in [
            'email TEXT',
            'email_verified INTEGER DEFAULT 0',
            'first_name TEXT',
            'last_name TEXT',
            'wifi_password_hash TEXT',
            'is_admin INTEGER DEFAULT 0',
            'password_reset_token TEXT',
            'password_reset_expires TIMESTAMP'
        ]:
            try:
                cursor.execute(f'ALTER TABLE users ADD COLUMN {col_def}')
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Create settings table (key-value store)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create groups table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                system INTEGER DEFAULT 0,
                radius_vlan INTEGER,
                force_2fa INTEGER DEFAULT 0,
                oidc_claims TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration: Add missing columns to existing groups table
        try:
            cursor.execute('ALTER TABLE groups ADD COLUMN radius_vlan INTEGER')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE groups ADD COLUMN force_2fa INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE groups ADD COLUMN oidc_claims TEXT')
        except sqlite3.OperationalError:
            pass

        # Create websites table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id TEXT PRIMARY KEY,
                domains TEXT,
                root TEXT NOT NULL,
                http_ports TEXT,
                https_ports TEXT,
                auto_https INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                index_files TEXT,
                access_groups TEXT,
                php_enabled INTEGER DEFAULT 0,
                advanced TEXT,
                listen_port INTEGER,
                tls TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration: Add missing columns to existing websites table
        for col_def in [
            'access_groups TEXT',
            'php_enabled INTEGER DEFAULT 0',
            'advanced TEXT',
            'listen_port INTEGER',
            'tls TEXT'
        ]:
            try:
                cursor.execute(f'ALTER TABLE websites ADD COLUMN {col_def}')
            except sqlite3.OperationalError:
                pass

        # Create reverse_proxies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reverse_proxies (
                id TEXT PRIMARY KEY,
                domains TEXT,
                target TEXT NOT NULL,
                http_ports TEXT,
                https_ports TEXT,
                auto_https INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                access_groups TEXT,
                advanced TEXT,
                additional_directives TEXT,
                listen_port INTEGER,
                tls TEXT,
                websocket INTEGER DEFAULT 0,
                header_up_host TEXT,
                remove_origin INTEGER DEFAULT 0,
                remove_referer INTEGER DEFAULT 0,
                custom_headers TEXT,
                load_balance TEXT,
                managed INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration: Add missing columns to existing reverse_proxies table
        for col_def in [
            'websocket INTEGER DEFAULT 0',
            'header_up_host TEXT',
            'remove_origin INTEGER DEFAULT 0',
            'remove_referer INTEGER DEFAULT 0',
            'custom_headers TEXT',
            'load_balance TEXT',
            'managed INTEGER DEFAULT 0'
        ]:
            try:
                cursor.execute(f'ALTER TABLE reverse_proxies ADD COLUMN {col_def}')
            except sqlite3.OperationalError:
                pass

        # v1.3.17: All database migrations removed
        # Minimum version is 1.3.16, so all schemas are already up-to-date
        # New installations get complete schema from CREATE TABLE statements above

        # Create OAuth clients table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                allowed_groups TEXT NOT NULL DEFAULT '[]',
                allowed_scopes TEXT NOT NULL,
                grant_types TEXT NOT NULL,
                require_pkce INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                enabled INTEGER DEFAULT 1
            )
        ''')

        # Migration: Add missing columns to oauth_clients
        try:
            cursor.execute("ALTER TABLE oauth_clients ADD COLUMN allowed_groups TEXT NOT NULL DEFAULT '[]'")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("ALTER TABLE oauth_clients ADD COLUMN enabled INTEGER DEFAULT 1")
        except sqlite3.OperationalError:
            pass

        # Create OAuth authorization codes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scopes TEXT NOT NULL,
                code_challenge TEXT,
                code_challenge_method TEXT,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create OAuth tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS oauth_tokens (
                access_token TEXT PRIMARY KEY,
                refresh_token TEXT,
                client_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        # Create invite tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS invite_tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                groups TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_by TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        ''')

        # Create password reset tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                email TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                used BOOLEAN DEFAULT 0
            )
        ''')

        # Create blocked IPs table for security monitoring
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                block_count INTEGER DEFAULT 1,
                status TEXT DEFAULT 'temporary',
                last_blocked_at REAL NOT NULL,
                block_until REAL,
                last_reason TEXT,
                is_external INTEGER DEFAULT 0,
                first_seen_at REAL NOT NULL,
                notes TEXT
            )
        ''')

        # Create permanent blocklist table for Caddy-level IP blocking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS permanent_blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_range TEXT NOT NULL UNIQUE,
                reason TEXT,
                added_at REAL NOT NULL,
                added_by TEXT
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_group_name ON groups(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_website_enabled ON websites(enabled)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON reverse_proxies(enabled)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_oauth_code_client ON oauth_authorization_codes(client_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_oauth_token_client ON oauth_tokens(client_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_oauth_token_user ON oauth_tokens(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_invite_token_expires ON invite_tokens(expires_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ip_status ON blocked_ips(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ip_block_until ON blocked_ips(block_until)')

        conn.commit()
        logger.info("Database initialized successfully")

def get_db_connection():
    """Get a database connection with row factory"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def get_all_users_from_db():
    """Get all users from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        rows = cursor.fetchall()
        users = []
        for row in rows:
            user = dict(row)
            user['groups'] = json.loads(user['groups'])
            user['totp_enabled'] = bool(user.get('totp_enabled', 0))
            user['email_verified'] = bool(user.get('email_verified', 0))
            users.append(user)
        return users

def get_user_by_username_from_db(username: str):
    """Get user by username from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            user = dict(row)
            user['groups'] = json.loads(user['groups'])
            user['totp_enabled'] = bool(user.get('totp_enabled', 0))
            user['email_verified'] = bool(user.get('email_verified', 0))
            return user
    return None

def get_user_by_id_from_db(user_id: str):
    """Get user by ID from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        if row:
            user = dict(row)
            user['groups'] = json.loads(user['groups'])
            user['totp_enabled'] = bool(user.get('totp_enabled', 0))
            user['email_verified'] = bool(user.get('email_verified', 0))
            return user
    return None

def save_user_to_db(user: dict):
    """Save or update user in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO users
            (id, username, email, first_name, last_name, password_hash, groups, totp_secret, totp_enabled,
             email_verified, password_reset_token, password_reset_expires, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            user['id'],
            user['username'],
            user.get('email', ''),
            user.get('first_name', ''),
            user.get('last_name', ''),
            user['password_hash'],
            json.dumps(user.get('groups', [])),
            user.get('totp_secret'),
            1 if user.get('totp_enabled', False) else 0,
            1 if user.get('email_verified', False) else 0,
            user.get('password_reset_token'),
            user.get('password_reset_expires')
        ))
        conn.commit()

def delete_user_from_db(user_id: str):
    """Delete user from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()

def save_invite_token_to_db(invite: dict):
    """Save invite token to database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO invite_tokens (token, username, email, groups, expires_at, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            invite['token'],
            invite['username'],
            invite['email'],
            json.dumps(invite['groups']),
            invite['expires_at'],
            invite['created_by'],
            invite['created_at']
        ))
        conn.commit()

def get_invite_token_from_db(token: str):
    """Get invite token from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM invite_tokens WHERE token = ?', (token,))
        row = cursor.fetchone()
        if row:
            return {
                'token': row['token'],
                'username': row['username'],
                'email': row['email'],
                'groups': json.loads(row['groups']),
                'expires_at': row['expires_at'],
                'created_by': row['created_by'],
                'created_at': row['created_at']
            }
        return None

def delete_invite_token_from_db(token: str):
    """Delete invite token from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM invite_tokens WHERE token = ?', (token,))
        conn.commit()

def get_all_invite_tokens_from_db():
    """Get all invite tokens from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM invite_tokens ORDER BY created_at DESC')
        rows = cursor.fetchall()
        invites = []
        for row in rows:
            row_dict = dict(row)
            invites.append({
                'token': row_dict['token'],
                'username': row_dict['username'],
                'email': row_dict['email'],
                'groups': json.loads(row_dict['groups']) if row_dict['groups'] else [],
                'expires_at': row_dict['expires_at'],
                'created_by': row_dict['created_by'],
                'created_at': row_dict['created_at']
            })
        return invites

def save_password_reset_token_to_db(reset_token: dict):
    """Save password reset token to database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO password_reset_tokens (token, user_id, email, expires_at, created_at, used)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            reset_token['token'],
            reset_token['user_id'],
            reset_token['email'],
            reset_token['expires_at'],
            reset_token['created_at'],
            reset_token.get('used', False)
        ))
        conn.commit()

def get_password_reset_token_from_db(token: str):
    """Get password reset token from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM password_reset_tokens WHERE token = ?', (token,))
        row = cursor.fetchone()
        if row:
            return {
                'token': row['token'],
                'user_id': row['user_id'],
                'email': row['email'],
                'expires_at': row['expires_at'],
                'created_at': row['created_at'],
                'used': bool(row['used'])
            }
        return None

def mark_password_reset_token_used(token: str):
    """Mark password reset token as used"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE password_reset_tokens SET used = 1 WHERE token = ?', (token,))
        conn.commit()

def delete_password_reset_token_from_db(token: str):
    """Delete password reset token from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM password_reset_tokens WHERE token = ?', (token,))
        conn.commit()

def get_all_blocked_ips_from_db():
    """Get all blocked IPs from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM blocked_ips ORDER BY last_blocked_at DESC')
        rows = cursor.fetchall()
        blocked = []
        for row in rows:
            blocked.append(dict(row))
        return blocked

def get_blocked_ip_from_db(ip_address: str):
    """Get specific blocked IP from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM blocked_ips WHERE ip_address = ?', (ip_address,))
        row = cursor.fetchone()
        return dict(row) if row else None

def save_blocked_ip_to_db(ip_data: dict):
    """Save or update blocked IP in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips
            (ip_address, block_count, status, last_blocked_at, block_until, last_reason, is_external, first_seen_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip_data['ip_address'],
            ip_data.get('block_count', 1),
            ip_data.get('status', 'temporary'),
            ip_data['last_blocked_at'],
            ip_data.get('block_until'),
            ip_data.get('last_reason'),
            ip_data.get('is_external', 0),
            ip_data.get('first_seen_at', ip_data['last_blocked_at']),
            ip_data.get('notes')
        ))
        conn.commit()

def update_blocked_ip_status(ip_address: str, status: str):
    """Update the status of a blocked IP"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE blocked_ips
            SET status = ?
            WHERE ip_address = ?
        ''', (status, ip_address))
        conn.commit()

def delete_blocked_ip_from_db(ip_address: str):
    """Delete blocked IP from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))
        conn.commit()

# ============================================================================
# PERMANENT BLOCKLIST FUNCTIONS (Caddy-level IP blocking)
# ============================================================================

def validate_ip_or_cidr(value: str) -> bool:
    """Validate IP address or CIDR notation"""
    import ipaddress
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

def get_permanent_blocklist():
    """Get all permanent blocklist entries"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM permanent_blocklist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]

def is_ip_in_permanent_blocklist(ip_address: str) -> dict | None:
    """
    Check if an IP address falls within any CIDR range in the permanent blocklist.
    Returns the blocklist entry if found, None otherwise.
    """
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return None

    blocklist = get_permanent_blocklist()
    for entry in blocklist:
        try:
            network = ipaddress.ip_network(entry['ip_range'], strict=False)
            if ip_obj in network:
                return entry
        except ValueError:
            # If ip_range is invalid, skip it
            continue

    return None

def is_external_ip(ip_address: str) -> bool:
    """
    Check if an IP address is external (not private/loopback).
    Returns True if the IP is external (internet-facing), False if internal/private.
    """
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return not (ip_obj.is_loopback or ip_obj.is_private)
    except ValueError:
        return False

def get_permanent_blocklist_entry(entry_id: int):
    """Get a specific permanent blocklist entry by ID"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM permanent_blocklist WHERE id = ?', (entry_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def add_to_permanent_blocklist(ip_range: str, reason: str = None, added_by: str = None):
    """Add an IP or CIDR range to the permanent blocklist"""
    import ipaddress
    # Normalize the IP/CIDR
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        normalized = str(network)
    except ValueError:
        # Single IP without CIDR notation
        normalized = ip_range

    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO permanent_blocklist (ip_range, reason, added_at, added_by)
            VALUES (?, ?, ?, ?)
        ''', (normalized, reason, time.time(), added_by))
        conn.commit()
        return cursor.lastrowid

def remove_from_permanent_blocklist(entry_id: int):
    """Remove an entry from the permanent blocklist by ID"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM permanent_blocklist WHERE id = ?', (entry_id,))
        conn.commit()
        return cursor.rowcount > 0

def permanently_block_ip(ip_address: str, reason: str, is_external: bool = False):
    """
    Permanently block an IP address via Caddy-level blocklist.
    All blocks are now permanent - no more temporary blocks.
    Returns info about the block.
    """
    current_time = time.time()

    # Check if already in permanent blocklist
    existing = is_ip_in_permanent_blocklist(ip_address)
    if existing:
        logger.info(f"IP {ip_address} already in permanent blocklist: {existing['ip_range']}")
        return {
            'ip_address': ip_address,
            'reason': existing.get('reason', reason),
            'added_at': existing.get('added_at', current_time),
            'is_external': is_external,
            'already_blocked': True
        }

    # Add to permanent blocklist
    try:
        entry_id = add_to_permanent_blocklist(ip_address, reason, "system")
        logger.critical(f"PERMANENT BLOCK: {ip_address} added to blocklist. Reason: {reason}")

        return {
            'ip_address': ip_address,
            'entry_id': entry_id,
            'reason': reason,
            'added_at': current_time,
            'is_external': is_external,
            'already_blocked': False,
            '_needs_caddy_reload': True
        }
    except Exception as e:
        if 'UNIQUE constraint failed' in str(e):
            logger.info(f"IP {ip_address} already in permanent blocklist (constraint)")
            return {
                'ip_address': ip_address,
                'reason': reason,
                'added_at': current_time,
                'is_external': is_external,
                'already_blocked': True
            }
        logger.error(f"Failed to add {ip_address} to permanent blocklist: {e}")
        raise

async def track_admin_403_attempt(ip_address: str, endpoint: str, is_external: bool = False):
    """
    Track 403 errors on admin endpoints and permanently block IPs that exceed the threshold.
    Returns True if the IP was blocked, False otherwise.
    """
    global admin_403_attempts

    current_time = time.time()

    # Check if IP is already in permanent blocklist
    if is_ip_in_permanent_blocklist(ip_address):
        return False  # Already permanently blocked

    # Track this 403 attempt
    if ip_address not in admin_403_attempts:
        admin_403_attempts[ip_address] = []

    admin_403_attempts[ip_address].append(current_time)

    # Clean old attempts outside the window
    admin_403_attempts[ip_address] = [
        ts for ts in admin_403_attempts[ip_address]
        if current_time - ts < ADMIN_403_WINDOW
    ]

    # Check if threshold exceeded - instant permanent ban
    if len(admin_403_attempts[ip_address]) >= ADMIN_403_MAX_ATTEMPTS:
        reason = f"Admin endpoint probing: {len(admin_403_attempts[ip_address])} 403 errors in {ADMIN_403_WINDOW}s on {endpoint}"
        ip_data = permanently_block_ip(ip_address, reason, is_external)

        # Clear the attempts since we've blocked them
        admin_403_attempts[ip_address] = []

        if not ip_data.get('already_blocked'):
            logger.critical(f"PERMANENT BLOCK - ADMIN PROBING: {ip_address} hit {endpoint} {ADMIN_403_MAX_ATTEMPTS}+ times in {ADMIN_403_WINDOW}s")

            # Broadcast blocked IP event via SSE
            await broadcast_sse_event('ip_permanently_blocked', {
                'ip_address': ip_address,
                'reason': reason,
                'is_external': int(is_external)
            })

            # Reload Caddy to apply block
            if ip_data.get('_needs_caddy_reload'):
                try:
                    await reload_caddy()
                    logger.info(f"Caddy reloaded to apply permanent block for {ip_address}")
                except Exception as e:
                    logger.error(f"Failed to reload Caddy: {e}")

            await send_ntfy_notification(
                "Security Alert: IP Permanently Blocked",
                f"🔒 IP PERMANENTLY BLOCKED - ADMIN ENDPOINT PROBING\n\n"
                f"Source IP: {ip_address}\n"
                f"IP Type: {'EXTERNAL (Internet)' if is_external else 'Internal/Private'}\n"
                f"Endpoint: {endpoint}\n"
                f"Attempts: {ADMIN_403_MAX_ATTEMPTS}+ in {ADMIN_403_WINDOW} seconds\n"
                f"Block Type: PERMANENT (Caddy + App level)\n\n"
                f"This IP was probing admin endpoints without authentication.",
                tags="rotating_light,shield",
                priority="high"
            )

        return True

    return False

def get_settings_from_db():
    """Get all settings from database as a dictionary (uses cache if available)"""
    global _cached_settings

    # Return cached settings if available
    if _cached_settings is not None:
        return _cached_settings

    # Load from database
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT key, value FROM settings')
        rows = cursor.fetchall()
        settings = {}
        for row in rows:
            try:
                value = json.loads(row['value'])
            except:
                value = row['value']
            # Automatically decrypt encrypted settings (those starting with 'enc:')
            if isinstance(value, str) and value.startswith('enc:'):
                try:
                    value = decrypt_setting(value)
                except Exception as e:
                    logger.error(f"Failed to decrypt setting {row['key']}: {e}")
                    # Keep the encrypted value to avoid breaking things
            settings[row['key']] = value

        # Merge with defaults for any missing keys
        merged_settings = {**default_settings, **settings}

        # Special handling for notification_events: merge defaults with saved events
        # This ensures new events added in updates are included with their defaults
        if 'notification_events' in settings and 'notification_events' in default_settings:
            # Start with defaults, then overlay user's saved preferences
            default_events = default_settings['notification_events']
            saved_events = settings['notification_events']
            merged_events = {**default_events, **saved_events}
            merged_settings['notification_events'] = merged_events

        _cached_settings = merged_settings
        return _cached_settings

def reload_settings_cache():
    """Force reload of settings cache from database"""
    global _cached_settings
    _cached_settings = None
    settings = get_settings_from_db()
    # Apply log level to CaddyMAN logger when settings reload
    apply_log_level(settings)
    return settings

def apply_log_level(settings: dict = None):
    """Apply log level from settings to CaddyMAN logger

    Log levels:
    - DEBUG: Detailed information, typically only for debugging
    - INFO: General informational messages (default)
    - WARN: Warning messages for potentially harmful situations
    - ERROR: Error messages for serious problems
    """
    if settings is None:
        settings = get_settings_from_db()

    log_level_str = settings.get("caddy_log_level", "WARN").upper()

    # Map Caddy log levels to Python logging levels
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    log_level = level_map.get(log_level_str, logging.INFO)

    # Apply to CaddyMAN logger
    logger.setLevel(log_level)

    # Also apply to all handlers (console and file)
    for handler in logger.handlers:
        handler.setLevel(log_level)

    # Apply to root logger handlers too (affects all loggers)
    for handler in logging.root.handlers:
        handler.setLevel(log_level)

    # Log at WARNING level so it shows for WARN/ERROR/CRITICAL settings
    # (INFO and DEBUG users will see other logs confirming level is working)
    logger.warning(f"CaddyMAN log level set to: {log_level_str}")

def save_settings_to_db(settings: dict):
    """Save settings to database and update cache"""
    global _cached_settings
    # Always update last_version to current VERSION when saving settings
    settings['last_version'] = VERSION
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        for key, value in settings.items():
            cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, json.dumps(value) if not isinstance(value, str) else value))
        conn.commit()
    # Update cache with new settings
    reload_settings_cache()

def get_caddy_admin_url():
    """Get the Caddy admin URL from settings"""
    settings = get_settings_from_db()
    port = settings.get("caddy_admin_port", 12999)
    return f"http://localhost:{port}"

# Groups database functions
def get_all_groups_from_db():
    """Get all groups from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM groups ORDER BY name')
        rows = cursor.fetchall()
        groups = []
        for row in rows:
            row_dict = dict(row)
            groups.append({
                'id': row_dict['id'],
                'name': row_dict['name'],
                'description': row_dict['description'],
                'system': bool(row_dict['system']),
                'radius_vlan': row_dict.get('radius_vlan'),
                'force_2fa': bool(row_dict.get('force_2fa', 0)),
                'oidc_claims': row_dict.get('oidc_claims')
            })
        return groups

def get_group_by_id_from_db(group_id: str):
    """Get a group by ID"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,))
        row = cursor.fetchone()
        if row:
            row_dict = dict(row)
            return {
                'id': row_dict['id'],
                'name': row_dict['name'],
                'description': row_dict['description'],
                'system': bool(row_dict['system']),
                'radius_vlan': row_dict.get('radius_vlan'),
                'force_2fa': bool(row_dict.get('force_2fa', 0)),
                'oidc_claims': row_dict.get('oidc_claims')
            }
        return None

def save_group_to_db(group: dict):
    """Save/update a group in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO groups (id, name, description, system, radius_vlan, force_2fa, oidc_claims, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            group['id'],
            group['name'],
            group.get('description', ''),
            int(group.get('system', False)),
            group.get('radius_vlan'),
            int(group.get('force_2fa', False)),
            group.get('oidc_claims')
        ))
        conn.commit()

def delete_group_from_db(group_id: str):
    """Delete a group from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM groups WHERE id = ? AND system = 0', (group_id,))
        conn.commit()

# OAuth/OIDC Helper Functions
def generate_rsa_keypair():
    """Generate RSA key pair for OIDC JWT signing"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem

def ensure_oidc_keys():
    """Ensure OIDC signing keys exist, generate if needed"""
    settings = get_settings_from_db()
    if not settings.get('oidc_signing_key_private') or not settings.get('oidc_signing_key_public'):
        logger.info("Generating OIDC RSA keypair...")
        private_key, public_key = generate_rsa_keypair()
        save_settings_to_db({
            'oidc_signing_key_private': private_key,
            'oidc_signing_key_public': public_key
        })
        logger.info("OIDC keys generated successfully")
        return private_key, public_key
    return settings['oidc_signing_key_private'], settings['oidc_signing_key_public']

def create_jwt_token(user_id: str, client_id: str, scopes: List[str], expires_in: int = 3600):
    """
    Create a JWT access token
    Security: Includes jti for replay prevention, no sensitive data in payload
    """
    settings = get_settings_from_db()
    private_key, _ = ensure_oidc_keys()

    now = int(time.time())
    user = get_user_by_id_from_db(user_id)

    # Security: Block admin users from OIDC
    if user.get('is_admin', False):
        raise ValueError("Admin users cannot use OIDC authentication")

    payload = {
        'iss': settings.get('oidc_issuer', 'http://localhost:12888'),
        'sub': user_id,
        'aud': client_id,
        'exp': now + expires_in,
        'iat': now,
        'jti': secrets.token_urlsafe(16),  # Security: JWT ID for replay prevention
        'scope': ' '.join(scopes),
        'username': user.get('username', ''),
        'email': user.get('email', ''),
        'email_verified': user.get('email_verified', False),
        'name': f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
        'given_name': user.get('first_name', ''),
        'family_name': user.get('last_name', ''),
        'groups': user.get('groups', [])
    }

    # Include kid (key ID) in JWT header for JWKS validation
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': 'default'})
    return token

def create_id_token(user_id: str, client_id: str, username: str, email: str, nonce: Optional[str] = None, groups: Optional[List[str]] = None):
    """
    Create an OpenID Connect ID token
    """
    settings = get_settings_from_db()
    private_key, _ = ensure_oidc_keys()

    now = int(time.time())

    payload = {
        'iss': settings.get('oidc_issuer', 'http://localhost:12888'),
        'sub': username,  # Use username as subject for better compatibility
        'aud': client_id,
        'exp': now + 3600,
        'iat': now,
        'auth_time': now,
        'preferred_username': username,
        'name': username,
        'email': email,
        'email_verified': bool(email),
        'user_id': user_id  # Keep UUID as separate claim
    }

    if nonce:
        payload['nonce'] = nonce

    # Include groups if provided
    if groups:
        payload['groups'] = groups

    # Include kid (key ID) in JWT header for JWKS validation
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': 'default'})
    return token

def get_group_names_from_ids(group_ids: List[str]) -> List[str]:
    """Convert group IDs to group names for OIDC claims"""
    if not group_ids:
        return []

    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        # Create placeholders for SQL IN clause
        placeholders = ','.join('?' * len(group_ids))
        cursor.execute(f'SELECT name FROM groups WHERE id IN ({placeholders})', group_ids)
        rows = cursor.fetchall()
        return [row['name'] for row in rows]

# OAuth Database Functions
def get_all_oauth_clients_from_db():
    """Get all OAuth clients from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM oauth_clients ORDER BY name')
        rows = cursor.fetchall()
        clients = []
        for row in rows:
            # sqlite3.Row doesn't implement .get(); access columns safely
            try:
                allowed_groups_json = row['allowed_groups']
            except Exception:
                allowed_groups_json = '[]'

            clients.append({
                'client_id': row['client_id'],
                'client_secret_hash': row['client_secret_hash'],
                'name': row['name'],
                'redirect_uris': json.loads(row['redirect_uris']),
                'allowed_groups': json.loads(allowed_groups_json or '[]'),
                'allowed_scopes': json.loads(row['allowed_scopes']),
                'grant_types': json.loads(row['grant_types']),
                'require_pkce': bool(row['require_pkce']),
                'created_at': row['created_at'],
                'enabled': bool(row['enabled'])
            })
        return clients

def get_oauth_client_by_id_from_db(client_id: str):
    """Get an OAuth client by ID"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM oauth_clients WHERE client_id = ?', (client_id,))
        row = cursor.fetchone()
        if row:
            try:
                allowed_groups_json = row['allowed_groups']
            except Exception:
                allowed_groups_json = '[]'

            return {
                'client_id': row['client_id'],
                'client_secret_hash': row['client_secret_hash'],
                'name': row['name'],
                'redirect_uris': json.loads(row['redirect_uris']),
                'allowed_groups': json.loads(allowed_groups_json or '[]'),
                'allowed_scopes': json.loads(row['allowed_scopes']),
                'grant_types': json.loads(row['grant_types']),
                'require_pkce': bool(row['require_pkce']),
                'created_at': row['created_at'],
                'enabled': bool(row['enabled'])
            }
        return None

def save_oauth_client_to_db(client: dict):
    """Save or update OAuth client in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO oauth_clients
            (client_id, client_secret_hash, name, redirect_uris, allowed_groups, allowed_scopes, grant_types,
             require_pkce, created_at, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            client['client_id'],
            client['client_secret_hash'],
            client['name'],
            json.dumps(client['redirect_uris']),
            json.dumps(client.get('allowed_groups', [])),
            json.dumps(client['allowed_scopes']),
            json.dumps(client['grant_types']),
            1 if client.get('require_pkce', True) else 0,
            client.get('created_at', datetime.now().isoformat()),
            1 if client.get('enabled', True) else 0
        ))
        conn.commit()

def delete_oauth_client_from_db(client_id: str):
    """Delete OAuth client from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM oauth_clients WHERE client_id = ?', (client_id,))
        conn.commit()

def save_oauth_code_to_db(code: dict):
    """Save OAuth authorization code to database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO oauth_authorization_codes
            (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method,
             expires_at, used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            code['code'],
            code['client_id'],
            code['user_id'],
            code['redirect_uri'],
            json.dumps(code['scopes']),
            code.get('code_challenge'),
            code.get('code_challenge_method'),
            code['expires_at'],
            0
        ))
        conn.commit()

def get_oauth_code_from_db(code: str):
    """Get OAuth authorization code from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM oauth_authorization_codes WHERE code = ?', (code,))
        row = cursor.fetchone()
        if row:
            return {
                'code': row['code'],
                'client_id': row['client_id'],
                'user_id': row['user_id'],
                'redirect_uri': row['redirect_uri'],
                'scopes': json.loads(row['scopes']),
                'code_challenge': row['code_challenge'],
                'code_challenge_method': row['code_challenge_method'],
                'expires_at': row['expires_at'],
                'used': bool(row['used'])
            }
        return None

def mark_oauth_code_used(code: str):
    """Mark OAuth authorization code as used"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE oauth_authorization_codes SET used = 1 WHERE code = ?', (code,))
        conn.commit()

def save_oauth_token_to_db(token: dict):
    """Save OAuth token to database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO oauth_tokens
            (access_token, refresh_token, client_id, user_id, scopes, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            token['access_token'],
            token.get('refresh_token'),
            token['client_id'],
            token['user_id'],
            json.dumps(token['scopes']),
            token['expires_at'],
            token['created_at']
        ))
        conn.commit()

def get_oauth_token_from_db(access_token: str):
    """Get OAuth token from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM oauth_tokens WHERE access_token = ?', (access_token,))
        row = cursor.fetchone()
        if row:
            return {
                'access_token': row['access_token'],
                'refresh_token': row['refresh_token'],
                'client_id': row['client_id'],
                'user_id': row['user_id'],
                'scopes': json.loads(row['scopes']),
                'expires_at': row['expires_at'],
                'created_at': row['created_at']
            }
        return None

def revoke_oauth_token(access_token: str):
    """Revoke OAuth token"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM oauth_tokens WHERE access_token = ?', (access_token,))
        conn.commit()

# Websites database functions
def get_all_websites_from_db():
    """Get all websites from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM websites ORDER BY created_at')
        rows = cursor.fetchall()
        websites = []
        for row in rows:
            websites.append({
                'id': row['id'],
                'domains': json.loads(row['domains']) if row['domains'] else [],
                'root': row['root'],
                'http_ports': json.loads(row['http_ports']) if row['http_ports'] else [],
                'https_ports': json.loads(row['https_ports']) if row['https_ports'] else [],
                'auto_https': bool(row['auto_https']),
                'enabled': bool(row['enabled']),
                'index_files': json.loads(row['index_files']) if row['index_files'] else [],
                'access_groups': json.loads(row['access_groups']) if row['access_groups'] else [],
                'php_enabled': bool(row['php_enabled']),
                'advanced': json.loads(row['advanced']) if row['advanced'] else None,
                'listen_port': row['listen_port'],
                'tls': row['tls']
            })
        return websites

def get_website_by_id_from_db(website_id: str):
    """Get a website by ID"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM websites WHERE id = ?', (website_id,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row['id'],
                'domains': json.loads(row['domains']) if row['domains'] else [],
                'root': row['root'],
                'http_ports': json.loads(row['http_ports']) if row['http_ports'] else [],
                'https_ports': json.loads(row['https_ports']) if row['https_ports'] else [],
                'auto_https': bool(row['auto_https']),
                'enabled': bool(row['enabled']),
                'index_files': json.loads(row['index_files']) if row['index_files'] else [],
                'access_groups': json.loads(row['access_groups']) if row['access_groups'] else [],
                'php_enabled': bool(row['php_enabled']),
                'advanced': json.loads(row['advanced']) if row['advanced'] else None,
                'listen_port': row['listen_port'],
                'tls': row['tls']
            }
        return None

def save_website_to_db(website: dict):
    """Save/update a website in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO websites
            (id, domains, root, http_ports, https_ports, auto_https, enabled, index_files,
             access_groups, php_enabled, advanced, listen_port, tls, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            website['id'],
            json.dumps(website.get('domains', [])),
            website['root'],
            json.dumps(website.get('http_ports', [])),
            json.dumps(website.get('https_ports', [])),
            int(website.get('auto_https', False)),
            int(website.get('enabled', True)),
            json.dumps(website.get('index_files', [])),
            json.dumps(website.get('access_groups', [])),
            int(website.get('php_enabled', False)),
            json.dumps(website.get('advanced')) if website.get('advanced') else None,
            website.get('listen_port'),
            website.get('tls')
        ))
        conn.commit()

def delete_website_from_db(website_id: str):
    """Delete a website from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM websites WHERE id = ?', (website_id,))
        conn.commit()

# Reverse proxies database functions
def get_all_proxies_from_db():
    """Get all reverse proxies from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        # Order by managed DESC (managed=1 first), then by created_at
        cursor.execute('SELECT * FROM reverse_proxies ORDER BY managed DESC, created_at')
        rows = cursor.fetchall()
        proxies = []
        for row in rows:
            proxies.append({
                'id': row['id'],
                'domains': json.loads(row['domains']) if row['domains'] else [],
                'target': row['target'],
                'upstream': row['target'],  # Alias for frontend compatibility
                'http_ports': json.loads(row['http_ports']) if row['http_ports'] else [],
                'https_ports': json.loads(row['https_ports']) if row['https_ports'] else [],
                'auto_https': bool(row['auto_https']),
                'enabled': bool(row['enabled']),
                'access_groups': json.loads(row['access_groups']) if row['access_groups'] else [],
                'advanced': json.loads(row['advanced']) if row['advanced'] else None,
                'additional_directives': row['additional_directives'] if 'additional_directives' in row.keys() else '',
                'listen_port': row['listen_port'],
                'tls': row['tls'],
                'websocket': bool(row['websocket']) if 'websocket' in row.keys() else False,
                'header_up_host': row['header_up_host'] if 'header_up_host' in row.keys() else None,
                'remove_origin': bool(row['remove_origin']) if 'remove_origin' in row.keys() else False,
                'remove_referer': bool(row['remove_referer']) if 'remove_referer' in row.keys() else False,
                'custom_headers': json.loads(row['custom_headers']) if ('custom_headers' in row.keys() and row['custom_headers']) else None,
                'load_balance': row['load_balance'] if 'load_balance' in row.keys() else None,
                'managed': bool(row['managed']) if 'managed' in row.keys() else False
            })
        return proxies

def get_proxy_by_id_from_db(proxy_id: str):
    """Get a reverse proxy by ID"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM reverse_proxies WHERE id = ?', (proxy_id,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row['id'],
                'domains': json.loads(row['domains']) if row['domains'] else [],
                'target': row['target'],
                'upstream': row['target'],  # Alias for frontend compatibility
                'http_ports': json.loads(row['http_ports']) if row['http_ports'] else [],
                'https_ports': json.loads(row['https_ports']) if row['https_ports'] else [],
                'auto_https': bool(row['auto_https']),
                'enabled': bool(row['enabled']),
                'access_groups': json.loads(row['access_groups']) if row['access_groups'] else [],
                'advanced': json.loads(row['advanced']) if row['advanced'] else None,
                'additional_directives': row['additional_directives'] if 'additional_directives' in row.keys() else '',
                'listen_port': row['listen_port'],
                'tls': row['tls'],
                'websocket': bool(row['websocket']) if 'websocket' in row.keys() else False,
                'header_up_host': row['header_up_host'] if 'header_up_host' in row.keys() else None,
                'remove_origin': bool(row['remove_origin']) if 'remove_origin' in row.keys() else False,
                'remove_referer': bool(row['remove_referer']) if 'remove_referer' in row.keys() else False,
                'custom_headers': json.loads(row['custom_headers']) if ('custom_headers' in row.keys() and row['custom_headers']) else None,
                'load_balance': row['load_balance'] if 'load_balance' in row.keys() else None,
                'managed': bool(row['managed']) if 'managed' in row.keys() else False
            }
        return None

def save_proxy_to_db(proxy: dict):
    """Save/update a reverse proxy in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()

        # Handle both 'upstream' (from frontend) and 'target' (from database)
        target = proxy.get('target') or proxy.get('upstream')

        cursor.execute('''
            INSERT OR REPLACE INTO reverse_proxies
            (id, domains, target, http_ports, https_ports, auto_https, enabled,
             access_groups, advanced, additional_directives, listen_port, tls,
             websocket, header_up_host, remove_origin, remove_referer, custom_headers, load_balance,
             updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            proxy['id'],
            json.dumps(proxy.get('domains', [])),
            target,
            json.dumps(proxy.get('http_ports', [])),
            json.dumps(proxy.get('https_ports', [])),
            int(proxy.get('auto_https', False)),
            int(proxy.get('enabled', True)),
            json.dumps(proxy.get('access_groups', [])),
            json.dumps(proxy.get('advanced')) if proxy.get('advanced') else None,
            proxy.get('additional_directives', ''),
            proxy.get('listen_port'),
            proxy.get('tls'),
            int(proxy.get('websocket', False)),
            proxy.get('header_up_host'),
            int(proxy.get('remove_origin', False)),
            int(proxy.get('remove_referer', False)),
            json.dumps(proxy.get('custom_headers')) if proxy.get('custom_headers') else None,
            proxy.get('load_balance')
        ))
        conn.commit()

def delete_proxy_from_db(proxy_id: str):
    """Delete a reverse proxy from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM reverse_proxies WHERE id = ?', (proxy_id,))
        conn.commit()


def sync_managed_domain_proxy():
    """
    Sync the managed proxy for the domain_url setting.
    Creates/updates/deletes the system-managed proxy based on domain_url.
    Automatically removes duplicate user-created proxies with the same domain.
    """
    settings = get_settings_from_db()
    domain_url = settings.get('domain_url', '').strip()
    manager_port = settings.get('manager_port', 8000)

    # Extract domain from URL
    domain = ''
    if domain_url:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(domain_url)
            domain = parsed.netloc or parsed.path  # Handle cases like "example.com" without scheme
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
        except Exception as e:
            logger.error(f"Failed to parse domain_url '{domain_url}': {e}")
            domain = ''

    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()

        # Get existing managed proxy
        cursor.execute('SELECT id, domains, http_ports, https_ports FROM reverse_proxies WHERE managed = 1')
        managed_proxy = cursor.fetchone()

        # If no domain_url, delete any existing managed proxy
        if not domain:
            if managed_proxy:
                cursor.execute('DELETE FROM reverse_proxies WHERE managed = 1')
                conn.commit()
                logger.info("Deleted managed proxy (domain_url is empty)")
            return

        # Check for duplicate user-created proxies with same domain
        cursor.execute('SELECT id, domains FROM reverse_proxies WHERE managed = 0')
        user_proxies = cursor.fetchall()

        for proxy_id, proxy_domains in user_proxies:
            if proxy_domains:
                # Handle both JSON array format and old comma-separated string format
                try:
                    proxy_domain_list = json.loads(proxy_domains)
                except (json.JSONDecodeError, TypeError):
                    # Fallback for old string format
                    proxy_domain_list = [d.strip() for d in str(proxy_domains).split(',')]

                if domain in proxy_domain_list:
                    # Delete user-created proxy with same domain
                    cursor.execute('DELETE FROM reverse_proxies WHERE id = ?', (proxy_id,))
                    logger.info(f"Deleted user-created proxy '{proxy_id}' - replaced by managed proxy for {domain}")

        # Create or update managed proxy
        proxy_id = "managed_domain_proxy"

        if managed_proxy:
            # Update existing managed proxy
            cursor.execute('''
                UPDATE reverse_proxies
                SET domains = ?, target = ?, http_ports = ?, https_ports = ?, auto_https = ?,
                    advanced = ?, header_up_host = ?, access_groups = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (json.dumps([domain]), f'127.0.0.1:{manager_port}',
                  json.dumps([80]), json.dumps([443]), 1,
                  json.dumps({'flush_interval': -1}), '{http.reverse_proxy.upstream.hostport}',
                  json.dumps([]), proxy_id))
            logger.info(f"Updated managed proxy for domain '{domain}'")
        else:
            # Create new managed proxy
            logger.info(f"Creating managed proxy for domain '{domain}'")
            cursor.execute('''
                INSERT INTO reverse_proxies
                (id, domains, target, http_ports, https_ports, auto_https, enabled, access_groups,
                 advanced, additional_directives, listen_port, tls, websocket, header_up_host,
                 remove_origin, remove_referer, custom_headers, load_balance, managed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (proxy_id, json.dumps([domain]), f'127.0.0.1:{manager_port}',
                  json.dumps([80]), json.dumps([443]), 1, 1, json.dumps([]),
                  json.dumps({'flush_interval': -1}), '', None, None, 0,
                  '{http.reverse_proxy.upstream.hostport}', 0, 0, None, None, 1))

        conn.commit()


# Initialize SQLite database
init_database()

# Create default admin group in database if it doesn't exist
groups = get_all_groups_from_db()
if not groups:
    admin_group = {
        "id": "admin_group",
        "name": "admin",
        "description": "Administrator group - cannot be deleted",
        "system": True
    }
    save_group_to_db(admin_group)
    logger.info("Created default admin group")

# Auto-detect password hashing algorithm and prompt for migration if needed
users = get_all_users_from_db()

if not users:
    # Fresh installation detected
    logger.info("Fresh installation - creating default admin user")

    # Create default admin user
    default_admin = {
        "id": str(uuid.uuid4()),
        "username": "admin",
        "password_hash": hash_password("changeme"),
        "groups": ["admin_group"],
        "totp_secret": None,
        "totp_enabled": False,
        "force_password_change": True
    }
    save_user_to_db(default_admin)
    logger.info("Created default admin user with Argon2id: admin/changeme (password change required)")
else:
    # v1.3.17+: Existing installation - verify all passwords are Argon2id
    # bcrypt support removed - minimum version 1.3.16 ensures migration already happened
    first_user = users[0]
    first_hash = first_user.get('password_hash', '')

    if not first_hash.startswith('$argon2'):
        error_msg = (
            f"\n{'='*80}\n"
            f"PASSWORD HASH COMPATIBILITY ERROR\n"
            f"{'='*80}\n"
            f"This database contains bcrypt password hashes.\n"
            f"v1.3.17+ only supports Argon2id password hashing.\n\n"
            f"To fix this:\n"
            f"1. Downgrade to v1.3.16\n"
            f"2. Run the Argon2id migration when prompted\n"
            f"3. Upgrade back to v1.3.17\n\n"
            f"Alternatively, delete CaddyMAN.db to start fresh.\n"
            f"{'='*80}\n"
        )
        logger.critical(error_msg)
        print(error_msg)
        sys.exit(1)

    logger.info("Verified Argon2id password hashes - startup continuing")

# Initialize settings in database if they don't exist
db_settings = get_settings_from_db()
if not db_settings:
    # No settings in DB yet, save defaults
    save_settings_to_db(default_settings)
    logger.info("Initialized default settings in database")
    db_settings = get_settings_from_db()

# ============================================================================
# VERSION COMPATIBILITY CHECK (v1.3.17+)
# ============================================================================
# This ensures:
# 1. Current version meets the minimum requirement set by database
# 2. Database is updated with current version and minimum requirement
# 3. Downgrades are ALLOWED (e.g., v1.3.18 -> v1.3.17) as long as minimum version is met
# ============================================================================
last_version = db_settings.get('last_version', VERSION)  # Default to current if not set
db_minimum_version = db_settings.get('minimum_version', '1.0.0')  # Minimum required by DB

def version_tuple(v):
    """Convert version string to tuple for comparison"""
    return tuple(map(int, (v.split('.')))) if v else (0, 0, 0)

current_version_tuple = version_tuple(VERSION)
db_minimum_version_tuple = version_tuple(db_minimum_version)
last_version_tuple = version_tuple(last_version)

# Log downgrade if happening (informational only, not blocking)
if current_version_tuple < last_version_tuple:
    logger.warning(f"Downgrade detected: v{last_version} -> v{VERSION} (minimum required: v{db_minimum_version})")
    print(f"INFO: Downgrading from v{last_version} to v{VERSION}")

# Check: Current version must meet database's minimum requirement
if current_version_tuple < db_minimum_version_tuple:
    error_msg = (
        f"\n{'='*80}\n"
        f"VERSION TOO OLD ERROR\n"
        f"{'='*80}\n"
        f"Current CaddyMAN version: v{VERSION}\n"
        f"Database last used with: v{last_version}\n"
        f"Database minimum required: v{db_minimum_version}\n\n"
        f"This database requires at least v{db_minimum_version} to run.\n"
        f"You are running v{VERSION} which is too old.\n\n"
        f"The database schema/features were modified by v{last_version},\n"
        f"which set a minimum version requirement of v{db_minimum_version}.\n\n"
        f"You can downgrade, but only to v{db_minimum_version} or newer.\n"
        f"To use v{VERSION}, you would need to recreate your database.\n"
        f"{'='*80}\n"
    )
    logger.critical(error_msg)
    print(error_msg)
    sys.exit(1)

# All checks passed - update database with current version info
# This sets last_version = VERSION and minimum_version from default_settings
if last_version != VERSION:
    logger.info(f"Updating database version: v{last_version} -> v{VERSION}")
    # Update both last_version and minimum_version
    db_settings['last_version'] = VERSION
    db_settings['minimum_version'] = default_settings['minimum_version']  # Current build's requirement
    save_settings_to_db(db_settings)
    logger.info(f"Database now requires minimum version: v{default_settings['minimum_version']}")
else:
    logger.debug(f"Database version current: v{VERSION}")

# Sync managed domain proxy on startup
sync_managed_domain_proxy()

def create_session(user_id: str) -> tuple:
    """Create a new session with CSRF token. Returns (session_id, csrf_token)"""
    session_id = secrets.token_urlsafe(32)  # Cryptographically secure session ID
    csrf_token = secrets.token_urlsafe(32)  # CSRF protection token
    sessions[session_id] = {
        "user_id": user_id,
        "expires_at": time.time() + (3 * 24 * 60 * 60),
        "csrf_token": csrf_token
    }
    return session_id, csrf_token

def get_cookie_domain() -> Optional[str]:
    """
    Get the cookie domain for SSO across subdomains.
    Extracts base domain from domain_url setting (e.g., ".jvr.nz" from "https://users.jvr.nz")
    Returns None if domain_url is not set (cookies will be host-only)
    """
    try:
        settings = get_settings_from_db()
        domain_url = settings.get('domain_url', '').strip()
        if not domain_url or domain_url.startswith('http://localhost') or domain_url.startswith('http://127.0.0.1'):
            return None  # Don't set domain for localhost

        from urllib.parse import urlparse
        parsed = urlparse(domain_url)
        base_domain = parsed.netloc

        # Remove port if present
        if ':' in base_domain:
            base_domain = base_domain.split(':')[0]

        # Extract base domain (e.g., jvr.nz from users.jvr.nz)
        parts = base_domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])  # Get last two parts (e.g., jvr.nz)
            return '.' + base_domain  # Prepend dot for subdomain sharing (e.g., .jvr.nz)

        return None
    except Exception as e:
        logger.warning(f"Failed to get cookie domain: {e}")
        return None

def verify_csrf_token(session_id: Optional[str], token: Optional[str]) -> bool:
    """Verify CSRF token matches the session"""
    if not session_id or not token:
        return False
    session = sessions.get(session_id)
    if not session:
        return False
    return secrets.compare_digest(session.get("csrf_token", ""), token)

def is_account_locked(client_ip: str) -> bool:
    """Check if an IP is currently locked out due to failed attempts"""
    if client_ip not in failed_login_attempts:
        return False
    attempts = failed_login_attempts[client_ip]
    current_time = time.time()
    # Filter to recent attempts within lockout window
    recent_attempts = [t for t in attempts if current_time - t < LOCKOUT_DURATION]
    return len(recent_attempts) >= MAX_LOGIN_ATTEMPTS

def validate_redirect_url(url: str) -> str:
    """Validate and sanitize redirect URL to prevent open redirect attacks"""
    if not url:
        return "/"
    # Only allow relative URLs (starting with /) or same-origin
    url = url.strip()
    # Block absolute URLs to external sites
    if url.startswith('//') or '://' in url:
        return "/"
    # Ensure it starts with /
    if not url.startswith('/'):
        return "/"
    # Block javascript: and data: schemes
    if url.lower().startswith(('javascript:', 'data:', 'vbscript:')):
        return "/"
    return url

def require_csrf(request: Request, session_id: Optional[str]) -> None:
    """Verify CSRF token from request header. Raises HTTPException if invalid."""
    csrf_token = request.headers.get("X-CSRF-Token")
    if not verify_csrf_token(session_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

def get_session_user(session_id: Optional[str]) -> Optional[Dict]:
    if not session_id or session_id not in sessions:
        return None
    session = sessions[session_id]
    if time.time() > session["expires_at"]:
        del sessions[session_id]
        return None
    # Get user from database
    user = get_user_by_id_from_db(session["user_id"])
    return user

def check_access(user: Optional[Dict], access_groups: List[str]) -> bool:
    if not access_groups:
        return True
    if not user:
        return False
    user_groups = set(user.get("groups", []))
    return bool(user_groups.intersection(access_groups))
    
def count_admin_users() -> int:
    """Count how many users are in the admin group"""
    users = get_all_users_from_db()
    admin_count = sum(1 for u in users if "admin_group" in u.get("groups", []))
    return admin_count
    
async def send_notification(title: str, message: str, notification_type: str = "info"):
    """
    Send notification with rich formatting

    notification_type: "info", "success", "warning", "critical", "alert"
    """
    settings = get_settings_from_db()
    if not settings.get("notification_service"):
        return

    # Define notification styling based on type
    notification_styles = {
        "info": {
            "priority": 3,
            "tags": ["information_source"],
            "icon": "https://em-content.zobj.net/source/twitter/53/information_2139.png"
        },
        "success": {
            "priority": 3,
            "tags": ["white_check_mark"],
            "icon": "https://em-content.zobj.net/source/twitter/53/check-mark-button_2705.png"
        },
        "warning": {
            "priority": 4,
            "tags": ["warning"],
            "icon": "https://em-content.zobj.net/source/twitter/53/warning_26a0.png"
        },
        "critical": {
            "priority": 5,
            "tags": ["rotating_light", "warning"],
            "icon": "https://em-content.zobj.net/source/twitter/53/police-car-light_1f6a8.png"
        },
        "alert": {
            "priority": 4,
            "tags": ["bell"],
            "icon": "https://em-content.zobj.net/source/twitter/53/bell_1f514.png"
        }
    }

    style = notification_styles.get(notification_type, notification_styles["info"])

    # Retry logic: 3 attempts with 15 second delays
    max_attempts = 3
    retry_delay = 15

    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if settings["notification_service"] == "gotify":
                    await client.post(f"{settings['notification_url']}/message",
                        params={"token": settings["notification_token"]},
                        json={"title": title, "message": message, "priority": style["priority"]})
                elif settings["notification_service"] == "ntfy":
                    # Get hostname for better context
                    import socket
                    hostname = socket.gethostname()

                    # Build ntfy headers (ntfy uses X- prefixed headers for metadata)
                    # Note: HTTP headers must be ASCII-only, so emojis go in the message body
                    headers = {
                        "X-Title": f"{hostname} - {title}",
                        "X-Priority": str(style["priority"]),
                        "X-Tags": ",".join(style["tags"]),
                        "X-Icon": style["icon"],
                        "Content-Type": "text/plain; charset=utf-8"
                    }

                    # Add click action for certain notification types
                    if notification_type in ["critical", "alert"]:
                        headers["X-Click"] = f"http://{hostname}:8000"

                    # Send message as plain text body to ntfy
                    await client.post(
                        settings["notification_url"],
                        content=message.encode('utf-8'),
                        headers=headers
                    )

            # Success! Log and exit retry loop
            logger.info(f"Notification sent: {title} (type: {notification_type})" + (f" (attempt {attempt})" if attempt > 1 else ""))

            # Log notification to in-memory list
            notification_entry = {
                "timestamp": datetime.now().isoformat(),
                "title": title,
                "message": message,
                "type": notification_type
            }
            notification_log.insert(0, notification_entry)
            if len(notification_log) > MAX_NOTIFICATION_LOG:
                notification_log.pop()

            # Broadcast new notification via SSE
            await broadcast_sse_event('notification', notification_entry)

            return  # Success, exit function

        except Exception as e:
            if attempt < max_attempts:
                logger.warning(f"Failed to send notification '{title}' (attempt {attempt}/{max_attempts}): {type(e).__name__}: {e}. Retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
            else:
                # Final attempt failed
                logger.error(f"Failed to send notification '{title}' after {max_attempts} attempts: {type(e).__name__}: {e}")
                logger.debug(f"Notification details - Type: {notification_type}, Message: {message[:100]}", exc_info=True)

def should_send_notification(event_type: str) -> bool:
    """Check if notifications are enabled for a specific event type"""
    settings = get_settings_from_db()
    if not settings.get("notification_service"):
        return False

    notification_events = settings.get("notification_events", {})
    event_config = notification_events.get(event_type, {})
    return event_config.get("enabled", False)

async def send_event_notification(event_type: str, title: str, message: str, **context):
    """
    Send a notification for a specific event if enabled in settings.

    Args:
        event_type: Event identifier (e.g., "admin_login", "caddy_crashed")
        title: Notification title
        message: Notification message body
        **context: Additional context to include in message (username, ip, etc.)
    """
    if not should_send_notification(event_type):
        return

    settings = get_settings_from_db()
    notification_events = settings.get("notification_events", {})
    event_config = notification_events.get(event_type, {})
    severity = event_config.get("severity", "info")

    # Add context to message if provided
    if context:
        context_lines = [f"{key.replace('_', ' ').title()}: {value}" for key, value in context.items() if value]
        if context_lines:
            message = f"{message}\n\n" + "\n".join(context_lines)

    # Send notification in background to avoid blocking the caller (especially during startup)
    asyncio.create_task(send_notification(title, message, severity))

async def log_activity(username: str, action: str, details: str = "", ip: str = ""):
    """Log user activity with timestamp"""
    activity = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "action": action,
        "details": details,
        "ip": ip
    }
    activity_log.insert(0, activity)  # Add to beginning

    # Keep only last MAX_ACTIVITY_LOG entries
    if len(activity_log) > MAX_ACTIVITY_LOG:
        activity_log.pop()

    logger.info(f"Activity: {username} - {action} - {details} from {ip}")

    # Broadcast new activity via SSE
    await broadcast_sse_event('activity', activity)

async def check_for_updates():
    global update_available
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(UPDATE_CHECK_URL)
            if response.status_code == 200:
                data = response.json()
                remote_version = data.get("version", "0.0.0")

                # Parse versions properly
                def parse_version(v):
                    try:
                        return tuple(int(x) for x in v.split('.'))
                    except:
                        return (0, 0, 0)

                current = parse_version(VERSION)
                remote = parse_version(remote_version)
            #    print("========================")
            #    print("T.V:"+str(current)+" - L.V:"+str(remote))
            #    print("========================")
                if remote > current:
                    # Verify SHA256 hash of the download
                    sha256_valid = False
                    sha256_error = None
                    expected_sha256 = data.get("sha256", "").lower()
                    download_url = data.get("download_url", "")

                    if expected_sha256 and download_url:
                        try:
                            logger.info(f"Verifying SHA256 for update {remote_version}...")
                            # Download the file
                            download_response = await client.get(download_url, follow_redirects=True)
                            if download_response.status_code == 200:
                                # Calculate SHA256
                                file_content = download_response.content
                                calculated_sha256 = hashlib.sha256(file_content).hexdigest().lower()

                                if calculated_sha256 == expected_sha256:
                                    sha256_valid = True
                                    logger.info(f"SHA256 verification passed for update {remote_version}")
                                else:
                                    sha256_error = f"SHA256 mismatch! Expected: {expected_sha256[:16]}..., Got: {calculated_sha256[:16]}..."
                                    logger.warning(f"SHA256 verification FAILED for update {remote_version}: {sha256_error}")
                            else:
                                sha256_error = f"Failed to download file for verification (HTTP {download_response.status_code})"
                                logger.warning(sha256_error)
                        except Exception as e:
                            sha256_error = f"SHA256 verification error: {str(e)}"
                            logger.error(sha256_error)
                    else:
                        sha256_error = "No SHA256 hash provided in update manifest"
                        logger.warning(sha256_error)

                    # Add SHA256 verification status to update data
                    data['sha256_verified'] = sha256_valid
                    data['sha256_error'] = sha256_error

                    # Only send notification if this is a new update
                    was_update_available = update_available is not None
                    update_available = data
                    logger.info(f"Update available: {remote_version}")

                    # Send notification only if this is a newly detected update
                    if not was_update_available:
                        # Include SHA256 warning in notification if verification failed
                        sha256_warning = ""
                        if not sha256_valid:
                            sha256_warning = f"\n\n⚠️ WARNING: SHA256 verification failed!\n{sha256_error}\nDo not install this update unless you trust the source."

                        await send_event_notification(
                            "update_available",
                            "CaddyMAN Update Available" + (" (SHA256 Warning!)" if not sha256_valid else ""),
                            f"Version {remote_version} is now available for download.\n\n"
                            f"Current version: {VERSION}\n"
                            f"New version: {remote_version}\n"
                            f"SHA256 Verified: {'✓ Yes' if sha256_valid else '✗ FAILED'}{sha256_warning}\n\n"
                            f"Download from the dashboard or use caddyman-update.exe to install.",
                            current_version=VERSION,
                            new_version=remote_version
                        )

                        # Broadcast update available via SSE
                        await broadcast_sse_event('update_available', {
                            'version': remote_version,
                            'download_url': data.get('download_url'),
                            'current_version': VERSION,
                            'sha256_verified': sha256_valid,
                            'sha256_error': sha256_error
                        })
                else:
                    update_available = None
                    logger.debug(f"No update. Current: {VERSION}, Remote: {remote_version}")
            else:
                update_available = None
    except Exception as e:
        logger.debug(f"Update check failed: {e}")
        print(f"Update check failed: {e}")
        update_available = None

async def health_check_loop():
    global last_restart_time
    while True:
        try:
            # Wait 60 seconds before each check cycle (reduces disk reads)
            await asyncio.sleep(60)

            # Read settings once per check cycle
            settings = get_settings_from_db()
            if not settings.get("health_check_enabled") or not settings.get("health_check_domain"):
                continue

            domain = settings["health_check_domain"]
            interval = settings.get("health_check_interval", 60)
            max_failures = settings.get("restart_after_failures", 3)

            # Build the URL - handle if user already included scheme
            if domain.startswith('http://') or domain.startswith('https://'):
                url = domain
            else:
                url = f"https://{domain}"  # Default to HTTPS

            failures = 0
            is_up = False

            for attempt in range(max_failures):
                try:
                    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                        response = await client.get(url, follow_redirects=True)
                        # Any response (even 401, 403, 404) means the server is up
                        # Only 5xx errors or connection failures mean it's down
                        if response.status_code < 500:
                            is_up = True
                            logger.debug(f"Health check passed: {url} returned {response.status_code}")
                            break
                        else:
                            logger.warning(f"Health check attempt {attempt + 1}/{max_failures}: {url} returned {response.status_code}")
                except Exception as e:
                    logger.warning(f"Health check attempt {attempt + 1}/{max_failures}: {url} failed - {e}")

                failures += 1
                if attempt < max_failures - 1:  # Don't sleep after last attempt
                    await asyncio.sleep(interval)
            
            if failures >= max_failures:
                time_since_restart = time.time() - last_restart_time
                hours_since_restart = time_since_restart / 3600

                if time_since_restart < 3600:
                    logger.warning(f"Skipping restart - last restart was {hours_since_restart:.1f} hours ago (cooldown: 1 hour)")
                    asyncio.create_task(send_notification(
                        "Restart Cooldown Active",
                        f"⏱️ {domain} is down but restart skipped\n\n"
                        f"Last restart: {hours_since_restart:.1f}h ago\n"
                        f"Cooldown period: 1 hour\n"
                        f"Time remaining: {60 - (hours_since_restart * 60):.0f} minutes",
                        "warning"
                    ))
                    continue

                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        await client.get("https://1.1.1.1")

                    logger.critical(f"{domain} down - initiating system restart (last restart: {hours_since_restart:.1f}h ago)")
                    asyncio.create_task(send_notification(
                        "System Restart Initiated",
                        f"🔄 System will restart in 10 seconds\n\n"
                        f"Reason: {domain} health check failed\n"
                        f"Last restart: {hours_since_restart:.1f}h ago\n"
                        f"Consecutive failures: {max_failures}",
                        "critical"
                    ))

                    # Update and save restart time BEFORE restarting
                    last_restart_time = time.time()
                    save_last_restart_time()

                    if platform.system() == "Windows":
                        subprocess.Popen(["shutdown", "/r", "/t", "10"])
                    else:
                        subprocess.Popen(["sudo", "reboot"])
                except:
                    logger.warning("Domain down but no internet")
                    asyncio.create_task(send_notification(
                        "Health Check Failed",
                        f"⚠️ {domain} is unreachable\n\n"
                        f"Status: Domain down\n"
                        f"Internet: Not available\n"
                        f"Action: Restart skipped (no internet connection)",
                        "alert"
                    ))
        except Exception as e:
            logger.error(f"Health check error: {e}")

async def broadcast_sse_event(event_type: str, data: dict):
    """
    Generic broadcast function for all SSE events.
    Sends any event type with arbitrary data to all connected SSE clients.
    """
    global status_sse_clients
    if not status_sse_clients:
        return

    event_data = {'event': event_type, **data}
    message = f"data: {json.dumps(event_data)}\n\n"

    # Send to all connected clients, remove disconnected ones
    disconnected = []
    for queue in status_sse_clients:
        try:
            await queue.put(message)
        except:
            disconnected.append(queue)

    # Remove disconnected clients
    for queue in disconnected:
        status_sse_clients.remove(queue)

async def broadcast_status_update(item_type: str, item_id: str, online: bool):
    """
    Broadcast proxy/website status update (legacy wrapper for backward compatibility).
    """
    await broadcast_sse_event('status', {'type': item_type, 'id': item_id, 'online': online})

async def status_monitor_loop():
    """
    Background task to monitor proxy and website status.
    Checks every 5 minutes and sends notifications on status changes.
    """
    global status_cache
    while True:
        try:
            # Wait 5 minutes between checks (300 seconds)
            await asyncio.sleep(30)

            # Check all enabled proxies
            proxies = get_all_proxies_from_db()
            for proxy in proxies:
                if not proxy.get('enabled', False):
                    continue

                proxy_id = proxy.get('id')
                upstream = proxy.get('upstream', '')

                # If no upstream field, try to extract from advanced config
                if not upstream and proxy.get('advanced'):
                    advanced_config = proxy.get('advanced')
                    logger.info(f"Background health check for proxy {proxy_id}: advanced config type={type(advanced_config)}, has routes={'routes' in advanced_config if isinstance(advanced_config, dict) else 'N/A'}")
                    # Check if it's a routes array format
                    if isinstance(advanced_config, dict) and 'routes' in advanced_config:
                        # Extract upstream from first route's handler
                        routes = advanced_config.get('routes', [])
                        logger.info(f"Background health check for proxy {proxy_id}: found {len(routes)} routes")
                        for route in routes:
                            if isinstance(route, dict) and 'handle' in route:
                                handlers = route.get('handle', [])
                                for handler in handlers:
                                    if isinstance(handler, dict) and handler.get('handler') == 'reverse_proxy':
                                        upstreams = handler.get('upstreams', [])
                                        if upstreams and isinstance(upstreams, list) and len(upstreams) > 0:
                                            dial = upstreams[0].get('dial', '')
                                            if dial:
                                                # Convert dial address to HTTP URL for health check
                                                upstream = f"http://{dial}"
                                                logger.info(f"Background health check for proxy {proxy_id}: extracted upstream={upstream}")
                                                break
                                if upstream:
                                    break
                            if upstream:
                                break

                if not upstream:
                    logger.info(f"Background health check for proxy {proxy_id}: no upstream found, skipping")
                    continue

                # Extract first upstream if load balanced
                if ',' in upstream:
                    upstream = upstream.split(',')[0].strip()

                # Check status
                is_online = False
                try:
                    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                        response = await client.head(upstream)
                        # ANY response code means the server is online
                        is_online = True
                except (httpx.TimeoutException, httpx.ConnectError):
                    is_online = False
                except Exception as e:
                    # Other errors (redirects, SSL issues, etc.) likely mean server is responding
                    # Try a GET request as fallback (some servers don't support HEAD)
                    try:
                        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                            response = await client.get(upstream)
                            is_online = True
                    except (httpx.TimeoutException, httpx.ConnectError):
                        is_online = False
                    except:
                        # Even if GET fails with other errors, server is likely responding
                        is_online = True
                        logger.debug(f"Proxy {upstream} responded with error but is online: {type(e).__name__}")

                # Check for status change
                previous_status = status_cache.get(f'proxy_{proxy_id}')
                if previous_status is None:
                    # First check - just store status, no notification
                    status_cache[f'proxy_{proxy_id}'] = is_online
                    # Send initial status to SSE clients
                    await broadcast_status_update('proxy', proxy_id, is_online)
                elif previous_status and not is_online:
                    # Was online, now offline
                    logger.warning(f"Proxy went offline: {proxy.get('domains', ['Unknown'])[0]} -> {upstream}")
                    await send_event_notification(
                        "proxy_down",
                        "Reverse Proxy Down",
                        f"Reverse proxy is no longer responding!\n\n"
                        f"Domain: {', '.join(proxy.get('domains', ['Unknown']))}\n"
                        f"Upstream: {upstream}\n"
                        f"Status: Connection timeout or refused\n\n"
                        f"Action: Check if the upstream service is running.",
                        domains=', '.join(proxy.get('domains', [])),
                        upstream=upstream
                    )
                    status_cache[f'proxy_{proxy_id}'] = False
                    # Broadcast status change to SSE clients
                    await broadcast_status_update('proxy', proxy_id, False)
                elif not previous_status and is_online:
                    # Was offline, now online
                    logger.info(f"Proxy back online: {proxy.get('domains', ['Unknown'])[0]} -> {upstream}")
                    await send_event_notification(
                        "proxy_back_online",
                        "Reverse Proxy Back Online",
                        f"Reverse proxy is responding again!\n\n"
                        f"Domain: {', '.join(proxy.get('domains', ['Unknown']))}\n"
                        f"Upstream: {upstream}\n"
                        f"Status: Online",
                        domains=', '.join(proxy.get('domains', [])),
                        upstream=upstream
                    )
                    status_cache[f'proxy_{proxy_id}'] = True
                    # Broadcast status change to SSE clients
                    await broadcast_status_update('proxy', proxy_id, True)

            # Static websites: perform health checks so UI can show Online/Protected/Offline
            websites = get_all_websites_from_db()
            for website in websites:
                if not website.get('enabled', False):
                    continue

                website_id = website.get('id')
                domains = website.get('domains', [])
                if not domains:
                    continue

                domain = domains[0] if isinstance(domains, list) else domains
                http_ports = website.get('http_ports', [])
                https_ports = website.get('https_ports', [])

                # Construct URL - prefer HTTPS
                if https_ports:
                    port = https_ports[0] if isinstance(https_ports, list) else https_ports
                    url = f"https://{domain}:{port}" if port not in [443, '443'] else f"https://{domain}"
                elif http_ports:
                    port = http_ports[0] if isinstance(http_ports, list) else http_ports
                    url = f"http://{domain}:{port}" if port not in [80, '80'] else f"http://{domain}"
                else:
                    url = f"http://{domain}"

                is_online = False
                status_code = None
                is_protected = False

                try:
                    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                        response = await client.head(url)
                        status_code = response.status_code
                        if status_code < 500:
                            is_online = True
                            if status_code in (401, 403):
                                is_protected = True
                except (httpx.TimeoutException, httpx.ConnectError):
                    is_online = False
                except Exception:
                    # Some servers block HEAD; try GET fallback
                    try:
                        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                            response = await client.get(url)
                            status_code = response.status_code
                            if status_code < 500:
                                is_online = True
                                if status_code in (401, 403):
                                    is_protected = True
                    except (httpx.TimeoutException, httpx.ConnectError):
                        is_online = False
                    except Exception as e:
                        is_online = True
                        status_code = getattr(e, '__class__', e).__name__

                previous_status = status_cache.get(f'website_{website_id}')

                # store details
                status_details[f'website_{website_id}'] = {'online': is_online, 'status': status_code, 'protected': is_protected}

                if previous_status is None:
                    status_cache[f'website_{website_id}'] = is_online
                    await broadcast_sse_event('status', {'type': 'website', 'id': website_id, 'online': is_online, 'status': status_code, 'protected': is_protected})
                elif previous_status and not is_online:
                    logger.warning(f"Website went offline: {domain} ({url})")
                    await send_event_notification(
                        "website_down",
                        "Website Down",
                        f"Website is not responding!\n\nDomain: {domain}\nURL: {url}\nStatus: Connection timeout or refused\n\nAction: Check Caddy and website files.",
                        domains=domain
                    )
                    status_cache[f'website_{website_id}'] = False
                    await broadcast_sse_event('status', {'type': 'website', 'id': website_id, 'online': False, 'status': status_code, 'protected': is_protected})
                elif not previous_status and is_online:
                    logger.info(f"Website back online: {domain} ({url})")
                    await send_event_notification(
                        "website_back_online",
                        "Website Back Online",
                        f"Website is responding again!\n\nDomain: {domain}\nURL: {url}\nStatus: Online",
                        domains=domain
                    )
                    status_cache[f'website_{website_id}'] = True
                    await broadcast_sse_event('status', {'type': 'website', 'id': website_id, 'online': True, 'status': status_code, 'protected': is_protected})
            await asyncio.sleep(270)
        except Exception as e:
            logger.error(f"Status monitor error: {e}")

async def cleanup_expired_sessions():
    while True:
        await asyncio.sleep(3600)  # Every hour
        current_time = time.time()
        expired = [sid for sid, sess in sessions.items() if current_time > sess["expires_at"]]
        for sid in expired:
            del sessions[sid]
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")

async def monitor_invites():
    """
    Monitor pending invites and broadcast SSE updates:
    - On creation (handled elsewhere)
    - Every 60 seconds when > 1 minute remaining
    - Every 1 second when < 1 minute remaining
    - On expiry
    """
    # Track last broadcast time for each invite token
    last_broadcast = {}

    while True:
        await asyncio.sleep(1)  # Check every second

        try:
            invites = get_all_invite_tokens_from_db()
            current_time = datetime.now().timestamp()
            current_tokens = set()

            for invite in invites:
                token = invite['token']
                current_tokens.add(token)
                expires_at = invite['expires_at']
                time_remaining = expires_at - current_time

                # Check if expired
                if time_remaining <= 0:
                    # Broadcast expiry event
                    await broadcast_sse_event('invite_expired', {
                        'token': token,
                        'username': invite['username'],
                        'email': invite['email']
                    })

                    # Delete expired invite from database
                    delete_invite_token_from_db(token)

                    # Remove from tracking
                    if token in last_broadcast:
                        del last_broadcast[token]

                    logger.info(f"Invite expired and deleted: {invite['username']} ({invite['email']})")
                    continue

                # Get last broadcast time for this token
                last_time = last_broadcast.get(token, 0)
                time_since_last = current_time - last_time

                # Determine broadcast interval based on time remaining
                if time_remaining < 60:
                    # Less than 1 minute: broadcast every 1 second
                    broadcast_interval = 1
                else:
                    # More than 1 minute: broadcast every 60 seconds
                    broadcast_interval = 60

                # Broadcast if enough time has passed
                if time_since_last >= broadcast_interval:
                    await broadcast_sse_event('invite_update', {
                        'token': token,
                        'username': invite['username'],
                        'email': invite['email'],
                        'expires_at': expires_at,
                        'created_by': invite['created_by'],
                        'time_remaining': time_remaining
                    })
                    last_broadcast[token] = current_time

            # Clean up tracking for deleted invites
            tokens_to_remove = set(last_broadcast.keys()) - current_tokens
            for token in tokens_to_remove:
                del last_broadcast[token]

        except Exception as e:
            logger.error(f"Invite monitor error: {e}")

async def monitor_caddy():
    """Monitor Caddy process and detect crashes"""
    global caddy_process, caddy_stop_reason
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        if caddy_process and caddy_process.returncode is not None:
            # Caddy has stopped unexpectedly
            exit_code = caddy_process.returncode

            # Try to read the last few lines of stderr log to get the error
            error_msg = ""
            try:
                stderr_log_path = os.path.join(LOG_DIR, "caddy.stderr.log")
                if os.path.exists(stderr_log_path):
                    with open(stderr_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        # Get last 5 non-empty lines
                        recent_lines = [line.strip() for line in lines[-10:] if line.strip()]
                        if recent_lines:
                            error_msg = " | ".join(recent_lines[-3:])
            except Exception as e:
                logger.error(f"Could not read Caddy error log: {e}")

            if exit_code == 0:
                caddy_stop_reason = "Stopped normally"
            elif error_msg:
                caddy_stop_reason = f"Crashed (exit code {exit_code}): {error_msg[:200]}"
            else:
                caddy_stop_reason = f"Crashed with exit code {exit_code}"

            logger.warning(f"Caddy process ended: {caddy_stop_reason}")
            caddy_process = None

            # Broadcast Caddy status change via SSE
            await broadcast_sse_event('caddy_status', {
                'status': 'stopped',
                'reason': caddy_stop_reason
            })

async def start_caddy():
    global caddy_process, caddy_stop_reason
    async with config_lock:
        if caddy_process and caddy_process.returncode is None:
            return {"status": "already_running"}
        try:
            # Get admin port from settings
            settings = get_settings_from_db()
            admin_port = settings.get("caddy_admin_port", 12999)

            stdout_log = open(os.path.join(LOG_DIR, "caddy.stdout.log"), "a")
            stderr_log = open(os.path.join(LOG_DIR, "caddy.stderr.log"), "a")

            # Set CADDY_ADMIN environment variable to configure admin endpoint
            env = os.environ.copy()
            env["CADDY_ADMIN"] = f"localhost:{admin_port}"

            # Start Caddy with environment variable specifying admin API port
            caddy_process = await asyncio.create_subprocess_exec(
                CADDY_BIN, "run",
                stdout=stdout_log, stderr=stderr_log,
                env=env
            )
            caddy_stop_reason = ""  # Clear stop reason on successful start
            logger.info(f"Caddy started (PID {caddy_process.pid}) with admin API on port {admin_port}")
            await asyncio.sleep(2)

            # Broadcast Caddy status change via SSE
            await broadcast_sse_event('caddy_status', {
                'status': 'running',
                'pid': caddy_process.pid
            })

            return {"status": "started", "pid": caddy_process.pid}
        except Exception as e:
            caddy_stop_reason = f"Failed to start: {str(e)}"
            logger.error(f"Failed to start Caddy: {e}")
            raise HTTPException(status_code=500, detail=str(e))

# LDAP Server Implementation
ldap_server_task = None

def user_to_ldap_entry(user: dict, base_dn: str) -> dict:
    """
    Convert database user to LDAP entry format
    Security: Only exposes non-sensitive user data
    """
    # Get user's groups
    groups = user.get('groups', [])
    group_names = []
    all_groups = get_all_groups_from_db()
    for group in all_groups:
        if group['id'] in groups:
            group_names.append(group['name'])

    return {
        'dn': f'uid={user["username"]},{base_dn}',
        'attributes': {
            'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            'cn': [user['username']],
            'uid': [user['username']],
            'mail': [user.get('email', '')] if user.get('email') else [],
            'givenName': [user.get('first_name', '')] if user.get('first_name') else [],
            'sn': [user.get('last_name', user['username'])] if user.get('last_name') else [user['username']],
            'memberOf': [f'cn={g},{base_dn}' for g in group_names]
        }
    }

def parse_ldap_message(data: bytes) -> dict:
    """
    Parse LDAP message (BER encoding)
    Security: Validates message structure and limits sizes
    """
    try:
        if len(data) < 7:
            return None

        # Basic BER parsing
        if data[0] != 0x30:  # SEQUENCE tag
            return None

        # Get message ID (usually at position 2-4)
        msg_id = 1
        if data[2] == 0x02:  # INTEGER tag
            msg_id_len = data[3]
            if msg_id_len == 1:
                msg_id = data[4]

        # Determine operation type
        operation = data[5] if len(data) > 5 else 0

        return {
            'message_id': msg_id,
            'operation': operation,
            'data': data
        }
    except Exception as e:
        logger.error(f"LDAP message parse error: {e}")
        return None

def encode_ldap_length(length: int) -> bytes:
    """Encode BER length - handles both short and long form"""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        # For lengths >= 256, use multi-byte encoding
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')
        return bytes([0x80 | len(length_bytes)]) + length_bytes

def encode_ldap_string(s: str) -> bytes:
    """Encode string in LDAP format (OCTET STRING)"""
    s_bytes = s.encode('utf-8')
    length_encoded = encode_ldap_length(len(s_bytes))
    return bytes([0x04]) + length_encoded + s_bytes

def encode_ldap_sequence(items: list) -> bytes:
    """Encode LDAP sequence"""
    content = b''.join(items)
    length_encoded = encode_ldap_length(len(content))
    return bytes([0x30]) + length_encoded + content

def build_ldap_bind_response(msg_id: int, result_code: int, dn: str = "", message: str = "") -> bytes:
    """
    Build LDAP BIND response
    result_code: 0=success, 49=invalidCredentials, 32=noSuchObject
    """
    # Message ID
    msg_id_encoded = bytes([0x02, 0x01, msg_id])

    # Result code (ENUMERATED)
    result_encoded = bytes([0x0a, 0x01, result_code])

    # Matched DN (usually empty)
    matched_dn = encode_ldap_string(dn)

    # Diagnostic message
    diag_msg = encode_ldap_string(message)

    # BindResponse (APPLICATION 1)
    bind_content = result_encoded + matched_dn + diag_msg
    bind_response = bytes([0x61]) + encode_ldap_length(len(bind_content)) + bind_content

    # Complete message
    return encode_ldap_sequence([msg_id_encoded, bind_response])

def build_ldap_search_result_entry(msg_id: int, dn: str, attributes: dict) -> bytes:
    """Build LDAP SearchResultEntry"""
    msg_id_encoded = bytes([0x02, 0x01, msg_id])

    # Object name (DN)
    object_name = encode_ldap_string(dn)

    # Attributes
    attr_list = []
    for attr_name, attr_values in attributes.items():
        if not attr_values:  # Skip empty attributes
            continue
        # Attribute type
        attr_type = encode_ldap_string(attr_name)
        # Attribute values (SET OF)
        values = b''.join([encode_ldap_string(v) for v in attr_values])
        values_set = bytes([0x31]) + encode_ldap_length(len(values)) + values
        # Attribute sequence
        attr_seq = encode_ldap_sequence([attr_type, values_set])
        attr_list.append(attr_seq)

    attributes_seq = encode_ldap_sequence(attr_list)

    # SearchResultEntry (APPLICATION 4)
    entry_content = object_name + attributes_seq
    search_entry = bytes([0x64]) + encode_ldap_length(len(entry_content)) + entry_content

    return encode_ldap_sequence([msg_id_encoded, search_entry])

def build_ldap_search_result_done(msg_id: int, result_code: int = 0) -> bytes:
    """Build LDAP SearchResultDone"""
    msg_id_encoded = bytes([0x02, 0x01, msg_id])
    result_encoded = bytes([0x0a, 0x01, result_code])
    matched_dn = encode_ldap_string("")
    diag_msg = encode_ldap_string("")

    # SearchResultDone (APPLICATION 5)
    done_content = result_encoded + matched_dn + diag_msg
    search_done = bytes([0x65]) + encode_ldap_length(len(done_content)) + done_content

    return encode_ldap_sequence([msg_id_encoded, search_done])

async def handle_ldap_bind(client, msg_id: int, data: bytes, settings: dict):
    """
    Handle LDAP BIND request
    Security: Rate limiting, no admin access, proper credential validation
    """
    try:
        # Extract bind DN and password from data
        # This is a simplified parser - production would use a full ASN.1 parser
        bind_dn = ""
        password = ""

        # Parse simple BIND (version 3)
        idx = 6  # Skip sequence header and message ID
        while idx < len(data) - 5:
            if data[idx] == 0x04:  # OCTET STRING (DN)
                length = data[idx + 1]
                if idx + 2 + length <= len(data):
                    bind_dn = data[idx + 2:idx + 2 + length].decode('utf-8', errors='ignore')
                    idx += 2 + length
            elif data[idx] == 0x80:  # Simple password (context-specific [0])
                length = data[idx + 1]
                if idx + 2 + length <= len(data):
                    password = data[idx + 2:idx + 2 + length].decode('utf-8', errors='ignore')
                    break
            else:
                idx += 1

        # Anonymous BIND (empty DN and password)
        if not bind_dn and not password:
            logger.info("LDAP: Anonymous BIND accepted (read-only)")
            response = build_ldap_bind_response(msg_id, 0, "", "Anonymous bind successful")
            client.send(response)
            return True

        # DEBUG: Log the BIND DN to see what Emby is sending
        logger.info(f"LDAP: BIND request with DN: {bind_dn}")

        # Extract username from DN (cn=username or uid=username,...)
        username = None
        if bind_dn:
            parts = bind_dn.split(',')
            for part in parts:
                part_lower = part.strip().lower()
                if part_lower.startswith('cn=') or part_lower.startswith('uid='):
                    username = part.split('=', 1)[1].strip()
                    break

        if not username or not password:
            logger.warning(f"LDAP: Invalid BIND request - DN: {bind_dn}")
            await log_activity(username if username else "unknown", "LDAP_AUTH_FAILED", "Invalid BIND request", "LDAP")
            await send_event_notification("ldap_auth_failed", "LDAP Authentication Failed",
                f"Failed LDAP authentication attempt.", username=username if username else "unknown", reason="Invalid BIND request")
            response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
            client.send(response)
            return False

        # Security: Prevent admin access via LDAP
        user = get_user_by_username_from_db(username)
        if not user:
            logger.warning(f"LDAP: User not found - {username}")
            await log_activity(username, "LDAP_AUTH_FAILED", "User not found", "LDAP")
            await send_event_notification("ldap_auth_failed", "LDAP Authentication Failed",
                f"Failed LDAP authentication attempt.", username=username, reason="User not found")
            await asyncio.sleep(1)  # Rate limiting
            response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
            client.send(response)
            return False

        # Security: Block admin users from LDAP authentication
        if user.get('is_admin', False):
            logger.warning(f"LDAP: Admin user blocked - {username}")
            await log_activity(username, "LDAP_AUTH_FAILED", "Admin user blocked from LDAP", "LDAP")
            await send_event_notification("ldap_auth_failed", "LDAP Authentication Failed",
                f"Failed LDAP authentication attempt.", username=username, reason="Admin user blocked from LDAP")
            await asyncio.sleep(2)  # Extra delay for admin attempts
            response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
            client.send(response)
            return False

        # Check if this is the configured bind DN (service account)
        configured_bind_dn = settings.get('ldap_bind_dn', '')
        is_bind_user = False
        if configured_bind_dn:
            # Extract username from configured bind DN
            bind_username = None
            for part in configured_bind_dn.split(','):
                part_lower = part.strip().lower()
                if part_lower.startswith('cn=') or part_lower.startswith('uid='):
                    bind_username = part.split('=', 1)[1].strip()
                    break
            is_bind_user = (bind_username == username)

        # Check if user is in allowed groups (if specified)
        # Service account (bind DN user) bypasses group check to allow searching
        allowed_groups = settings.get('ldap_allowed_groups', [])
        if allowed_groups and not is_bind_user:
            user_groups = user.get('groups', [])
            # Check if user has at least one allowed group
            if not any(group in allowed_groups for group in user_groups):
                logger.warning(f"LDAP: User not in allowed groups - {username}")
                await log_activity(username, "LDAP_AUTH_DENIED", "User not in allowed groups", "LDAP")
                await send_event_notification("ldap_auth_denied", "LDAP Access Denied",
                    f"LDAP authentication denied - user not in allowed groups.",
                    username=username, reason="Not in allowed groups")
                await asyncio.sleep(1)  # Rate limiting
                response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
                client.send(response)
                return False

        # Check if user is required to have 2FA but hasn't set it up
        if user_requires_2fa(user) and not user.get("totp_enabled", False) and not is_bind_user:
            logger.warning(f"LDAP: User requires 2FA but hasn't configured it - {username}")
            await log_activity(username, "LDAP_AUTH_DENIED", "2FA required but not configured", "LDAP")
            await send_event_notification("ldap_auth_denied", "LDAP Access Denied",
                f"LDAP authentication denied - 2FA required but not configured.",
                username=username, reason="2FA required but not configured")
            await asyncio.sleep(1)  # Rate limiting
            response = build_ldap_bind_response(msg_id, 49, "", "2FA required - please configure in user portal")
            client.send(response)
            return False

        # Check if Enhanced Security Mode is enabled (for 2FA enforcement)
        settings_db = get_settings_from_db()
        enhanced_security = settings_db.get('enhanced_security', False)

        # Check if user has 2FA enabled
        totp_enabled = user.get('totp_enabled', False)
        totp_secret = user.get('totp_secret', '')

        # If Enhanced Security is ON and user has 2FA, password must include TOTP
        if enhanced_security and totp_enabled and totp_secret:
            # Password format: actualPassword + 6digitTOTP (e.g., "mypass123456")
            if len(password) < 6:
                logger.warning(f"LDAP: Failed BIND - {username} (password too short for 2FA)")
                await log_activity(username, "LDAP_AUTH_FAILED", "Password too short for 2FA", "LDAP")
                await send_event_notification("ldap_auth_failed", "LDAP Authentication Failed",
                    f"Failed LDAP authentication attempt.", username=username, reason="Password too short for 2FA")
                await asyncio.sleep(1)
                response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
                client.send(response)
                return False

            # Split password and TOTP code
            actual_password = password[:-6]  # Everything except last 6 digits
            totp_code = password[-6:]  # Last 6 digits

            # Verify password
            if not verify_password(actual_password, user['password_hash']):
                logger.warning(f"LDAP: Failed BIND - {username} (incorrect password with 2FA)")
                await log_activity(username, "LDAP_AUTH_FAILED", "Invalid password", "LDAP")
                await send_event_notification("ldap_auth_failed", "LDAP Authentication Failed",
                    f"Failed LDAP authentication attempt.", username=username, reason="Invalid password")
                await asyncio.sleep(1)
                response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
                client.send(response)
                return False

            # Verify TOTP code
            if not verify_totp(totp_secret, totp_code):
                logger.warning(f"LDAP: Failed BIND - {username} (incorrect 2FA code)")
                await log_activity(username, "LDAP_AUTH_FAILED", "Invalid 2FA code", "LDAP")
                await send_event_notification("ldap_auth_failed", "LDAP Authentication Failed",
                    f"Failed LDAP authentication attempt.", username=username, reason="Invalid 2FA code")
                await asyncio.sleep(1)
                response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
                client.send(response)
                return False

            logger.info(f"LDAP: Successful BIND with 2FA - {username}")
            await log_activity(username, "LDAP_AUTH_SUCCESS", "Authentication with 2FA successful", "LDAP")
            await send_event_notification("ldap_auth_success", "LDAP Authentication Success",
                f"Successful LDAP authentication with 2FA.", username=username, method="Password + 2FA")
            response = build_ldap_bind_response(msg_id, 0, "", "Bind successful")
            client.send(response)
            return True
        else:
            # No 2FA required, just verify password
            if verify_password(password, user['password_hash']):
                logger.info(f"LDAP: Successful BIND - {username}")
                await log_activity(username, "LDAP_AUTH_SUCCESS", "Authentication successful", "LDAP")
                await send_event_notification("ldap_auth_success", "LDAP Authentication Success",
                    f"Successful LDAP authentication.", username=username, method="Password")
                response = build_ldap_bind_response(msg_id, 0, "", "Bind successful")
                client.send(response)
                return True
            else:
                logger.warning(f"LDAP: Failed BIND - {username} (incorrect password)")
                await log_activity(username, "LDAP_AUTH_FAILED", "Invalid password", "LDAP")
                await send_event_notification("ldap_auth_failed", "LDAP Authentication Failed",
                    f"Failed LDAP authentication attempt.", username=username, reason="Invalid password")
                await asyncio.sleep(1)  # Rate limiting
                response = build_ldap_bind_response(msg_id, 49, "", "Invalid credentials")
                client.send(response)
                return False

    except Exception as e:
        logger.error(f"LDAP BIND error: {e}")
        response = build_ldap_bind_response(msg_id, 1, "", "Server error")
        client.send(response)
        return False

def parse_ldap_search_base_dn(data: bytes) -> str:
    """
    Parse the base DN from an LDAP SEARCH request
    Returns empty string if parsing fails
    """
    try:
        # LDAP SEARCH request structure:
        # SEQUENCE { messageID, SearchRequest }
        # SearchRequest { baseObject (OCTET STRING), scope, derefAliases, ... }

        # Skip to SearchRequest (after messageID)
        # Typically: 0x30 (SEQ) [len] 0x02 (INT) 0x01 [msgid] 0x63 (SearchRequest)
        idx = 0
        while idx < len(data) - 10:
            if data[idx] == 0x63:  # SearchRequest APPLICATION tag
                idx += 1
                # Skip length encoding
                length_byte = data[idx]
                idx += 1
                if length_byte & 0x80:  # Long form
                    num_bytes = length_byte & 0x7f
                    idx += num_bytes

                # Now at baseObject (OCTET STRING)
                if idx < len(data) and data[idx] == 0x04:
                    idx += 1
                    str_len = data[idx]
                    idx += 1
                    if str_len & 0x80:  # Long form length
                        num_bytes = str_len & 0x7f
                        str_len = int.from_bytes(data[idx:idx+num_bytes], 'big')
                        idx += num_bytes

                    base_dn = data[idx:idx+str_len].decode('utf-8')
                    return base_dn
            idx += 1

        return ""
    except Exception as e:
        logger.debug(f"LDAP: Could not parse search base DN: {e}")
        return ""

async def handle_ldap_search(client, msg_id: int, data: bytes, settings: dict, authenticated: bool):
    """
    Handle LDAP SEARCH request
    Security: Only returns data for authenticated users, no sensitive data, group filtering
    Supports hierarchical search: can search base DN or specific group OUs
    """
    try:
        configured_base_dn = settings.get('ldap_base_dn', 'dc=example,dc=com')
        allowed_groups = settings.get('ldap_allowed_groups', [])

        # Parse the requested base DN from client
        requested_base_dn = parse_ldap_search_base_dn(data)

        # Parse the LDAP search filter (e.g., (uid=test))
        search_filter_username = None
        try:
            # Look for 'uid' or 'cn' attribute in the filter
            # Search for these strings in the binary data
            data_str = data.decode('latin-1')  # Use latin-1 to preserve byte values

            # Look for "uid" followed by a string value
            if 'uid' in data_str:
                idx = data_str.index('uid')
                # Skip past 'uid' and look for the next OCTET STRING (0x04)
                idx += 3
                while idx < len(data) - 10:
                    if data[idx] == 0x04:  # OCTET STRING tag
                        str_len = data[idx + 1]
                        if str_len < 128 and idx + 2 + str_len <= len(data):
                            search_filter_username = data[idx + 2:idx + 2 + str_len].decode('utf-8', errors='ignore')
                            logger.info(f"LDAP: SEARCH filter for uid={search_filter_username}")
                            break
                    idx += 1
            elif 'cn' in data_str:
                idx = data_str.index('cn')
                idx += 2
                while idx < len(data) - 10:
                    if data[idx] == 0x04:  # OCTET STRING tag
                        str_len = data[idx + 1]
                        if str_len < 128 and idx + 2 + str_len <= len(data):
                            search_filter_username = data[idx + 2:idx + 2 + str_len].decode('utf-8', errors='ignore')
                            logger.info(f"LDAP: SEARCH filter for cn={search_filter_username}")
                            break
                    idx += 1
        except Exception as e:
            logger.debug(f"LDAP: Could not parse search filter: {e}")

        logger.info(f"LDAP: SEARCH request for base DN: {requested_base_dn or configured_base_dn}")

        # Determine which base DN to use and if we need to filter by specific group
        search_base_dn = requested_base_dn if requested_base_dn else configured_base_dn
        filter_group = None

        # Check if searching a specific group OU (e.g., ou=wifi,dc=jvr,dc=home)
        if requested_base_dn and requested_base_dn.lower() != configured_base_dn.lower():
            # Extract OU from requested base DN
            # Format: ou=<groupname>,<base_dn>
            if ',' in requested_base_dn:
                ou_part = requested_base_dn.split(',')[0].lower()
                remaining_dn = ','.join(requested_base_dn.split(',')[1:]).lower()

                # Verify it's a sub-DN of our configured base
                if remaining_dn == configured_base_dn.lower() and ou_part.startswith('ou='):
                    filter_group = ou_part[3:]  # Extract group name after 'ou='
                    logger.info(f"LDAP: Filtering results to group: {filter_group}")

        users = get_all_users_from_db()
        all_groups = get_all_groups_from_db()

        # Create a mapping of group IDs to names for quick lookup
        group_id_to_name = {g['id']: g['name'] for g in all_groups}

        returned_count = 0

        # Filter users based on admin status and group membership
        for user in users:
            # Security: Skip admin users
            if user.get('is_admin', False):
                continue

            # Apply LDAP search filter if present (e.g., uid=test)
            if search_filter_username:
                if user.get('username', '').lower() != search_filter_username.lower():
                    continue

            user_groups = user.get('groups', [])
            user_group_names = [group_id_to_name.get(gid, '') for gid in user_groups]

            # If searching specific group OU, only return users in that group
            if filter_group:
                if filter_group not in user_group_names:
                    continue

            # Security: Check if user is in allowed groups (if specified)
            if allowed_groups:
                # Check if user has at least one allowed group
                if not any(group in allowed_groups for group in user_groups):
                    continue

            entry = user_to_ldap_entry(user, search_base_dn)
            entry_response = build_ldap_search_result_entry(msg_id, entry['dn'], entry['attributes'])
            client.send(entry_response)
            returned_count += 1

        # Send SearchResultDone
        done_response = build_ldap_search_result_done(msg_id, 0)
        client.send(done_response)

        logger.info(f"LDAP: SEARCH completed - returned {returned_count} users")

    except Exception as e:
        logger.error(f"LDAP SEARCH error: {e}")
        done_response = build_ldap_search_result_done(msg_id, 1)  # Operations error
        client.send(done_response)

async def handle_ldap_client(client, addr, settings: dict):
    """
    Handle LDAP client connection
    Security: Connection timeout, size limits, proper error handling
    """
    # Security: Check if connection is from external/non-private IP
    import ipaddress
    try:
        client_ip = ipaddress.ip_address(addr[0])
        if not (client_ip.is_loopback or client_ip.is_private):
            logger.critical(f"LDAP: SECURITY ALERT - External IP attempting connection: {addr[0]}")
            await send_event_notification(
                "ldap_external_connection",
                "LDAP Security Alert",
                f"External IP address attempted to connect to LDAP server!\n\n"
                f"Source IP: {addr[0]}\n"
                f"Source Port: {addr[1]}\n"
                f"This could indicate:\n"
                f"- VPN failure exposing your server\n"
                f"- Port forwarding misconfiguration\n"
                f"- Network scan/attack attempt\n\n"
                f"Action: Verify firewall and VPN settings immediately.",
                source_ip=addr[0],
                source_port=addr[1]
            )
            # Close connection immediately for external IPs
            client.close()
            return
    except ValueError:
        pass  # Invalid IP, continue processing

    authenticated = False
    try:
        client.settimeout(30)  # 30 second timeout

        while True:
            try:
                data = client.recv(4096)  # Limit message size
                if not data:
                    break

                # Parse message
                msg = parse_ldap_message(data)
                if not msg:
                    logger.warning(f"LDAP: Invalid message from {addr}")
                    break

                msg_id = msg['message_id']
                operation = msg['operation']

                # Handle operations
                if operation == 0x60:  # BIND Request
                    authenticated = await handle_ldap_bind(client, msg_id, data, settings)
                elif operation == 0x63:  # SEARCH Request
                    await handle_ldap_search(client, msg_id, data, settings, authenticated)
                elif operation == 0x42:  # UNBIND Request
                    logger.info(f"LDAP: UNBIND from {addr}")
                    break
                else:
                    logger.warning(f"LDAP: Unsupported operation {operation} from {addr}")
                    # Send unsupported operation response
                    response = build_ldap_bind_response(msg_id, 2, "", "Protocol error")
                    client.send(response)
                    break

            except TimeoutError:
                logger.info(f"LDAP: Connection timeout from {addr}")
                break
            except Exception as e:
                logger.error(f"LDAP: Client handler error from {addr}: {e}")
                break

    finally:
        try:
            client.close()
        except:
            pass
        logger.info(f"LDAP: Connection closed from {addr}")

async def ldap_server():
    """
    Production-ready LDAP server
    Security: Proper authentication, no admin access, rate limiting
    """
    settings = get_settings_from_db()
    if not settings.get('ldap_enabled'):
        return

    port = settings.get('ldap_port', 3389)
    base_dn = settings.get('ldap_base_dn', 'dc=example,dc=com')

    logger.info(f"Starting LDAP server on port {port} with base DN: {base_dn}")

    import socket
    server = None

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Security: Bind to all interfaces (0.0.0.0) but filter connections by IP in handle_ldap_client
        # This allows connections from any private network (10.x, 172.16-31.x, 192.168.x) while blocking external IPs
        server.bind(('0.0.0.0', port))
        server.listen(10)
        server.setblocking(False)

        logger.info(f"LDAP server listening on 0.0.0.0:{port} (accepting connections from private networks only)")

        while True:
            try:
                try:
                    client, addr = server.accept()
                    logger.info(f"LDAP: New connection from {addr}")

                    # Handle each client in a separate task
                    asyncio.create_task(handle_ldap_client(client, addr, settings))

                except BlockingIOError:
                    await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"LDAP server error: {e}")
                await asyncio.sleep(1)

    except asyncio.CancelledError:
        logger.info("LDAP server task cancelled, closing socket...")
        if server:
            server.close()
        raise
    except Exception as e:
        logger.error(f"Failed to start LDAP server: {e}")
        if server:
            server.close()
        raise

async def start_ldap_server():
    """Start LDAP server task"""
    global ldap_server_task
    settings = get_settings_from_db()

    # Master switch - if auth protocols disabled, don't start anything
    if not settings.get('auth_protocols_enabled'):
        return

    if not settings.get('ldap_enabled'):
        return

    if ldap_server_task is None or ldap_server_task.done():
        ldap_server_task = asyncio.create_task(ldap_server())
        logger.info("LDAP server task started")

async def stop_ldap_server():
    """Stop LDAP server task"""
    global ldap_server_task

    if ldap_server_task and not ldap_server_task.done():
        ldap_server_task.cancel()
        try:
            await ldap_server_task
        except asyncio.CancelledError:
            pass
        logger.info("LDAP server stopped")

# RADIUS Server Implementation
radius_server_task = None

# EAP-TTLS State Management
eap_sessions = {}  # session_id -> {state, tls_context, username, etc}

# EAP Constants
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4

EAP_TYPE_IDENTITY = 1
EAP_TYPE_TTLS = 21
EAP_TYPE_PEAP = 25
# Note: PAP is not an EAP type, it's handled via RADIUS directly without EAP encapsulation

# TLS Flags
TLS_FLAG_LENGTH = 0x80
TLS_FLAG_MORE = 0x40
TLS_FLAG_START = 0x20

def ensure_radius_tls_cert():
    """
    Ensure RADIUS server has a TLS certificate for EAP-TTLS
    Returns (cert_path, key_path)
    """
    # Use same directory as database file
    cert_dir = os.path.join(os.path.dirname(os.path.abspath(DB_FILE)), "radius_certs")
    os.makedirs(cert_dir, exist_ok=True)

    cert_path = os.path.join(cert_dir, "server.crt")
    key_path = os.path.join(cert_dir, "server.key")

    # Check if cert exists and is valid
    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            # Verify cert is still valid
            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                if cert.not_valid_after_utc > datetime.now(timezone.utc):
                    return (cert_path, key_path)
        except:
            pass

    # Generate new certificate
    logger.info("Generating new RADIUS TLS certificate...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "HomeServer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CaddyMAN RADIUS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "radius.local"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("radius.local"),
            x509.DNSName("localhost"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Write certificate
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write private key
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    logger.info(f"RADIUS TLS certificate generated: {cert_path}")
    return (cert_path, key_path)

def generate_mppe_keys(master_key: bytes, nonce_client: bytes, nonce_server: bytes, tls_version: str = "1.2") -> tuple:
    """
    Generate MPPE keys for WPA2/WPA3
    Returns (send_key, recv_key)

    Behavior (TLS-version-aware):
    - For TLS >= 1.2: use the TLS 1.2 PRF (HMAC-SHA256) with the label
      "ttls keying material" and derive 64 bytes, then take the first 32
      bytes as the PMK portion (compatibility with many modern supplicants).
    - For TLS < 1.2: use the TLS 1.0/1.1 PRF (MD5+SHA1) with the RFC 5216
      label "client EAP encryption" (RFC-compliant fallback).

    The seed for derivation is client_random || server_random (nonce_client + nonce_server).
    """
    full_seed = nonce_client + nonce_server

    # Prefer TLS 1.2 exporter-style derivation for modern clients
    try:
        if tls_version and float(tls_version[:3]) >= 1.2:
            # Log at debug level: this is detailed protocol behavior useful during debugging
            logger.debug("[EAP-TTLS] TLS >= 1.2 negotiated; deriving PMK using TLS1.2 PRF + 'ttls keying material'")
            key_material = tls_prf_sha256(master_key, b"ttls keying material", full_seed, 64)
            # Use first 32 bytes as PMK-compatible key material
            send_key = key_material[:32]
            recv_key = key_material[32:64]
            return (send_key, recv_key)

        # Fallback RFC behavior (TLS 1.0 / 1.1 PRF)
        # Demote to debug to avoid exposing derivation details in normal logs
        logger.debug("[EAP-TTLS] Deriving PMK using TLS1.0 PRF (MD5+SHA1) + 'client EAP encryption'")
        key_material = tls_prf_md5_sha1(master_key, b"client EAP encryption", full_seed, 64)
        send_key = key_material[:32]
        recv_key = key_material[32:64]
        return (send_key, recv_key)

    except Exception as e:
        logger.exception(f"[EAP-TTLS] PMK derivation failed: {e}; using deterministic fallback")
        # Deterministic fallback (original behavior preserved)
        result = b''
        a = hashlib.sha1(b"client EAP encryption" + full_seed).digest()
        while len(result) < 64:
            result += hashlib.sha1(master_key + a).digest()
            a = hashlib.sha1(master_key + a).digest()
        send_key = result[:32]
        recv_key = result[32:64]
        return (send_key, recv_key)

def tls_prf_md5_sha1(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """
    TLS 1.0/1.1 PRF using MD5 and SHA1 (RFC 2246 Section 5)
    Used by EAP-TTLS per RFC 5216 (which references RFC 2246)

    PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed)
    where S1 and S2 are the two halves of the secret
    """
    import hmac

    full_seed = label + seed

    # Split secret into two halves
    secret_len = len(secret)
    half_len = (secret_len + 1) // 2  # Round up if odd length
    s1 = secret[:half_len]  # First half for MD5
    s2 = secret[secret_len - half_len:]  # Second half for SHA1 (overlap if odd)

    # Detailed PRF computation logs are sensitive; emit at debug level without secrets
    logger.debug("[PRF] Computing TLS 1.0/1.1 PRF (MD5+SHA1)")
    logger.debug(f"[PRF]   Label: {label}")
    logger.debug(f"[PRF]   Seed length: {len(seed)} bytes")

    # P_MD5
    def p_hash(secret: bytes, seed: bytes, length: int, hash_func):
        result = b''
        a = seed  # A(0) = seed
        while len(result) < length:
            a = hmac.new(secret, a, hash_func).digest()  # A(i) = HMAC(secret, A(i-1))
            result += hmac.new(secret, a + seed, hash_func).digest()
        return result[:length]

    p_md5_result = p_hash(s1, full_seed, length, hashlib.md5)
    p_sha1_result = p_hash(s2, full_seed, length, hashlib.sha1)

    # XOR the two results
    final = bytes([a ^ b for a, b in zip(p_md5_result, p_sha1_result)])

    # Avoid logging raw PRF outputs (sensitive keying material); log lengths at debug level
    logger.debug(f"[PRF] P_MD5 length: {len(p_md5_result)}")
    logger.debug(f"[PRF] P_SHA1 length: {len(p_sha1_result)}")
    logger.debug(f"[PRF] Result length: {len(final)}")
    return final

def tls_prf_sha256(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """
    TLS 1.2 PRF using HMAC-SHA256 (RFC 5246 Section 5)
    Used for deriving keying material per RFC 5705

    Args:
        secret: The master secret from TLS handshake
        label: The label string (e.g., b"client EAP encryption")
        seed: Additional seed data (empty for RFC 5705 without context)
        length: Number of bytes to generate

    Returns:
        Derived keying material of specified length
    """
    import hmac

    # TLS PRF: PRF(secret, label, seed) = P_SHA256(secret, label + seed)
    full_seed = label + seed

    # Detailed PRF computation logs are sensitive; emit minimal info at debug level
    logger.debug("[PRF] Computing TLS PRF (SHA256)")
    logger.debug(f"[PRF]   Label: {label}")
    logger.debug(f"[PRF]   Seed length: {len(seed)} bytes; full_seed length: {len(full_seed)} bytes")

    # P_SHA256 from RFC 5246 Section 5
    result = b''
    a = full_seed  # A(0) = full_seed
    iteration = 0

    while len(result) < length:
        iteration += 1
        # A(i) = HMAC_SHA256(secret, A(i-1))
        a = hmac.new(secret, a, hashlib.sha256).digest()
        # Append HMAC_SHA256(secret, A(i) + full_seed)
        chunk = hmac.new(secret, a + full_seed, hashlib.sha256).digest()
        result += chunk

        if iteration <= 2:
            logger.debug(f"[PRF] Iteration {iteration} computed (chunk length={len(chunk)})")

    final = result[:length]
    logger.debug(f"[PRF] Result length: {len(final)}")
    return final


def debug_pmk_variants(master_hex: str, client_hex: str, server_hex: str) -> dict:
    """
    Helper for debugging PMK derivation variants.
    Returns a dict with both TLS1.2-exporter-derived PMK and RFC-derived PMK (hex strings).

    Usage (example):
        debug_pmk_variants(master_hex, client_hex, server_hex)
    """
    try:
        master = bytes.fromhex(master_hex)
        client = bytes.fromhex(client_hex)
        server = bytes.fromhex(server_hex)
    except Exception:
        raise ValueError("Invalid hex input for master/client/server")

    seed = client + server

    # TLS1.2 exporter-style (label 'ttls keying material'), take first 32 bytes
    pmk_tls12 = tls_prf_sha256(master, b"ttls keying material", seed, 64)[:32]

    # RFC 5216 / TLS1.0 PRF (label 'client EAP encryption') — request 32 bytes
    pmk_rfc = tls_prf_md5_sha1(master, b"client EAP encryption", seed, 32)

    # Sensitive: avoid printing raw PMK material at info level
    logger.debug(f"[DEBUG-PMK] TLS1.2 PMK (hex): {pmk_tls12.hex()}")
    logger.debug(f"[DEBUG-PMK] RFC PMK   (hex): {pmk_rfc.hex()}")

    return {
        'pmk_tls12': pmk_tls12.hex(),
        'pmk_rfc': pmk_rfc.hex()
    }

# MSCHAPv2 Helper Functions for PEAP
def mschapv2_challenge_hash(peer_challenge: bytes, authenticator_challenge: bytes, username: str) -> bytes:
    """Generate MSCHAPv2 challenge hash (RFC 2759 Section 8.2)"""
    sha1 = hashlib.sha1()
    sha1.update(peer_challenge)
    sha1.update(authenticator_challenge)
    sha1.update(username.encode('utf-8'))
    return sha1.digest()[:8]

def mschapv2_nt_password_hash(password: str) -> bytes:
    """Generate NT password hash (MD4 of UTF-16LE password)"""
    import hashlib
    # MD4 is not in standard hashlib, need to use a workaround
    try:
        # Try to use passlib if available
        from passlib.hash import nthash
        return bytes.fromhex(nthash.hash(password))
    except ImportError:
        # Fall back to manual MD4 implementation using hashlib
        try:
            # Some Python builds have MD4 available
            md4 = hashlib.new('md4')
            md4.update(password.encode('utf-16le'))
            return md4.digest()
        except ValueError:
            # MD4 not available - this is a problem for PEAP/MSCHAPv2
            logger.error("[PEAP] MD4 hash not available - cannot perform MSCHAPv2 authentication")
            raise HTTPException(status_code=500, detail="MSCHAPv2 authentication not supported (MD4 unavailable)")

def mschapv2_challenge_response(challenge: bytes, password_hash: bytes) -> bytes:
    """Generate MSCHAPv2 challenge response using DES (RFC 2759 Section 8.3)"""
    from Crypto.Cipher import DES

    # Expand 16-byte password hash to 21 bytes by padding with zeros
    z_password_hash = password_hash + b'\x00' * 5

    # Split into three 7-byte keys
    response = b''
    for i in range(3):
        # Extract 7 bytes
        key_7 = z_password_hash[i*7:(i+1)*7]
        # Expand to 8-byte DES key
        des_key = des_expand_key(key_7)
        # Encrypt challenge
        cipher = DES.new(des_key, DES.MODE_ECB)
        response += cipher.encrypt(challenge)

    return response

def des_expand_key(key_7: bytes) -> bytes:
    """Expand 7-byte key to 8-byte DES key with parity bits"""
    key_8 = bytearray(8)
    key_8[0] = key_7[0] & 0xFE
    key_8[1] = ((key_7[0] << 7) | (key_7[1] >> 1)) & 0xFE
    key_8[2] = ((key_7[1] << 6) | (key_7[2] >> 2)) & 0xFE
    key_8[3] = ((key_7[2] << 5) | (key_7[3] >> 3)) & 0xFE
    key_8[4] = ((key_7[3] << 4) | (key_7[4] >> 4)) & 0xFE
    key_8[5] = ((key_7[4] << 3) | (key_7[5] >> 5)) & 0xFE
    key_8[6] = ((key_7[5] << 2) | (key_7[6] >> 6)) & 0xFE
    key_8[7] = (key_7[6] << 1) & 0xFE
    return bytes(key_8)

def mschapv2_generate_nt_response(authenticator_challenge: bytes, peer_challenge: bytes, username: str, password: str) -> bytes:
    """Generate MSCHAPv2 NT-Response (RFC 2759 Section 8.1)"""
    challenge = mschapv2_challenge_hash(peer_challenge, authenticator_challenge, username)
    password_hash = mschapv2_nt_password_hash(password)
    return mschapv2_challenge_response(challenge, password_hash)

def build_eap_packet(code: int, identifier: int, eap_type: Optional[int] = None, data: bytes = b'') -> bytes:
    """Build an EAP packet"""
    if eap_type is not None:
        # EAP Request/Response with type
        packet = struct.pack('!BBH', code, identifier, 5 + len(data)) + bytes([eap_type]) + data
    else:
        # EAP Success/Failure (no type field)
        packet = struct.pack('!BBH', code, identifier, 4)
    return packet

def parse_eap_packet(data: bytes) -> dict:
    """Parse an EAP packet"""
    if len(data) < 4:
        return None

    code = data[0]
    identifier = data[1]
    length = struct.unpack('!H', data[2:4])[0]

    if len(data) < length:
        return None

    result = {
        'code': code,
        'identifier': identifier,
        'length': length
    }

    if code in [EAP_CODE_REQUEST, EAP_CODE_RESPONSE] and length > 4:
        result['type'] = data[4]
        result['data'] = data[5:length]

    return result

# ====================================================================
# WiFi Password Encryption and MSCHAPv2 Helper Functions
# ====================================================================

def get_wifi_encryption_key() -> bytes:
    """
    Get encryption key for WiFi passwords using pepper-based encryption (v1.3.11+).
    This ensures WiFi passwords are protected with the same security as other secrets.
    """
    # Use the same pepper-based Fernet key as other settings
    # This is more secure than storing an encryption key in the database
    return _get_pepper_fernet_key()

def encrypt_wifi_password(plaintext_password: str) -> str:
    """
    Encrypt a WiFi password and return the encrypted NT hash.
    Stores the encrypted NT hash, not the plaintext.
    """
    # Calculate NT hash
    nt_hash_value = nthash.hash(plaintext_password)

    # Encrypt the NT hash
    fernet_key = get_wifi_encryption_key()
    f = Fernet(fernet_key)
    encrypted = f.encrypt(nt_hash_value.encode())

    return encrypted.decode()

def decrypt_wifi_password_hash(encrypted_hash: str) -> str:
    """
    Decrypt a WiFi password hash (returns the NT hash, not plaintext).
    """
    fernet_key = get_wifi_encryption_key()
    f = Fernet(fernet_key)
    decrypted = f.decrypt(encrypted_hash.encode())

    return decrypted.decode()

def verify_mschapv2_response(nt_hash: str, auth_challenge: bytes, peer_challenge: bytes,
                             username: str, nt_response: bytes) -> tuple:
    """
    Verify MSCHAPv2 response and generate authenticator response.

    Args:
        nt_hash: NT hash of the password (32 hex chars)
        auth_challenge: 16-byte authenticator challenge
        peer_challenge: 16-byte peer challenge
        username: Username
        nt_response: 24-byte NT response from client

    Returns:
        (is_valid: bool, authenticator_response: str)
    """
    try:
        # Convert NT hash to bytes
        nt_hash_bytes = bytes.fromhex(nt_hash)

        # Generate the challenge
        # ChallengeHash = SHA1(PeerChallenge + AuthenticatorChallenge + Username)
        challenge_hash = hashlib.sha1(peer_challenge + auth_challenge + username.encode()).digest()[:8]

        # Calculate expected NT response
        # NTResponse = ChallengeResponse(Challenge, PasswordHash)
        # This uses DES encryption with the NT hash
        import Crypto.Cipher.DES as DES_module

        def des_encrypt_one_block(key7: bytes, data: bytes) -> bytes:
            """DES encrypt one block with 7-byte key"""
            # Expand 7-byte key to 8-byte DES key with parity
            key8 = bytes([
                key7[0] & 0xFE,
                ((key7[0] << 7) | (key7[1] >> 1)) & 0xFE,
                ((key7[1] << 6) | (key7[2] >> 2)) & 0xFE,
                ((key7[2] << 5) | (key7[3] >> 3)) & 0xFE,
                ((key7[3] << 4) | (key7[4] >> 4)) & 0xFE,
                ((key7[4] << 3) | (key7[5] >> 5)) & 0xFE,
                ((key7[5] << 2) | (key7[6] >> 6)) & 0xFE,
                (key7[6] << 1) & 0xFE
            ])
            cipher = DES_module.new(key8, DES_module.MODE_ECB)
            return cipher.encrypt(data)

        # Split NT hash into 3 keys and encrypt challenge
        expected_response = b''
        for i in range(0, 21, 7):
            key = nt_hash_bytes[i:i+7]
            if len(key) < 7:
                key += b'\x00' * (7 - len(key))
            expected_response += des_encrypt_one_block(key, challenge_hash)

        # Check if response matches
        is_valid = (expected_response == nt_response)

        # Generate authenticator response
        # AuthenticatorResponse = GenerateAuthenticatorResponse(PasswordHash, NTResponse,
        #                                                       PeerChallenge, AuthenticatorChallenge, Username)
        magic1 = b'\x4D\x61\x67\x69\x63\x20\x73\x65\x72\x76\x65\x72\x20\x74\x6F\x20\x63\x6C\x69\x65\x6E\x74\x20\x73\x69\x67\x6E\x69\x6E\x67\x20\x63\x6F\x6E\x73\x74\x61\x6E\x74'
        magic2 = b'\x50\x61\x64\x20\x74\x6F\x20\x6D\x61\x6B\x65\x20\x69\x74\x20\x64\x6F\x20\x6D\x6F\x72\x65\x20\x74\x68\x61\x6E\x20\x6F\x6E\x65\x20\x69\x74\x65\x72\x61\x74\x69\x6F\x6E'

        # HashNtPasswordHash = MD4(NT hash)
        password_hash_hash = hashlib.new('md4', nt_hash_bytes, usedforsecurity=False).digest()

        # Generate authenticator response
        digest = hashlib.sha1(password_hash_hash + nt_response + magic1).digest()
        challenge_digest = hashlib.sha1(digest + auth_challenge + magic2).digest()

        auth_response = "S=" + challenge_digest.hex().upper()

        return (is_valid, auth_response)

    except Exception as e:
        logger.error(f"[MSCHAPv2] Verification error: {e}")
        return (False, "")

class EAPTTLSSession:
    """Manage EAP-TTLS and EAP-PEAP session state"""

    def __init__(self, session_id: str, eap_method: str = 'TTLS'):
        self.session_id = session_id
        self.eap_method = eap_method  # 'TTLS' or 'PEAP'
        self.state = 'INIT'  # INIT -> IDENTITY -> TLS_START -> TLS_HANDSHAKE -> TLS_TUNNEL -> SUCCESS/FAILURE
        self.identifier = 0
        self.username = None
        self.tls_in_buffer = b''
        self.tls_out_buffer = b''
        self.fragment_offset = 0
        self.total_length = 0
        self.ssl_context = None
        self.ssl_obj = None  # SSL object
        self.bio_in = None  # BIO for input
        self.bio_out = None  # BIO for output
        self.authenticated = False
        self.master_key: Optional[bytes] = None
        self.client_random: Optional[bytes] = None
        self.server_random: Optional[bytes] = None
        self.tls_secrets = {}  # Store TLS secrets from keylog callback
        self.keylog_file = None  # Temporary file for SSL keylog (fallback only)
        self.keylog_buffer = None  # In-memory buffer for keylog data (preferred)

        # PEAP/MSCHAPv2 specific fields
        self.mschapv2_challenge = None  # Authenticator challenge for MSCHAPv2
        self.mschapv2_ident = 0  # MSCHAPv2 identifier

    def keylog_callback(self, conn, line):
        """Callback to capture TLS keylog data.

        This is called by OpenSSL/Python SSL for each key material line.
        We store the secrets in the session for later use.
        """
        try:
            line_str = line.decode('utf-8').strip() if isinstance(line, bytes) else str(line).strip()
            logger.debug(f"[EAP-TTLS] Keylog callback: {line_str[:50]}...")

            # Parse CLIENT_RANDOM lines
            if line_str.startswith('CLIENT_RANDOM '):
                parts = line_str.split()
                if len(parts) == 3:
                    self.tls_secrets['client_random_hex'] = parts[1]
                    self.tls_secrets['master_secret_hex'] = parts[2]
                    logger.debug(f"[EAP-TTLS] Captured master secret from keylog callback")
        except Exception as e:
            logger.debug(f"[EAP-TTLS] Keylog callback error: {e}")

    def create_ssl_context(self, cert_path: str, key_path: str, enable_keylog: bool = False):
        """Create SSL context for TLS handshake.

        enable_keylog: when True and Python supports it, creates a temporary keylog file
        that will be read into memory and deleted after use. This is required for PMK
        derivation since BIO-wrapped SSL objects don't expose export_keying_material().

        Note: Python's ssl.SSLContext.keylog_filename only accepts file paths (strings),
        not callbacks, so we must use a temporary file that gets read and deleted.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4')
        # Don't verify client cert
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Set up keylog file for keying material extraction (required for EAP-TTLS)
        # The file will be read into memory immediately after handshake and deleted
        if enable_keylog:
            if hasattr(ssl.SSLContext, 'keylog_filename'):
                import tempfile
                # Create a temporary file that will be read and deleted after use
                self.keylog_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.keylog')
                keylog_path = self.keylog_file.name
                self.keylog_file.close()  # Close handle so SSL library can write to it
                context.keylog_filename = keylog_path
                self.keylog_buffer = None  # Will store file contents after reading
                logger.debug(f"[EAP-TTLS] Keylog file created (will be read to memory): {keylog_path}")
            else:
                self.keylog_file = None
                self.keylog_buffer = None
                logger.error(f"[EAP-TTLS] CRITICAL: Python version does not support keylog_filename - RADIUS authentication will fail!")
        else:
            self.keylog_file = None
            self.keylog_buffer = None

        return context

def handle_eap_ttls_session(session: EAPTTLSSession, eap_packet: dict, cert_path: str, key_path: str, settings: dict) -> bytes:
    """
    Handle EAP-TTLS and EAP-PEAP protocol state machine
    Returns EAP response packet to send back
    """
    eap_type = eap_packet.get('type')
    eap_data = eap_packet.get('data', b'')
    identifier = eap_packet['identifier']

    # Determine which EAP type to use based on session method
    session_eap_type = EAP_TYPE_PEAP if session.eap_method == 'PEAP' else EAP_TYPE_TTLS
    method_label = session.eap_method  # 'PEAP' or 'TTLS'

    # State: Waiting for Identity
    if session.state == 'INIT' and eap_type == EAP_TYPE_IDENTITY:
        # Extract identity
        session.username = eap_data.decode('utf-8', errors='ignore')
        logger.info(f"[{method_label}] Identity: {session.username}")
        session.state = 'IDENTITY'
        session.identifier = (identifier + 1) % 256

        # Send TLS Start (PEAP or TTLS)
        tls_flags = TLS_FLAG_START
        tls_data = bytes([tls_flags])
        return build_eap_packet(EAP_CODE_REQUEST, session.identifier, session_eap_type, tls_data)

    # State: TLS Handshake (PEAP and TTLS)
    elif session.state in ['IDENTITY', 'TTLS_START', 'TTLS_HANDSHAKE', 'TLS_START', 'TLS_HANDSHAKE'] and eap_type == session_eap_type:
        if len(eap_data) < 1:
            return build_eap_packet(EAP_CODE_FAILURE, identifier)

        flags = eap_data[0]
        offset = 1

        # Check for length field
        if flags & TLS_FLAG_LENGTH:
            if len(eap_data) < 5:
                return build_eap_packet(EAP_CODE_FAILURE, identifier)
            session.total_length = struct.unpack('!I', eap_data[1:5])[0]
            offset = 5

        # Extract TLS data
        tls_data = eap_data[offset:]
        session.tls_in_buffer += tls_data

        # If more fragments expected, request next fragment
        if flags & TLS_FLAG_MORE:
            session.identifier = (identifier + 1) % 256
            return build_eap_packet(EAP_CODE_REQUEST, session.identifier, session_eap_type, bytes([0]))

        # Process TLS handshake
        try:
            # Create SSL context if not exists
            if session.ssl_context is None:
                from ssl import MemoryBIO

                session.state = 'TTLS_HANDSHAKE'
                # Always enable keylog for keying material extraction (required for proper PMK derivation)
                # The keylog file is cleaned up after use and is necessary because BIO-wrapped
                # SSL objects don't expose export_keying_material() method
                context = session.create_ssl_context(cert_path, key_path, enable_keylog=True)
                session.ssl_context = context  # Store context in session

                bio_in = MemoryBIO()
                bio_out = MemoryBIO()
                session.ssl_obj = context.wrap_bio(bio_in, bio_out, server_side=True)
                session.bio_in = bio_in
                session.bio_out = bio_out

                logger.debug(f"[EAP-TTLS] Created new SSL context for {session.username}")

            # Feed TLS data to SSL
            if session.tls_in_buffer:
                logger.debug(f"[EAP-TTLS] Writing {len(session.tls_in_buffer)} bytes to bio_in")
                session.bio_in.write(session.tls_in_buffer)
                session.tls_in_buffer = b''

            # Try to do handshake - may need multiple rounds
            handshake_complete = False
            max_rounds = 10  # Prevent infinite loop
            for round in range(max_rounds):
                try:
                    logger.debug(f"[EAP-TTLS] Calling do_handshake(), round {round + 1}")
                    session.ssl_obj.do_handshake()
                    # Handshake complete, move to tunnel state
                    handshake_complete = True
                    session.state = 'TTLS_TUNNEL'
                    logger.info(f"[EAP-TTLS] TLS handshake complete for {session.username}")

                    # Extract server_random from the TLS session if we captured ServerHello
                    # During handshake, bio_out contained ServerHello with server_random
                    # We should have captured it earlier, but if not, we'll use zeros
                    if not session.server_random:
                        logger.warning(f"[EAP-TTLS] server_random was not captured during handshake")

                    # Extract keying material for MPPE keys (RFC 5216 Section 2.3)
                    # Use TLS Exporter as defined in RFC 5705
                    try:
                        # Log TLS version
                        tls_version = None
                        try:
                            if hasattr(session, 'ssl_obj') and session.ssl_obj is not None:
                                tls_version = session.ssl_obj.version()
                                logger.info(f"[EAP-TTLS] TLS version negotiated: {tls_version}")
                        except Exception:
                            pass

                        # Try to derive PMK using SSL's exporter API (preferred method)
                        session.master_key = None
                        ssl_obj = getattr(session, 'ssl_obj', None)

                        # Try to access the underlying SSL object (for BIO-wrapped objects)
                        # In Python 3.11+, export_keying_material is available
                        ssl_real = None
                        if ssl_obj is not None:
                            # Debug: log what type of object we have
                            logger.debug(f"[EAP-TTLS] SSL object type: {type(ssl_obj)}")
                            logger.debug(f"[EAP-TTLS] SSL object dir: {[m for m in dir(ssl_obj) if not m.startswith('_')]}")

                            # Try direct access first
                            if hasattr(ssl_obj, 'export_keying_material'):
                                ssl_real = ssl_obj
                                logger.debug("[EAP-TTLS] Using ssl_obj.export_keying_material directly")
                            # Try accessing _sslobj (internal attribute)
                            elif hasattr(ssl_obj, '_sslobj') and ssl_obj._sslobj is not None:
                                logger.debug(f"[EAP-TTLS] Found _sslobj attribute, type: {type(ssl_obj._sslobj)}")
                                if hasattr(ssl_obj._sslobj, 'export_keying_material'):
                                    ssl_real = ssl_obj._sslobj
                                    logger.debug("[EAP-TTLS] Using _sslobj for export_keying_material")
                                else:
                                    logger.debug("[EAP-TTLS] _sslobj does not have export_keying_material")
                            else:
                                logger.debug("[EAP-TTLS] No _sslobj attribute found or it is None")

                        # ALTERNATIVE: Try to get session info for master_secret and client_random
                        # SSLObject created with wrap_bio() doesn't have export_keying_material()
                        # but we might be able to access session() which returns session data
                        if ssl_real is None and ssl_obj is not None:
                            try:
                                # Check if we can access session information
                                if hasattr(ssl_obj, 'session') and callable(ssl_obj.session):
                                    session_info = ssl_obj.session()
                                    logger.debug(f"[EAP-TTLS] Got session info: {type(session_info)}")
                                    logger.debug(f"[EAP-TTLS] Session info attributes: {dir(session_info)}")
                                elif hasattr(ssl_obj, 'get_channel_binding'):
                                    binding = ssl_obj.get_channel_binding('tls-unique')
                                    logger.debug(f"[EAP-TTLS] Got channel binding: {binding.hex() if binding else 'None'}")
                            except Exception as ex:
                                logger.debug(f"[EAP-TTLS] Could not access session info: {ex}")

                        # Prefer SSL export_keying_material() if available (most robust)
                        if ssl_real is not None:
                            # Try the TLS1.2-style 'ttls keying material' first (64 bytes -> take first 32)
                            try:
                                cand = ssl_real.export_keying_material(b"ttls keying material", 64, None)
                                if cand and len(cand) >= 32:
                                    session.master_key = cand[:32]
                                    logger.info(f"[EAP-TTLS] Derived PMK using SSL exporter 'ttls keying material' (len={len(session.master_key)})")
                            except Exception as ex:
                                logger.debug(f"[EAP-TTLS] SSL exporter 'ttls keying material' failed: {ex}")

                            # If not derived yet, try RFC label 'client EAP encryption' (32 bytes)
                            if session.master_key is None:
                                try:
                                    cand2 = ssl_real.export_keying_material(b"client EAP encryption", 32, None)
                                    if cand2 and len(cand2) == 32:
                                        session.master_key = cand2
                                        logger.info(f"[EAP-TTLS] Derived PMK using SSL exporter 'client EAP encryption' (len={len(session.master_key)})")
                                except Exception as ex:
                                    logger.debug(f"[EAP-TTLS] SSL exporter 'client EAP encryption' failed: {ex}")

                        # If exporter not available or failed, fall back to keylog parsing + PRF
                        if session.master_key is None:
                            logger.debug(f"[EAP-TTLS] SSL exporter not available, falling back to keylog parsing")

                            # Try to get keylog data from memory first (preferred), then from file
                            keylog_data = None

                            # Method 1: Check if we already have data in memory buffer
                            if hasattr(session, 'keylog_buffer') and session.keylog_buffer:
                                keylog_data = session.keylog_buffer
                                logger.info(f"[EAP-TTLS] Using keylog data from in-memory buffer ({len(keylog_data)} bytes)")

                            # Method 2: Read from file and store in memory, then delete file immediately
                            if not keylog_data and session.keylog_file and os.path.exists(session.keylog_file.name):
                                try:
                                    with open(session.keylog_file.name, 'r') as f:
                                        keylog_data = f.read()
                                    # Store in memory buffer so we don't need the file anymore
                                    session.keylog_buffer = keylog_data
                                    # Delete the file immediately after reading
                                    try:
                                        os.unlink(session.keylog_file.name)
                                        logger.debug(f"[EAP-TTLS] Read keylog to memory ({len(keylog_data)} bytes) and deleted file")
                                        session.keylog_file = None  # Mark as cleaned up
                                    except Exception as del_err:
                                        logger.debug(f"[EAP-TTLS] Could not delete keylog file yet: {del_err}")
                                except Exception as e:
                                    logger.warning(f"[EAP-TTLS] Could not read keylog file: {e}")

                            # Parse keylog data if we have any
                            master_secret = None
                            client_random = None
                            if keylog_data:
                                # Parse CLIENT_RANDOM <client_random> <master_secret>
                                for line in keylog_data.strip().split('\n'):
                                    if line.startswith('CLIENT_RANDOM '):
                                        parts = line.split()
                                        if len(parts) == 3:
                                            client_random_hex = parts[1]
                                            master_secret_hex = parts[2]
                                            client_random = bytes.fromhex(client_random_hex)
                                            master_secret = bytes.fromhex(master_secret_hex)
                                            logger.debug(f"[EAP-TTLS] Extracted master secret (len): {len(master_secret)} bytes")
                                            logger.debug(f"[EAP-TTLS] Client random (hex start): {client_random.hex()[:32]}... (len={len(client_random)})")
                                            break

                            if master_secret and client_random:
                                # Get server random from SSL connection
                                # We should have extracted it from ServerHello earlier
                                # RFC 5216 Section 2.3: PRF(master_secret, "client EAP encryption",
                                #                          client_random + server_random)
                                if not session.server_random:
                                    logger.warning(f"[EAP-TTLS] server_random not available, using zeros (PMK will mismatch!)")
                                    server_random = b'\x00' * 32
                                else:
                                    server_random = session.server_random
                                    logger.debug(f"[EAP-TTLS] Using server_random (hex start): {server_random.hex()[:32]}... (len={len(server_random)})")

                                # Derive keying material using TLS PRF (RFC 5705 Section 4)
                                # RFC 5705 without context: PRF(master_secret, label, client_random || server_random)
                                # For EAP-TTLS (RFC 5216), context is empty
                                # Use RFC 5216 seed ordering: client_random || server_random
                                seed = client_random + server_random
                                logger.debug(f"[EAP-TTLS] PRF inputs: label='client EAP encryption', master_secret_len={len(master_secret)}")
                                logger.debug(f"[EAP-TTLS] PRF inputs: client_random(hex start)={client_random.hex()[:32]}... server_random(hex start)={server_random.hex()[:32]}... seed_len={len(seed)}")
                                # Notes:
                                # - Use TLS 1.0 PRF (MD5+SHA1) per RFC 5216
                                # - PMK = PRF(master_secret, "client EAP encryption", client_random || server_random)
                                # CRITICAL FIX: Only generate 32 bytes for PMK, not 128!
                                # Generating more bytes causes A(i) to evolve differently than wpa_supplicant
                                # wpa_supplicant uses "client EAP encryption" per RFC 5216 (NOT "ttls keying material" from draft!)
                                # Derive PMK. Historically there are two common behaviours:
                                # - RFC 5216: use TLS 1.0 PRF (MD5+SHA1) with label b"client EAP encryption" and seed = client||server
                                # - Some implementations (and test tools) derive keying material using the TLS1.2 PRF (HMAC-SHA256)
                                #   with the draft label b"ttls keying material" (producing 64 bytes, where first 32 are PMK)
                                # To maximize compatibility, choose derivation based on negotiated TLS version when available.
                                try:
                                    # Choose PRF based on negotiated TLS version if possible
                                    if tls_version and ('1.2' in tls_version or '1.3' in tls_version):
                                        # try TLS1.2 PRF with 'ttls keying material' (64 bytes, first 32 bytes = PMK)
                                        session.master_key = tls_prf_sha256(master_secret, b"ttls keying material", seed, 64)[:32]
                                        logger.info("[EAP-TTLS] Fallback: derived PMK via TLS1.2 PRF (keylog input)")
                                    else:
                                        # RFC 5216: TLS1.0 PRF (MD5+SHA1) with 'client EAP encryption'
                                        session.master_key = tls_prf_md5_sha1(master_secret, b"client EAP encryption", seed, 32)
                                        logger.info("[EAP-TTLS] Fallback: derived PMK via RFC PRF (keylog input)")
                                except Exception as e:
                                    logger.warning(f"[EAP-TTLS] PMK derivation failed: {e}")
                                    session.master_key = None
                            else:
                                logger.warning(f"[EAP-TTLS] Could not parse master secret from keylog file")
                                session.master_key = None

                        if session.master_key is None:
                            logger.warning("[EAP-TTLS] No SSL exporter and no keylog available to derive keying material")
                    except Exception as e:
                        logger.warning(f"[EAP-TTLS] Could not derive keying material from keylog: {e}")
                        import traceback
                        logger.debug(traceback.format_exc())
                        session.master_key = None
                    break
                except ssl.SSLWantReadError:
                    # Need more data from client
                    logger.debug(f"[EAP-TTLS] SSL wants more read data (round {round + 1})")
                    break  # Exit loop, we'll get more data in next packet
                except ssl.SSLWantWriteError:
                    # Need to send data to client - check if there's data in bio_out
                    logger.debug(f"[EAP-TTLS] SSL wants to write data (round {round + 1})")
                    # Try to read from bio_out and continue loop
                    try:
                        pending = session.bio_out.read()
                        if pending:
                            logger.debug(f"[EAP-TTLS] Got {len(pending)} bytes from bio_out during handshake")
                            # Try to extract server_random from ServerHello
                            if not session.server_random:
                                try:
                                    # Parse TLS record: type(1) + version(2) + length(2) + data
                                    if len(pending) >= 5 and pending[0] == 0x16:  # Handshake
                                        pos = 5  # Skip record header
                                        # Parse handshake: type(1) + length(3) + data
                                        if len(pending) > pos and pending[pos] == 0x02:  # ServerHello
                                            # ServerHello: type(1) + length(3) + version(2) + random(32)
                                            pos += 1 + 3 + 2  # Skip type, length, version
                                            if len(pending) >= pos + 32:
                                                session.server_random = pending[pos:pos+32]
                                                if session.server_random:
                                                    logger.debug(f"[EAP-TTLS] Extracted server_random from handshake (hex start): {session.server_random.hex()[:32]}... (len={len(session.server_random)})")
                                except Exception as e:
                                    logger.debug(f"[EAP-TTLS] Could not extract server_random from handshake: {e}")
                    except:
                        pass
                    # Continue loop to try handshake again
                except ssl.SSLError as e:
                    logger.error(f"[EAP-TTLS] SSL error during handshake: {e}")
                    raise  # Re-raise to outer exception handler

            # Get TLS response data (there may be data to send even if handshake not complete)
            tls_response = b''
            try:
                tls_response = session.bio_out.read()
                # Try to extract server_random from ServerHello if not already captured
                if tls_response and not session.server_random:
                    try:
                        # Parse TLS record: type(1) + version(2) + length(2) + data
                        if len(tls_response) >= 5 and tls_response[0] == 0x16:  # Handshake
                            pos = 5  # Skip record header
                            # Parse handshake: type(1) + length(3) + data
                            if len(tls_response) > pos and tls_response[pos] == 0x02:  # ServerHello
                                # ServerHello: type(1) + length(3) + version(2) + random(32)
                                pos += 1 + 3 + 2  # Skip type, length, version
                                if len(tls_response) >= pos + 32:
                                    session.server_random = tls_response[pos:pos+32]
                                    if session.server_random:
                                        logger.debug(f"[EAP-TTLS] Extracted server_random (hex start): {session.server_random.hex()[:32]}... (len={len(session.server_random)})")
                    except Exception as e:
                        logger.debug(f"[EAP-TTLS] Could not extract server_random: {e}")
            except:
                pass

            if tls_response:
                # Send TLS data back
                logger.debug(f"[EAP-TTLS] Sending {len(tls_response)} bytes of TLS data")
                session.tls_out_buffer = tls_response

                # Fragment if needed (max 1024 bytes per fragment)
                if len(session.tls_out_buffer) > 1024:
                    fragment = session.tls_out_buffer[:1024]
                    session.tls_out_buffer = session.tls_out_buffer[1024:]
                    flags = TLS_FLAG_MORE | TLS_FLAG_LENGTH
                    ttls_data = bytes([flags]) + struct.pack('!I', len(tls_response)) + fragment
                else:
                    fragment = session.tls_out_buffer
                    session.tls_out_buffer = b''
                    flags = 0
                    ttls_data = bytes([flags]) + fragment

                session.identifier = (identifier + 1) % 256
                return build_eap_packet(EAP_CODE_REQUEST, session.identifier, session_eap_type, ttls_data)

            # If handshake complete and no data to send, send empty ACK to prompt client for inner auth
            if handshake_complete:
                logger.debug(f"[EAP-TTLS] Handshake complete, waiting for inner auth")
                session.identifier = (identifier + 1) % 256
                return build_eap_packet(EAP_CODE_REQUEST, session.identifier, session_eap_type, bytes([0]))

            # Still in handshake but no data ready - send ACK to get more data
            session.identifier = (identifier + 1) % 256
            return build_eap_packet(EAP_CODE_REQUEST, session.identifier, session_eap_type, bytes([0]))

        except Exception as e:
            import traceback
            logger.error(f"[EAP-TTLS] TLS handshake error: {e}")
            logger.error(f"[EAP-TTLS] Traceback: {traceback.format_exc()}")
            logger.error(f"[EAP-TTLS] Session state: {session.state}, buffer size: {len(session.tls_in_buffer)}")
            return build_eap_packet(EAP_CODE_FAILURE, identifier)

    # State: Inside TLS tunnel - handle inner authentication (PAP for TTLS, MSCHAPv2 for PEAP)
    elif session.state == 'TTLS_TUNNEL' and eap_type == session_eap_type:
        if len(eap_data) < 1:
            return build_eap_packet(EAP_CODE_FAILURE, identifier)

        flags = eap_data[0]
        tls_data = eap_data[1:]

        # If client sent empty ACK after TLS handshake, prompt for inner auth
        if not tls_data or len(tls_data) == 0:
            logger.debug(f"[{session.eap_method}] Received empty ACK, prompting for inner authentication")

            # For PEAP, send encrypted inner EAP-Request-Identity
            if session.eap_method == 'PEAP':
                # Build inner EAP-Request-Identity
                inner_identifier = 0  # Start inner EAP at identifier 0
                inner_eap = build_eap_packet(EAP_CODE_REQUEST, inner_identifier, EAP_TYPE_IDENTITY, b'')

                # For PEAPv0, strip the EAP header and only send Type + Data
                # inner_eap format: Code(1) + ID(1) + Length(2) + Type(1) + Data
                peapv0_data = inner_eap[4:]  # Skip code, id, length - keep Type + Data
                logger.debug(f"[PEAP] Initial PEAPv0 inner data (Type+Data): {peapv0_data.hex()}")

                # Encrypt it through TLS tunnel
                session.ssl_obj.write(peapv0_data)
                encrypted_data = session.bio_out.read()

                # Send as PEAP packet with encrypted inner EAP
                session.identifier = (identifier + 1) % 256
                peap_data = bytes([0]) + encrypted_data  # flags=0 + TLS data
                logger.debug(f"[PEAP] Sending encrypted inner EAP-Request-Identity (len={len(encrypted_data)})")
                return build_eap_packet(EAP_CODE_REQUEST, session.identifier, session_eap_type, peap_data)
            else:
                # For TTLS, just send empty request to prompt for AVP data
                session.identifier = (identifier + 1) % 256
                return build_eap_packet(EAP_CODE_REQUEST, session.identifier, session_eap_type, bytes([0]))

        try:
            # Feed encrypted data to SSL
            session.bio_in.write(tls_data)

            # Read decrypted inner authentication
            # For PEAP, we need to read all available data from the TLS stream
            inner_data = b''
            while True:
                try:
                    chunk = session.ssl_obj.read(4096)
                    if chunk:
                        inner_data += chunk
                    else:
                        break
                except ssl.SSLWantReadError:
                    # No more data available
                    break

            logger.debug(f"[{session.eap_method}] Read {len(inner_data)} bytes from TLS tunnel")

            if inner_data:
                # Handle different inner protocols based on EAP method
                if session.eap_method == 'PEAP':
                    # PEAP uses inner EAP with MSCHAPv2
                    return handle_peap_inner_auth(session, inner_data, identifier, settings)
                else:
                    # TTLS uses AVP format with PAP
                    # Parse inner PAP authentication (AVP format)
                    # AVP: Code(1) + Identifier(1) + Length(2) + Type(1) + Data
                    username, password = parse_pap_avp(inner_data)

                    logger.debug(f"[EAP-TTLS] Parsed AVP: username={username}, password={password}")

                if username and password:
                    logger.info(f"[EAP-TTLS] Inner PAP auth: username={username}, password_len={len(password)}")
                    logger.debug(f"[EAP-TTLS] Received password: {password[:20]}..." if len(password) > 20 else f"[EAP-TTLS] Received password: {password}")

                    # Authenticate user
                    user = get_user_by_username_from_db(username)

                    if not user:
                        logger.warning(f"[EAP-TTLS] User not found in database: {username}")
                        session.authenticated = False
                        return build_eap_packet(EAP_CODE_FAILURE, identifier)

                    logger.debug(f"[EAP-TTLS] User found, verifying password...")
                    if verify_password(password, user['password_hash']):
                        # Check allowed groups
                        allowed_groups = settings.get('radius_allowed_groups', [])
                        if allowed_groups:
                            user_groups = user.get('groups', [])
                            if not any(group in allowed_groups for group in user_groups):
                                logger.warning(f"[EAP-TTLS] User not in allowed groups: {username}")
                                session.authenticated = False
                                return build_eap_packet(EAP_CODE_FAILURE, identifier)

                        # Check if admin user (block admins from RADIUS)
                        if user.get('is_admin', False):
                            logger.warning(f"[EAP-TTLS] Admin user blocked: {username}")
                            session.authenticated = False
                            return build_eap_packet(EAP_CODE_FAILURE, identifier)

                        logger.info(f"[EAP-TTLS] Password verification SUCCESS for {username}")
                        session.authenticated = True
                        session.username = username

                        # Send EAP-Success at outer layer (RFC 5281: after inner auth success)
                        # The protected success result has been sent via TLS
                        logger.info(f"[EAP-TTLS] Sending EAP-Success for {username}")
                        return build_eap_packet(EAP_CODE_SUCCESS, identifier)
                    else:
                        logger.warning(f"[EAP-TTLS] Password verification FAILED for {username}")
                        session.authenticated = False
                        return build_eap_packet(EAP_CODE_FAILURE, identifier)
                else:
                    logger.error(f"[EAP-TTLS] Failed to parse PAP credentials from AVP data (len={len(inner_data)})")
                    logger.debug(f"[EAP-TTLS] AVP data: {inner_data[:100].hex() if len(inner_data) > 100 else inner_data.hex()}")
                    return build_eap_packet(EAP_CODE_FAILURE, identifier)

            # If we received empty ACK after sending success, send final EAP Success
            # Avoid logging potentially-sensitive inner_data at info level
            logger.debug(f"[EAP-TTLS] Checking for ACK: authenticated={session.authenticated}, inner_data_len={len(inner_data) if inner_data else 0}")
            if session.authenticated and not inner_data:
                logger.info(f"[EAP-TTLS] Received ACK after success, sending final EAP-Success")
                return build_eap_packet(EAP_CODE_SUCCESS, identifier)

        except Exception as e:
            logger.error(f"[EAP-TTLS] Tunnel error: {e}")
            return build_eap_packet(EAP_CODE_FAILURE, identifier)

    # Unknown state/type
    return build_eap_packet(EAP_CODE_FAILURE, identifier)

def handle_peap_inner_auth(session: EAPTTLSSession, inner_data: bytes, outer_identifier: int, settings: dict) -> bytes:
    """
    Handle PEAP inner EAP-MSCHAPv2 authentication
    Returns EAP response packet
    """
    # Debug log the received inner data
    logger.debug(f"[PEAP] Received inner data (len={len(inner_data)}): {inner_data.hex()}")

    # PEAP version 0 (PEAPv0) strips the EAP header and only sends Type + Data
    # We need to reconstruct the full EAP packet
    # Format received: Type (1 byte) + Data (variable)
    # Format needed: Code (1) + Identifier (1) + Length (2) + Type (1) + Data
    if len(inner_data) >= 1:
        inner_type = inner_data[0]
        inner_data_payload = inner_data[1:]

        # Reconstruct full EAP packet (assume it's a Response with identifier 0)
        # We'll extract the real identifier from the outer packet context
        eap_length = 5 + len(inner_data_payload)  # header (5 bytes) + data
        reconstructed_eap = struct.pack('!BBH', EAP_CODE_RESPONSE, 0, eap_length) + inner_data

        logger.debug(f"[PEAP] Reconstructed EAP packet from PEAPv0 format: {reconstructed_eap.hex()}")

        # Parse the reconstructed packet
        inner_eap = parse_eap_packet(reconstructed_eap)
    else:
        inner_eap = None

    if not inner_eap:
        logger.error(f"[PEAP] Invalid inner EAP packet (len={len(inner_data)}) - full data: {inner_data.hex()}")
        return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

    inner_type = inner_eap.get('type')
    inner_data_payload = inner_eap.get('data', b'')
    inner_identifier = inner_eap['identifier']

    # Handle EAP-Identity (inner)
    if inner_type == EAP_TYPE_IDENTITY:
        session.username = inner_data_payload.decode('utf-8', errors='ignore')
        logger.info(f"[PEAP] Inner identity: {session.username}")

        # Generate MSCHAPv2 Challenge
        session.mschapv2_challenge = secrets.token_bytes(16)
        session.mschapv2_ident = (inner_identifier + 1) % 256

        # Build MSCHAPv2 Challenge packet
        # MSCHAPv2 OpCode: 1=Challenge
        mschap_challenge = struct.pack('!BB', 1, session.mschapv2_ident)  # OpCode, MS-CHAPv2-ID
        mschap_challenge += struct.pack('!H', 10 + len(session.mschapv2_challenge))  # MS-Length
        mschap_challenge += bytes([len(session.mschapv2_challenge)])  # Value-Size
        mschap_challenge += session.mschapv2_challenge  # Challenge
        mschap_challenge += b'CaddyMAN'  # Name (server name)

        # Wrap in inner EAP packet (EAP Type 26 = EAP-MSCHAPv2)
        inner_eap_response = build_eap_packet(EAP_CODE_REQUEST, session.mschapv2_ident, 26, mschap_challenge)

        # For PEAPv0, strip the EAP header (code, id, length) and only send Type + Data
        # inner_eap_response format: Code(1) + ID(1) + Length(2) + Type(1) + Data
        peapv0_data = inner_eap_response[4:]  # Skip first 4 bytes (code, id, length)
        logger.debug(f"[PEAP] Sending PEAPv0 inner data (Type+Data): {peapv0_data[:20].hex()}...")

        # Encrypt and send through TLS tunnel
        session.ssl_obj.write(peapv0_data)
        tls_response = session.bio_out.read(4096)

        # Build outer EAP-PEAP packet
        flags = 0
        peap_data = bytes([flags]) + tls_response
        return build_eap_packet(EAP_CODE_REQUEST, outer_identifier, EAP_TYPE_PEAP, peap_data)

    # Handle EAP-MSCHAPv2 Response
    elif inner_type == 26:  # EAP-MSCHAPv2
        if len(inner_data_payload) < 5:
            logger.error("[PEAP] MSCHAPv2 packet too short")
            return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

        opcode = inner_data_payload[0]
        mschap_id = inner_data_payload[1]
        ms_length = struct.unpack('!H', inner_data_payload[2:4])[0]

        # OpCode 2 = Response
        if opcode == 2:
            logger.debug(f"[PEAP] Received MSCHAPv2 Response")

            # Parse MSCHAPv2 Response
            # Response format: OpCode(1) + MS-CHAPv2-ID(1) + MS-Length(2) + Value-Size(1) + Response(49) + Name(variable)
            if len(inner_data_payload) < 54:  # Minimum: 5 header + 49 response
                logger.error("[PEAP] MSCHAPv2 response too short")
                return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

            value_size = inner_data_payload[4]
            if value_size != 49:
                logger.error(f"[PEAP] Invalid MSCHAPv2 response size: {value_size}")
                return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

            # Extract response components
            peer_challenge = inner_data_payload[5:21]  # 16 bytes
            reserved = inner_data_payload[21:29]  # 8 bytes (should be zero)
            nt_response = inner_data_payload[29:53]  # 24 bytes
            flags_byte = inner_data_payload[53]

            # Extract username from Name field
            username_bytes = inner_data_payload[54:ms_length]
            username = username_bytes.decode('utf-8', errors='ignore')

            logger.info(f"[PEAP] MSCHAPv2 auth for user: {username}")

            # Authenticate user
            user = get_user_by_username_from_db(username)
            if not user:
                logger.warning(f"[PEAP] User not found: {username}")
                return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

            # Check security policies
            allowed_groups = settings.get('radius_allowed_groups', [])
            if allowed_groups:
                user_groups = user.get('groups', [])
                if not any(group in allowed_groups for group in user_groups):
                    logger.warning(f"[PEAP] User not in allowed groups: {username}")
                    return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

            if user.get('is_admin', False):
                logger.warning(f"[PEAP] Admin user blocked: {username}")
                return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

            # Verify MSCHAPv2 response using WiFi password NT hash
            wifi_password_hash = user.get('wifi_password_hash')
            if not wifi_password_hash:
                logger.warning(f"[PEAP] User {username} has no WiFi password configured")
                return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

            try:
                # Decrypt the NT hash
                nt_hash = decrypt_wifi_password_hash(wifi_password_hash)

                # Verify the MSCHAPv2 response
                is_valid, auth_response_string = verify_mschapv2_response(
                    nt_hash,
                    session.mschapv2_challenge,
                    peer_challenge,
                    username,
                    nt_response
                )

                if not is_valid:
                    logger.warning(f"[PEAP] MSCHAPv2 verification FAILED for {username}")
                    return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

                logger.info(f"[PEAP] MSCHAPv2 verification SUCCESS for {username}")
                session.authenticated = True
                session.username = username

            except Exception as e:
                logger.error(f"[PEAP] MSCHAPv2 verification error: {e}")
                return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

            # Send MSCHAPv2 Success message with proper authenticator response
            auth_string = auth_response_string.encode('ascii')
            mschap_success = struct.pack('!BB', 3, mschap_id)  # OpCode 3 = Success, MS-CHAPv2-ID
            mschap_success += struct.pack('!H', 4 + len(auth_string))  # MS-Length
            mschap_success += auth_string

            # Wrap in EAP-Request-MSCHAPv2 (Type 26)
            # Use the same MSCHAPv2 identifier we used for challenge
            inner_mschap_eap = build_eap_packet(EAP_CODE_REQUEST, session.mschapv2_ident, 26, mschap_success)

            # For PEAPv0, strip the EAP header (code, id, length) and only send Type + Type-Data
            peapv0_mschap = inner_mschap_eap[4:]  # Skip first 4 bytes (code, id, length)
            logger.debug(f"[PEAP] Full EAP packet: {inner_mschap_eap.hex()}")
            logger.debug(f"[PEAP] Sending PEAPv0 MSCHAPv2 success (Type+Data, len={len(peapv0_mschap)}): {peapv0_mschap.hex()}")

            # Encrypt and send through TLS tunnel
            session.ssl_obj.write(peapv0_mschap)
            tls_response = session.bio_out.read(4096)

            # Send outer EAP-PEAP Request with encrypted MSCHAPv2 success
            if tls_response:
                flags = 0
                peap_data = bytes([flags]) + tls_response
                session.identifier = (outer_identifier + 1) % 256
                # Mark that we're waiting for MSCHAPv2 success acknowledgment
                session.awaiting_mschapv2_ack = True
                return build_eap_packet(EAP_CODE_REQUEST, session.identifier, EAP_TYPE_PEAP, peap_data)
            else:
                logger.error("[PEAP] No TLS response after MSCHAPv2 success")
                return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

    # Handle EAP-NAK (type 3) - client rejecting further authentication
    # If session is already authenticated (MSCHAPv2 succeeded), NAK means client is done
    if inner_type == 3:  # EAP-NAK
        if session.authenticated:
            logger.info(f"[PEAP] Received NAK after authentication - client wants to finish")
            # Client is indicating it's done with inner auth, send outer EAP-Success
            logger.info(f"[PEAP] Authentication SUCCESS for {session.username}")
            return build_eap_packet(EAP_CODE_SUCCESS, outer_identifier)
        else:
            logger.error("[PEAP] Received NAK before authentication complete")
            return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

    logger.error(f"[PEAP] Unhandled inner EAP type: {inner_type}")
    return build_eap_packet(EAP_CODE_FAILURE, outer_identifier)

def parse_pap_avp(data: bytes) -> tuple:
    """
    Parse PAP credentials from TTLS AVP format
    Returns (username, password)
    """
    username = None
    password = None

    pos = 0
    while pos < len(data):
        if pos + 8 > len(data):
            break

        # AVP Header: Code(4) + Flags(1) + Length(3)
        avp_code = struct.unpack('!I', data[pos:pos+4])[0]
        _ = data[pos+4]  # avp_flags (not used)
        avp_length = struct.unpack('!I', b'\x00' + data[pos+5:pos+8])[0]

        if pos + avp_length > len(data):
            break

        avp_data = data[pos+8:pos+avp_length]

        # User-Name AVP (code 1)
        if avp_code == 1:
            username = avp_data.rstrip(b'\x00').decode('utf-8', errors='ignore')
        # User-Password AVP (code 2)
        elif avp_code == 2:
            password = avp_data.rstrip(b'\x00').decode('utf-8', errors='ignore')

        # Move to next AVP (pad to 4-byte boundary)
        pos += avp_length
        if pos % 4:
            pos += 4 - (pos % 4)

    return (username, password)

def encrypt_with_ssl(ssl_obj, bio_out, data: bytes) -> bytes:
    """Encrypt data using SSL connection"""
    ssl_obj.write(data)
    return bio_out.read()

async def handle_eap_radius_request(packet: dict, addr, server, settings: dict):
    """
    Handle RADIUS request with EAP-Message
    Implements EAP-TTLS with PAP inner authentication
    """
    identifier = packet['identifier']
    authenticator = packet['authenticator']
    attributes = packet['attributes']
    secret = settings.get('radius_secret', '').encode('utf-8')

    logger.info(f"[RADIUS] Received packet: code={packet['code']}, identifier={identifier}")

    # Get TLS certificate
    cert_path, key_path = ensure_radius_tls_cert()

    # Extract EAP-Message (can be fragmented across multiple attributes)
    eap_data = b''.join(attributes.get(79, []))

    if not eap_data:
        logger.warning(f"[RADIUS] Empty EAP-Message from {addr}")
        response = build_radius_response(3, identifier, authenticator, secret)
        server.sendto(response, addr)
        return

    # Parse EAP packet
    eap_packet = parse_eap_packet(eap_data)
    if not eap_packet:
        logger.warning(f"[RADIUS] Invalid EAP packet from {addr}")
        response = build_radius_response(3, identifier, authenticator, secret)
        server.sendto(response, addr)
        return

    # Create session ID from client address
    session_id = f"{addr[0]}:{addr[1]}"

    # Get or create EAP session
    if session_id not in eap_sessions:
        # Use configured EAP method from settings (default to TTLS for backward compatibility)
        configured_method = settings.get('radius_eap_method', 'TTLS')
        if configured_method == 'PEAP':
            eap_method = 'PEAP'
        else:
            eap_method = 'TTLS'

        eap_sessions[session_id] = EAPTTLSSession(session_id, eap_method)
        logger.info(f"[EAP] New {eap_method} session created: {session_id}")

    session = eap_sessions[session_id]

    # Handle EAP-TTLS or EAP-PEAP state machine
    eap_response = handle_eap_ttls_session(session, eap_packet, cert_path, key_path, settings)

    # Check if authentication is complete
    if eap_response[0] == EAP_CODE_SUCCESS:
        # Authentication successful - send Access-Accept
        method_label = session.eap_method
        logger.info(f"[{method_label}] Authentication SUCCESS for {session.username}")

        # Log activity
        await log_activity(session.username, "RADIUS_AUTH_SUCCESS", f"{method_label} authentication successful", f"RADIUS:{addr[0]}")

        # Build Access-Accept with EAP-Success and MPPE keys
        response_attrs = []

        # Add EAP-Message with Success
        response_attrs.append((79, eap_response))

        # Generate MPPE keys for WPA2/WPA3 from TLS keying material
        if session.master_key and len(session.master_key) >= 32:
            # session.master_key IS the PMK (32 bytes)
            # For EAP-TTLS with PAP, we only derive 32 bytes for the PMK
            # MS-MPPE-Recv-Key = PMK (used for WPA2 4-way handshake)
            # MS-MPPE-Send-Key = Also use PMK (some implementations expect both)
            mppe_recv_key = session.master_key  # This is the PMK
            mppe_send_key = session.master_key  # Use same key for both
            logger.info(f"[{method_label}] Using derived PMK from TLS keying material")
            logger.debug(f"[{method_label}] PMK (MS-MPPE-Recv-Key) (hex start): {mppe_recv_key.hex()[:32]}... (len={len(mppe_recv_key)})")
            logger.debug(f"[{method_label}] MS-MPPE-Send-Key (hex start): {mppe_send_key.hex()[:32]}... (len={len(mppe_send_key)})")
        else:
            # Fallback to random keys if keying material not available
            import secrets
            mppe_send_key = secrets.token_bytes(32)
            mppe_recv_key = secrets.token_bytes(32)
            logger.warning(f"[{method_label}] Using random MPPE keys (keying material unavailable)")

        # Add MS-MPPE keys as vendor-specific attributes (RFC 2548)
        # Vendor ID: 311 (Microsoft)
        # MS-MPPE-Send-Key: vendor attr 16
        # MS-MPPE-Recv-Key: vendor attr 17
        try:
            # Encrypt MPPE keys using RADIUS request authenticator and secret
            def encrypt_mppe_key(key: bytes, request_auth: bytes, secret: bytes) -> bytes:
                """Encrypt MPPE key for RADIUS transmission (RFC 2548 Section 2.4.2)"""
                # Salt: 2 random bytes with high bit set
                import secrets as sec
                salt = sec.token_bytes(2)
                salt = bytes([(salt[0] | 0x80), salt[1]])  # Set high bit of first byte

                # Create plaintext: Length(1) + Key(N) + Padding
                plaintext = bytes([len(key)]) + key
                # Pad to 16-byte boundary
                if len(plaintext) % 16:
                    plaintext += b'\x00' * (16 - (len(plaintext) % 16))

                # Encrypt using MD5(secret + request_auth + salt)
                encrypted = b''
                b_prev = hashlib.md5(secret + request_auth + salt).digest()
                for i in range(0, len(plaintext), 16):
                    chunk = plaintext[i:i+16]
                    xor_chunk = bytes([a ^ b for a, b in zip(chunk, b_prev)])
                    encrypted += xor_chunk
                    b_prev = hashlib.md5(secret + xor_chunk).digest()

                return salt + encrypted

            logger.debug(f"[EAP-TTLS] About to encrypt MPPE keys (debug)")
            logger.debug(f"[EAP-TTLS]   mppe_recv_key (PMK) (hex start): {mppe_recv_key.hex()[:32]}... (len={len(mppe_recv_key)})")
            logger.debug(f"[EAP-TTLS]   mppe_send_key (hex start): {mppe_send_key.hex()[:32]}... (len={len(mppe_send_key)})")
            logger.debug(f"[EAP-TTLS]   authenticator (hex start): {authenticator.hex()[:32]}... (len={len(authenticator)})")
            logger.debug(f"[EAP-TTLS]   secret (len): {len(secret)}")

            mppe_send_encrypted = encrypt_mppe_key(mppe_send_key, authenticator, secret)
            mppe_recv_encrypted = encrypt_mppe_key(mppe_recv_key, authenticator, secret)

            logger.debug(f"[EAP-TTLS] Encrypted MPPE values (debug)")
            logger.debug(f"[EAP-TTLS]   mppe_recv_encrypted (hex start): {mppe_recv_encrypted.hex()[:32]}... (len={len(mppe_recv_encrypted)})")
            logger.debug(f"[EAP-TTLS]   mppe_send_encrypted (hex start): {mppe_send_encrypted.hex()[:32]}... (len={len(mppe_send_encrypted)})")

            # Build vendor-specific attribute (attribute 26)
            # Format: Type(1) + Length(1) + Vendor-Id(4) + Vendor-Type(1) + Vendor-Length(1) + Data
            def build_vendor_attr(vendor_id: int, vendor_type: int, vendor_data: bytes) -> bytes:
                vendor_length = 2 + len(vendor_data)  # Type(1) + Length(1) + Data
                vendor_payload = struct.pack('!I', vendor_id) + bytes([vendor_type, vendor_length]) + vendor_data
                return vendor_payload

            # Microsoft Vendor ID = 311
            mppe_send_vsa = build_vendor_attr(311, 16, mppe_send_encrypted)
            mppe_recv_vsa = build_vendor_attr(311, 17, mppe_recv_encrypted)

            response_attrs.append((26, mppe_send_vsa))  # Vendor-Specific Attribute
            response_attrs.append((26, mppe_recv_vsa))  # Vendor-Specific Attribute

            logger.debug(f"[EAP-TTLS] Added MS-MPPE keys to Access-Accept")
        except Exception as e:
            logger.error(f"[EAP-TTLS] Failed to add MPPE keys: {e}")

        # VLAN assignment (if enabled)
        if settings.get('radius_vlan_assignment', False):
            user = get_user_by_username_from_db(session.username)
            if user:
                groups = user.get('groups', [])
                if groups:
                    all_groups = get_all_groups_from_db()
                    for group in all_groups:
                        if group['id'] == groups[0]:
                            vlan_id = group.get('radius_vlan')
                            if vlan_id:
                                response_attrs.append((64, struct.pack('!I', 13)))  # Tunnel-Type = VLAN
                                response_attrs.append((65, struct.pack('!I', 6)))   # Tunnel-Medium-Type = IEEE-802
                                response_attrs.append((81, str(vlan_id).encode()))  # Tunnel-Private-Group-ID
                                logger.info(f"[RADIUS] Assigned VLAN {vlan_id} to {session.username}")
                            break

        response = build_radius_response(2, identifier, authenticator, secret, response_attrs)
        server.sendto(response, addr)

        # Clean up session and temporary files (if not already deleted)
        if session.keylog_file:
            if hasattr(session.keylog_file, 'name') and os.path.exists(session.keylog_file.name):
                try:
                    os.unlink(session.keylog_file.name)
                    logger.debug(f"[EAP-TTLS] Cleaned up keylog file: {session.keylog_file.name}")
                except Exception as e:
                    logger.debug(f"[EAP-TTLS] Keylog file already cleaned up or inaccessible: {e}")
        del eap_sessions[session_id]

    elif eap_response[0] == EAP_CODE_FAILURE:
        # Authentication failed - send Access-Reject
        method_label = session.eap_method if hasattr(session, 'eap_method') else 'EAP'
        logger.warning(f"[{method_label}] Authentication FAILED for session {session_id}")

        response_attrs = [(79, eap_response)]
        response = build_radius_response(3, identifier, authenticator, secret, response_attrs)
        server.sendto(response, addr)

        # Clean up session and temporary files (if not already deleted)
        if session_id in eap_sessions:
            session = eap_sessions[session_id]
            if session.keylog_file:
                if hasattr(session.keylog_file, 'name') and os.path.exists(session.keylog_file.name):
                    try:
                        os.unlink(session.keylog_file.name)
                        logger.debug(f"[EAP-TTLS] Cleaned up keylog file: {session.keylog_file.name}")
                    except Exception as e:
                        logger.debug(f"[EAP-TTLS] Keylog file already cleaned up or inaccessible: {e}")
            del eap_sessions[session_id]

    else:
        # Continue EAP conversation - send Access-Challenge
        response_attrs = [(79, eap_response)]
        logger.info(f"[RADIUS] Sending Access-Challenge with identifier={identifier}, EAP response len={len(eap_response)}")
        response = build_radius_response(11, identifier, authenticator, secret, response_attrs)  # Access-Challenge
        logger.debug(f"[RADIUS] About to send packet hex (debug): {response.hex()}")
        server.sendto(response, addr)
        logger.info(f"[RADIUS] Packet sent to {addr}")

def md5_hash(data: bytes) -> bytes:
    """MD5 hash for RADIUS"""
    import hashlib
    return hashlib.md5(data).digest()

def parse_radius_packet(data: bytes) -> dict:
    """
    Parse RADIUS packet
    Security: Validates packet structure and sizes
    """
    try:
        if len(data) < 20:
            return None

        code = data[0]
        identifier = data[1]
        length = (data[2] << 8) | data[3]
        authenticator = data[4:20]

        if len(data) < length:
            return None

        # Parse attributes
        attributes = {}
        pos = 20
        while pos < length:
            if pos + 2 > length:
                break

            attr_type = data[pos]
            attr_len = data[pos + 1]

            if attr_len < 2 or pos + attr_len > length:
                break

            attr_value = data[pos + 2:pos + attr_len]

            if attr_type not in attributes:
                attributes[attr_type] = []
            attributes[attr_type].append(attr_value)

            pos += attr_len

        return {
            'code': code,
            'identifier': identifier,
            'length': length,
            'authenticator': authenticator,
            'attributes': attributes,
            'raw': data
        }

    except Exception as e:
        logger.error(f"RADIUS packet parse error: {e}")
        return None

def extract_radius_username(attributes: dict) -> str:
    """Extract username from RADIUS attributes"""
    # Attribute 1 = User-Name
    if 1 in attributes and attributes[1]:
        try:
            return attributes[1][0].decode('utf-8', errors='ignore')
        except:
            pass
    return None

def extract_radius_password(attributes: dict, authenticator: bytes, secret: bytes) -> str:
    """
    Extract and decrypt password from RADIUS attributes
    Security: Proper decryption of User-Password attribute
    """
    # Attribute 2 = User-Password (encrypted)
    if 2 in attributes and attributes[2]:
        try:
            encrypted_password = attributes[2][0]

            # Decrypt password using shared secret and authenticator
            # Password is XORed with MD5(secret + authenticator)
            password = b''
            b = authenticator

            for i in range(0, len(encrypted_password), 16):
                chunk = encrypted_password[i:i+16]
                hash_input = secret + b
                hash_output = md5_hash(hash_input)

                # XOR to decrypt
                decrypted_chunk = bytes([chunk[j] ^ hash_output[j] for j in range(len(chunk))])
                password += decrypted_chunk
                b = chunk

            # Remove padding (null bytes)
            password = password.rstrip(b'\x00')
            return password.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Password decryption error: {e}")

    return None

def build_radius_response(code: int, identifier: int, authenticator: bytes, secret: bytes, attributes: list = []) -> bytes:
    """
    Build RADIUS response packet with Message-Authenticator for EAP
    code: 2=Access-Accept, 3=Access-Reject, 11=Access-Challenge
    """
    # Check if this is an EAP packet (has EAP-Message attribute 79)
    has_eap = any(attr_type == 79 for attr_type, _ in attributes)
    logger.debug(f"[RADIUS] build_radius_response: code={code}, has_eap={has_eap}, attrs={[(t, len(v) if isinstance(v, bytes) else v) for t, v in attributes]}")

    # Build attributes section
    attrs_data = b''
    for attr_type, attr_value in attributes:
        if isinstance(attr_value, str):
            attr_value = attr_value.encode('utf-8')
        elif isinstance(attr_value, int):
            attr_value = attr_value.to_bytes(4, 'big')
        elif not isinstance(attr_value, bytes):
            logger.error(f"[RADIUS] Invalid attribute value type: {type(attr_value)} for attr {attr_type}")
            continue

        # Special handling for EAP-Message (79) - fragment if needed
        if attr_type == 79 and len(attr_value) > 253:
            # Fragment EAP-Message across multiple attributes (max 253 bytes each)
            logger.debug(f"[RADIUS] Fragmenting EAP-Message: {len(attr_value)} bytes into multiple attributes")
            offset = 0
            while offset < len(attr_value):
                chunk_size = min(253, len(attr_value) - offset)
                chunk = attr_value[offset:offset + chunk_size]
                attr_len = 2 + len(chunk)
                attrs_data += bytes([attr_type, attr_len]) + chunk
                offset += chunk_size
                logger.debug(f"[RADIUS] Added EAP-Message fragment: offset={offset-chunk_size}, size={chunk_size}")
            continue

        attr_len = 2 + len(attr_value)

        # RADIUS attributes have a max length of 255
        if attr_len > 255:
            logger.error(f"[RADIUS] Attribute {attr_type} too long: {attr_len} bytes (not EAP-Message)")
            continue

        try:
            attrs_data += bytes([attr_type, attr_len]) + attr_value
        except Exception as e:
            logger.error(f"[RADIUS] Error building attribute {attr_type}: {e}, len={attr_len}, value_len={len(attr_value)}")
            raise

    # Add Message-Authenticator attribute (80) for EAP packets
    # This is HMAC-MD5 and must be added BEFORE calculating the authenticator
    if has_eap:
        logger.debug(f"[RADIUS] Adding Message-Authenticator to EAP response")
        # Add placeholder Message-Authenticator (16 zero bytes)
        msg_auth_attr = bytes([80, 18]) + (b'\x00' * 16)
        attrs_data += msg_auth_attr
        logger.debug(f"[RADIUS] Total attrs length after Message-Auth: {len(attrs_data)}")

    # Build packet with placeholder authenticator and attrs with ZERO Message-Authenticator
    length = 20 + len(attrs_data)

    # Calculate Message-Authenticator if EAP (HMAC-MD5 over entire packet)
    # RFC 2869: For response packets, use the Request-Authenticator from the Access-Request
    if has_eap:
        # Build packet for HMAC with Request-Authenticator and ZERO Message-Authenticator
        packet_for_hmac = bytes([code, identifier]) + length.to_bytes(2, 'big') + authenticator + attrs_data

        logger.debug(f"[RADIUS] HMAC input packet (debug): {packet_for_hmac.hex()}")
        logger.debug(f"[RADIUS] HMAC secret (len): {len(secret)}")
        logger.debug(f"[RADIUS] Request-Authenticator (hex start): {authenticator.hex()[:32]}... (len={len(authenticator)})")

        # Calculate HMAC-MD5
        import hmac as hmac_module
        msg_auth = hmac_module.new(secret, packet_for_hmac, hashlib.md5).digest()
        logger.debug(f"[RADIUS] Message-Auth calculated (hex start): {msg_auth.hex()[:32]}... (len={len(msg_auth)})")

        # Replace the ZERO Message-Authenticator in attrs_data with calculated value
        msg_auth_pos = len(attrs_data) - 18  # 18 = 2 (header) + 16 (value)
        attrs_data = attrs_data[:msg_auth_pos + 2] + msg_auth + attrs_data[msg_auth_pos + 18:]
        logger.debug(f"[RADIUS] Updated attrs_data with Message-Auth (debug)")

    # Now calculate response authenticator with the CORRECT Message-Authenticator in attrs
    # MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
    packet = bytes([code, identifier]) + length.to_bytes(2, 'big') + (b'\x00' * 16) + attrs_data
    response_auth = md5_hash(
        packet[:4] + authenticator + attrs_data + secret
    )

    # Build final packet with response authenticator
    packet = packet[:4] + response_auth + packet[20:]

    if has_eap:
        # Verify Message-Authenticator in final packet
        final_msg_auth_pos = 20 + len(attrs_data) - 16
        final_msg_auth = packet[final_msg_auth_pos:final_msg_auth_pos + 16]
        logger.debug(f"[RADIUS] Final packet Message-Auth (hex start): {final_msg_auth.hex()[:32]}... (len={len(final_msg_auth)})")
        logger.debug(f"[RADIUS] Final packet hex (debug): {packet.hex()}")

    return packet

async def handle_radius_request(data: bytes, addr, server, settings: dict):
    """
    Handle RADIUS Access-Request with EAP-TTLS support
    Security: Rate limiting, no admin access, proper authentication
    """
    try:
        # Security: Check if connection is from external/non-private IP
        import ipaddress
        try:
            client_ip = ipaddress.ip_address(addr[0])
            if not (client_ip.is_loopback or client_ip.is_private):
                logger.critical(f"RADIUS: SECURITY ALERT - External IP attempting connection: {addr[0]} - REJECTED")
                await send_event_notification(
                    "radius_external_connection",
                    "RADIUS Security Alert",
                    f"External IP address attempted to connect to RADIUS server!\n\n"
                    f"Source IP: {addr[0]}\n"
                    f"Source Port: {addr[1]}\n"
                    f"This could indicate:\n"
                    f"- VPN failure exposing your server\n"
                    f"- Port forwarding misconfiguration\n"
                    f"- Network scan/attack attempt\n\n"
                    f"Action: Connection REJECTED. Verify firewall and VPN settings immediately.",
                    source_ip=addr[0],
                    source_port=addr[1]
                )
                # REJECT external connections - do not process
                return
        except ValueError:
            pass  # Invalid IP, continue processing

        secret = settings.get('radius_secret', '').encode('utf-8')
        if not secret:
            logger.error("RADIUS: No shared secret configured")
            return

        # Parse packet
        packet = parse_radius_packet(data)
        if not packet or packet['code'] != 1:  # Access-Request
            logger.warning(f"RADIUS: Invalid packet from {addr}")
            return

        identifier = packet['identifier']
        authenticator = packet['authenticator']
        attributes = packet['attributes']

        # Check for EAP-Message attribute (79)
        if 79 in attributes:
            # EAP authentication
            await handle_eap_radius_request(packet, addr, server, settings)
            return

        # Legacy PAP authentication (fallback)
        # Extract username and password
        username = extract_radius_username(attributes)
        password = extract_radius_password(attributes, authenticator, secret)

        if not username:
            logger.warning(f"RADIUS: No username in request from {addr}")
            response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
            server.sendto(response, addr)
            return

        logger.info(f"RADIUS: Access-Request for user '{username}' from {addr}")

        # Authenticate user
        user = get_user_by_username_from_db(username)

        if not user:
            logger.warning(f"RADIUS: User not found - {username}")
            await asyncio.sleep(1)  # Rate limiting
            response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
            server.sendto(response, addr)
            return

        # Security: Block admin users from RADIUS authentication
        if user.get('is_admin', False):
            logger.warning(f"RADIUS: Admin user blocked - {username}")
            await log_activity(username, "RADIUS_AUTH_DENIED", "Admin users cannot use RADIUS", f"RADIUS:{addr[0]}")
            await send_event_notification("radius_auth_denied", "RADIUS Access Denied",
                f"RADIUS authentication denied - admin users not allowed.",
                username=username, ip_address=addr[0], reason="Admin user")
            await asyncio.sleep(2)  # Extra delay for admin attempts
            response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
            server.sendto(response, addr)
            return

        # Check if user is in allowed groups (if specified)
        allowed_groups = settings.get('radius_allowed_groups', [])
        if allowed_groups:
            user_groups = user.get('groups', [])
            # Check if user has at least one allowed group
            if not any(group in allowed_groups for group in user_groups):
                logger.warning(f"RADIUS: User not in allowed groups - {username}")
                await log_activity(username, "RADIUS_AUTH_DENIED", "User not in allowed groups", f"RADIUS:{addr[0]}")
                await send_event_notification("radius_auth_denied", "RADIUS Access Denied",
                    f"RADIUS authentication denied - user not in allowed groups.",
                    username=username, ip_address=addr[0], reason="Not in allowed groups")
                await asyncio.sleep(1)  # Rate limiting
                response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
                server.sendto(response, addr)
                return

        # PAP authentication - use WiFi password for security
        # (limits damage if PAP traffic is intercepted and RADIUS secret is weak)
        wifi_password_hash = user.get('wifi_password_hash')
        if not wifi_password_hash:
            logger.warning(f"RADIUS PAP: User {username} has no WiFi password configured")
            await log_activity(username, "RADIUS_AUTH_FAILED", "No WiFi password set (required for PAP)", f"RADIUS:{addr[0]}")
            await send_event_notification("radius_auth_failed", "RADIUS Authentication Failed",
                f"User attempted PAP authentication without WiFi password configured.",
                username=username, ip_address=addr[0], reason="No WiFi password")
            await asyncio.sleep(1)  # Rate limiting
            response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
            server.sendto(response, addr)
            return

        try:
            # Decrypt the stored NT hash
            stored_nt_hash = decrypt_wifi_password_hash(wifi_password_hash)

            # Hash the provided password to NT hash
            provided_nt_hash = nthash.hash(password)

            # Compare NT hashes
            if provided_nt_hash != stored_nt_hash:
                logger.warning(f"RADIUS PAP: Authentication failed for {username}")
                await log_activity(username, "RADIUS_AUTH_FAILED", "Invalid WiFi password", f"RADIUS:{addr[0]}")
                await send_event_notification("radius_auth_failed", "RADIUS Authentication Failed",
                    f"Failed RADIUS PAP authentication attempt.",
                    username=username, ip_address=addr[0], reason="Invalid WiFi password")
                await asyncio.sleep(1)  # Rate limiting
                response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
                server.sendto(response, addr)
                return
        except Exception as e:
            logger.error(f"RADIUS PAP: Error verifying WiFi password for {username}: {e}")
            await asyncio.sleep(1)  # Rate limiting
            response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
            server.sendto(response, addr)
            return

        # Authentication successful
        logger.info(f"RADIUS: Authentication successful for {username}")
        await log_activity(username, "RADIUS_AUTH_SUCCESS", "Authentication successful", f"RADIUS:{addr[0]}")
        await send_event_notification("radius_auth_success", "RADIUS Authentication Success",
            f"Successful RADIUS authentication.",
            username=username, ip_address=addr[0])

        # Build Access-Accept with VLAN assignment
        response_attrs = []

        # VLAN assignment (if enabled)
        if settings.get('radius_vlan_assignment', False):
            # Get user's primary group
            groups = user.get('groups', [])
            if groups:
                all_groups = get_all_groups_from_db()
                for group in all_groups:
                    if group['id'] == groups[0]:  # Primary group
                        vlan_id = group.get('radius_vlan')
                        if vlan_id:
                            # Tunnel-Type (64) = VLAN (13)
                            response_attrs.append((64, 13))
                            # Tunnel-Medium-Type (65) = IEEE-802 (6)
                            response_attrs.append((65, 6))
                            # Tunnel-Private-Group-ID (81) = VLAN ID
                            response_attrs.append((81, str(vlan_id)))
                            logger.info(f"RADIUS: Assigned VLAN {vlan_id} to {username}")
                        break

        response = build_radius_response(2, identifier, authenticator, secret, response_attrs)  # Access-Accept
        server.sendto(response, addr)
        logger.info(f"RADIUS: Access-Accept sent for {username}")

    except Exception as e:
        logger.error(f"RADIUS request handler error: {e}")
        try:
            response = build_radius_response(3, identifier, authenticator, secret)  # Access-Reject
            server.sendto(response, addr)
        except:
            pass

async def radius_server():
    """
    Production-ready RADIUS server for WiFi/Network authentication
    Security: Proper authentication, no admin access, VLAN assignment
    """
    settings = get_settings_from_db()
    if not settings.get('radius_enabled'):
        return

    auth_port = settings.get('radius_auth_port', 1812)
    secret = settings.get('radius_secret', '')

    if not secret:
        logger.error("RADIUS: Cannot start - no shared secret configured")
        return

    logger.info(f"Starting RADIUS server on UDP port {auth_port}")

    import socket
    server = None

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Security: Bind to all interfaces (0.0.0.0) but filter connections by IP in handle_radius_request
        # This allows connections from any private network (10.x, 172.16-31.x, 192.168.x) while blocking external IPs
        server.bind(('0.0.0.0', auth_port))
        server.setblocking(False)

        logger.info(f"RADIUS server listening on 0.0.0.0:{auth_port} (accepting connections from private networks only)")

        while True:
            try:
                try:
                    data, addr = server.recvfrom(4096)  # Limit packet size
                    logger.info(f"RADIUS: Packet received from {addr}")

                    # Handle request in separate task
                    asyncio.create_task(handle_radius_request(data, addr, server, settings))

                except BlockingIOError:
                    await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"RADIUS server error: {e}")
                await asyncio.sleep(1)

    except asyncio.CancelledError:
        logger.info("RADIUS server task cancelled, closing socket...")
        if server:
            server.close()
        raise
    except Exception as e:
        logger.error(f"Failed to start RADIUS server: {e}")
        if server:
            server.close()
        raise

async def start_radius_server():
    """Start RADIUS server task"""
    global radius_server_task
    settings = get_settings_from_db()

    # Master switch - if auth protocols disabled, don't start anything
    if not settings.get('auth_protocols_enabled'):
        return

    if not settings.get('radius_enabled'):
        return

    if radius_server_task is None or radius_server_task.done():
        radius_server_task = asyncio.create_task(radius_server())
        logger.info("RADIUS server task started")

async def stop_radius_server():
    """Stop RADIUS server task"""
    global radius_server_task

    if radius_server_task and not radius_server_task.done():
        radius_server_task.cancel()
        try:
            await radius_server_task
        except asyncio.CancelledError:
            pass
        logger.info("RADIUS server stopped")

# Email Functions
async def send_email(to: str, subject: str, body: str):
    """Send email via SMTP"""
    settings = get_settings_from_db()
    # Master switch - if auth protocols disabled, don't send emails
    if not settings.get('auth_protocols_enabled'):
        logger.warning("Authentication protocols not enabled, email not sent")
        return False
    if not settings.get('smtp_enabled'):
        logger.warning("SMTP not enabled, email not sent")
        return False

    smtp_server = settings.get('smtp_server', '')
    smtp_port = settings.get('smtp_port', 587)
    smtp_username = settings.get('smtp_username', '')
    smtp_password = settings.get('smtp_password', '')
    use_tls_setting = settings.get('smtp_use_tls', True)

    try:
        message = EmailMessage()
        message["From"] = f"{settings.get('smtp_from_name', 'CaddyIAM')} <{settings.get('smtp_from_address', 'noreply@example.com')}>"
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)

        logger.info(f"Attempting to send email via {smtp_server}:{smtp_port} (TLS: {use_tls_setting}, User: {smtp_username[:3]}***)")

        # Use SMTP client directly for better control
        if smtp_port == 465:
            # Implicit TLS/SSL
            logger.debug(f"Using implicit TLS (port 465)")
            smtp = aiosmtplib.SMTP(hostname=smtp_server, port=smtp_port, use_tls=True, timeout=30)
        else:
            # STARTTLS (port 587) or plain (port 25)
            logger.debug(f"Using STARTTLS (port {smtp_port})")
            smtp = aiosmtplib.SMTP(hostname=smtp_server, port=smtp_port, timeout=30)

        await smtp.connect()

        # STARTTLS if needed and not already using TLS
        if smtp_port != 465 and use_tls_setting:
            await smtp.starttls()

        # Login with credentials
        if smtp_username and smtp_password:
            logger.debug(f"Authenticating as {smtp_username}")
            await smtp.login(smtp_username, smtp_password)

        # Send the message
        await smtp.send_message(message)
        await smtp.quit()

        logger.info(f"Email sent successfully to {to}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {type(e).__name__}: {e}")
        logger.error(f"SMTP config: server={smtp_server}, port={smtp_port}, TLS={use_tls_setting}, user={smtp_username[:3] if smtp_username else '(none)'}***")
        return False

async def send_user_invite(user_id: str):
    """Send invitation email to user"""
    user = get_user_by_id_from_db(user_id)
    if not user or not user.get('email'):
        return False

    # Generate invite token (password reset token)
    reset_token = secrets.token_urlsafe(32)
    expires = (datetime.now().timestamp() + 86400)  # 24 hours

    # Save token to user
    user['password_reset_token'] = reset_token
    user['password_reset_expires'] = str(expires)
    save_user_to_db(user)

    # Build invite email
    settings = get_settings_from_db()
    setup_url = f"{settings.get('oidc_issuer', 'http://localhost:12888')}/setup-password?token={reset_token}"

    subject = "Welcome to CaddyIAM"
    body = f"""Hello {user.get('first_name', user.get('username'))},

You've been invited to CaddyIAM!

Username: {user.get('username')}
Setup your password: {setup_url}

This link expires in 24 hours.

Best regards,
CaddyIAM Team
"""

    return await send_email(user['email'], subject, body)

async def send_password_reset(user_id: str):
    """Send password reset email to user"""
    user = get_user_by_id_from_db(user_id)
    if not user or not user.get('email'):
        return False

    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    expires = (datetime.now().timestamp() + 3600)  # 1 hour

    # Save token to user
    user['password_reset_token'] = reset_token
    user['password_reset_expires'] = str(expires)
    save_user_to_db(user)

    # Build reset email
    settings = get_settings_from_db()
    org_name = settings.get('organization_name', 'CaddyMAN')
    reset_url = f"{settings.get('oidc_issuer', 'http://localhost:12888')}/reset-password?token={reset_token}"

    subject = f"{org_name} Password Reset Request"
    body = f"""Hello {user.get('first_name', user.get('username'))},

A password reset was requested for your {org_name} account.

Reset your password: {reset_url}

This link expires in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
{org_name} Team
"""

    return await send_email(user['email'], subject, body)

async def send_invite_email(email: str, username: str, invite_url: str, expiry_hours: int):
    """Send invite link email to new user"""
    settings = get_settings_from_db()
    org_name = settings.get('organization_name', 'CaddyMAN')

    subject = f"You've been invited to {org_name}"
    body = f"""Hello,

You've been invited to create an account on {org_name}.

Username: {username}

Set up your account: {invite_url}

This link expires in {expiry_hours} hour{'s' if expiry_hours != 1 else ''}.

Best regards,
{org_name} Team
"""
    return await send_email(email, subject, body)

async def send_password_reset_email(email: str, username: str, reset_url: str, expiry_hours: int):
    """Send password reset email to user"""
    settings = get_settings_from_db()
    org_name = settings.get('organization_name', 'CaddyMAN')

    subject = f"{org_name} Password Reset Request"
    body = f"""Hello {username},

You have requested to reset your password for your {org_name} account.

Click the link below to reset your password:
{reset_url}

This link expires in {expiry_hours} hour{'s' if expiry_hours != 1 else ''}.

If you did not request this password reset, please ignore this email and your password will remain unchanged.

Best regards,
{org_name} Team
"""
    return await send_email(email, subject, body)

async def start_php_cgi():
    """Start PHP-CGI process on port 9000"""
    global php_cgi_process
    settings = get_settings_from_db()

    # Only start if PHP is enabled and path is configured
    if not settings.get("php_enabled") or not settings.get("php_path"):
        return

    # Check if already running
    if php_cgi_process and php_cgi_process.returncode is None:
        return

    try:
        php_path = settings["php_path"]
        # If path is a directory, append platform-specific php-cgi executable
        if os.path.isdir(php_path):
            php_path = os.path.join(php_path, get_php_cgi_executable())

        # Check if php-cgi exists
        if not os.path.exists(php_path):
            logger.error(f"PHP-CGI not found at: {php_path}")
            return

        # Start PHP-CGI on port 9000
        php_cgi_process = await asyncio.create_subprocess_exec(
            php_path, "-b", "127.0.0.1:9000",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logger.info(f"PHP-CGI started (PID {php_cgi_process.pid})")
    except Exception as e:
        logger.error(f"Failed to start PHP-CGI: {e}")

async def stop_php_cgi():
    """Stop PHP-CGI process"""
    global php_cgi_process
    if php_cgi_process and php_cgi_process.returncode is None:
        php_cgi_process.terminate()
        try:
            await asyncio.wait_for(php_cgi_process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            php_cgi_process.kill()
            await php_cgi_process.wait()
        php_cgi_process = None
        logger.info("PHP-CGI stopped")

async def stop_caddy():
    global caddy_process, caddy_stop_reason
    async with config_lock:
        if caddy_process and caddy_process.returncode is None:
            caddy_process.terminate()
            try:
                await asyncio.wait_for(caddy_process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                caddy_process.kill()
                await caddy_process.wait()
            caddy_process = None
            caddy_stop_reason = "Manually stopped by user"
            return {"status": "stopped"}
        return {"status": "not_running"}

def build_caddy_config():
    try:
        settings = get_settings_from_db()
        proxies = get_all_proxies_from_db()
        websites = get_all_websites_from_db()
        servers = {}
        https_redirects = {}  # Maps (source_http_port, domain_pattern) to target_https_port
        
        def add_auth_handler(route, access_groups):
            """Adds authentication using reverse_proxy handle_response (Caddy v2.10+ compatible)"""
            if not access_groups:
                return

            # Get all users from database
            users = get_all_users_from_db()

            # Find users who belong to any of the required groups
            allowed_users = []
            for user in users:
                user_groups = set(user.get("groups", []))
                if user_groups.intersection(access_groups):
                    allowed_users.append(user)

            if not allowed_users:
                logger.warning(f"No users found for access groups: {access_groups}")

            # Store the original handlers
            original_handlers = route["handle"].copy()

            # Create auth check using reverse_proxy with handle_response
            auth_handler = {
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8000"}],
                "rewrite": {
                    "uri": "/api/auth/verify"
                },
                "headers": {
                    "request": {
                        "set": {
                            "X-Required-Groups": [",".join(access_groups)],
                            "X-Original-URI": ["{http.request.uri}"]
                        }
                    }
                },
                "handle_response": [
                    {
                        # If auth succeeds (200), continue to the original handlers
                        "match": {
                            "status_code": [200]
                        },
                        "routes": [
                            {
                                "handle": original_handlers
                            }
                        ]
                    }
                    # For 401/403, the default behavior is to pass through the upstream response
                    # which includes the HTML login page or JSON error
                ]
            }

            # Replace all handlers with just the auth handler
            route["handle"] = [auth_handler]
            

        
        for proxy in proxies:
            if not proxy.get("enabled", True):
                continue

            # Check if advanced config is in routes array format
            advanced_config = proxy.get("advanced")
            if advanced_config and isinstance(advanced_config, dict) and "routes" in advanced_config:
                # Handle advanced routes array format: {"routes": [...]}
                advanced_routes = advanced_config.get("routes", [])
                if not advanced_routes:
                    continue

                # Extract domains from the routes
                extracted_domains = []
                for route in advanced_routes:
                    if isinstance(route, dict) and "match" in route:
                        for matcher in route.get("match", []):
                            if isinstance(matcher, dict) and "host" in matcher:
                                extracted_domains.extend(matcher["host"])

                # Remove duplicates while preserving order
                unique_domains = []
                for domain in extracted_domains:
                    if domain not in unique_domains:
                        unique_domains.append(domain)

                domains = unique_domains if unique_domains else proxy.get("domains", [])

                # Handle legacy format (listen_port + tls)
                if "listen_port" in proxy and proxy.get("listen_port") is not None:
                    if proxy.get("tls"):
                        https_ports = [proxy["listen_port"]]
                        http_ports = []
                    else:
                        http_ports = [proxy["listen_port"]]
                        https_ports = []
                else:
                    # New format with http_ports and https_ports
                    http_ports = proxy.get("http_ports", [])
                    https_ports = proxy.get("https_ports", [])

                # If no ports specified but we have advanced routes, default to 443 (HTTPS)
                if not http_ports and not https_ports:
                    logger.info(f"Advanced routes proxy has no ports configured, defaulting to HTTPS port 443")
                    https_ports = [443]

                # Auto HTTPS redirect setup
                if proxy.get("auto_https") and http_ports and domains:
                    # Only add default 443 if user didn't specify any HTTPS ports
                    if not https_ports:
                        https_ports.append(443)
                    # Store redirect mappings for each HTTP port to target HTTPS port
                    target_https_port = https_ports[0] if https_ports else 443
                    for http_port in http_ports:
                        for domain in domains:
                            https_redirects[(http_port, domain)] = target_https_port

                # Add the advanced routes directly to servers (not wrapped)
                for port in http_ports:
                    if port not in servers:
                        servers[port] = {"routes": [], "has_tls": False}
                    for route in advanced_routes:
                        # Deep copy the route to avoid mutation
                        route_copy = copy.deepcopy(route)
                        add_auth_handler(route_copy, proxy.get("access_groups", []))
                        servers[port]["routes"].append(route_copy)

                for port in https_ports:
                    if port not in servers:
                        servers[port] = {"routes": [], "has_tls": True}
                    for route in advanced_routes:
                        # Deep copy the route to avoid mutation
                        route_copy = copy.deepcopy(route)
                        add_auth_handler(route_copy, proxy.get("access_groups", []))
                        servers[port]["routes"].append(route_copy)
                    servers[port]["has_tls"] = True

                # Continue to next proxy - skip normal processing
                continue

            # Standard processing for non-routes-array proxies
            domains = proxy.get("domains", [])
            if not domains:
                continue

            # Handle legacy format (listen_port + tls)
            if "listen_port" in proxy and proxy.get("listen_port") is not None:
                if proxy.get("tls"):
                    https_ports = [proxy["listen_port"]]
                    http_ports = []
                else:
                    http_ports = [proxy["listen_port"]]
                    https_ports = []
            else:
                # New format with http_ports and https_ports
                http_ports = proxy.get("http_ports", [])
                https_ports = proxy.get("https_ports", [])

            # Skip if no ports specified
            if not http_ports and not https_ports:
                continue

            # Auto HTTPS redirect setup
            if proxy.get("auto_https") and http_ports and domains:
                # Only add default 443 if user didn't specify any HTTPS ports
                if not https_ports:
                    https_ports.append(443)
                # Store redirect mappings for each HTTP port to target HTTPS port
                target_https_port = https_ports[0] if https_ports else 443
                for http_port in http_ports:
                    for domain in domains:
                        https_redirects[(http_port, domain)] = target_https_port

            # Build route handler
            route_base = {"match": [{"host": domains}], "handle": []}

            # Check if advanced_config is a complete handler or just settings to merge
            if advanced_config and isinstance(advanced_config, dict) and "handler" in advanced_config:
                # Advanced config is a complete handler (has "handler" key)
                route_base["handle"].append(advanced_config)
            else:
                # Build normal reverse_proxy handler
                handler = {"handler": "reverse_proxy", "upstreams": []}
                upstreams = proxy["upstream"].split(",") if "," in proxy["upstream"] else [proxy["upstream"]]
                for upstream in upstreams:
                    # Strip http:// or https:// scheme from upstream - Caddy dial expects host:port only
                    dial_addr = upstream.strip()
                    if dial_addr.startswith('http://'):
                        dial_addr = dial_addr[7:]  # Remove 'http://'
                    elif dial_addr.startswith('https://'):
                        dial_addr = dial_addr[8:]  # Remove 'https://'
                    handler["upstreams"].append({"dial": dial_addr})
                if proxy.get("load_balance"):
                    handler["load_balancing"] = {"selection_policy": {"policy": proxy["load_balance"]}}
                if proxy.get("header_up_host") or proxy.get("remove_origin") or proxy.get("remove_referer") or proxy.get("custom_headers"):
                    handler["headers"] = {"request": {}}
                    if proxy.get("header_up_host"):
                        handler["headers"]["request"]["set"] = {"Host": [proxy["header_up_host"]]}
                    remove_headers = []
                    if proxy.get("remove_origin"):
                        remove_headers.append("Origin")
                    if proxy.get("remove_referer"):
                        remove_headers.append("Referer")
                    if remove_headers:
                        handler["headers"]["request"]["delete"] = remove_headers
                    if proxy.get("custom_headers"):
                        if "set" not in handler["headers"]["request"]:
                            handler["headers"]["request"]["set"] = {}
                        for key, value in proxy["custom_headers"].items():
                            handler["headers"]["request"]["set"][key] = [value]
                if proxy.get("websocket"):
                    handler["headers"] = handler.get("headers", {})
                    handler["headers"]["request"] = handler["headers"].get("request", {})
                    handler["headers"]["request"]["set"] = handler["headers"]["request"].get("set", {})
                    handler["headers"]["request"]["set"].update({
                        "Connection": ["{http.request.header.Connection}"],
                        "Upgrade": ["{http.request.header.Upgrade}"]
                    })

                # Parse additional_directives (raw Caddyfile text) and convert to JSON
                if proxy.get("additional_directives"):
                    directives = proxy["additional_directives"].strip()
                    if directives:
                        # Parse line by line
                        for line in directives.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue

                            # Handle header_up directives
                            if line.startswith('header_up '):
                                rest = line[10:].strip()  # Remove 'header_up '

                                # Check if it's a delete operation (starts with -)
                                if rest.startswith('-'):
                                    header_name = rest[1:].strip()
                                    handler["headers"] = handler.get("headers", {})
                                    handler["headers"]["request"] = handler["headers"].get("request", {})
                                    if "delete" not in handler["headers"]["request"]:
                                        handler["headers"]["request"]["delete"] = []
                                    if header_name not in handler["headers"]["request"]["delete"]:
                                        handler["headers"]["request"]["delete"].append(header_name)

                                # Check if it's a set operation (contains space or :)
                                elif ' ' in rest or ':' in rest:
                                    # Parse "header_up Host 10.10.0.7:5055" or "header_up Host: value"
                                    # First try splitting on space (most common format)
                                    parts = rest.split(None, 1)
                                    if len(parts) == 2:
                                        header_name = parts[0].strip()
                                        header_value = parts[1].strip()
                                        # Remove leading colon if present (e.g., "Host: value" -> "value")
                                        if header_value.startswith(':'):
                                            header_value = header_value[1:].strip()
                                    elif ':' in rest:
                                        # Fallback: split on first colon only if no space found
                                        idx = rest.index(':')
                                        header_name = rest[:idx].strip()
                                        header_value = rest[idx+1:].strip()
                                    else:
                                        continue

                                    handler["headers"] = handler.get("headers", {})
                                    handler["headers"]["request"] = handler["headers"].get("request", {})
                                    handler["headers"]["request"]["set"] = handler["headers"]["request"].get("set", {})
                                    handler["headers"]["request"]["set"][header_name] = [header_value]

                            # Handle header_down directives
                            elif line.startswith('header_down '):
                                rest = line[12:].strip()  # Remove 'header_down '

                                # Check if it's a delete operation (starts with -)
                                if rest.startswith('-'):
                                    header_name = rest[1:].strip()
                                    handler["headers"] = handler.get("headers", {})
                                    handler["headers"]["response"] = handler["headers"].get("response", {})
                                    if "delete" not in handler["headers"]["response"]:
                                        handler["headers"]["response"]["delete"] = []
                                    if header_name not in handler["headers"]["response"]["delete"]:
                                        handler["headers"]["response"]["delete"].append(header_name)

                                # Check if it's a set operation
                                elif ':' in rest or ' ' in rest:
                                    if ':' in rest:
                                        parts = rest.split(':', 1)
                                        header_name = parts[0].strip()
                                        header_value = parts[1].strip()
                                    else:
                                        parts = rest.split(None, 1)
                                        if len(parts) == 2:
                                            header_name = parts[0].strip()
                                            header_value = parts[1].strip()
                                        else:
                                            continue

                                    handler["headers"] = handler.get("headers", {})
                                    handler["headers"]["response"] = handler["headers"].get("response", {})
                                    handler["headers"]["response"]["set"] = handler["headers"]["response"].get("set", {})
                                    handler["headers"]["response"]["set"][header_name] = [header_value]

                            # Handle flush_interval directive (for SSE and streaming)
                            elif line.startswith('flush_interval '):
                                flush_value = line[15:].strip()  # Remove 'flush_interval '
                                try:
                                    # Parse the value as integer (supports -1 for immediate flush)
                                    handler["flush_interval"] = int(flush_value)
                                except ValueError:
                                    logger.warning(f"Invalid flush_interval value: {flush_value}")

                # Merge advanced_config settings into handler if it's not a complete handler
                if advanced_config and isinstance(advanced_config, dict) and "handler" not in advanced_config:
                    # advanced_config contains settings (like flush_interval) to merge into the handler
                    handler.update(advanced_config)

                route_base["handle"].append(handler)

            # Add routes for HTTP ports
            for port in http_ports:
                if port not in servers:
                    servers[port] = {"routes": [], "has_tls": False}
                route = {**route_base}  # Copy route
                route["handle"] = [h.copy() if isinstance(h, dict) else h for h in route_base["handle"]]
                add_auth_handler(route, proxy.get("access_groups", []))
                servers[port]["routes"].append(route)

            # Add routes for HTTPS ports
            for port in https_ports:
                if port not in servers:
                    servers[port] = {"routes": [], "has_tls": True}
                route = {**route_base}  # Copy route
                route["handle"] = [h.copy() if isinstance(h, dict) else h for h in route_base["handle"]]
                add_auth_handler(route, proxy.get("access_groups", []))
                servers[port]["routes"].append(route)
                servers[port]["has_tls"] = True
        
        for site in websites:
            if not site.get("enabled", True):
                continue
            domains = site.get("domains", [])

            # Handle legacy format (listen_port + tls)
            if "listen_port" in site and site.get("listen_port") is not None:
                if site.get("tls"):
                    https_ports = [site["listen_port"]]
                    http_ports = []
                else:
                    http_ports = [site["listen_port"]]
                    https_ports = []
            else:
                # New format with http_ports and https_ports
                http_ports = site.get("http_ports", [])
                https_ports = site.get("https_ports", [])

            # Skip if no ports specified
            if not http_ports and not https_ports:
                continue

            # Auto HTTPS redirect setup
            # Track sites that need HTTP->HTTPS redirect
            auto_https_redirect = False
            if site.get("auto_https") and http_ports:
                auto_https_redirect = True
                # Only add default 443 if user didn't specify any HTTPS ports
                if not https_ports:
                    https_ports.append(443)
                # Store redirect mappings for each HTTP port to target HTTPS port
                target_https_port = https_ports[0] if https_ports else 443
                for http_port in http_ports:
                    if domains:
                        for domain in domains:
                            https_redirects[(http_port, domain)] = target_https_port
                    else:
                        # Add wildcard redirect for sites without domains
                        https_redirects[(http_port, "*")] = target_https_port

            # Build route base
            route_base = {"handle": []}
            if domains:
                route_base["match"] = [{"host": domains}]
            if site.get("advanced"):
                route_base["handle"].append(site["advanced"])
            else:
                root_path = site["root"]
                if not os.path.isabs(root_path):
                    root_path = os.path.abspath(root_path)

                # Add PHP handler if enabled for this site
                if site.get("php_enabled") and settings.get("php_enabled") and settings.get("php_path"):
                    # Get the PHP-CGI path
                    php_path = settings["php_path"]
                    if os.path.isdir(php_path):
                        php_path = os.path.join(php_path, get_php_cgi_executable())

                    # Set root variable first
                    route_base["handle"].append({
                        "handler": "vars",
                        "root": root_path
                    })

                    # Get index files - default to index.html, index.htm, index.php for PHP sites
                    index_files = site.get("index_files")
                    if not index_files:  # None or empty list
                        index_files = ["index.html", "index.htm", "index.php"]
                    elif "index.php" not in index_files:
                        index_files = index_files + ["index.php"]

                    # Add PHP subroute with proper FastCGI configuration
                    route_base["handle"].append({
                        "handler": "subroute",
                        "routes": [
                            {
                                "match": [{
                                    "file": {
                                        "try_files": ["{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"],
                                        "split_path": [".php"]
                                    }
                                }],
                                "handle": [{
                                    "handler": "reverse_proxy",
                                    "transport": {
                                        "protocol": "fastcgi",
                                        "split_path": [".php"],
                                        "env": {
                                            "SCRIPT_FILENAME": "{http.vars.root}{http.matchers.file.relative}"
                                        },
                                        "root": root_path
                                    },
                                    "upstreams": [{
                                        "dial": "127.0.0.1:9000"
                                    }]
                                }]
                            },
                            {
                                "handle": [{
                                    "handler": "file_server",
                                    "index_names": index_files
                                }]
                            }
                        ]
                    })
                else:
                    # No PHP - just add regular file_server
                    # Default to index.html, index.htm for non-PHP sites
                    index_files = site.get("index_files")
                    if not index_files:  # None or empty list
                        index_files = ["index.html", "index.htm"]
                    route_base["handle"].append({
                        "handler": "file_server",
                        "root": root_path,
                        "index_names": index_files
                    })

            # Add routes for HTTP ports
            for port in http_ports:
                # Skip adding content to HTTP port if auto_https is enabled for this site
                # The redirect will be added later
                if auto_https_redirect:
                    # Just ensure HTTP port exists in servers, but don't add the content route
                    if port not in servers:
                        servers[port] = {"routes": [], "has_tls": False}
                    continue

                if port not in servers:
                    servers[port] = {"routes": [], "has_tls": False}
                route = {**route_base}  # Copy route
                route["handle"] = [h.copy() if isinstance(h, dict) else h for h in route_base["handle"]]
                add_auth_handler(route, site.get("access_groups", []))
                servers[port]["routes"].append(route)

            # Add routes for HTTPS ports
            for port in https_ports:
                if port not in servers:
                    servers[port] = {"routes": [], "has_tls": True}
                route = {**route_base}  # Copy route
                route["handle"] = [h.copy() if isinstance(h, dict) else h for h in route_base["handle"]]
                add_auth_handler(route, site.get("access_groups", []))
                servers[port]["routes"].append(route)
                servers[port]["has_tls"] = True
        
        if https_redirects:
            # Group by source HTTP port, then by target HTTPS port
            # Structure: {http_port: {https_port: [domains]}}
            port_redirects = {}
            for (http_port, domain), https_port in https_redirects.items():
                if http_port not in port_redirects:
                    port_redirects[http_port] = {}
                if https_port not in port_redirects[http_port]:
                    port_redirects[http_port][https_port] = []
                port_redirects[http_port][https_port].append(domain)

            # Create redirect routes for each HTTP port
            for http_port, redirect_targets in port_redirects.items():
                if http_port not in servers:
                    continue  # Skip if this HTTP port isn't actually in use

                # Collect all domains that need HTTPS redirect on this port
                all_redirect_domains = []
                for target_https_port, domains in redirect_targets.items():
                    all_redirect_domains.extend(domains)

                    # Build the redirect Location header
                    # Use {http.request.host} which strips the port from the Host header
                    if target_https_port == 443:
                        # Standard HTTPS port - omit from URL
                        location = "https://{http.request.host}{http.request.uri}"
                    else:
                        # Non-standard HTTPS port - must specify explicitly
                        location = f"https://{{http.request.host}}:{target_https_port}{{http.request.uri}}"

                    redirect_route = {
                        "handle": [{"handler": "static_response", "headers": {"Location": [location]}, "status_code": 308}],
                        "terminal": True
                    }

                    # Only add host match if we have specific domains (not wildcard)
                    if "*" not in domains:
                        redirect_route["match"] = [{"host": domains}]

                    # Exclude ACME challenge paths from redirect - Let's Encrypt needs HTTP access
                    # Use a compatibility switch: older Caddy versions don't support
                    # the `path_prefix` matcher. By default we use the widely-supported
                    # wildcard `path` matcher. If you explicitly enable
                    # `caddy_use_path_prefix` in settings, we'll emit `path_prefix`.
                    if "match" not in redirect_route:
                        redirect_route["match"] = [{}]
                    use_path_prefix = False
                    try:
                        # `settings` is defined at top of build_caddy_config()
                        use_path_prefix = bool(settings.get("caddy_use_path_prefix", False))
                    except Exception:
                        use_path_prefix = False

                    if use_path_prefix:
                        redirect_route["match"][0]["not"] = [{"path_prefix": ["/.well-known/acme-challenge/"]}]
                    else:
                        redirect_route["match"][0]["not"] = [{"path": ["/.well-known/acme-challenge/*"]}]

                    # Insert at beginning so it matches before other routes
                    servers[http_port]["routes"].insert(0, redirect_route)


        # Add routes to bypass authentication for auth endpoints
        # These must come BEFORE any auth-protected routes
        for port, server_data in servers.items():
            # Ensure ACME challenge requests are handled by Caddy's ACME handler
            # before any reverse_proxy or redirect routes so HTTP-01 can succeed.
            # dint know if this is correct / working.
            acme_bypass_route = {
                "match": [{"path": ["/.well-known/acme-challenge/*"]}],
                "handle": [{"handler": "acme_server"}],
                "terminal": True
            }
            # Insert at beginning so ACME requests are handled first
            server_data["routes"].insert(0, acme_bypass_route)

            # Add permanent IP blocklist route - blocks at Caddy level before any other processing
            blocklist = get_permanent_blocklist()
            if blocklist:
                blocked_ranges = [entry['ip_range'] for entry in blocklist]
                block_route = {
                    "match": [{"remote_ip": {"ranges": blocked_ranges}}],
                    "handle": [{
                        "handler": "static_response",
                        "status_code": 403,
                        "body": "Access denied"
                    }],
                    "terminal": True
                }
                # Insert at position 0 so it's processed FIRST (before ACME)
                server_data["routes"].insert(0, block_route)

            # Bypass for API auth endpoints (manager login, website auth, etc.)
            # Note: auth_allowed_hosts is populated below, so we'll create this route after that
            api_auth_bypass_route_placeholder = True
            # Bypass for auth pages (login, 2FA challenge) - for CaddyMAN admin domain AND protected sites
            # Only include sites that have access_groups configured (CaddyMAN handles their auth)
            # Exclude sites with no access control or sites that handle their own auth (like Audiobookshelf)
            manager_domains = [settings.get("domain_url", "localhost:8000")]
            # Extract just the domain from domain_url (remove http:// and port)
            import re
            manager_domain = re.sub(r'^https?://', '', manager_domains[0]).split(':')[0]

            # Collect all domains that have CaddyMAN access control enabled
            auth_allowed_hosts = [manager_domain]
            with closing(get_db_connection()) as conn:
                cursor = conn.cursor()
                import json

                # Check file_server sites (websites table)
                cursor.execute('SELECT domains, access_groups FROM websites WHERE enabled = 1')
                for row in cursor.fetchall():
                    domains_json = row[0]
                    access_groups_json = row[1]
                    if domains_json and access_groups_json:
                        domains = json.loads(domains_json)
                        access_groups = json.loads(access_groups_json)
                        # Only include if access control is configured
                        if access_groups:  # Not empty list
                            for domain in domains:
                                clean_domain = domain.split(':')[0]
                                if clean_domain not in auth_allowed_hosts:
                                    auth_allowed_hosts.append(clean_domain)

                # Check reverse_proxy sites (reverse_proxies table)
                cursor.execute('SELECT domains, access_groups FROM reverse_proxies WHERE enabled = 1')
                for row in cursor.fetchall():
                    domains_json = row[0]
                    access_groups_json = row[1]
                    if domains_json and access_groups_json:
                        domains = json.loads(domains_json)
                        access_groups = json.loads(access_groups_json)
                        # Only include if access control is configured
                        if access_groups:  # Not empty list
                            for domain in domains:
                                clean_domain = domain.split(':')[0]
                                if clean_domain not in auth_allowed_hosts:
                                    auth_allowed_hosts.append(clean_domain)

            # Create API auth bypass route with host restriction (only for CaddyMAN and protected sites)
            api_auth_bypass_route = {
                "match": [
                    {
                        "host": auth_allowed_hosts,
                        "path": ["/api/auth/*", "/api/website-auth/*"]
                    }
                ],
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": "localhost:8000"}]
                }]
            }

            auth_pages_bypass_route = {
                "match": [
                    {
                        "host": auth_allowed_hosts,
                        "path": ["/auth/*"]
                    }
                ],
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": "localhost:8000"}]
                }]
            }
            # Insert at the beginning so they match before auth-protected routes
            server_data["routes"].insert(0, auth_pages_bypass_route)
            server_data["routes"].insert(0, api_auth_bypass_route)

        # Build base config with automatic HTTPS disabled
        # Note: Admin port is configured via --admin flag when starting Caddy
        config = {
            "apps": {
                "http": {
                    "servers": {}
                }
            }
        }

        # Add logging configuration
        log_level = settings.get("caddy_log_level", "WARN")
        config["logging"] = {
            "logs": {
                "default": {
                    "level": log_level
                }
            }
        }

        for port, server_data in servers.items():
            server_config = {"listen": [f":{port}"], "routes": server_data["routes"]}
            if server_data["has_tls"]:
                server_config["tls_connection_policies"] = [{}]
                # Enable automatic HTTPS for certificate provisioning
                server_config["automatic_https"] = {"disable": False}
            config["apps"]["http"]["servers"][f"srv_{port}"] = server_config
        return config
    except Exception as e:
        logger.error(f"Failed to build config: {e}")
        raise

async def reload_caddy():
    config = build_caddy_config()

    # Debug: Print the complete Caddy config JSON that will be sent to Caddy
    settings = get_settings_from_db()
    debug_enabled = DEBUG_MODE or settings.get("caddy_log_level", "WARN") == "DEBUG"
    if debug_enabled:
        import json
        logger.info("="*80)
        logger.info("CADDY CONFIG JSON (what would be sent to http://localhost:12999/config/):")
        logger.info(json.dumps(config, indent=2))
        logger.info("="*80)

    try:
        admin_url = get_caddy_admin_url()
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{admin_url}/load", json=config)
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Caddy reload failed: {response.text}")
            return {"status": "reloaded"}
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Cannot connect to Caddy")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@atexit.register
def cleanup():
    if caddy_process and caddy_process.returncode is None:
        caddy_process.terminate()



async def periodic_update_check():
    while True:
        await asyncio.sleep(12 * 60 * 60)
        await check_for_updates()

# API Endpoints
@app.get("/favicon.ico")
async def favicon():
    favicon_path = os.path.join(static_dir, "..", "ico.ico")
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path, media_type="image/x-icon")
    # Fallback to bundled if not found in root
    favicon_bundled = resource_path("ico.ico")
    if os.path.exists(favicon_bundled):
        return FileResponse(favicon_bundled, media_type="image/x-icon")
    # Return 204 No Content instead of 404 to avoid console errors
    return Response(status_code=204)

@app.get("/robots.txt")
async def robots_txt():
    """Serve robots.txt - tell search engines not to index CaddyMAN admin panel"""
    robots_content = """User-agent: *
Disallow: /
"""
    return Response(content=robots_content, media_type="text/plain")

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint - behavior depends on admin_path_mode setting"""
    settings = get_settings_from_db()

    # If admin_path_mode is enabled, redirect to user portal login
    if settings.get('admin_path_mode', False):
        return RedirectResponse(url="/user-portal")

    # Default behavior: serve admin interface
    index_path = os.path.join(static_dir, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
        html_content = html_content.replace('""" + VERSION + """', VERSION)
    return HTMLResponse(content=html_content)

@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    """Admin interface endpoint - serves admin UI when admin_path_mode is enabled"""
    settings = get_settings_from_db()

    # Only serve admin interface if admin_path_mode is enabled
    # Otherwise, this route is not used (admin is at root)
    if not settings.get('admin_path_mode', False):
        # If admin_path_mode is disabled, / serves the admin interface
        raise HTTPException(status_code=404, detail="Not found")

    # Serve admin interface
    index_path = os.path.join(static_dir, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
        html_content = html_content.replace('""" + VERSION + """', VERSION)
    return HTMLResponse(content=html_content)

@app.get("/login", response_class=HTMLResponse)
async def login_page(return_to: Optional[str] = None, session_id: Optional[str] = Cookie(None)):
    """OAuth/OIDC login page with optional return URL"""
    # Security: Validate return_to URL to prevent open redirect attacks
    if return_to and not validate_return_url(return_to):
        logger.warning(f"[Security] Invalid return_to URL rejected: {return_to}")
        return_to = None  # Reset to safe default

    # Check if user is already logged in
    if session_id and session_id in sessions:
        # User is already authenticated, redirect them
        if return_to:
            return RedirectResponse(url=return_to)
        else:
            return RedirectResponse(url="/user-portal")

    # Not logged in, show login page
    oauth_login_path = os.path.join(static_dir, "oauth_login.html")
    with open(oauth_login_path, "r", encoding="utf-8") as f:
        html_content = f.read()

        # If return_to is provided, inject it into the page so the frontend can use it after login
        if return_to:
            # Add a script tag to store the return URL
            return_to_script = f'<script>sessionStorage.setItem("returnTo", {json.dumps(return_to)});</script>'
            html_content = html_content.replace('</head>', f'{return_to_script}</head>')

    return HTMLResponse(content=html_content)


@app.post("/api/login")
async def oauth_login(login_data: LoginRequest, request: Request, response: Response):
    """Generic login endpoint for OAuth/OIDC - allows all users"""
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Check if IP is in permanent blocklist (CIDR ranges)
    permanent_block = is_ip_in_permanent_blocklist(client_ip)
    if permanent_block:
        logger.warning(f"Login attempt from permanently blocked IP {client_ip} (blocklist: {permanent_block['ip_range']})")
        raise HTTPException(status_code=403, detail="Access permanently blocked.")

    # Check if IP is locked out
    if is_account_locked(client_ip):
        await log_activity(login_data.username, "LOGIN_BLOCKED", "IP locked out due to too many failed attempts", client_ip)
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Try again in {LOCKOUT_DURATION // 60} minutes.")

    # Get user from database
    user = get_user_by_username_from_db(login_data.username)

    if not user or not verify_password(login_data.password, user["password_hash"]):
        await log_activity(login_data.username, "LOGIN_FAILED", "Invalid credentials", client_ip)

        # Track failed login attempts
        current_time = time.time()
        if client_ip not in failed_login_attempts:
            failed_login_attempts[client_ip] = []

        failed_login_attempts[client_ip] = [
            t for t in failed_login_attempts[client_ip] if current_time - t < LOCKOUT_DURATION
        ]
        failed_login_attempts[client_ip].append(current_time)

        attempt_count = len(failed_login_attempts[client_ip])
        remaining_attempts = MAX_LOGIN_ATTEMPTS - attempt_count

        if remaining_attempts <= 0:
            raise HTTPException(status_code=429, detail=f"Account locked. Try again in {LOCKOUT_DURATION // 60} minutes.")

        raise HTTPException(status_code=401, detail=f"Invalid credentials. {remaining_attempts} attempts remaining.")

    # Check if user is required to have 2FA but hasn't set it up
    if user_requires_2fa(user) and not user.get("totp_enabled", False):
        await log_activity(user["username"], "LOGIN_BLOCKED", "2FA required but not configured", client_ip)
        raise HTTPException(
            status_code=403,
            detail="Your account requires 2FA to be enabled. Please visit the user portal to set up 2FA."
        )

    # Check 2FA if enabled for this user AND enhanced security is enabled
    settings = get_settings_from_db()
    if settings.get("enhanced_security", False) and user.get("totp_enabled", False):
        # Accept either totp_token or two_factor_token (user portal uses the latter)
        token = login_data.totp_token or login_data.two_factor_token

        if not token:
            # User has 2FA enabled but didn't provide token - return requires_2fa response
            return {
                "requires_2fa": True,
                "message": "Please enter your 2FA code"
            }

        if not verify_totp(user.get("totp_secret", ""), token):
            await log_activity(user["username"], "LOGIN_FAILED", "Invalid 2FA token", client_ip)
            raise HTTPException(status_code=401, detail="Invalid 2FA token")

    # Successful login - clear failed attempts for this IP
    if client_ip in failed_login_attempts:
        del failed_login_attempts[client_ip]

    session_id, csrf_token = create_session(user["id"])
    # Set secure cookie with SameSite=Lax (allows cookie on redirects)
    # Only set secure=True for non-local access (external/public IPs should use HTTPS)
    cookie_domain = get_cookie_domain()  # Get domain for SSO across subdomains
    response.set_cookie(
        "session_id",
        session_id,
        domain=cookie_domain,  # Enable SSO across subdomains (e.g., .jvr.nz)
        httponly=True,
        secure=not is_local_request(request),  # True for external access, False for local
        max_age=3*24*60*60,
        samesite="lax"
    )

    await log_activity(user["username"], "LOGIN_SUCCESS", "OAuth/OIDC login successful", client_ip)

    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "groups": user.get("groups", [])
        },
        "csrf_token": csrf_token
    }


@app.post("/api/auth/login")
async def admin_login(login_data: LoginRequest, request: Request, response: Response):
    """Admin panel login endpoint - admin users only"""
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Check if IP is in permanent blocklist (CIDR ranges)
    permanent_block = is_ip_in_permanent_blocklist(client_ip)
    if permanent_block:
        logger.warning(f"Admin login attempt from permanently blocked IP {client_ip} (blocklist: {permanent_block['ip_range']})")
        raise HTTPException(status_code=403, detail="Access permanently blocked.")

    # Check if IP is locked out
    if is_account_locked(client_ip):
        await log_activity(login_data.username, "LOGIN_BLOCKED", "IP locked out due to too many failed attempts", client_ip)
        await send_event_notification("account_lockout", "Account Locked Out",
            f"IP address locked out due to too many failed login attempts.",
            username=login_data.username, ip_address=client_ip, lockout_duration=f"{LOCKOUT_DURATION // 60} minutes")
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Try again in {LOCKOUT_DURATION // 60} minutes.")

    # Get user from database
    user = get_user_by_username_from_db(login_data.username)

    if not user or not verify_password(login_data.password, user["password_hash"]):
        await log_activity(login_data.username, "LOGIN_FAILED", "Invalid credentials", client_ip)

        # Track failed login attempts
        current_time = time.time()
        if client_ip not in failed_login_attempts:
            failed_login_attempts[client_ip] = []

        # Add current attempt and remove attempts older than lockout duration
        failed_login_attempts[client_ip] = [
            t for t in failed_login_attempts[client_ip] if current_time - t < LOCKOUT_DURATION
        ]
        failed_login_attempts[client_ip].append(current_time)

        attempt_count = len(failed_login_attempts[client_ip])
        remaining_attempts = MAX_LOGIN_ATTEMPTS - attempt_count

        # Send notification on first failed attempt or every 3rd attempt
        if attempt_count == 1 or attempt_count % 3 == 0:
            import socket
            hostname = socket.gethostname()

            await send_event_notification("failed_login", "Failed Login Attempt",
                f"Unsuccessful login detected.",
                username=login_data.username, ip_address=client_ip, server=hostname,
                failed_attempts=f"{attempt_count}/{MAX_LOGIN_ATTEMPTS}")

        if remaining_attempts <= 0:
            raise HTTPException(status_code=429, detail=f"Account locked. Try again in {LOCKOUT_DURATION // 60} minutes.")

        raise HTTPException(status_code=401, detail=f"Invalid credentials. {remaining_attempts} attempts remaining.")

    # Check if user is an admin - only admins can access the admin panel
    if 'admin_group' not in user.get('groups', []):
        await log_activity(user["username"], "LOGIN_DENIED", "Non-admin user attempted to access admin panel", client_ip)
        raise HTTPException(status_code=403, detail="Access denied. Admin privileges required.")

    # Check if user is required to have 2FA but hasn't set it up
    if user_requires_2fa(user) and not user.get("totp_enabled", False):
        await log_activity(user["username"], "LOGIN_BLOCKED", "2FA required but not configured", client_ip)
        raise HTTPException(
            status_code=403,
            detail="Your account requires 2FA to be enabled. Please visit the user portal to set up 2FA."
        )

    # Check 2FA if enabled for this user AND enhanced security is enabled
    settings = get_settings_from_db()
    if settings.get("enhanced_security", False) and user.get("totp_enabled", False):
        if not login_data.totp_token:
            # User has 2FA enabled but didn't provide token
            raise HTTPException(status_code=403, detail="2FA token required")

        if not verify_totp(user.get("totp_secret", ""), login_data.totp_token):
            await log_activity(user["username"], "LOGIN_FAILED", "Invalid 2FA token", client_ip)
            raise HTTPException(status_code=401, detail="Invalid 2FA token")

    # Successful login - clear failed attempts for this IP
    if client_ip in failed_login_attempts:
        del failed_login_attempts[client_ip]

    session_id, csrf_token = create_session(user["id"])
    # Set secure cookie with SameSite protection
    # Only set secure=True for non-local access (external/public IPs should use HTTPS)
    cookie_domain = get_cookie_domain()  # Get domain for SSO across subdomains
    response.set_cookie(
        "session_id",
        session_id,
        domain=cookie_domain,  # Enable SSO across subdomains (e.g., .jvr.nz)
        httponly=True,
        secure=not is_local_request(request),  # True for external access, False for local
        max_age=3*24*60*60,
        samesite="strict"
    )

    await log_activity(user["username"], "LOGIN_SUCCESS", "User logged in", client_ip)

    # Send notification for admin login if user is in admin group
    if "admin_group" in user.get("groups", []):
        import socket
        hostname = socket.gethostname()
        await send_event_notification("admin_login", "Admin Login",
            f"Administrator logged into CaddyMAN.",
            username=user["username"], ip_address=client_ip, server=hostname)

    # Check if user needs to change default password
    needs_password_change = user.get("force_password_change", False)

    return {
        "status": "success",
        "user": {"id": user["id"], "username": user["username"], "groups": user["groups"]},
        "csrf_token": csrf_token,
        "needs_password_change": needs_password_change
    }   

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response, session_id: Optional[str] = Cookie(None)):
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    
    user = get_session_user(session_id)
    if user:
        await log_activity(user.get("username", "unknown"), "LOGOUT", "User logged out", client_ip)
    
    if session_id and session_id in sessions:
        del sessions[session_id]
    response.delete_cookie("session_id")
    return {"status": "logged_out"}

@app.get("/api/auth/me")
async def get_current_user(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"id": user["id"], "username": user["username"], "groups": user["groups"]}

@app.get("/api/system/network-info")
async def get_network_info():
    """Get server network addresses for LDAP/RADIUS client configuration"""
    import socket
    addresses = []

    try:
        # Get hostname
        hostname = socket.gethostname()

        # Get all IP addresses associated with this host
        host_info = socket.getaddrinfo(hostname, None)

        # Extract unique IPv4 addresses using proper IP validation
        seen = set()
        for info in host_info:
            try:
                import ipaddress
                ip = info[4][0]
                addr = ipaddress.ip_address(ip)

                # Only include non-localhost IPv4 addresses
                if addr.version == 4 and not addr.is_loopback and ip not in seen:
                    addresses.append(ip)
                    seen.add(ip)

            except (ValueError, IndexError, TypeError):
                # ValueError: invalid IP
                # IndexError: missing info[4] or info[4][0]
                # TypeError: info[4] isn't subscriptable
                continue

        # If no addresses found, try to get local IP by connecting to external host
        if not addresses:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Connect to Google DNS (doesn't actually send data)
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
                if local_ip and not local_ip.startswith('127.'):
                    addresses.append(local_ip)
            finally:
                s.close()

    except Exception as e:
        logger.error(f"Failed to get network info: {e}")

    # Always include localhost as fallback
    if not addresses:
        addresses.append('localhost')

    return {"addresses": addresses}

@app.get("/api/auth/verify")
@app.post("/api/auth/verify")
async def verify_auth(request: Request, session_id: Optional[str] = Cookie(None)):
    """
    Forward auth endpoint for Caddy to verify website authentication
    SSO: Uses session_id (CaddyMAN main session) for unified single sign-on
    v1.3.17+: Legacy website_session cookie support removed
    """
    # Security: Rate limiting and brute force protection
    client_ip = request.client.host if request.client else "unknown"
    current_time = time.time()

    # Check if IP is in permanent blocklist (CIDR ranges) - Caddy + App level block
    permanent_block = is_ip_in_permanent_blocklist(client_ip)
    if permanent_block:
        logger.warning(f"IP {client_ip} blocked by permanent blocklist entry: {permanent_block['ip_range']}")
        raise HTTPException(status_code=403, detail="Access permanently blocked.")

    # Track this attempt
    if client_ip not in auth_verify_attempts:
        auth_verify_attempts[client_ip] = []

    # Clean old attempts outside the time window
    auth_verify_attempts[client_ip] = [
        ts for ts in auth_verify_attempts[client_ip]
        if current_time - ts < AUTH_VERIFY_WINDOW
    ]

    # Add current attempt
    auth_verify_attempts[client_ip].append(current_time)

    # Check if exceeded rate limit - instant permanent ban
    if len(auth_verify_attempts[client_ip]) > MAX_AUTH_VERIFY_ATTEMPTS:
        is_external = is_external_ip(client_ip)
        reason = f"Rapid brute force: {len(auth_verify_attempts[client_ip])} auth attempts in {AUTH_VERIFY_WINDOW}s"
        ip_data = permanently_block_ip(client_ip, reason, is_external)

        # Clear attempts since we've blocked them
        auth_verify_attempts[client_ip] = []

        if not ip_data.get('already_blocked'):
            logger.critical(f"PERMANENT BLOCK - RAPID BRUTE FORCE: {client_ip} made {MAX_AUTH_VERIFY_ATTEMPTS}+ attempts in {AUTH_VERIFY_WINDOW}s")

            # Broadcast blocked IP event via SSE
            await broadcast_sse_event('ip_permanently_blocked', {
                'ip_address': client_ip,
                'reason': reason,
                'is_external': is_external
            })

            # Contextual message based on whether this is external or internal
            if is_external:
                context_msg = (
                    "If you're hosting public websites, brute force attempts are normal.\n"
                    "CaddyMAN automatically blocks attackers permanently."
                )
            else:
                context_msg = "This may indicate a compromised device on your local network."

            await send_event_notification(
                "suspicious_activity",
                "IP Permanently Blocked - Brute Force" if is_external else "Suspicious Activity - IP Blocked",
                f"IP permanently blocked for rapid brute force attack!\n\n"
                f"Source IP: {client_ip}\n"
                f"IP Type: {'EXTERNAL (Internet)' if is_external else 'Internal/Private'}\n"
                f"Attempts: {MAX_AUTH_VERIFY_ATTEMPTS}+ in {AUTH_VERIFY_WINDOW} seconds\n"
                f"Endpoint: /api/auth/verify\n"
                f"Block Type: PERMANENT (Caddy + App level)\n\n"
                f"{context_msg}",
                source_ip=client_ip,
                attempts=MAX_AUTH_VERIFY_ATTEMPTS,
                is_external=is_external
            )

            # Reload Caddy to apply permanent block
            if ip_data.get('_needs_caddy_reload'):
                try:
                    await reload_caddy()
                    logger.info(f"Caddy reloaded to apply permanent block for {client_ip}")
                except Exception as e:
                    logger.error(f"Failed to reload Caddy: {e}")

        raise HTTPException(status_code=403, detail="Access permanently blocked.")

    session = None
    session_source = None

    # Check for main CaddyMAN session (SSO)
    if session_id:
        main_session = sessions.get(session_id)
        if main_session:
            # Check if session is expired
            if main_session["expires_at"] < time.time():
                del sessions[session_id]
            else:
                # Convert main session to format expected by this endpoint
                user = get_user_by_id_from_db(main_session["user_id"])
                if user:
                    session = {
                        "user_id": user["id"],
                        "username": user["username"],
                        "groups": user.get("groups", []),
                        "expires": main_session["expires_at"]
                    }
                    session_source = "session_id"

    # Get required groups from request headers
    required_groups_str = request.headers.get("X-Required-Groups", "")
    required_groups = [g.strip() for g in required_groups_str.split(",") if g.strip()]

    # If not authenticated, redirect to login page
    if not session:
        # SLOW BRUTE FORCE DETECTION - DISABLED
        # Commented out to avoid blocking legitimate monitoring tools (e.g., Uptime Kuma)
        # TODO: Re-enable when custom monitoring with authentication handshake is implemented
        #
        # # Track this 401 for slow brute force detection
        # global auth_verify_401_attempts
        # if client_ip not in auth_verify_401_attempts:
        #     auth_verify_401_attempts[client_ip] = []
        #
        # # Clean old 401 attempts outside the long window
        # auth_verify_401_attempts[client_ip] = [
        #     ts for ts in auth_verify_401_attempts[client_ip]
        #     if current_time - ts < SLOW_BRUTE_FORCE_WINDOW
        # ]
        #
        # # Add current 401
        # auth_verify_401_attempts[client_ip].append(current_time)
        #
        # # Check if exceeded slow brute force threshold - instant permanent ban
        # if len(auth_verify_401_attempts[client_ip]) >= SLOW_BRUTE_FORCE_MAX_401S:
        #     is_external = is_external_ip(client_ip)
        #     reason = f"Slow brute force: {len(auth_verify_401_attempts[client_ip])} 401 errors in {SLOW_BRUTE_FORCE_WINDOW//3600} hours"
        #     ip_data = permanently_block_ip(client_ip, reason, is_external)
        #
        #     # Clear the 401 attempts since we've blocked them
        #     auth_verify_401_attempts[client_ip] = []
        #
        #     if not ip_data.get('already_blocked'):
        #         logger.critical(f"PERMANENT BLOCK - SLOW BRUTE FORCE: {client_ip} made {SLOW_BRUTE_FORCE_MAX_401S}+ 401 requests in {SLOW_BRUTE_FORCE_WINDOW//3600} hours")
        #
        #         # Broadcast blocked IP event via SSE
        #         await broadcast_sse_event('ip_permanently_blocked', {
        #             'ip_address': client_ip,
        #             'reason': reason,
        #             'is_external': is_external
        #         })
        #
        #         await send_event_notification(
        #             "suspicious_activity",
        #             "IP Permanently Blocked - Slow Brute Force",
        #             f"IP permanently blocked for slow brute force attack!\n\n"
        #             f"Source IP: {client_ip}\n"
        #             f"IP Type: {'EXTERNAL (Internet)' if is_external else 'Internal/Private'}\n"
        #             f"401 Errors: {SLOW_BRUTE_FORCE_MAX_401S}+ in {SLOW_BRUTE_FORCE_WINDOW//3600} hours\n"
        #             f"Endpoint: /api/auth/verify\n"
        #             f"Block Type: PERMANENT (Caddy + App level)\n\n"
        #             f"This IP was making slow, persistent requests to evade rapid rate limiting.",
        #             source_ip=client_ip,
        #             attempts=SLOW_BRUTE_FORCE_MAX_401S,
        #             is_external=is_external
        #         )
        #
        #         # Reload Caddy to apply permanent block
        #         if ip_data.get('_needs_caddy_reload'):
        #             try:
        #                 await reload_caddy()
        #                 logger.info(f"Caddy reloaded to apply permanent block for {client_ip} (slow brute force)")
        #             except Exception as e:
        #                 logger.error(f"Failed to reload Caddy: {e}")
        #
        #     raise HTTPException(status_code=403, detail="Access permanently blocked.")

        # Get the original URL from headers (set by Caddy forward_auth) or from request
        original_url = request.headers.get("X-Original-URI", request.headers.get("X-Forwarded-Uri", "/"))

        # If we only got the path, check for query string in separate header
        if "?" not in original_url:
            query = request.headers.get("X-Forwarded-Query", "")
            if query:
                original_url += "?" + query

        # Return redirect to login page with original URL
        redirect_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0; url=/auth/login?redirect={original_url}">
    <title>Redirecting to Login...</title>
</head>
<body>
    <p>Redirecting to login page...</p>
    <script>
        window.location.href = '/auth/login?redirect=' + encodeURIComponent('{original_url}');
    </script>
</body>
</html>
        """
        return HTMLResponse(content=redirect_html, status_code=401)

    # Check if user has required groups
    if required_groups:
        user_groups = set(session.get("groups", []))
        if not user_groups.intersection(required_groups):
            raise HTTPException(status_code=403, detail="Access denied - insufficient permissions")

    # Log SSO source for debugging
    logger.info(f"Auth verify successful for {session['username']} using {session_source}")

    # Return success with user info in headers for Caddy to forward
    return Response(
        status_code=200,
        headers={
            "X-User-ID": session["user_id"],
            "X-Username": session["username"],
            "X-User-Groups": ",".join(session.get("groups", [])),
            "X-Auth-Source": session_source  # Indicate which session type was used
        }
    )

@app.get("/api/users")
async def get_users(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Get users from database
    users = get_all_users_from_db()
    return [{"id": u["id"], "username": u["username"], "groups": u["groups"], "email": u.get("email", ""), "totp_enabled": u.get("totp_enabled", False)} for u in users]

@app.post("/api/users")
async def create_user(user_create: UserCreate, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Always require minimum password length
    if not user_create.password or len(user_create.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters long")

    # Check password strength if enhanced security is enabled
    settings = get_settings_from_db()
    if settings.get("enhanced_security", False):
        is_valid, error_msg = validate_password_strength(user_create.password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)

        # Check against Have I Been Pwned
        if await check_password_pwned(user_create.password):
            raise HTTPException(
                status_code=400,
                detail="This password has been found in data breaches and cannot be used. Please choose a different password."
            )

    async with config_lock:
        # Check if username exists
        if get_user_by_username_from_db(user_create.username):
            raise HTTPException(status_code=400, detail="Username already exists")
        new_user = {
            "id": str(uuid.uuid4()),
            "username": user_create.username,
            "password_hash": hash_password(user_create.password),
            "groups": user_create.groups,
            "email": user_create.email or "",
            "totp_secret": None,
            "totp_enabled": False
        }
        save_user_to_db(new_user)
        # Convert group IDs to group names for notification
        all_groups = get_all_groups_from_db()
        group_names = [g['name'] for g in all_groups if g['id'] in new_user["groups"]]
        await send_event_notification("user_created", "User Created",
            f"New user account created.", username=new_user["username"], groups=", ".join(group_names),
            created_by=user.get("username", "admin"))
    return {"id": new_user["id"], "username": new_user["username"], "groups": new_user["groups"]}


@app.put("/api/users/{user_id}")
async def update_user(user_id: str, user_update: UserCreate, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Check password strength if enhanced security is enabled and password is being updated
    settings = get_settings_from_db()
    if user_update.password and settings.get("enhanced_security", False):
        is_valid, error_msg = validate_password_strength(user_update.password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)

        # Check against Have I Been Pwned
        if await check_password_pwned(user_update.password):
            raise HTTPException(
                status_code=400,
                detail="This password has been found in data breaches and cannot be used. Please choose a different password."
            )

    async with config_lock:
        existing_user = get_user_by_id_from_db(user_id)
        if not existing_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if trying to remove admin_group from the last admin
        was_admin = "admin_group" in existing_user.get("groups", [])
        will_be_admin = "admin_group" in user_update.groups

        if was_admin and not will_be_admin:
            admin_count = sum(1 for u in get_all_users_from_db() if "admin_group" in u.get("groups", []))
            if admin_count <= 1:
                raise HTTPException(
                    status_code=403,
                    detail="Cannot remove admin group from the last admin user. Add another admin first."
                )

        # Check username conflict only if username changed
        if existing_user["username"] != user_update.username:
            if get_user_by_username_from_db(user_update.username):
                raise HTTPException(status_code=400, detail="Username already exists")

        # Only update password if provided
        updated_user = {
            "id": user_id,
            "username": user_update.username,
            "password_hash": hash_password(user_update.password) if user_update.password else existing_user["password_hash"],
            "groups": user_update.groups,
            "email": user_update.email or "",
            "totp_secret": existing_user.get("totp_secret"),
            "totp_enabled": existing_user.get("totp_enabled", False)
        }
        save_user_to_db(updated_user)
    return {"id": updated_user["id"], "username": updated_user["username"], "groups": updated_user["groups"], "email": updated_user.get("email", "")}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Check if this is the last admin user
    target_user = get_user_by_id_from_db(user_id)

    if target_user and "admin_group" in target_user.get("groups", []):
        admin_count = sum(1 for u in get_all_users_from_db() if "admin_group" in u.get("groups", []))
        if admin_count <= 1:
            raise HTTPException(
                status_code=403,
                detail="Cannot delete the last admin user. Add another admin first."
            )

    async with config_lock:
        deleted_username = target_user.get("username", "unknown") if target_user else "unknown"
        delete_user_from_db(user_id)
        await send_event_notification("user_deleted", "User Deleted",
            f"User account has been deleted.", username=deleted_username,
            deleted_by=user.get("username", "admin"))
    return {"status": "deleted"}

@app.post("/api/users/{user_id}/send-invite")
async def api_send_user_invite(
    user_id: str,
    request: Request,
    session_id: Optional[str] = Cookie(None)
):
    """Send invitation email to user"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    success = await send_user_invite(user_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to send invite. Check SMTP settings and user email.")

    return {"status": "sent"}

@app.post("/api/users/{user_id}/send-password-reset")
async def api_send_password_reset(
    user_id: str,
    request: Request,
    session_id: Optional[str] = Cookie(None)
):
    """Send password reset email to user"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    success = await send_password_reset(user_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to send password reset. Check SMTP settings and user email.")

    return {"status": "sent"}

class InviteLinkRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    groups: List[str] = Field(default_factory=list, max_items=20)
    expiry_hours: int = Field(24, ge=1, le=720)  # Min 1 hour, max 30 days

@app.get("/api/users/pending-invites")
async def get_pending_invites(session_id: Optional[str] = Cookie(None)):
    """Get all pending (non-expired) invite tokens"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Only admins can see pending invites
    if 'admin_group' not in user.get('groups', []):
        raise HTTPException(status_code=403, detail="Only administrators can view pending invites")

    all_invites = get_all_invite_tokens_from_db()
    current_time = datetime.now().timestamp()

    # Filter only non-expired invites and add time remaining
    pending_invites = []
    for invite in all_invites:
        if invite['expires_at'] > current_time:
            time_remaining = invite['expires_at'] - current_time
            hours_remaining = int(time_remaining / 3600)
            minutes_remaining = int((time_remaining % 3600) / 60)

            pending_invites.append({
                'token': invite['token'],
                'username': invite['username'],
                'email': invite['email'],
                'groups': invite['groups'],
                'expires_at': invite['expires_at'],
                'created_by': invite['created_by'],
                'created_at': invite['created_at'],
                'time_remaining': f"{hours_remaining}h {minutes_remaining}m"
            })
        else:
            # Auto-delete expired invites
            delete_invite_token_from_db(invite['token'])

    return pending_invites

@app.post("/api/users/invite-link")
async def generate_invite_link(
    invite_data: InviteLinkRequest,
    request: Request,
    session_id: Optional[str] = Cookie(None)
):
    """
    Generate an invite link for a new user
    Security: Requires authentication, CSRF protection, input validation, rate limiting
    """
    # Authentication check
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # CSRF protection
    require_csrf(request, session_id)

    # Security: Only admins can generate invite links
    if 'admin_group' not in user.get('groups', []):
        logger.warning(f"Non-admin user {user.get('username')} attempted to generate invite link")
        raise HTTPException(status_code=403, detail="Only administrators can generate invite links")

    # Input validation - username
    if not invite_data.username or len(invite_data.username) < 1 or len(invite_data.username) > 50:
        logger.warning(f"Invalid invite link username length: '{invite_data.username}' (len={len(invite_data.username) if invite_data.username else 0}) from {user.get('username')}")
        raise HTTPException(status_code=400, detail="Username must be between 1 and 50 characters")

    if not re.match(r'^[a-zA-Z0-9_-]+$', invite_data.username):
        logger.warning(f"Invalid invite link username characters: '{invite_data.username}' from {user.get('username')}")
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, hyphens, and underscores")

    # Security: Prevent creating admin users via invite links
    if 'admin_group' in invite_data.groups:
        logger.warning(f"User {user.get('username')} attempted to create admin via invite link")
        raise HTTPException(status_code=403, detail="Cannot create admin users via invite links. Use the admin panel instead.")

    # Check if username already exists
    if get_user_by_username_from_db(invite_data.username):
        raise HTTPException(status_code=400, detail="Username already exists")

    # Delete any existing pending invites for this username (replace old with new)
    all_invites = get_all_invite_tokens_from_db()
    current_time = datetime.now().timestamp()
    for existing_invite in all_invites:
        if existing_invite['username'] == invite_data.username and existing_invite['expires_at'] > current_time:
            delete_invite_token_from_db(existing_invite['token'])
            logger.info(f"Replaced existing invite for username '{invite_data.username}' with new invite by {user.get('username')}")

    # Validate groups exist
    all_groups = get_all_groups_from_db()
    valid_group_ids = {g['id'] for g in all_groups}
    for group_id in invite_data.groups:
        if group_id not in valid_group_ids:
            raise HTTPException(status_code=400, detail=f"Invalid group: {group_id}")

    # Check if SMTP is configured
    settings = get_settings_from_db()
    if not settings.get('smtp_enabled'):
        raise HTTPException(status_code=400, detail="SMTP is not configured. Cannot send invite emails.")

    # Generate cryptographically secure token
    token = secrets.token_urlsafe(32)
    expiry = datetime.now().timestamp() + (invite_data.expiry_hours * 3600)

    # Store invite token in database
    invite_record = {
        'token': token,
        'username': invite_data.username,
        'email': invite_data.email,
        'groups': invite_data.groups,
        'expires_at': expiry,
        'created_by': user.get('username', 'admin'),
        'created_at': datetime.now().timestamp()
    }
    save_invite_token_to_db(invite_record)

    # Broadcast new invite via SSE
    await broadcast_sse_event('invite_created', {
        'username': invite_data.username,
        'email': invite_data.email,
        'expires_at': expiry,
        'created_by': user.get('username', 'admin')
    })

    # Build invite URL using domain_url setting
    domain_url = settings.get('domain_url', f"http://localhost:{settings.get('manager_port', 8000)}")
    # Remove trailing slash if present
    domain_url = domain_url.rstrip('/')
    invite_url = f"{domain_url}/user-portal?token={token}"

    # Send email
    try:
        await send_invite_email(invite_data.email, invite_data.username, invite_url, invite_data.expiry_hours)
    except Exception as e:
        logger.error(f"Failed to send invite email: {e}")
        # Don't fail the request - admin can copy the link manually
        pass

    return {
        "status": "success",
        "invite_url": invite_url,
        "expires_in_hours": invite_data.expiry_hours
    }

# User Portal Endpoints

@app.get("/user-portal", response_class=HTMLResponse)
@app.get("/user-portal/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
async def user_portal_root():
    """Serve the user portal HTML (also accessible via /login for convenience)"""
    portal_path = os.path.join(static_dir, "user-portal-index.html")
    with open(portal_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/user-portal/style.css")
async def user_portal_css():
    """Serve user portal CSS"""
    css_path = os.path.join(static_dir, "user-portal-style.css")
    with open(css_path, "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="text/css")

@app.get("/user-portal/script.js")
async def user_portal_js():
    """Serve user portal JavaScript"""
    js_path = os.path.join(static_dir, "user-portal-script.js")
    with open(js_path, "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="application/javascript")

@app.get("/api/user")
async def get_user_info(session_id: Optional[str] = Cookie(None)):
    """Get current user information for user portal"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Get full user details from database
    full_user = get_user_by_id_from_db(user["id"])
    if not full_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Convert group IDs to group names
    group_ids = full_user.get("groups", [])
    group_names = []
    for group_id in group_ids:
        group = get_group_by_id_from_db(group_id)
        if group:
            group_names.append(group.get("name", group_id))
        else:
            group_names.append(group_id)

    return {
        "id": full_user["id"],
        "username": full_user["username"],
        "email": full_user.get("email", ""),
        "groups": group_names,
        "totp_enabled": full_user.get("totp_enabled", False)
    }

@app.get("/api/user-portal/branding")
async def get_user_portal_branding():
    """Get public branding information for user portal (no authentication required)"""
    settings = get_settings_from_db()
    return {
        "organization_name": settings.get("organization_name", "CaddyMAN")
    }

@app.get("/api/user-portal/settings")
async def get_user_portal_settings():
    """Get public settings for user portal (no authentication required)"""
    settings = get_settings_from_db()
    return {
        "enhanced_security": settings.get("enhanced_security", False),
        "organization_name": settings.get("organization_name", "CaddyMAN")
    }

@app.get("/api/user-portal/invite/{token}")
async def verify_invite_token(token: str):
    """Verify an invite token and return user details for setup page"""
    if not token or len(token) < 10:
        raise HTTPException(status_code=400, detail="Invalid token")

    invite = get_invite_token_from_db(token)
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found")

    # Check if token has expired
    if datetime.now().timestamp() > invite['expires_at']:
        delete_invite_token_from_db(token)
        raise HTTPException(status_code=410, detail="Invite link has expired")

    # Return invite details (but not the token itself)
    return {
        "username": invite['username'],
        "email": invite['email'],
        "groups": invite['groups']
    }

class SetupAccountRequest(BaseModel):
    token: str
    password: str = Field(..., min_length=4)

@app.post("/api/user-portal/setup")
async def setup_account(setup_data: SetupAccountRequest, request: Request):
    """Complete account setup from invite link"""
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Get invite token
    invite = get_invite_token_from_db(setup_data.token)
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found")

    # Check if token has expired
    if datetime.now().timestamp() > invite['expires_at']:
        delete_invite_token_from_db(setup_data.token)
        raise HTTPException(status_code=410, detail="Invite link has expired")

    # Check if user already exists
    if get_user_by_username_from_db(invite['username']):
        raise HTTPException(status_code=400, detail="User already exists")

    # Validate password with Enhanced Security Mode check
    settings = get_settings_from_db()
    if settings.get("enhanced_security", False):
        is_valid, error_msg = validate_password_strength(setup_data.password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
    else:
        if len(setup_data.password) < 4:
            raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    # Create the user
    new_user = {
        "id": str(uuid.uuid4()),
        "username": invite['username'],
        "password_hash": hash_password(setup_data.password),
        "groups": invite['groups'],
        "email": invite['email'],
        "totp_secret": None,
        "totp_enabled": False
    }
    save_user_to_db(new_user)

    # Delete the consumed invite token
    delete_invite_token_from_db(setup_data.token)

    # Check if user needs to enable 2FA due to group requirements
    requires_2fa = user_requires_2fa(new_user)

    # Log activity
    await log_activity(invite['username'], "ACCOUNT_SETUP", f"Account activated via invite link", client_ip)
    await send_event_notification("user_created", "New User Account Created",
        f"User '{invite['username']}' completed account setup via invite link.",
        username=invite['username'], client_ip=client_ip)

    logger.info(f"User {invite['username']} completed account setup via invite link")

    return {
        "status": "success",
        "message": "Account activated successfully",
        "requires_2fa": requires_2fa
    }

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=4)

@app.post("/api/user-portal/change-password")
async def change_password(password_data: ChangePasswordRequest, request: Request, session_id: Optional[str] = Cookie(None)):
    """Allow user to change their own password"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Verify current password
    if not verify_password(password_data.current_password, user.get('password_hash', '')):
        await log_activity(user.get('username'), "PASSWORD_CHANGE_FAILED", "Incorrect current password", client_ip)
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Validate new password with Enhanced Security Mode check
    settings = get_settings_from_db()
    if settings.get("enhanced_security", False):
        is_valid, error_msg = validate_password_strength(password_data.new_password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
    else:
        if len(password_data.new_password) < 4:
            raise HTTPException(status_code=400, detail="New password must be at least 4 characters")

    # Update password
    user['password_hash'] = hash_password(password_data.new_password)
    save_user_to_db(user)

    # Log activity
    await log_activity(user.get('username'), "PASSWORD_CHANGED", "User changed their own password", client_ip)
    await send_event_notification("password_changed", "Password Changed",
        f"User '{user.get('username')}' changed their password.",
        username=user.get('username'), client_ip=client_ip)

    logger.info(f"User {user.get('username')} changed their password")

    return {"status": "success", "message": "Password changed successfully"}

class UpdateEmailRequest(BaseModel):
    email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

@app.post("/api/user-portal/update-email")
async def update_email(email_data: UpdateEmailRequest, request: Request, session_id: Optional[str] = Cookie(None)):
    """Allow user to update their email address"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Update email
    user['email'] = email_data.email
    save_user_to_db(user)

    # Log activity
    await log_activity(user.get('username'), "EMAIL_UPDATED", f"Email updated to {email_data.email}", client_ip)

    logger.info(f"User {user.get('username')} updated their email to {email_data.email}")

    return {"status": "success", "message": "Email updated successfully"}

# ====================================================================
# WiFi Password Management API Endpoints
# ====================================================================

@app.get("/api/user-portal/wifi-password-status")
async def get_wifi_password_status(session_id: Optional[str] = Cookie(None)):
    """Check if user has WiFi password configured and if they're eligible"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Check if RADIUS is enabled AND using PAP or PEAP (EAP-TTLS is secure, doesn't need WiFi password)
    settings = get_settings_from_db()
    radius_enabled = settings.get('radius_enabled', False)
    radius_auth_method = settings.get('radius_auth_method', 'eap-ttls')  # Default to most secure

    # WiFi password only needed for PAP (weak encryption) or PEAP (MSCHAPv2 requires NT hash)
    # EAP-TTLS is TLS-protected and uses normal account password securely
    wifi_password_needed = radius_auth_method in ['pap', 'peap']

    # Check if user is in allowed RADIUS groups
    # If no groups specified, all users are eligible (matches RADIUS auth logic)
    allowed_groups = settings.get('radius_allowed_groups', [])
    user_groups = user.get('groups', [])
    is_in_radius_group = any(group in allowed_groups for group in user_groups) if allowed_groups else True

    # Check if user has WiFi password configured
    has_wifi_password = bool(user.get('wifi_password_hash'))

    return {
        "has_wifi_password": has_wifi_password,
        "is_eligible": radius_enabled and is_in_radius_group and wifi_password_needed,
        "radius_enabled": radius_enabled,
        "in_radius_group": is_in_radius_group,
        "wifi_password_needed": wifi_password_needed,
        "radius_auth_method": radius_auth_method
    }

class SetWifiPasswordRequest(BaseModel):
    wifi_password: str = Field(..., min_length=8)
    account_password: str

@app.post("/api/user-portal/set-wifi-password")
async def set_wifi_password(wifi_data: SetWifiPasswordRequest, request: Request, session_id: Optional[str] = Cookie(None)):
    """Set or update WiFi password for RADIUS authentication"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Check eligibility
    settings = get_settings_from_db()
    radius_eap_method = settings.get('radius_eap_method', 'TTLS')
    if radius_eap_method != 'PEAP':
        raise HTTPException(status_code=403, detail="WiFi password feature is only available when PEAP is enabled")

    allowed_groups = settings.get('radius_allowed_groups', [])
    user_groups = user.get('groups', [])
    if allowed_groups and not any(group in allowed_groups for group in user_groups):
        raise HTTPException(status_code=403, detail="You are not in a RADIUS-allowed group")

    # Verify account password
    if not verify_password(wifi_data.account_password, user.get('password_hash', '')):
        await log_activity(user.get('username'), "WIFI_PASSWORD_SET_FAILED", "Incorrect account password", client_ip)
        raise HTTPException(status_code=401, detail="Account password is incorrect")

    # Validate WiFi password
    if len(wifi_data.wifi_password) < 8:
        raise HTTPException(status_code=400, detail="WiFi password must be at least 8 characters")

    # Check that WiFi password is different from account password
    if verify_password(wifi_data.wifi_password, user.get('password_hash', '')):
        raise HTTPException(status_code=400, detail="WiFi password must be different from your account password")

    # Encrypt and store WiFi password
    try:
        encrypted_hash = encrypt_wifi_password(wifi_data.wifi_password)
        user['wifi_password_hash'] = encrypted_hash
        save_user_to_db(user)

        # Log activity
        await log_activity(user.get('username'), "WIFI_PASSWORD_SET", "WiFi password configured", client_ip)
        logger.info(f"User {user.get('username')} set their WiFi password")

        return {"status": "success", "message": "WiFi password set successfully"}
    except Exception as e:
        logger.error(f"Error setting WiFi password: {e}")
        raise HTTPException(status_code=500, detail="Failed to set WiFi password")

@app.delete("/api/user-portal/delete-wifi-password")
async def delete_wifi_password(request: Request, session_id: Optional[str] = Cookie(None)):
    """Delete WiFi password"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Remove WiFi password
    user['wifi_password_hash'] = None
    save_user_to_db(user)

    # Log activity
    await log_activity(user.get('username'), "WIFI_PASSWORD_DELETED", "WiFi password removed", client_ip)
    logger.info(f"User {user.get('username')} deleted their WiFi password")

    return {"status": "success", "message": "WiFi password deleted successfully"}

@app.post("/api/user-portal/enable-2fa")
async def enable_2fa_for_user(request: Request, session_id: Optional[str] = Cookie(None)):
    """Generate TOTP secret and QR code for user to enable 2FA"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if user.get('totp_enabled'):
        raise HTTPException(status_code=400, detail="2FA is already enabled")

    # Generate TOTP secret
    secret = pyotp.random_base32()

    # Store secret temporarily (not enabled yet)
    user['totp_secret'] = secret
    save_user_to_db(user)

    # Generate QR code
    totp = pyotp.TOTP(secret)
    username = user.get('username', 'user')
    qr_uri = totp.provisioning_uri(name=username, issuer_name="CaddyMAN")

    # Generate QR code as base64 image
    import qrcode
    from io import BytesIO
    import base64

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return {
        "status": "success",
        "qr_code": f"data:image/png;base64,{qr_base64}",
        "secret": secret
    }

class Verify2FARequest(BaseModel):
    token: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$')

@app.post("/api/user-portal/verify-2fa")
async def verify_2fa_for_user(verify_data: Verify2FARequest, request: Request, session_id: Optional[str] = Cookie(None)):
    """Verify TOTP token and enable 2FA for user"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    secret = user.get('totp_secret')
    if not secret:
        raise HTTPException(status_code=400, detail="2FA setup not started")

    # Verify the token
    totp = pyotp.TOTP(secret)
    if not totp.verify(verify_data.token, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid verification code")

    # Enable 2FA
    user['totp_enabled'] = True
    save_user_to_db(user)

    # Log activity
    await log_activity(user.get('username'), "2FA_ENABLED", "User enabled 2FA", client_ip)
    await send_event_notification("2fa_enabled", "2FA Enabled",
        f"User '{user.get('username')}' enabled two-factor authentication.",
        username=user.get('username'), client_ip=client_ip)

    logger.info(f"User {user.get('username')} enabled 2FA")

    return {"status": "success", "message": "2FA enabled successfully"}

@app.post("/api/user-portal/disable-2fa")
async def disable_2fa_for_user(request: Request, session_id: Optional[str] = Cookie(None)):
    """Disable 2FA for user"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    if not user.get('totp_enabled'):
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    # Disable 2FA
    user['totp_enabled'] = False
    user['totp_secret'] = None
    save_user_to_db(user)

    # Log activity
    await log_activity(user.get('username'), "2FA_DISABLED", "User disabled 2FA", client_ip)
    await send_event_notification("2fa_disabled", "2FA Disabled",
        f"User '{user.get('username')}' disabled two-factor authentication.",
        username=user.get('username'), client_ip=client_ip)

    logger.info(f"User {user.get('username')} disabled 2FA")

    return {"status": "success", "message": "2FA disabled successfully"}

# Password Reset Endpoints

class RequestPasswordResetRequest(BaseModel):
    email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

@app.post("/api/user-portal/request-password-reset")
async def request_password_reset(reset_request: RequestPasswordResetRequest, request: Request):
    """Request a password reset link via email"""
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Check if SMTP is configured
    settings = get_settings_from_db()
    if not settings.get('smtp_enabled'):
        raise HTTPException(status_code=400, detail="Password reset is not available. SMTP is not configured.")

    # Find user by email
    users = get_all_users_from_db()
    user = None
    for u in users:
        if u.get('email', '').lower() == reset_request.email.lower():
            user = u
            break

    # Always return success to prevent email enumeration
    # But only send email if user exists
    if user:
        # Generate secure reset token
        token = secrets.token_urlsafe(32)
        expiry_hours = 1  # 1 hour expiry
        expiry = datetime.now().timestamp() + (expiry_hours * 3600)

        # Save reset token
        reset_token = {
            'token': token,
            'user_id': user['id'],
            'email': user['email'],
            'expires_at': expiry,
            'created_at': datetime.now().timestamp(),
            'used': False
        }
        save_password_reset_token_to_db(reset_token)

        # Build reset URL using domain_url setting
        domain_url = settings.get('domain_url', f"http://localhost:{settings.get('manager_port', 8000)}")
        # Remove trailing slash if present
        domain_url = domain_url.rstrip('/')
        reset_url = f"{domain_url}/user-portal?reset_token={token}"

        # Send email
        try:
            await send_password_reset_email(user['email'], user['username'], reset_url, expiry_hours)
            logger.info(f"Password reset email sent to {user['email']} for user {user['username']}")
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")

        # Log activity
        await log_activity(user['username'], "PASSWORD_RESET_REQUESTED",
            f"Password reset requested for {user['email']}", client_ip)

    # Always return success (prevent email enumeration)
    return {
        "status": "success",
        "message": "If an account exists with this email, a password reset link has been sent."
    }

@app.get("/api/user-portal/verify-reset-token/{token}")
async def verify_reset_token(token: str):
    """Verify a password reset token"""
    if not token or len(token) < 10:
        raise HTTPException(status_code=400, detail="Invalid token")

    reset = get_password_reset_token_from_db(token)
    if not reset:
        raise HTTPException(status_code=404, detail="Reset token not found")

    # Check if token has expired
    if datetime.now().timestamp() > reset['expires_at']:
        delete_password_reset_token_from_db(token)
        raise HTTPException(status_code=410, detail="Reset link has expired")

    # Check if token was already used
    if reset['used']:
        raise HTTPException(status_code=410, detail="Reset link has already been used")

    # Get user info
    users = get_all_users_from_db()
    user = None
    for u in users:
        if u['id'] == reset['user_id']:
            user = u
            break

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "username": user['username'],
        "email": reset['email'],
        "requires_2fa": user.get('totp_enabled', False)
    }

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=4)
    two_factor_token: Optional[str] = None

@app.post("/api/user-portal/reset-password")
async def reset_password(reset_data: ResetPasswordRequest, request: Request):
    """Reset password using reset token"""
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Get reset token
    reset = get_password_reset_token_from_db(reset_data.token)
    if not reset:
        raise HTTPException(status_code=404, detail="Reset token not found")

    # Check if token has expired
    if datetime.now().timestamp() > reset['expires_at']:
        delete_password_reset_token_from_db(reset_data.token)
        raise HTTPException(status_code=410, detail="Reset link has expired")

    # Check if token was already used
    if reset['used']:
        raise HTTPException(status_code=410, detail="Reset link has already been used")

    # Validate new password with Enhanced Security Mode check
    settings = get_settings_from_db()
    if settings.get("enhanced_security", False):
        is_valid, error_msg = validate_password_strength(reset_data.new_password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
    else:
        if len(reset_data.new_password) < 4:
            raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    # Get user
    users = get_all_users_from_db()
    user = None
    for u in users:
        if u['id'] == reset['user_id']:
            user = u
            break

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify 2FA if enabled
    if user.get('totp_enabled', False):
        if not reset_data.two_factor_token:
            raise HTTPException(status_code=400, detail="2FA code is required for this account")

        totp_secret = user.get('totp_secret')
        if not totp_secret:
            raise HTTPException(status_code=500, detail="2FA is enabled but secret is missing")

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(reset_data.two_factor_token, valid_window=1):
            await log_activity(user['username'], "PASSWORD_RESET_FAILED", "Invalid 2FA code during password reset", client_ip)
            raise HTTPException(status_code=401, detail="Invalid 2FA code")

    # Update password
    user['password_hash'] = hash_password(reset_data.new_password)
    save_user_to_db(user)

    # Mark token as used
    mark_password_reset_token_used(reset_data.token)

    # Log activity
    await log_activity(user['username'], "PASSWORD_RESET", "Password reset via email link", client_ip)
    await send_event_notification("password_reset", "Password Reset",
        f"User '{user['username']}' reset their password via email link.",
        username=user['username'], client_ip=client_ip)

    logger.info(f"User {user['username']} reset their password via email link")

    return {"status": "success", "message": "Password has been reset successfully"}

@app.get("/api/groups")
async def get_groups(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return get_all_groups_from_db()

@app.post("/api/groups")
async def create_group(group: Group, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Check for duplicate group name
    groups = get_all_groups_from_db()
    if any(g.get("name", "").lower() == group.name.lower() for g in groups):
        raise HTTPException(status_code=400, detail=f"Group '{group.name}' already exists")

    group.id = str(uuid.uuid4())
    save_group_to_db(group.model_dump())
    await reload_caddy()
    return group

@app.put("/api/groups/{group_id}")
async def update_group(group_id: str, group: Group, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Check if group exists
    existing_group = get_group_by_id_from_db(group_id)
    if not existing_group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Check for duplicate group name (excluding the current group)
    all_groups = get_all_groups_from_db()
    if any(g.get("id") != group_id and g.get("name", "").lower() == group.name.lower() for g in all_groups):
        raise HTTPException(status_code=400, detail=f"Group '{group.name}' already exists")

    # Prevent changing system flag
    if existing_group.get("system", False):
        group.system = True

    # Validate OIDC claims if provided
    if group.oidc_claims:
        try:
            json.loads(group.oidc_claims)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON in oidc_claims")

    # Update group
    group.id = group_id
    save_group_to_db(group.model_dump())
    await reload_caddy()
    return group

@app.delete("/api/groups/{group_id}")
async def delete_group(group_id: str, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    group = get_group_by_id_from_db(group_id)
    if group and group.get("system", False):
        raise HTTPException(status_code=403, detail="Cannot delete system group")

    delete_group_from_db(group_id)
    await reload_caddy()
    return {"status": "deleted"}

# OAuth/OIDC Endpoints

@app.get("/.well-known/openid-configuration")
async def oidc_discovery():
    """OIDC Discovery endpoint"""
    settings = get_settings_from_db()
    if not settings.get('auth_protocols_enabled') or not settings.get('oidc_enabled'):
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    # (No helper here) NOTE: HTML error helper is defined in the authorize handler where needed.

    issuer = settings.get('oidc_issuer', 'http://localhost:12888')

    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/oauth/keys",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "groups", "abspermissions"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "username", "email", "email_verified",
            "name", "given_name", "family_name", "groups", "permissions"
        ],
        "code_challenge_methods_supported": ["S256"]
    }

@app.get("/oauth/keys")
async def jwks_endpoint():
    """JWKS public keys endpoint"""
    settings = get_settings_from_db()
    if not settings.get('auth_protocols_enabled') or not settings.get('oidc_enabled'):
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    _, public_key = ensure_oidc_keys()

    # Convert PEM to JWK
    from cryptography.hazmat.primitives import serialization

    public_key_obj = serialization.load_pem_public_key(
        public_key.encode('utf-8')
    )

    # Get public numbers
    numbers = public_key_obj.public_numbers()

    # Convert to base64url without padding
    def int_to_base64url(n):
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')

    jwk_key = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(numbers.n),
        "e": int_to_base64url(numbers.e),
        "kid": "default"
    }

    return {"keys": [jwk_key]}

@app.get("/oauth/authorize")
@app.get("/auth/openid")  # Alias for Audiobookshelf mobile app compatibility
async def oauth_authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid profile email",
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    session_id: Optional[str] = Cookie(None)
):
    """OAuth2 authorization endpoint"""
    settings = get_settings_from_db()
    if not settings.get('auth_protocols_enabled') or not settings.get('oidc_enabled'):
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    # Helper: return HTML error page when the request prefers HTML, otherwise raise JSON HTTPException
    def _respond_error(status_code: int, message: str):
        accept = ""
        try:
            # Use the injected request object to inspect headers
            if request and hasattr(request, 'headers'):
                accept = request.headers.get('accept', '')
        except Exception:
            accept = ''

        # Also consider common browser User-Agent values as a fallback
        try:
            ua = ''
            if request and hasattr(request, 'headers'):
                ua = request.headers.get('user-agent', '')
        except Exception:
            ua = ''

        if 'text/html' in accept or 'application/xhtml+xml' in accept or ('mozilla' in ua.lower()):
            html = f"""<html lang="en"><head> <meta charset="utf-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Authorization Error</title> <style> body {{ font-family: Arial, Helvetica, sans-serif; margin: 0; padding: 0; background-color: #121212; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; text-align: center; }} .container {{ background-color: #1e1e1e; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.3); max-width: 90%; width: 400px; }} h2 {{ font-size: 1.5rem; color: #e57373; }} p {{ font-size: 1rem; color: #b0bec5; }} a {{ color: #81c784; text-decoration: none; font-weight: bold; }} a:hover {{ text-decoration: underline; }} </style></head><body> <div class="container"> <h2>Authorization Error</h2> <p>{message}</p> <p><a href="javascript:history.back()">Back</a></p> </div></body></html>"""
            return HTMLResponse(html, status_code=status_code)
        # Default: raise HTTPException which yields JSON
        raise HTTPException(status_code=status_code, detail=message)

    # Validate response_type
    if response_type != "code":
        return _respond_error(400, "Unsupported response_type")

    # Validate client
    client = get_oauth_client_by_id_from_db(client_id)
    if not client or not client.get('enabled'):
        return _respond_error(400, "Invalid client_id")

    # Validate redirect_uri
    logger.debug(f"[OIDC] authorize request: client_id={client_id}, redirect_uri={redirect_uri}, stored_redirects={client.get('redirect_uris')}")
    if redirect_uri not in client['redirect_uris']:
        return _respond_error(400, "Invalid redirect_uri")

    # Check PKCE requirement
    if client.get('require_pkce') and not code_challenge:
        return _respond_error(400, "PKCE required for this client")

    # Check if user is authenticated
    user = get_session_user(session_id)
    if not user:
        # Redirect to login page with return URL
        from urllib.parse import quote
        authorize_params = urlencode({
            'response_type': response_type,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state or '',
            'code_challenge': code_challenge or '',
            'code_challenge_method': code_challenge_method or ''
        })
        return_url = f"/oauth/authorize?{authorize_params}"
        login_url = f"/login?return_to={quote(return_url)}"
        return HTMLResponse(f'<html><head><meta http-equiv="refresh" content="0;url={login_url}"></head></html>')

    # Security: Block admin users from OIDC
    if user.get('is_admin', False):
        await log_activity(user.get('username', 'unknown'), "OIDC_AUTH_DENIED", f"Admin users cannot use OIDC - Client: {client_id}", "OIDC")
        await send_event_notification("oidc_auth_denied", "OIDC Authorization Denied",
            f"OIDC authorization denied - admin users not allowed.",
            username=user.get('username', 'unknown'), client_id=client_id, reason="Admin user")
        return _respond_error(403, "Admin users cannot use OIDC authentication")

    # Check if user is in allowed groups (if specified)
    allowed_groups = client.get('allowed_groups', [])
    if allowed_groups:
        user_groups = user.get('groups', [])
        # Check if user has at least one allowed group
        if not any(group in allowed_groups for group in user_groups):
            await log_activity(user.get('username', 'unknown'), "OIDC_AUTH_DENIED", f"User not in allowed groups - Client: {client_id}", "OIDC")
            await send_event_notification("oidc_auth_denied", "OIDC Authorization Denied",
                f"OIDC authorization denied - user not in allowed groups.",
                username=user.get('username', 'unknown'), client_id=client_id, reason="Not in allowed groups")
            # If the incoming request prefers HTML (browser), render a user-friendly error page.
            # Otherwise, return the standard JSON error response.
            try:
                # FastAPI will provide a `request` object automatically if the route signature includes it.
                # Some test callers may not have `request` in scope; _respond_error handles that.
                return _respond_error(403, "User not authorized for this client")
            except HTTPException:
                # Re-raise JSON HTTPException for API clients
                raise

    # Check if user is required to have 2FA but hasn't set it up
    if user_requires_2fa(user) and not user.get("totp_enabled", False):
        await log_activity(user.get('username', 'unknown'), "OIDC_AUTH_DENIED", f"2FA required but not configured - Client: {client_id}", "OIDC")
        await send_event_notification("oidc_auth_denied", "OIDC Authorization Denied",
            f"OIDC authorization denied - 2FA required but not configured.",
            username=user.get('username', 'unknown'), client_id=client_id, reason="2FA required but not configured")
        return _respond_error(403, "Your account requires 2FA to be enabled. Please visit the user portal to set up 2FA.")

    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    scopes = scope.split()

    # Save authorization code
    save_oauth_code_to_db({
        'code': auth_code,
        'client_id': client_id,
        'user_id': user['id'],
        'redirect_uri': redirect_uri,
        'scopes': scopes,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'expires_at': (datetime.now().timestamp() + 600)  # 10 minutes
    })

    # Log successful authorization
    await log_activity(user.get('username', 'unknown'), "OIDC_AUTH_SUCCESS", f"Authorization granted - Client: {client_id}", "OIDC")
    await send_event_notification("oidc_auth_success", "OIDC Authorization Success",
        f"Successful OIDC authorization.",
        username=user.get('username', 'unknown'), client_id=client_id, scopes=scope)

    # Redirect back with code
    params = {'code': auth_code}
    if state:
        params['state'] = state

    redirect_url = f"{redirect_uri}?{urlencode(params)}"

    # Use HTTP 302 redirect for mobile app compatibility (custom URI schemes like audiobookshelf://)
    # HTML meta refresh doesn't work for native apps
    return RedirectResponse(url=redirect_url, status_code=302)

@app.post("/oauth/token")
async def oauth_token(
    request: Request,
    grant_type: str = Form(None),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None)
):
    """OAuth2 token endpoint"""
    # Check for client credentials in Authorization header (HTTP Basic Auth)
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            header_client_id, header_client_secret = decoded.split(':', 1)
            # Use credentials from header if not provided in form
            if not client_id:
                client_id = header_client_id
            if not client_secret:
                client_secret = header_client_secret
        except Exception as e:
            logger.warning(f"[OAUTH] Failed to parse Basic Auth header: {e}")

    settings = get_settings_from_db()
    if not settings.get('auth_protocols_enabled') or not settings.get('oidc_enabled'):
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    if grant_type == "authorization_code":
        # Validate required parameters
        if not all([code, redirect_uri, client_id]):
            raise HTTPException(status_code=400, detail="Missing required parameters")

        # Validate client
        client = get_oauth_client_by_id_from_db(client_id)
        if not client or not client.get('enabled'):
            raise HTTPException(status_code=400, detail="Invalid client")

        # Verify client_secret if provided
        if client_secret:
            if not verify_password(client_secret, client['client_secret_hash']):
                raise HTTPException(status_code=401, detail="Invalid client credentials")

        # Get authorization code
        auth_code = get_oauth_code_from_db(code)
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid authorization code")

        # Check if code is used
        if auth_code['used']:
            raise HTTPException(status_code=400, detail="Authorization code already used")

        # Check if code is expired
        if datetime.now().timestamp() > float(auth_code['expires_at']):
            raise HTTPException(status_code=400, detail="Authorization code expired")

        # Verify client_id matches
        if auth_code['client_id'] != client_id:
            raise HTTPException(status_code=400, detail="Client mismatch")

        # Verify redirect_uri matches
        if auth_code['redirect_uri'] != redirect_uri:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")

        # Verify PKCE if required
        if auth_code.get('code_challenge'):
            if not code_verifier:
                raise HTTPException(status_code=400, detail="Code verifier required")

            # Compute challenge from verifier
            import hashlib
            computed_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('utf-8')).digest()
            ).rstrip(b'=').decode('utf-8')

            if computed_challenge != auth_code['code_challenge']:
                raise HTTPException(status_code=400, detail="Invalid code verifier")

        # Mark code as used
        mark_oauth_code_used(code)

        # Generate tokens
        access_token = create_jwt_token(
            auth_code['user_id'],
            client_id,
            auth_code['scopes'],
            expires_in=3600
        )

        refresh_token_value = secrets.token_urlsafe(32)

        # Generate ID token for OpenID Connect
        user = get_user_by_id_from_db(auth_code['user_id'])
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        if not client_id:
            raise HTTPException(status_code=400, detail="Client ID required")

        # Ensure we have valid strings for required fields
        username = user.get('username') or auth_code['user_id']
        email = user.get('email', '')
        group_ids = user.get('groups', [])
        # Convert group IDs to names for better compatibility with apps like Mealie
        group_names = get_group_names_from_ids(group_ids)

        id_token = create_id_token(
            user_id=auth_code['user_id'],
            client_id=client_id,
            username=username,
            email=email,
            nonce=auth_code.get('nonce'),
            groups=group_names
        )

        # Save tokens
        save_oauth_token_to_db({
            'access_token': access_token,
            'refresh_token': refresh_token_value,
            'client_id': client_id,
            'user_id': auth_code['user_id'],
            'scopes': auth_code['scopes'],
            'expires_at': (datetime.now().timestamp() + 3600),
            'created_at': datetime.now().isoformat()
        })

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token_value,
            "id_token": id_token,
            "scope": ' '.join(auth_code['scopes'])
        }

    elif grant_type == "refresh_token":
        # Refresh token flow
        if not refresh_token or not client_id:
            raise HTTPException(status_code=400, detail="Missing required parameters")

        # Find token by refresh_token
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM oauth_tokens WHERE refresh_token = ? AND client_id = ?',
                         (refresh_token, client_id))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="Invalid refresh token")

            old_token = {
                'access_token': row['access_token'],
                'user_id': row['user_id'],
                'scopes': json.loads(row['scopes'])
            }

        # Generate new access token
        new_access_token = create_jwt_token(
            old_token['user_id'],
            client_id,
            old_token['scopes'],
            expires_in=3600
        )

        # Update token in database
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE oauth_tokens
                SET access_token = ?, expires_at = ?, created_at = ?
                WHERE refresh_token = ?
            ''', (
                new_access_token,
                datetime.now().timestamp() + 3600,
                datetime.now().isoformat(),
                refresh_token
            ))
            conn.commit()

        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": ' '.join(old_token['scopes'])
        }

    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

def merge_group_oidc_claims(user: dict) -> dict:
    """
    Merge OIDC claims from all groups the user belongs to.
    Returns a dictionary of merged custom claims.
    """
    merged_claims = {}
    user_groups = user.get('groups', [])

    if not user_groups:
        return merged_claims

    # Get all groups from database
    all_groups = get_all_groups_from_db()

    # Filter to only groups the user belongs to
    for group in all_groups:
        if group['id'] in user_groups:
            oidc_claims_json = group.get('oidc_claims')
            if oidc_claims_json:
                try:
                    # Parse JSON claims from group
                    group_claims = json.loads(oidc_claims_json)
                    # Merge into result (later groups override earlier ones)
                    merged_claims.update(group_claims)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in group {group['id']} oidc_claims: {e}")
                    continue

    return merged_claims

@app.get("/oauth/userinfo")
async def oauth_userinfo(authorization: Optional[str] = Header(None)):
    """OAuth2 UserInfo endpoint"""
    settings = get_settings_from_db()
    if not settings.get('auth_protocols_enabled') or not settings.get('oidc_enabled'):
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    # Extract bearer token
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    access_token = authorization[7:]  # Remove 'Bearer ' prefix

    # Get token from database
    token = get_oauth_token_from_db(access_token)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid access token")

    # Check if token is expired
    if datetime.now().timestamp() > float(token['expires_at']):
        raise HTTPException(status_code=401, detail="Access token expired")

    # Get user
    user = get_user_by_id_from_db(token['user_id'])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Build userinfo response based on scopes
    scopes = token['scopes']
    userinfo = {
        'sub': user.get('username', user['id']),  # Use username as sub (matching id_token)
        'user_id': user['id']  # Keep UUID as separate claim
    }

    if 'profile' in scopes:
        userinfo['preferred_username'] = user.get('username', '')
        userinfo['name'] = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        userinfo['given_name'] = user.get('first_name', '')
        userinfo['family_name'] = user.get('last_name', '')

    if 'email' in scopes:
        userinfo['email'] = user.get('email', '')
        userinfo['email_verified'] = user.get('email_verified', False)

    if 'groups' in scopes:
        userinfo['groups'] = user.get('groups', [])

    # Merge custom OIDC claims from user's groups (includes abspermissions if configured)
    custom_claims = merge_group_oidc_claims(user)
    userinfo.update(custom_claims)

    return userinfo

@app.post("/oauth/revoke")
async def oauth_revoke_post(token: str, client_id: Optional[str] = None):
    """OAuth2 token revocation endpoint (POST)"""
    settings = get_settings_from_db()
    if not settings.get('auth_protocols_enabled') or not settings.get('oidc_enabled'):
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    # Revoke the token
    revoke_oauth_token(token)

    return {"status": "revoked"}

@app.get("/oauth/revoke")
async def oauth_revoke_get(
    request: Request,
    post_logout_redirect_uri: Optional[str] = None,
    client_id: Optional[str] = None,
    state: Optional[str] = None,
    session_id: Optional[str] = Cookie(None)
):
    """OIDC logout endpoint (GET) - RP-Initiated Logout"""
    settings = get_settings_from_db()
    if not settings.get('auth_protocols_enabled') or not settings.get('oidc_enabled'):
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    # Logout the user by clearing their session
    if session_id and session_id in sessions:
        del sessions[session_id]

    # Validate redirect URI if provided
    if post_logout_redirect_uri and client_id:
        client = get_oauth_client_by_id_from_db(client_id)
        if client:
            # Check if redirect URI is in allowed list
            allowed_uris = client.get('redirect_uris', [])
            # For logout, we're more lenient - just check the base domain matches
            from urllib.parse import urlparse
            redirect_domain = urlparse(post_logout_redirect_uri).netloc
            allowed = any(urlparse(uri).netloc == redirect_domain for uri in allowed_uris)

            if allowed:
                # Redirect back to the client's post-logout page
                redirect_url = post_logout_redirect_uri
                if state:
                    from urllib.parse import urlencode
                    redirect_url += ('&' if '?' in redirect_url else '?') + urlencode({'state': state})
                return RedirectResponse(url=redirect_url)

    # If no valid redirect, show a simple logged out page
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logged Out</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                margin: 0;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 12px;
                text-align: center;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            }
            h1 { color: #1f2937; margin-bottom: 10px; }
            p { color: #6b7280; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✓ Logged Out</h1>
            <p>You have been successfully logged out.</p>
        </div>
    </body>
    </html>
    """)

# OAuth Client Management API

@app.get("/api/oauth/clients")
async def get_oauth_clients(session_id: Optional[str] = Cookie(None)):
    """Get all OAuth clients"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    clients = get_all_oauth_clients_from_db()
    # Don't return client secrets
    for client in clients:
        client.pop('client_secret_hash', None)

    return clients

class OAuthClientCreate(BaseModel):
    name: str
    redirect_uris: List[str]
    allowed_groups: Optional[List[str]] = []
    custom_client_id: Optional[str] = None  # Allow manual client ID for special cases (e.g., mobile apps)

@app.post("/api/oauth/clients")
async def create_oauth_client(
    client_data: OAuthClientCreate,
    request: Request,
    session_id: Optional[str] = Cookie(None)
):
    """Create a new OAuth client"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    name = client_data.name
    redirect_uris = client_data.redirect_uris
    allowed_groups = client_data.allowed_groups if client_data.allowed_groups else []

    # Use custom client ID if provided (for mobile apps with hardcoded IDs), otherwise generate
    if client_data.custom_client_id:
        # Validate custom client ID
        if not re.match(r'^[a-zA-Z0-9_-]+$', client_data.custom_client_id):
            raise HTTPException(status_code=400, detail="Custom Client ID can only contain letters, numbers, hyphens, and underscores")
        if len(client_data.custom_client_id) < 3 or len(client_data.custom_client_id) > 100:
            raise HTTPException(status_code=400, detail="Custom Client ID must be between 3 and 100 characters")
        # Check if custom ID already exists
        existing = get_oauth_client_by_id_from_db(client_data.custom_client_id)
        if existing:
            raise HTTPException(status_code=400, detail=f"Client ID '{client_data.custom_client_id}' already exists")
        client_id = client_data.custom_client_id
        logger.info(f"Creating OAuth client with custom Client ID: {client_id}")
    else:
        client_id = secrets.token_urlsafe(16)

    client_secret = secrets.token_urlsafe(32)
    client_secret_hash = hash_password(client_secret)

    # Save client
    client = {
        'client_id': client_id,
        'client_secret_hash': client_secret_hash,
        'name': name,
        'redirect_uris': redirect_uris,
        'allowed_groups': allowed_groups,
        'allowed_scopes': ['openid', 'profile', 'email', 'groups'],
        'grant_types': ['authorization_code', 'refresh_token'],
        'require_pkce': True,
        'created_at': datetime.now().isoformat(),
        'enabled': True
    }

    save_oauth_client_to_db(client)

    # Return client with secret (only time it's shown)
    return {
        'client_id': client_id,
        'client_secret': client_secret,
        'name': name,
        'redirect_uris': redirect_uris
    }

@app.get("/api/oauth/clients/{client_id}")
async def get_oauth_client(
    client_id: str,
    session_id: Optional[str] = Cookie(None)
):
    """Get a specific OAuth client"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    client = get_oauth_client_by_id_from_db(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="OAuth client not found")

    # Don't return client secret
    client.pop('client_secret_hash', None)
    return client

class OAuthClientUpdate(BaseModel):
    name: str
    redirect_uris: List[str]
    allowed_groups: Optional[List[str]] = []

@app.put("/api/oauth/clients/{client_id}")
async def update_oauth_client(
    client_id: str,
    client_data: OAuthClientUpdate,
    request: Request,
    session_id: Optional[str] = Cookie(None)
):
    """Update an existing OAuth client"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Check if client exists
    existing_client = get_oauth_client_by_id_from_db(client_id)
    if not existing_client:
        raise HTTPException(status_code=404, detail="OAuth client not found")

    # Update client data
    updated_client = {
        **existing_client,
        'name': client_data.name,
        'redirect_uris': client_data.redirect_uris,
        'allowed_groups': client_data.allowed_groups if client_data.allowed_groups else []
    }

    save_oauth_client_to_db(updated_client)

    # Return updated client without secret
    updated_client.pop('client_secret_hash', None)
    return updated_client

@app.delete("/api/oauth/clients/{client_id}")
async def delete_oauth_client(
    client_id: str,
    request: Request,
    session_id: Optional[str] = Cookie(None)
):
    """Delete an OAuth client"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    delete_oauth_client_from_db(client_id)
    return {"status": "deleted"}

@app.get("/api/settings")
async def get_settings(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Get settings from database and return all settings
    # Passwords will be displayed in password-type fields with show/hide buttons
    return get_settings_from_db()

@app.post("/api/settings")
async def update_settings(settings: Settings, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Validate LDAP bind DN (service account)
    if settings.ldap_bind_dn:
        # Extract username from bind DN
        bind_username = None
        for part in settings.ldap_bind_dn.split(','):
            part_lower = part.strip().lower()
            if part_lower.startswith('cn=') or part_lower.startswith('uid='):
                bind_username = part.split('=', 1)[1].strip()
                break

        if bind_username:
            # Check if this user exists
            bind_user = get_user_by_username_from_db(bind_username)
            if not bind_user:
                raise HTTPException(status_code=400, detail=f"LDAP Bind DN user '{bind_username}' does not exist. Please create this user first.")

            # Check if user is admin
            if bind_user.get('is_admin', False):
                raise HTTPException(status_code=400, detail=f"LDAP Bind DN user '{bind_username}' cannot be an admin. Service accounts should be regular users.")

            # Check if user is in allowed groups
            allowed_groups = settings.ldap_allowed_groups or []
            if allowed_groups:
                user_groups = bind_user.get('groups', [])
                if any(group in allowed_groups for group in user_groups):
                    raise HTTPException(status_code=400, detail=f"LDAP Bind DN user '{bind_username}' should not be in the allowed groups. Service accounts are for searching only, not authentication.")

    # Get previous settings state
    old_settings = get_settings_from_db()
    old_php_enabled = old_settings.get("php_enabled", False)
    new_php_enabled = settings.php_enabled
    old_ldap_enabled = old_settings.get("ldap_enabled", False)
    old_radius_enabled = old_settings.get("radius_enabled", False)
    old_log_level = old_settings.get("caddy_log_level", "WARN")

    # Save settings to database only (no longer in JSON)
    save_settings_to_db(settings.model_dump())

    # Sync managed domain proxy if domain_url or manager_port changed
    domain_or_port_changed = (
        old_settings.get("domain_url") != settings.domain_url or
        old_settings.get("manager_port") != settings.manager_port
    )
    if domain_or_port_changed:
        logger.info("Domain URL or manager port changed, syncing managed proxy...")
        sync_managed_domain_proxy()

    # Broadcast debug mode change via SSE if log level changed to/from DEBUG
    old_debug = old_log_level == "DEBUG"
    new_debug = settings.caddy_log_level == "DEBUG"
    if old_debug != new_debug:
        await broadcast_sse_event('debug_mode_changed', {
            'debug_mode': new_debug
        })

    # Handle PHP process based on state change
    if old_php_enabled and not new_php_enabled:
        # PHP was disabled - stop PHP processes
        await stop_php_cgi()
    elif not old_php_enabled and new_php_enabled:
        # PHP was enabled - start PHP processes
        await start_php_cgi()

    # Handle LDAP server restart if settings changed
    ldap_settings_changed = (
        old_settings.get("ldap_port") != settings.ldap_port or
        old_settings.get("ldap_base_dn") != settings.ldap_base_dn or
        old_settings.get("ldap_bind_dn") != settings.ldap_bind_dn or
        old_settings.get("ldap_allowed_groups") != settings.ldap_allowed_groups or
        old_ldap_enabled != settings.ldap_enabled
    )
    if ldap_settings_changed:
        logger.info("LDAP settings changed, restarting LDAP server...")
        await stop_ldap_server()
        await asyncio.sleep(0.5)  # Give it time to fully stop
        await start_ldap_server()

    # Handle RADIUS server restart if settings changed
    radius_settings_changed = (
        old_settings.get("radius_auth_port") != settings.radius_auth_port or
        old_settings.get("radius_secret") != settings.radius_secret or
        old_settings.get("radius_allowed_groups") != settings.radius_allowed_groups or
        old_settings.get("radius_vlan_assignment") != settings.radius_vlan_assignment or
        old_radius_enabled != settings.radius_enabled
    )
    if radius_settings_changed:
        logger.info("RADIUS settings changed, restarting RADIUS server...")
        await stop_radius_server()
        await asyncio.sleep(0.5)  # Give it time to fully stop
        await start_radius_server()

    # Check if Caddy is stopped and try to restart it (only if stopped)
    caddy_was_stopped = not caddy_process or caddy_process.returncode is not None
    if caddy_was_stopped:
        logger.info("Caddy is stopped, attempting to restart after settings change...")
        try:
            await start_caddy()
            await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"Failed to auto-restart Caddy: {e}")
    else:
        # Caddy is running, just reload config (hot reload)
        await reload_caddy()

    return {"status": "updated"}

@app.post("/api/smtp/test-email")
async def send_smtp_test_email(request: Request, session_id: Optional[str] = Cookie(None)):
    """Send a test email to all admin users to verify SMTP configuration"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Get SMTP settings
    settings = get_settings_from_db()
    if not settings.get("smtp_enabled", False):
        raise HTTPException(status_code=400, detail="SMTP is not enabled. Please enable and configure SMTP first.")

    # Get all admin users with email addresses
    all_users = get_all_users_from_db()
    admin_emails = []
    for u in all_users:
        if "admin_group" in u.get("groups", []) and u.get("email"):
            admin_emails.append((u["username"], u["email"]))

    if not admin_emails:
        raise HTTPException(status_code=400, detail="No admin users with email addresses found. Please add email addresses to admin accounts.")

    # Send test email to each admin
    success_count = 0
    failed_emails = []

    for username, email in admin_emails:
        result = await send_email(
            to=email,
            subject="CaddyMAN SMTP Test Email",
            body=f"""Hello {username},

This is a test email from CaddyMAN to verify your SMTP configuration is working correctly.

If you received this email, your SMTP settings are configured properly!

Server Details:
- SMTP Server: {settings.get('smtp_server', 'N/A')}
- Port: {settings.get('smtp_port', 'N/A')}
- TLS: {'Enabled' if settings.get('smtp_use_tls', False) else 'Disabled'}
- From: {settings.get('smtp_from_name', 'CaddyIAM')} <{settings.get('smtp_from_address', 'N/A')}>

---
CaddyMAN v{VERSION}
"""
        )

        if result:
            success_count += 1
            logger.info(f"Test email sent successfully to {username} ({email})")
        else:
            failed_emails.append(f"{username} ({email})")

    if success_count == 0:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send test emails. Check SMTP configuration. Failed recipients: {', '.join(failed_emails)}"
        )

    result_message = f"Test email sent successfully to {success_count} admin(s)"
    if failed_emails:
        result_message += f". Failed: {', '.join(failed_emails)}"

    return {"status": "success", "message": result_message, "sent": success_count, "failed": len(failed_emails)}

@app.get("/api/proxies")
async def get_proxies(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return get_all_proxies_from_db()

@app.get("/api/proxies/{proxy_id}/status")
async def check_proxy_status(proxy_id: str, session_id: Optional[str] = Cookie(None)):
    """
    Check if a reverse proxy's upstream is online.
    Returns online: true if ANY HTTP response received (even 404, 401, 500).
    Returns online: false only on connection timeout/refused.
    """
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    proxy = get_proxy_by_id_from_db(proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy not found")

    # If proxy is disabled, return offline
    if not proxy.get('enabled', False):
        return {"online": False, "status": "disabled"}

    upstream = proxy.get('upstream', '')

    # If no upstream field, try to extract from advanced config
    if not upstream and proxy.get('advanced'):
        advanced_config = proxy.get('advanced')
        logger.info(f"Health check for proxy {proxy_id}: advanced config type={type(advanced_config)}, has routes={'routes' in advanced_config if isinstance(advanced_config, dict) else 'N/A'}")
        # Check if it's a routes array format
        if isinstance(advanced_config, dict) and 'routes' in advanced_config:
            # Extract upstream from first route's handler
            routes = advanced_config.get('routes', [])
            logger.info(f"Health check for proxy {proxy_id}: found {len(routes)} routes")
            for route in routes:
                if isinstance(route, dict) and 'handle' in route:
                    handlers = route.get('handle', [])
                    for handler in handlers:
                        if isinstance(handler, dict) and handler.get('handler') == 'reverse_proxy':
                            upstreams = handler.get('upstreams', [])
                            if upstreams and isinstance(upstreams, list) and len(upstreams) > 0:
                                dial = upstreams[0].get('dial', '')
                                if dial:
                                    # Convert dial address to HTTP URL for health check
                                    upstream = f"http://{dial}"
                                    logger.info(f"Health check for proxy {proxy_id}: extracted upstream={upstream}")
                                    break
                        if upstream:
                            break
                if upstream:
                    break

    if not upstream:
        logger.warning(f"Health check for proxy {proxy_id}: no upstream found")
        return {"online": False, "status": "no_upstream"}

    # Extract first upstream if load balanced
    if ',' in upstream:
        upstream = upstream.split(',')[0].strip()

    # Make a quick HEAD request with short timeout
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
            response = await client.head(upstream)
            # ANY response code means the server is online
            return {"online": True, "status": response.status_code, "upstream": upstream}
    except httpx.TimeoutException:
        return {"online": False, "status": "timeout", "upstream": upstream}
    except httpx.ConnectError:
        return {"online": False, "status": "connection_refused", "upstream": upstream}
    except Exception as e:
        # HEAD failed, try GET as fallback (some servers don't support HEAD)
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                response = await client.get(upstream)
                return {"online": True, "status": response.status_code, "upstream": upstream, "method": "GET"}
        except (httpx.TimeoutException, httpx.ConnectError) as e2:
            return {"online": False, "status": f"connection_failed", "error": type(e2).__name__, "upstream": upstream}
        except Exception as e2:
            # Even if GET fails with other errors, server is responding
            return {"online": True, "status": f"responding_with_error", "error": type(e2).__name__, "upstream": upstream}

@app.post("/api/proxies")
async def create_or_update_proxy(proxy: ReverseProxy, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Check if this is an update or create
    existing = get_proxy_by_id_from_db(proxy.id)
    is_update = existing is not None

    # Prevent editing of managed proxies
    if existing and existing.get('managed', False):
        raise HTTPException(status_code=403, detail="Cannot modify system-managed proxy. It is automatically managed based on Domain URL in Settings.")

    save_proxy_to_db(proxy.model_dump())
    await reload_caddy()

    # Send notification
    event_type = "proxy_modified" if is_update else "proxy_added"
    title = "Reverse Proxy Modified" if is_update else "Reverse Proxy Added"
    await send_event_notification(event_type, title,
        f"Reverse proxy configuration changed.",
        domains=", ".join(proxy.domains), upstream=proxy.upstream,
        modified_by=user.get("username", "admin"))

    return {"status": "saved"}

@app.delete("/api/proxies/{proxy_id}")
async def delete_proxy(proxy_id: str, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Get proxy info before deleting
    proxy = get_proxy_by_id_from_db(proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy not found")

    # Prevent deletion of managed proxies
    if proxy.get('managed', False):
        raise HTTPException(status_code=403, detail="Cannot delete system-managed proxy. Clear the Domain URL in Settings to remove it.")

    proxy_domains = ", ".join(proxy.get("domains", [])) if proxy else "unknown"

    delete_proxy_from_db(proxy_id)
    await reload_caddy()

    await send_event_notification("proxy_deleted", "Reverse Proxy Deleted",
        f"Reverse proxy configuration removed.", domains=proxy_domains,
        deleted_by=user.get("username", "admin"))

    return {"status": "deleted"}

@app.get("/api/version")
async def get_version():
    return {"version": VERSION}

@app.get("/api/status/all")
async def get_all_status(session_id: Optional[str] = Cookie(None)):
    """
    Get current status for all enabled proxies and websites.
    Returns cached status from the background monitor.
    """
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    result = {
        "proxies": {},
        "websites": {}
    }

    # Get all enabled proxies
    proxies = get_all_proxies_from_db()
    for proxy in proxies:
        if proxy.get('enabled', False):
            proxy_id = proxy.get('id')
            result["proxies"][proxy_id] = status_cache.get(f'proxy_{proxy_id}', False)

    # Get all enabled websites
    websites = get_all_websites_from_db()
    for website in websites:
        if website.get('enabled', False):
            website_id = website.get('id')
            result["websites"][website_id] = status_cache.get(f'website_{website_id}', False)

    # Provide optional detailed status information for clients that can use it
    result['details'] = {'proxies': {}, 'websites': {}}
    for key, details in status_details.items():
        if key.startswith('proxy_'):
            pid = key.split('_', 1)[1]
            result['details']['proxies'][pid] = details
        elif key.startswith('website_'):
            wid = key.split('_', 1)[1]
            result['details']['websites'][wid] = details

    return result

@app.get("/api/status/stream")
async def status_stream(session_id: Optional[str] = Cookie(None)):
    """
    Server-Sent Events endpoint for real-time status updates.
    Streams proxy and website status changes to connected clients.
    """
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    global status_sse_clients

    async def event_generator():
        # Create a queue for this client
        queue = asyncio.Queue()
        status_sse_clients.append(queue)

        try:
            # Send initial status for all proxies and websites
            proxies = get_all_proxies_from_db()
            for proxy in proxies:
                if proxy.get('enabled', False):
                    proxy_id = proxy.get('id')
                    online = status_cache.get(f'proxy_{proxy_id}', False)
                    details = status_details.get(f'proxy_{proxy_id}', {})
                    yield f"data: {json.dumps({'event': 'status', 'type': 'proxy', 'id': proxy_id, 'online': online, 'status': details.get('status'), 'protected': details.get('protected', False)})}\n\n"

            websites = get_all_websites_from_db()
            for website in websites:
                if website.get('enabled', False):
                    website_id = website.get('id')
                    online = status_cache.get(f'website_{website_id}', False)
                    details = status_details.get(f'website_{website_id}', {})
                    yield f"data: {json.dumps({'event': 'status', 'type': 'website', 'id': website_id, 'online': online, 'status': details.get('status'), 'protected': details.get('protected', False)})}\n\n"

            # Send initial Caddy status
            global caddy_process, caddy_stop_reason
            if caddy_process and caddy_process.returncode is None:
                yield f"data: {json.dumps({'event': 'caddy_status', 'status': 'running', 'pid': caddy_process.pid})}\n\n"
            else:
                yield f"data: {json.dumps({'event': 'caddy_status', 'status': 'stopped', 'reason': caddy_stop_reason})}\n\n"

            # Send recent activity (last 5 entries)
            for activity in activity_log[:5]:
                yield f"data: {json.dumps({'event': 'activity', **activity})}\n\n"

            # Send recent notifications (last 5 entries)
            for notification in notification_log[:5]:
                yield f"data: {json.dumps({'event': 'notification', **notification})}\n\n"

            # Send pending invites (initial state)
            invites = get_all_invite_tokens_from_db()
            current_time = datetime.now().timestamp()
            for invite in invites:
                time_remaining = invite['expires_at'] - current_time
                if time_remaining > 0:
                    yield f"data: {json.dumps({'event': 'invite_update', 'token': invite['token'], 'username': invite['username'], 'email': invite['email'], 'expires_at': invite['expires_at'], 'created_by': invite['created_by'], 'time_remaining': time_remaining})}\n\n"

            # NOTE: Blocked IPs SSE removed in v1.3.22 - all blocks are now permanent
            # Permanent blocklist is managed in Settings page

            # Send update status if available
            global update_available
            if update_available:
                yield f"data: {json.dumps({'event': 'update_available', 'version': update_available.get('version'), 'download_url': update_available.get('download_url'), 'current_version': VERSION})}\n\n"

            # Keep connection alive and send updates
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield message
                except asyncio.TimeoutError:
                    # Send keep-alive comment every 30 seconds
                    yield ": keep-alive\n\n"
        finally:
            # Remove client from list when disconnected
            if queue in status_sse_clients:
                status_sse_clients.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",  # Disable buffering in nginx
            "Connection": "keep-alive"
        }
    )

@app.get("/api/websites")
async def get_websites(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return get_all_websites_from_db()

@app.get("/api/websites/{website_id}/status")
async def check_website_status(website_id: str, session_id: Optional[str] = Cookie(None)):
    """
    Check if a website is online.
    Returns online: true if ANY HTTP response received (even 404, 401, 500).
    Returns online: false only on connection timeout/refused.
    """
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    website = get_website_by_id_from_db(website_id)
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")

    # If website is disabled, return offline
    if not website.get('enabled', False):
        return {"online": False, "status": "disabled"}

    domains = website.get('domains', [])
    if not domains:
        return {"online": False, "status": "no_domains"}

    # Use first domain
    domain = domains[0] if isinstance(domains, list) else domains

    # Construct URL - try HTTPS first, then HTTP
    http_ports = website.get('http_ports', [])
    https_ports = website.get('https_ports', [])

    # Prefer HTTPS if configured
    if https_ports:
        port = https_ports[0] if isinstance(https_ports, list) else https_ports
        url = f"https://{domain}:{port}" if port not in [443, '443'] else f"https://{domain}"
    elif http_ports:
        port = http_ports[0] if isinstance(http_ports, list) else http_ports
        url = f"http://{domain}:{port}" if port not in [80, '80'] else f"http://{domain}"
    else:
        url = f"http://{domain}"

    # Make a quick HEAD request with short timeout
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
            response = await client.head(url)
            # ANY response code means the server is online
            protected = True if response.status_code in (401, 403) else False
            return {"online": True, "status": response.status_code, "protected": protected, "url": url}
    except httpx.TimeoutException:
        return {"online": False, "status": "timeout", "url": url}
    except httpx.ConnectError:
        return {"online": False, "status": "connection_refused", "url": url}
    except Exception as e:
        # HEAD failed, try GET as fallback (some servers don't support HEAD)
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                response = await client.get(url)
                protected = True if response.status_code in (401, 403) else False
                return {"online": True, "status": response.status_code, "protected": protected, "url": url, "method": "GET"}
        except (httpx.TimeoutException, httpx.ConnectError) as e2:
            return {"online": False, "status": f"connection_failed", "error": type(e2).__name__, "url": url}
        except Exception as e2:
            # Even if GET fails with other errors, server is responding
            return {"online": True, "status": f"responding_with_error", "error": type(e2).__name__, "url": url}

@app.post("/api/websites")
async def create_or_update_website(website: Website, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Security: Validate root path to prevent exposing sensitive files
    import os

    # Root path is required
    if not website.root or not website.root.strip():
        raise HTTPException(
            status_code=400,
            detail="Security Error: Website root path is required. "
                   "Please specify a directory path (e.g., 'www' or 'public')."
        )

    try:
        # Get absolute paths
        caddyman_dir = os.path.abspath(os.path.dirname(__file__))
        website_root = os.path.abspath(website.root.strip())

        # Check if website root is the same as CaddyMAN directory
        if website_root == caddyman_dir:
            await send_event_notification(
                "insecure_bind_detected",
                "Security: Unsafe Website Path Blocked",
                f"User attempted to host website from CaddyMAN directory!\n\n"
                f"User: {user.get('username', 'Unknown')}\n"
                f"Attempted Path: {website_root}\n"
                f"CaddyMAN Path: {caddyman_dir}\n\n"
                f"This would expose: CaddyMAN.db, pepper.enc, and other sensitive files.\n"
                f"Action: Blocked automatically.",
                username=user.get("username", "Unknown"),
                attempted_path=website_root
            )
            raise HTTPException(
                status_code=400,
                detail="Security Error: Cannot host website from CaddyMAN directory. "
                       "This would expose sensitive files (database, config, etc.). "
                       "Please use a subdirectory like 'www' or 'public'."
            )

        # Check if website root is a parent directory of CaddyMAN
        if caddyman_dir.startswith(website_root + os.sep):
            await send_event_notification(
                "insecure_bind_detected",
                "Security: Unsafe Website Path Blocked",
                f"User attempted to host website from parent of CaddyMAN directory!\n\n"
                f"User: {user.get('username', 'Unknown')}\n"
                f"Attempted Path: {website_root}\n"
                f"CaddyMAN Path: {caddyman_dir}\n\n"
                f"This would expose the entire CaddyMAN installation.\n"
                f"Action: Blocked automatically.",
                username=user.get("username", "Unknown"),
                attempted_path=website_root
            )
            raise HTTPException(
                status_code=400,
                detail="Security Error: Cannot host website from a parent directory of CaddyMAN. "
                       "This would expose the CaddyMAN installation. "
                       "Please use a separate directory."
            )

        # NEW: Enforce at least one subfolder deep from CaddyMAN directory
        # This prevents exposing sensitive files even if they're in the same directory
        if website_root.startswith(caddyman_dir + os.sep):
            # Website root is inside CaddyMAN directory - must be at least 1 level deep
            relative_path = os.path.relpath(website_root, caddyman_dir)
            path_parts = relative_path.split(os.sep)

            # If only 1 level deep or less, block it
            if len(path_parts) < 1 or (len(path_parts) == 1 and path_parts[0] in ['.', '']):
                await send_event_notification(
                    "insecure_bind_detected",
                    "Security: Unsafe Website Path Blocked",
                    f"User attempted to host website from CaddyMAN directory!\n\n"
                    f"User: {user.get('username', 'Unknown')}\n"
                    f"Attempted Path: {website_root}\n"
                    f"CaddyMAN Path: {caddyman_dir}\n\n"
                    f"Website root must be at least one subfolder deep to prevent exposing sensitive files.\n"
                    f"Action: Blocked automatically.",
                    username=user.get("username", "Unknown"),
                    attempted_path=website_root
                )
                raise HTTPException(
                    status_code=400,
                    detail="Security Error: Website root must be at least one subfolder deep. "
                           "This prevents exposing CaddyMAN.db, pepper.enc, and other sensitive files. "
                           "Example: Use 'www', 'public', or 'sites/mysite' instead."
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Path validation error: {e}")
        # Continue if path validation fails (path might not exist yet)

    # Check if this is an update or create
    existing = get_website_by_id_from_db(website.id)
    is_update = existing is not None

    save_website_to_db(website.model_dump())
    await reload_caddy()

    # Send notification
    event_type = "website_modified" if is_update else "website_added"
    title = "Website Modified" if is_update else "Website Added"
    await send_event_notification(event_type, title,
        f"Website configuration changed.",
        domains=", ".join(website.domains), root=website.root,
        modified_by=user.get("username", "admin"))

    return {"status": "saved"}

@app.delete("/api/websites/{website_id}")
async def delete_website(website_id: str, request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_csrf(request, session_id)

    # Get website info before deleting
    website = get_website_by_id_from_db(website_id)
    website_domains = ", ".join(website.get("domains", [])) if website else "unknown"

    delete_website_from_db(website_id)
    await reload_caddy()

    await send_event_notification("website_deleted", "Website Deleted",
        f"Website configuration removed.", domains=website_domains,
        deleted_by=user.get("username", "admin"))

    return {"status": "deleted"}

@app.get("/api/caddy/status")
async def caddy_status(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if caddy_process and caddy_process.returncode is None:
        return {"status": "running", "pid": caddy_process.pid}
    return {"status": "stopped", "reason": caddy_stop_reason}

@app.get("/api/update/check")
async def check_update(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    await check_for_updates()
    return {"current_version": VERSION, "update_available": update_available}

# Auto-install endpoint removed in v1.3.11 - use caddyman-update.exe instead
# Manual download still available via download button in dashboard

@app.get("/api/activity")
async def get_activity(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"activities": activity_log}

@app.get("/api/notifications")
async def get_notifications(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"notifications": notification_log}

# NOTE: /api/blocked-ips endpoints removed in v1.3.22
# All IP blocking is now permanent via the permanent_blocklist table
# Use /api/permanent-blocklist endpoints instead

# ============================================================================
# PERMANENT BLOCKLIST API ENDPOINTS
# ============================================================================

@app.get("/api/settings/permanent-blocklist")
async def get_permanent_blocklist_endpoint(session_id: Optional[str] = Cookie(None)):
    """Get all entries in the permanent IP blocklist"""
    user = get_session_user(session_id)
    if not user or "admin_group" not in user.get("groups", []):
        raise HTTPException(status_code=403, detail="Admin access required")

    blocklist = get_permanent_blocklist()
    return {"blocklist": blocklist}

@app.post("/api/settings/permanent-blocklist")
async def add_permanent_blocklist_endpoint(
    request: Request,
    session_id: Optional[str] = Cookie(None)
):
    """Add an IP or CIDR range to the permanent blocklist"""
    user = get_session_user(session_id)
    if not user or "admin_group" not in user.get("groups", []):
        raise HTTPException(status_code=403, detail="Admin access required")

    data = await request.json()
    ip_range = data.get('ip_range', '').strip()
    reason = data.get('reason', '').strip() or None

    if not ip_range:
        raise HTTPException(status_code=400, detail="IP range is required")

    # Validate IP/CIDR format
    if not validate_ip_or_cidr(ip_range):
        raise HTTPException(status_code=400, detail="Invalid IP address or CIDR notation")

    try:
        entry_id = add_to_permanent_blocklist(ip_range, reason, user.get('username', 'admin'))
    except Exception as e:
        if 'UNIQUE constraint failed' in str(e):
            raise HTTPException(status_code=400, detail="IP/range already in blocklist")
        raise

    # Reload Caddy to apply the block
    try:
        await reload_caddy()
    except Exception as e:
        logger.warning(f"Failed to reload Caddy after adding permanent block: {e}")

    # Broadcast update
    await broadcast_sse_event('permanent_blocklist_updated', {
        'action': 'added',
        'ip_range': ip_range
    })

    await log_activity(user.get('username', 'admin'), "PERMANENT_BLOCK_ADDED",
                      f"Added {ip_range} to permanent blocklist",
                      "admin")

    return {"status": "success", "id": entry_id, "ip_range": ip_range}

@app.delete("/api/settings/permanent-blocklist/{entry_id}")
async def remove_permanent_blocklist_endpoint(
    entry_id: int,
    session_id: Optional[str] = Cookie(None)
):
    """Remove an entry from the permanent blocklist"""
    user = get_session_user(session_id)
    if not user or "admin_group" not in user.get("groups", []):
        raise HTTPException(status_code=403, detail="Admin access required")

    # Get the entry first for logging
    entry = get_permanent_blocklist_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    ip_range = entry['ip_range']

    # Remove from database
    remove_from_permanent_blocklist(entry_id)

    # Reload Caddy to remove the block
    try:
        await reload_caddy()
    except Exception as e:
        logger.warning(f"Failed to reload Caddy after removing permanent block: {e}")

    # Broadcast update
    await broadcast_sse_event('permanent_blocklist_updated', {
        'action': 'removed',
        'ip_range': ip_range
    })

    await log_activity(user.get('username', 'admin'), "PERMANENT_BLOCK_REMOVED",
                      f"Removed {ip_range} from permanent blocklist",
                      "admin")

    return {"status": "success", "ip_range": ip_range}

@app.get("/api/debug-status")
async def get_debug_status(session_id: Optional[str] = Cookie(None)):
    """Get debug mode status"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Check both environment variable and log level setting
    settings = get_settings_from_db()
    debug_enabled = DEBUG_MODE or settings.get("caddy_log_level", "WARN") == "DEBUG"

    return {
        "debug_mode": debug_enabled,
        "docs_enabled": debug_enabled
    }

@app.get("/api/runtime-info")
async def get_runtime_info(session_id: Optional[str] = Cookie(None)):
    """Get runtime environment information (platform, execution mode, etc.)"""
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    is_frozen = getattr(sys, 'frozen', False)
    system = platform.system()

    return {
        "platform": system.lower(),  # "windows", "linux", "darwin"
        "is_executable": is_frozen,
        "is_script": not is_frozen,
        "executable_name": "CaddyMAN.exe" if system == "Windows" and is_frozen else "CaddyMAN" if is_frozen else "CaddyMAN.py",
        "python_version": platform.python_version() if not is_frozen else None,
        "caddy_path": CADDY_BIN,
        "php_cgi_name": get_php_cgi_executable()
    }

@app.get("/api/security/warnings")
async def get_security_warnings(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    settings = get_settings_from_db()
    if not settings.get("enhanced_security", False):
        return {"warnings": []}

    warnings = []
    users = get_all_users_from_db()

    # Note: We can't check actual passwords since they're hashed
    # But we can warn about admin users without 2FA enabled
    for u in users:
        # Only warn about admin group users when Enhanced Security is on
        if "admin_group" in u.get("groups", []) and not u.get("totp_enabled", False):
            warnings.append({
                "type": "no_2fa",
                "user_id": u["id"],
                "username": u["username"],
                "message": f"User '{u['username']}' does not have 2FA enabled"
            })

    return {"warnings": warnings}

@app.post("/api/users/{user_id}/2fa/enable")
async def enable_2fa(user_id: str, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Only allow users to enable 2FA for themselves (or admins can do it for anyone)
    is_admin = "admin_group" in user.get("groups", [])
    if not is_admin and user.get("id") != user_id:
        raise HTTPException(status_code=403, detail="You can only enable 2FA for yourself")

    async with config_lock:
        target_user = get_user_by_id_from_db(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Generate new TOTP secret
        secret = generate_totp_secret()
        qr_code = generate_totp_qr_code(target_user["username"], secret)

        # Save secret but don't enable yet (user needs to verify first)
        target_user["totp_secret"] = secret
        target_user["totp_enabled"] = False  # Will be enabled after verification

        save_user_to_db(target_user)

    return {
        "secret": secret,
        "qr_code": qr_code
    }

@app.post("/api/users/{user_id}/2fa/verify")
async def verify_and_enable_2fa(user_id: str, token: dict, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Only allow users to verify 2FA for themselves (or admins can do it for anyone)
    is_admin = "admin_group" in user.get("groups", [])
    if not is_admin and user.get("id") != user_id:
        raise HTTPException(status_code=403, detail="You can only verify 2FA for yourself")

    async with config_lock:
        target_user = get_user_by_id_from_db(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        if not target_user.get("totp_secret"):
            raise HTTPException(status_code=400, detail="2FA not initialized. Call enable endpoint first.")

        # Verify the token
        if not verify_totp(target_user["totp_secret"], token.get("token", "")):
            raise HTTPException(status_code=400, detail="Invalid 2FA token")

        # Enable 2FA
        target_user["totp_enabled"] = True
        save_user_to_db(target_user)

    return {"status": "2FA enabled successfully"}

@app.post("/api/users/{user_id}/2fa/disable")
async def disable_2fa(user_id: str, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Only allow users to disable 2FA for themselves (or admins can do it for anyone)
    is_admin = "admin_group" in user.get("groups", [])
    if not is_admin and user.get("id") != user_id:
        raise HTTPException(status_code=403, detail="You can only disable 2FA for yourself")

    async with config_lock:
        target_user = get_user_by_id_from_db(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        target_user["totp_secret"] = None
        target_user["totp_enabled"] = False

        save_user_to_db(target_user)

    return {"status": "2FA disabled successfully"}

# Website Authentication Endpoints (for protected websites with 2FA support)
@app.post("/api/website-auth/validate")
async def validate_website_auth(request: Request, credentials: dict):
    """
    Validate username/password for website access.
    Returns challenge_id if 2FA is required, or session cookie if auth is complete.
    """
    username = credentials.get("username")
    password = credentials.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    # Find user from database
    user = get_user_by_username_from_db(username)

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check if user has 2FA enabled
    if user.get("totp_enabled", False):
        # Create a pending 2FA challenge
        challenge_id = secrets.token_urlsafe(32)
        pending_2fa_challenges[challenge_id] = {
            "username": username,
            "user_id": user["id"],
            "groups": user.get("groups", []),
            "expires": time.time() + 300,  # 5 minutes to complete 2FA
            "original_url": credentials.get("original_url", "/")
        }

        # Clean up expired challenges
        current_time = time.time()
        expired = [cid for cid, data in pending_2fa_challenges.items() if data["expires"] < current_time]
        for cid in expired:
            del pending_2fa_challenges[cid]

        return {"requires_2fa": True, "challenge_id": challenge_id}

    # No 2FA required, create session directly using main sessions dict
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "user_id": user["id"],
        "expires_at": time.time() + 86400,  # 24 hours
        "csrf_token": csrf_token
    }

    return {"requires_2fa": False, "session_id": session_id}

@app.post("/api/website-auth/verify-2fa")
async def verify_website_2fa(credentials: dict):
    """
    Verify 2FA token and create session for website access.
    """
    challenge_id = credentials.get("challenge_id")
    token = credentials.get("token")

    if not challenge_id or not token:
        raise HTTPException(status_code=400, detail="Challenge ID and token required")

    # Get challenge
    challenge = pending_2fa_challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found or expired")

    # Check if expired
    if challenge["expires"] < time.time():
        del pending_2fa_challenges[challenge_id]
        raise HTTPException(status_code=401, detail="Challenge expired")

    # Get user from database
    user = get_user_by_username_from_db(challenge["username"])

    if not user:
        del pending_2fa_challenges[challenge_id]
        raise HTTPException(status_code=404, detail="User not found")

    # Verify TOTP
    if not verify_totp(user.get("totp_secret", ""), token):
        raise HTTPException(status_code=401, detail="Invalid 2FA token")

    # Create session using main sessions dict
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "user_id": challenge["user_id"],
        "expires_at": time.time() + 86400,  # 24 hours
        "csrf_token": csrf_token
    }

    # Clean up challenge
    original_url = challenge.get("original_url", "/")
    del pending_2fa_challenges[challenge_id]

    return {"session_id": session_id, "redirect_url": original_url}

# v1.3.17: Removed /api/website-auth/check-session endpoint - no longer needed with unified SSO

@app.get("/auth/login")
async def serve_website_login_page():
    """
    Serve the login page for website authentication.
    """
    login_page_path = os.path.join(static_dir, "website_login.html")
    with open(login_page_path, 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())

@app.get("/auth/2fa-challenge")
async def serve_2fa_challenge_page(challenge_id: str, redirect: str = "/"):
    """
    Serve the 2FA challenge page for website authentication.
    """
    challenge = pending_2fa_challenges.get(challenge_id)
    if not challenge:
        return HTMLResponse("<html><body><h1>Challenge expired or invalid</h1><p>Please try logging in again.</p></body></html>")

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Two-Factor Authentication Required</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #1a1a1a;
                color: #e0e0e0;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }}
            .container {{
                background: #252525;
                border: 1px solid #3a3a3a;
                border-radius: 12px;
                padding: 40px;
                width: 400px;
                max-width: 90%;
            }}
            h1 {{
                color: #3b82f6;
                margin-bottom: 10px;
                font-size: 24px;
            }}
            p {{
                color: #a0a0a0;
                margin-bottom: 30px;
            }}
            input {{
                width: 100%;
                padding: 12px;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                background: #2d2d2d;
                color: #e0e0e0;
                font-size: 18px;
                text-align: center;
                letter-spacing: 5px;
                margin-bottom: 20px;
            }}
            button {{
                width: 100%;
                padding: 12px;
                border: none;
                border-radius: 6px;
                background: #3b82f6;
                color: white;
                font-size: 16px;
                font-weight: 500;
                cursor: pointer;
            }}
            button:hover {{
                background: #2563eb;
            }}
            .error {{
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
                border: 1px solid #ef4444;
                padding: 12px;
                border-radius: 6px;
                margin-bottom: 20px;
                display: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Two-Factor Authentication</h1>
            <p>Enter the 6-digit code from your authenticator app to continue.</p>
            <div id="error" class="error"></div>
            <input type="text" id="token" placeholder="000000" maxlength="6" pattern="[0-9]{{6}}" autofocus>
            <button onclick="verify()">Verify</button>
        </div>

        <script>
            const challengeId = "{challenge_id}";
            const redirectUrl = "{redirect}";

            document.getElementById('token').addEventListener('keypress', function(e) {{
                if (e.key === 'Enter') {{
                    verify();
                }}
            }});

            async function verify() {{
                const token = document.getElementById('token').value;
                const errorDiv = document.getElementById('error');

                if (token.length !== 6) {{
                    errorDiv.textContent = 'Please enter a 6-digit code';
                    errorDiv.style.display = 'block';
                    return;
                }}

                try {{
                    const response = await fetch('/api/website-auth/verify-2fa', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            challenge_id: challengeId,
                            token: token
                        }})
                    }});

                    if (!response.ok) {{
                        const error = await response.json();
                        errorDiv.textContent = error.detail || 'Verification failed';
                        errorDiv.style.display = 'block';
                        return;
                    }}

                    const data = await response.json();

                    // Set the session cookie (v1.3.17: unified SSO with session_id)
                    document.cookie = `session_id=${{data.session_id}}; path=/; max-age=86400; SameSite=Lax`;

                    // Redirect to the URL we saved
                    window.location.href = redirectUrl || data.redirect_url || '/';
                }} catch (err) {{
                    errorDiv.textContent = 'An error occurred. Please try again.';
                    errorDiv.style.display = 'block';
                }}
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(html)

if __name__ == "__main__":
    import uvicorn
    settings = get_settings_from_db()
    manager_port = settings.get("manager_port", 8000)

    # When running as frozen exe with --windowed, disable uvicorn's default logging
    # Our own logging is already configured above
    is_frozen = getattr(sys, 'frozen', False)

    if is_frozen:
        # Frozen exe: disable uvicorn's logging config, use our own
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=manager_port,
            log_config=None  # Disable uvicorn's logging config
        )
    else:
        # Running as script: use uvicorn's default logging
        uvicorn.run(app, host="0.0.0.0", port=manager_port)