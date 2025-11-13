from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
from fastapi import FastAPI, HTTPException, Request, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from packaging import version
from pydantic import BaseModel, Field, field_validator
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
from pathlib import Path
from datetime import datetime
import platform
import bcrypt
from contextlib import asynccontextmanager
import sys
import pyotp
import qrcode
import io
import base64
import re
import sqlite3
from contextlib import closing

VERSION = "1.2.11"

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller"""
    try:
        # PyInstaller stores files in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
UPDATE_CHECK_URL = "" 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global health_check_task, caddy_monitor_task
    logger.info(f"Starting CaddyMAN v{VERSION}")
    load_last_restart_time()  # Load restart tracking from database
    await start_caddy()
    await start_php_cgi()
    await asyncio.sleep(2)
    try:
        await reload_caddy()
    except:
        pass
    health_check_task = asyncio.create_task(health_check_loop())
    caddy_monitor_task = asyncio.create_task(monitor_caddy())
    asyncio.create_task(periodic_update_check())
    asyncio.create_task(cleanup_expired_sessions())
    await check_for_updates()

    yield

    # Shutdown
    if health_check_task:
        health_check_task.cancel()
    if caddy_monitor_task:
        caddy_monitor_task.cancel()
    await stop_php_cgi()
    await stop_caddy()
    sessions.clear()
app = FastAPI(title="CaddyMAN", version=VERSION, lifespan=lifespan)



class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        
        # Allow login page and auth endpoints
        if (request.url.path in ["/", "/api/auth/login", "/api/auth/verify"] or
            request.url.path.startswith("/static/") or
            request.url.path.startswith("/api/website-auth/") or
            request.url.path.startswith("/auth/")):
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
# Get absolute path for reliability - works with PyInstaller
static_dir = resource_path("app")

# Mount /static to serve CSS/JS/etc
app.mount("/static", StaticFiles(directory=static_dir), name="static")

CADDY_ADMIN_URL = "http://localhost:2019"
# Use resource_path for caddy.exe to work with PyInstaller
CADDY_BIN = os.getenv("CADDY_BIN", resource_path("caddy.exe") if platform.system() == "Windows" else "caddy")
CONFIG_FILE = "caddy_manager_config.json"
DB_FILE = "caddy_manager.db"
BACKUP_DIR = "config_backups"
LOG_DIR = "logs"

caddy_process = None
php_cgi_process = None
config_lock = asyncio.Lock()
sessions = {}
website_sessions = {}  # Store website authentication sessions {session_id: {username, expires, groups}}
health_check_task = None
caddy_monitor_task = None
last_restart_time = 0
caddy_stop_reason = ""  # Track why Caddy stopped
update_available = None
activity_log = []  # Store recent activity
MAX_ACTIVITY_LOG = 100  # Keep last 100 activities
failed_login_attempts = {}  # Track failed login attempts by IP
pending_2fa_challenges = {}  # Track pending 2FA challenges {challenge_id: {username, expires, original_url}}

Path(BACKUP_DIR).mkdir(exist_ok=True)
Path(LOG_DIR).mkdir(exist_ok=True)

# Load last restart time from database (persists across reboots)
def load_last_restart_time():
    """Load the last restart timestamp from database, migrate from old file if exists"""
    global last_restart_time

    # Migration: Check if old last_restart.txt exists and migrate it
    old_file = "last_restart.txt"
    if os.path.exists(old_file):
        try:
            with open(old_file, 'r') as f:
                file_time = float(f.read().strip())
            logger.info(f"Migrating restart time from {old_file} to database")
            last_restart_time = file_time
            save_last_restart_time()  # Save to database
            os.remove(old_file)  # Remove old file after successful migration
            logger.info(f"Migration complete, removed {old_file}")
            return
        except Exception as e:
            logger.warning(f"Could not migrate from {old_file}: {e}")

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
    "theme": "dark", "http_port": 80, "https_port": 443,
    "health_check_enabled": False, "health_check_domain": "",
    "health_check_interval": 60, "restart_after_failures": 3,
    "notification_service": "", "notification_url": "", "notification_token": "",
    "php_enabled": False, "php_path": "",
    "manager_port": 8000, "enhanced_security": False,
    "caddy_log_level": "WARN"
}

# Models
class Settings(BaseModel):
    theme: str
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

    @field_validator('php_path')
    @classmethod
    def validate_php_path(cls, v, values):
        # Only validate if PHP is enabled
        if values.data.get('php_enabled', False) and v:
            php_path = v
            # If path is a directory, append php-cgi.exe
            if os.path.isdir(php_path):
                php_path = os.path.join(php_path, "php-cgi.exe")

            # Check if php-cgi.exe exists
            if not os.path.exists(php_path):
                raise ValueError(f"PHP-CGI executable not found at path: {php_path}")
        return v

class User(BaseModel):
    id: str
    username: str
    password_hash: str
    groups: List[str] = Field(default_factory=list)
    totp_secret: Optional[str] = None
    totp_enabled: bool = False

class Group(BaseModel):
    id: str
    name: str
    description: str = ""
    system: bool = False  # System groups cannot be deleted

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
    access_groups: List[str] = Field(default_factory=list)
    advanced: Optional[Dict[str, Any]] = None
    # Legacy fields for backward compatibility
    listen_port: Optional[int] = None
    tls: Optional[bool] = None
    @field_validator('domains')
    def validate_domains(cls, v):
        if not v or len(v) == 0:
            raise ValueError('At least one domain is required for reverse proxy')
        return v

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

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_token: Optional[str] = None

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

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
                listen_port INTEGER,
                tls TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_group_name ON groups(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_website_enabled ON websites(enabled)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON reverse_proxies(enabled)')

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
            user['totp_enabled'] = bool(user['totp_enabled'])
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
            user['totp_enabled'] = bool(user['totp_enabled'])
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
            user['totp_enabled'] = bool(user['totp_enabled'])
            return user
    return None

def save_user_to_db(user: dict):
    """Save or update user in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO users
            (id, username, password_hash, groups, totp_secret, totp_enabled, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            user['id'],
            user['username'],
            user['password_hash'],
            json.dumps(user.get('groups', [])),
            user.get('totp_secret'),
            1 if user.get('totp_enabled', False) else 0
        ))
        conn.commit()

def delete_user_from_db(user_id: str):
    """Delete user from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()

def get_settings_from_db():
    """Get all settings from database as a dictionary"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT key, value FROM settings')
        rows = cursor.fetchall()
        settings = {}
        for row in rows:
            try:
                settings[row['key']] = json.loads(row['value'])
            except:
                settings[row['key']] = row['value']
        # Merge with defaults for any missing keys
        return {**default_settings, **settings}

def save_settings_to_db(settings: dict):
    """Save settings to database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        for key, value in settings.items():
            cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, json.dumps(value) if not isinstance(value, str) else value))
        conn.commit()

# Groups database functions
def get_all_groups_from_db():
    """Get all groups from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM groups ORDER BY name')
        rows = cursor.fetchall()
        groups = []
        for row in rows:
            groups.append({
                'id': row['id'],
                'name': row['name'],
                'description': row['description'],
                'system': bool(row['system'])
            })
        return groups

def get_group_by_id_from_db(group_id: str):
    """Get a group by ID"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row['id'],
                'name': row['name'],
                'description': row['description'],
                'system': bool(row['system'])
            }
        return None

def save_group_to_db(group: dict):
    """Save/update a group in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO groups (id, name, description, system, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (group['id'], group['name'], group.get('description', ''), int(group.get('system', False))))
        conn.commit()

def delete_group_from_db(group_id: str):
    """Delete a group from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM groups WHERE id = ? AND system = 0', (group_id,))
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
                'advanced': row['advanced'],
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
                'advanced': row['advanced'],
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
            website.get('advanced'),
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
        cursor.execute('SELECT * FROM reverse_proxies ORDER BY created_at')
        rows = cursor.fetchall()
        proxies = []
        for row in rows:
            proxies.append({
                'id': row['id'],
                'domains': json.loads(row['domains']) if row['domains'] else [],
                'target': row['target'],
                'http_ports': json.loads(row['http_ports']) if row['http_ports'] else [],
                'https_ports': json.loads(row['https_ports']) if row['https_ports'] else [],
                'auto_https': bool(row['auto_https']),
                'enabled': bool(row['enabled']),
                'access_groups': json.loads(row['access_groups']) if row['access_groups'] else [],
                'advanced': row['advanced'],
                'listen_port': row['listen_port'],
                'tls': row['tls']
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
                'http_ports': json.loads(row['http_ports']) if row['http_ports'] else [],
                'https_ports': json.loads(row['https_ports']) if row['https_ports'] else [],
                'auto_https': bool(row['auto_https']),
                'enabled': bool(row['enabled']),
                'access_groups': json.loads(row['access_groups']) if row['access_groups'] else [],
                'advanced': row['advanced'],
                'listen_port': row['listen_port'],
                'tls': row['tls']
            }
        return None

def save_proxy_to_db(proxy: dict):
    """Save/update a reverse proxy in database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO reverse_proxies
            (id, domains, target, http_ports, https_ports, auto_https, enabled,
             access_groups, advanced, listen_port, tls, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            proxy['id'],
            json.dumps(proxy.get('domains', [])),
            proxy['target'],
            json.dumps(proxy.get('http_ports', [])),
            json.dumps(proxy.get('https_ports', [])),
            int(proxy.get('auto_https', False)),
            int(proxy.get('enabled', True)),
            json.dumps(proxy.get('access_groups', [])),
            proxy.get('advanced'),
            proxy.get('listen_port'),
            proxy.get('tls')
        ))
        conn.commit()

def delete_proxy_from_db(proxy_id: str):
    """Delete a reverse proxy from database"""
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM reverse_proxies WHERE id = ?', (proxy_id,))
        conn.commit()

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
    # Only return non-database fields (websites, proxies, groups)
    return {"reverse_proxies": [], "websites": [], "groups": []}

def save_config(config):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(BACKUP_DIR, f"config_{timestamp}.json")
        if os.path.exists(CONFIG_FILE):
            shutil.copy2(CONFIG_FILE, backup_file)
        with tempfile.NamedTemporaryFile('w', delete=False, dir='.') as tmp:
            json.dump(config, tmp, indent=2)
            tmp_name = tmp.name
        shutil.move(tmp_name, CONFIG_FILE)
        backups = sorted(Path(BACKUP_DIR).glob("config_*.json"))
        for old_backup in backups[:-10]:
            old_backup.unlink()
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise

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

# Create default admin user in database if no users exist
users = get_all_users_from_db()
if not users:
    default_admin = {
        "id": str(uuid.uuid4()),
        "username": "admin",
        "password_hash": hash_password("changeme"),
        "groups": ["admin_group"],
        "totp_secret": None,
        "totp_enabled": False
    }
    save_user_to_db(default_admin)
    logger.info("Created default admin user: admin/changeme")

# Initialize settings in database if they don't exist
db_settings = get_settings_from_db()
if not db_settings:
    # No settings in DB yet, save defaults
    save_settings_to_db(default_settings)
    logger.info("Initialized default settings in database")

def create_session(user_id: str) -> str:
    session_id = str(uuid.uuid4())
    sessions[session_id] = {"user_id": user_id, "expires_at": time.time() + (3 * 24 * 60 * 60)}
    return session_id

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
                # ntfy URL already includes topic (e.g., https://notify.jvr.nz/issues)
                await client.post(
                    settings["notification_url"],
                    content=message.encode('utf-8'),
                    headers=headers
                )
        logger.info(f"Notification sent: {title} (type: {notification_type})")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

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

async def check_for_updates():
    global update_available
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
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
                    update_available = data
                    logger.info(f"Update available: {remote_version}")
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
            await asyncio.sleep(60)
            settings = get_settings_from_db()
            if not settings.get("health_check_enabled") or not settings.get("health_check_domain"):
                continue
            
            domain = settings["health_check_domain"]
            interval = settings.get("health_check_interval", 60)
            max_failures = settings.get("restart_after_failures", 3)
            
            failures = 0
            for _ in range(max_failures):
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        response = await client.get(f"http://{domain}", follow_redirects=True)
                        if response.status_code < 500:
                            break
                except:
                    pass
                failures += 1
                await asyncio.sleep(interval)
            
            if failures >= max_failures:
                time_since_restart = time.time() - last_restart_time
                hours_since_restart = time_since_restart / 3600

                if time_since_restart < 3600:
                    logger.warning(f"Skipping restart - last restart was {hours_since_restart:.1f} hours ago (cooldown: 1 hour)")
                    await send_notification(
                        "Restart Cooldown Active",
                        f"⏱️ {domain} is down but restart skipped\n\n"
                        f"Last restart: {hours_since_restart:.1f}h ago\n"
                        f"Cooldown period: 1 hour\n"
                        f"Time remaining: {60 - (hours_since_restart * 60):.0f} minutes",
                        "warning"
                    )
                    continue

                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        await client.get("https://1.1.1.1")

                    logger.critical(f"{domain} down - initiating system restart (last restart: {hours_since_restart:.1f}h ago)")
                    await send_notification(
                        "System Restart Initiated",
                        f"🔄 System will restart in 10 seconds\n\n"
                        f"Reason: {domain} health check failed\n"
                        f"Last restart: {hours_since_restart:.1f}h ago\n"
                        f"Consecutive failures: {max_failures}",
                        "critical"
                    )

                    # Update and save restart time BEFORE restarting
                    last_restart_time = time.time()
                    save_last_restart_time()

                    if platform.system() == "Windows":
                        subprocess.Popen(["shutdown", "/r", "/t", "10"])
                    else:
                        subprocess.Popen(["sudo", "reboot"])
                except:
                    logger.warning("Domain down but no internet")
                    await send_notification(
                        "Health Check Failed",
                        f"⚠️ {domain} is unreachable\n\n"
                        f"Status: Domain down\n"
                        f"Internet: Not available\n"
                        f"Action: Restart skipped (no internet connection)",
                        "alert"
                    )
        except Exception as e:
            logger.error(f"Health check error: {e}")

async def cleanup_expired_sessions():
    while True:
        await asyncio.sleep(3600)  # Every hour
        current_time = time.time()
        expired = [sid for sid, sess in sessions.items() if current_time > sess["expires_at"]]
        for sid in expired:
            del sessions[sid]
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")

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

async def start_caddy():
    global caddy_process, caddy_stop_reason
    async with config_lock:
        if caddy_process and caddy_process.returncode is None:
            return {"status": "already_running"}
        try:
            stdout_log = open(os.path.join(LOG_DIR, "caddy.stdout.log"), "a")
            stderr_log = open(os.path.join(LOG_DIR, "caddy.stderr.log"), "a")
            caddy_process = await asyncio.create_subprocess_exec(CADDY_BIN, "run", stdout=stdout_log, stderr=stderr_log)
            caddy_stop_reason = ""  # Clear stop reason on successful start
            logger.info(f"Caddy started (PID {caddy_process.pid})")
            await asyncio.sleep(2)
            return {"status": "started", "pid": caddy_process.pid}
        except Exception as e:
            caddy_stop_reason = f"Failed to start: {str(e)}"
            logger.error(f"Failed to start Caddy: {e}")
            raise HTTPException(status_code=500, detail=str(e))

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
        # If path is a directory, append php-cgi.exe
        if os.path.isdir(php_path):
            php_path = os.path.join(php_path, "php-cgi.exe")

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
            if proxy.get("advanced"):
                route_base["handle"].append(proxy["advanced"])
            else:
                handler = {"handler": "reverse_proxy", "upstreams": []}
                upstreams = proxy["upstream"].split(",") if "," in proxy["upstream"] else [proxy["upstream"]]
                for upstream in upstreams:
                    handler["upstreams"].append({"dial": upstream.strip()})
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
            # Track sites that need HTTP→HTTPS redirect
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
                        php_path = os.path.join(php_path, "php-cgi.exe")

                    # Set root variable first
                    route_base["handle"].append({
                        "handler": "vars",
                        "root": root_path
                    })

                    # Get index files
                    index_files = site.get("index_files", ["index.html"])
                    if "index.php" not in index_files:
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
                    index_files = site.get("index_files", ["index.html"])
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

                for target_https_port, domains in redirect_targets.items():
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

                    # Insert at beginning so it matches before other routes
                    servers[http_port]["routes"].insert(0, redirect_route)

        # Add routes to bypass authentication for auth endpoints
        # These must come BEFORE any auth-protected routes
        for port, server_data in servers.items():
            # Bypass for API auth endpoints (manager login, website auth, etc.)
            api_auth_bypass_route = {
                "match": [{"path": ["/api/auth/*", "/api/website-auth/*"]}],
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": "localhost:8000"}]
                }]
            }
            # Bypass for auth pages (login, 2FA challenge)
            auth_pages_bypass_route = {
                "match": [{"path": ["/auth/*"]}],
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": "localhost:8000"}]
                }]
            }
            # Insert at the beginning so they match before auth-protected routes
            server_data["routes"].insert(0, auth_pages_bypass_route)
            server_data["routes"].insert(0, api_auth_bypass_route)

        # Build base config with automatic HTTPS disabled
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
                # Disable automatic HTTPS to prevent port 80 binding
                server_config["automatic_https"] = {"disable": True}
            config["apps"]["http"]["servers"][f"srv_{port}"] = server_config
        return config
    except Exception as e:
        logger.error(f"Failed to build config: {e}")
        raise

async def reload_caddy():
    config = build_caddy_config()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{CADDY_ADMIN_URL}/load", json=config)
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
@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = resource_path("app/index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
        html_content = html_content.replace('""" + VERSION + """', VERSION)
    return HTMLResponse(content=html_content)  
    

@app.post("/api/auth/login")
async def login(login_data: LoginRequest, request: Request, response: Response):
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Get user from database
    user = get_user_by_username_from_db(login_data.username)

    if not user or not verify_password(login_data.password, user["password_hash"]):
        await log_activity(login_data.username, "LOGIN_FAILED", "Invalid credentials", client_ip)

        # Track failed login attempts
        current_time = time.time()
        if client_ip not in failed_login_attempts:
            failed_login_attempts[client_ip] = []

        # Add current attempt and remove attempts older than 1 hour
        failed_login_attempts[client_ip] = [
            t for t in failed_login_attempts[client_ip] if current_time - t < 3600
        ]
        failed_login_attempts[client_ip].append(current_time)

        attempt_count = len(failed_login_attempts[client_ip])

        # Send notification on first failed attempt or every 3rd attempt
        if attempt_count == 1 or attempt_count % 3 == 0:
            import socket
            hostname = socket.gethostname()

            await send_notification(
                "Failed Login Attempt",
                f"🔐 Unsuccessful login detected\n\n"
                f"Username: {login_data.username}\n"
                f"IP Address: {client_ip}\n"
                f"Server: {hostname}\n"
                f"Failed attempts (last hour): {attempt_count}",
                "warning" if attempt_count < 5 else "alert"
            )

        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check 2FA if enabled for this user
    if user.get("totp_enabled", False):
        if not login_data.totp_token:
            # User has 2FA enabled but didn't provide token
            raise HTTPException(status_code=403, detail="2FA token required")

        if not verify_totp(user.get("totp_secret", ""), login_data.totp_token):
            await log_activity(user["username"], "LOGIN_FAILED", "Invalid 2FA token", client_ip)
            raise HTTPException(status_code=401, detail="Invalid 2FA token")

    # Successful login - clear failed attempts for this IP
    if client_ip in failed_login_attempts:
        del failed_login_attempts[client_ip]

    session_id = create_session(user["id"])
    response.set_cookie("session_id", session_id, httponly=True, max_age=3*24*60*60)

    await log_activity(user["username"], "LOGIN_SUCCESS", "User logged in", client_ip)

    return {"status": "success", "user": {"id": user["id"], "username": user["username"], "groups": user["groups"]}}   

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

@app.get("/api/auth/verify")
@app.post("/api/auth/verify")
async def verify_auth(request: Request, website_session: Optional[str] = Cookie(None)):
    """Forward auth endpoint for Caddy to verify website authentication"""
    # Check if user has a valid website session
    session = website_sessions.get(website_session) if website_session else None

    # Check if session is expired
    if session and session["expires"] < time.time():
        del website_sessions[session]
        session = None

    # Get required groups from request headers
    required_groups_str = request.headers.get("X-Required-Groups", "")
    required_groups = [g.strip() for g in required_groups_str.split(",") if g.strip()]

    # If not authenticated, redirect to login page
    if not session:
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

    # Return success with user info in headers for Caddy to forward
    return Response(
        status_code=200,
        headers={
            "X-User-ID": session["user_id"],
            "X-Username": session["username"],
            "X-User-Groups": ",".join(session.get("groups", []))
        }
    )

@app.get("/api/users")
async def get_users(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Get users from database
    users = get_all_users_from_db()
    return [{"id": u["id"], "username": u["username"], "groups": u["groups"], "totp_enabled": u.get("totp_enabled", False)} for u in users]

@app.post("/api/users")
async def create_user(user_create: UserCreate, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

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
            "totp_secret": None,
            "totp_enabled": False
        }
        save_user_to_db(new_user)
    return {"id": new_user["id"], "username": new_user["username"], "groups": new_user["groups"]}


@app.put("/api/users/{user_id}")
async def update_user(user_id: str, user_update: UserCreate, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

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
            "totp_secret": existing_user.get("totp_secret"),
            "totp_enabled": existing_user.get("totp_enabled", False)
        }
        save_user_to_db(updated_user)
    return {"id": updated_user["id"], "username": updated_user["username"], "groups": updated_user["groups"]}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
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
        delete_user_from_db(user_id)
    return {"status": "deleted"}

@app.get("/api/groups")
async def get_groups(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return get_all_groups_from_db()

@app.post("/api/groups")
async def create_group(group: Group, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Check for duplicate group name
    groups = get_all_groups_from_db()
    if any(g.get("name", "").lower() == group.name.lower() for g in groups):
        raise HTTPException(status_code=400, detail=f"Group '{group.name}' already exists")

    group.id = str(uuid.uuid4())
    save_group_to_db(group.model_dump())
    await reload_caddy()
    return group

@app.delete("/api/groups/{group_id}")
async def delete_group(group_id: str, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    group = get_group_by_id_from_db(group_id)
    if group and group.get("system", False):
        raise HTTPException(status_code=403, detail="Cannot delete system group")

    delete_group_from_db(group_id)
    await reload_caddy()
    return {"status": "deleted"}

@app.get("/api/settings")
async def get_settings(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Get settings from database
    return get_settings_from_db()

@app.post("/api/settings")
async def update_settings(settings: Settings, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Get previous PHP enabled state
    old_settings = get_settings_from_db()
    old_php_enabled = old_settings.get("php_enabled", False)
    new_php_enabled = settings.php_enabled

    # Save settings to database only (no longer in JSON)
    save_settings_to_db(settings.model_dump())

    # Handle PHP process based on state change
    if old_php_enabled and not new_php_enabled:
        # PHP was disabled - stop PHP processes
        await stop_php_cgi()
    elif not old_php_enabled and new_php_enabled:
        # PHP was enabled - start PHP processes
        await start_php_cgi()

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

@app.get("/api/proxies")
async def get_proxies(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return get_all_proxies_from_db()

@app.post("/api/proxies")
async def create_or_update_proxy(proxy: ReverseProxy, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    save_proxy_to_db(proxy.model_dump())
    await reload_caddy()
    return {"status": "saved"}

@app.delete("/api/proxies/{proxy_id}")
async def delete_proxy(proxy_id: str, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    delete_proxy_from_db(proxy_id)
    await reload_caddy()
    return {"status": "deleted"}

@app.get("/api/version")
async def get_version():
    return {"version": VERSION}

@app.get("/api/websites")
async def get_websites(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return get_all_websites_from_db()

@app.post("/api/websites")
async def create_or_update_website(website: Website, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    save_website_to_db(website.model_dump())
    await reload_caddy()
    return {"status": "saved"}

@app.delete("/api/websites/{website_id}")
async def delete_website(website_id: str, session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    delete_website_from_db(website_id)
    await reload_caddy()
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

@app.post("/api/update/install")
async def install_update(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not update_available:
        raise HTTPException(status_code=400, detail="No update available")

    try:
        download_url = update_available.get("download_url")
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.get(download_url)
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="Failed to download update")

        # Determine current executable path (works for both .py and .exe)
        if getattr(sys, 'frozen', False):
            # Running as PyInstaller executable
            current_exe = os.path.abspath(sys.executable)
        else:
            # Running as Python script
            current_exe = os.path.abspath(__file__)

        # Get directory where executable is located
        exe_dir = os.path.dirname(current_exe)
        exe_name = os.path.basename(current_exe)

        new_exe_name = "caddy_manager_new.exe" if platform.system() == "Windows" else "caddy_manager_new"
        new_exe_path = os.path.join(exe_dir, new_exe_name)

        # Download update to same directory as current executable
        with open(new_exe_path, "wb") as f:
            f.write(response.content)

        if platform.system() != "Windows":
            os.chmod(new_exe_path, 0o755)

        logger.info(f"Update downloaded to {new_exe_path}")

        # Create backup and replace
        backup_exe = current_exe + ".backup"

        logger.info(f"Creating backup: {current_exe} -> {backup_exe}")
        if os.path.exists(backup_exe):
            os.remove(backup_exe)
        shutil.move(current_exe, backup_exe)

        logger.info(f"Installing update: {new_exe_path} -> {current_exe}")
        shutil.move(new_exe_path, current_exe)

        logger.info("Update installed - restarting...")
        await send_notification(
            "Update Successful",
            f"✨ CaddyMAN has been updated\n\n"
            f"New version: {update_available['version']}\n"
            f"Previous version: {VERSION}\n"
            f"Status: Restarting application...",
            "success"
        )

        # Restart the application
        if platform.system() == "Windows":
            # Use subprocess to start new instance and exit current one
            subprocess.Popen([current_exe], creationflags=subprocess.CREATE_NEW_CONSOLE if hasattr(subprocess, 'CREATE_NEW_CONSOLE') else 0)
            os._exit(0)
        else:
            os.execv(current_exe, [current_exe])

    except Exception as e:
        logger.error(f"Update failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
        
@app.get("/api/activity")
async def get_activity(session_id: Optional[str] = Cookie(None)):
    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"activities": activity_log}

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

    # No 2FA required, create session directly
    session_id = secrets.token_urlsafe(32)
    website_sessions[session_id] = {
        "username": username,
        "user_id": user["id"],
        "groups": user.get("groups", []),
        "expires": time.time() + 86400  # 24 hours
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

    # Create session
    session_id = secrets.token_urlsafe(32)
    website_sessions[session_id] = {
        "username": challenge["username"],
        "user_id": challenge["user_id"],
        "groups": challenge["groups"],
        "expires": time.time() + 86400  # 24 hours
    }

    # Clean up challenge
    original_url = challenge.get("original_url", "/")
    del pending_2fa_challenges[challenge_id]

    return {"session_id": session_id, "redirect_url": original_url}

@app.get("/api/website-auth/check-session")
async def check_website_session(session_id: Optional[str] = Cookie(None, alias="website_session")):
    """
    Check if website session is valid and user has access to requested groups.
    """
    if not session_id:
        raise HTTPException(status_code=401, detail="No session")

    session = website_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    # Check if expired
    if session["expires"] < time.time():
        del website_sessions[session_id]
        raise HTTPException(status_code=401, detail="Session expired")

    return {
        "valid": True,
        "username": session["username"],
        "groups": session["groups"]
    }

@app.get("/auth/login")
async def serve_website_login_page():
    """
    Serve the login page for website authentication.
    """
    login_page_path = resource_path(os.path.join("app", "website_login.html"))
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

                    // Set the session cookie
                    document.cookie = `website_session=${{data.session_id}}; path=/; max-age=86400; SameSite=Lax`;

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
    uvicorn.run(app, host="0.0.0.0", port=manager_port)