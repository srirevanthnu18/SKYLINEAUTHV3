"""
SKYLINE — Centralized Configuration
All application-level settings live here.
Sensitive values (MONGO_URI, SECRET_KEY) are loaded from environment secrets.
Non-sensitive values can be overridden via environment variables or changed here.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask ──────────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-production')

    # ── MongoDB ────────────────────────────────────────────────────────────────
    MONGO_URI     = os.environ.get('MONGO_URI')
    DATABASE_NAME = os.environ.get('DATABASE_NAME', 'skyline')
    DB_DRIVER     = os.environ.get('DB_DRIVER', 'mongo')

    # ── Panel identity (change here to rebrand the panel) ─────────────────────
    PANEL_NAME    = os.environ.get('PANEL_NAME', 'SKYLINE')
    PANEL_VERSION = os.environ.get('PANEL_VERSION', '2.0')

    # ── KeyAuth API ───────────────────────────────────────────────────────────
    # The API URL is derived dynamically from the request host at runtime.
    # Override API_VERSION here to change the endpoint prefix (e.g. /api/1.3).
    API_VERSION = os.environ.get('API_VERSION', '1.2')

    # ── File uploads ───────────────────────────────────────────────────────────
    UPLOAD_FOLDER     = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads'
    )
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_BYTES', 2 * 1024 * 1024))  # 2 MB

    # ── Backups ────────────────────────────────────────────────────────────────
    BACKUP_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'backups'
    )

    # ── Optional Discord system webhook (global server logs) ──────────────────
    # Per-app event webhooks (login/register/license) are stored on each app
    # document in MongoDB and configured via the app settings page.
    DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')

    # ── Optional Discord bot (discord_bot.py) ─────────────────────────────────
    DISCORD_BOT_TOKEN  = os.environ.get('DISCORD_BOT_TOKEN', '')
    DISCORD_OWNER_ID   = os.environ.get('DISCORD_OWNER_ID', '')
    MGMT_SECRET        = os.environ.get('MGMT_SECRET', '')
