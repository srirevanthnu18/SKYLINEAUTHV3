# SKYLINE Authentication System

## Overview
SKYLINE is an open-source authentication/licensing management system built with Python and Flask, using MongoDB as its database. It provides a dashboard for managing applications, users, licenses, packages, and resellers. It is fully compatible with all official KeyAuth SDKs (Python, C#, C++).

## Architecture

- **Framework**: Flask (Python 3.12)
- **Database**: MongoDB via PyMongo
- **WSGI Server**: Gunicorn (production), Flask dev server (development)
- **Real-time**: Flask-SocketIO + eventlet
- **Port**: 5000

## Project Structure

- `app.py` - Flask application factory, blueprint registration, entry point
- `config.py` - **Centralized configuration** — all settings in one place
- `models.py` - Database access layer (MongoDB)
- `discord_logger.py` - Global server-level Discord webhook log handler (system logs)
- `discord_webhook.py` - **Per-app Discord event webhook** (login/register/license/error embeds)
- `socket_events.py` - Flask-SocketIO real-time chat event handlers
- `wsgi.py` - WSGI entry point for Gunicorn
- `routes/` - Flask blueprints for each section of the app
  - `auth.py` - Login/logout
  - `dashboard.py` - Main dashboard
  - `apps.py`, `apps_extra.py` - Application management (settings, webhook, variables, files, blacklists, logs, chat channels)
  - `users.py` - User management
  - `resellers.py` - Reseller management
  - `packages.py` - Package/license management
  - `profile.py` - Admin profile + profile picture upload
  - `admins.py` - Admin management
  - `api.py` - **KeyAuth-compatible REST API** (`/api/1.2/`)
  - `discord_mgmt.py` - Discord bot management API
  - `chat.py` - Real-time internal chat (with profile image support)
- `templates/` - Jinja2 HTML templates
- `static/` - CSS, JS, images, uploaded profile pics
- `sdk/` - Pre-filled SDK templates (Python, C#, C++)
- `KeyAuth-Source-Code-main/` - Reference PHP implementation (not used at runtime)

## Key Features

### Announcements System
Admins and superadmins can post announcements visible to all staff after login.
- After every login, users are automatically redirected to `/announcements` instead of the dashboard
- Announcements can be **pinned** to appear at the top
- Admins can create, edit, and delete announcements
- All admins and resellers can read announcements; only admins can write them
- Sidebar link under Overview for quick access

### KeyAuth SDK Compatibility
The API at `/api/1.2/` is fully compatible with all official KeyAuth SDKs (Python, C#, C++):
- **Actions supported**: `init`, `login`, `register`, `license`, `upgrade`, `check`, `log`, `var`, `checkblacklist`, `fetchOnline`, `fetchStats`, `ban`, `logout`, `chatget`, `chatsend`
- **HMAC-SHA256 response signing** — all responses include a `signature` header
- SDK files auto-generated with pre-filled credentials via the "Download SDK" button
- `sessionid` returned in `login`, `register`, and `license` responses (critical for all SDKs)

### Bug Fixes Applied (March 2026)
1. **`sessionid` missing from auth responses** — All SDKs read `response['sessionid']` after login/register/license. Added it to all three responses.
2. **Global username uniqueness index** — Replaced `username` sparse global index with a compound `(app_id, username)` partial index so users in different apps can share usernames without collision.
3. **Direct user creation** — `create_user_direct` now sets the `username` field explicitly when creating a user account (not a license), and marks the record with `is_license: False`.
4. **`is_license` flag** — `api_register` now blocks direct-user accounts from being used as license registration tokens (backward-compatible: old records without the flag default to license behaviour).
5. **Subscription name** — `subscription_name` (package name) is now stored on the user/license document at creation time. `format_user_info` falls back to a live package lookup for legacy records.

### Discord Event Webhook (Per-App)
Each app can have its own Discord webhook URL configured in the app settings page.
When set, structured embeds are sent for:
- **Login** — username, IP, HWID
- **Register** — username, IP, license key used
- **License auth** — license key, IP, HWID
- **Errors** — failed auth attempts with reason

### Discord System Webhook (Global)
Set `DISCORD_WEBHOOK_URL` env var for global server-level log forwarding (all Flask/Werkzeug logs batched into Discord embeds).

### Chat System
Real-time internal messaging between admins/resellers via WebSockets.
- Profile images loaded from database and shown in contact list, top bar, and message bubbles
- Falls back to letter initial if no profile image is uploaded
- Real-time messages also carry the sender's profile picture URL

## Configuration (`config.py`)

All non-sensitive settings can be changed in `config.py`:
- `PANEL_NAME` — rebrand the panel name
- `PANEL_VERSION` — version string displayed in UI
- `API_VERSION` — API endpoint prefix (default `1.2` → `/api/1.2/`)
- `MAX_CONTENT_LENGTH` — max file upload size

## Environment Variables (Secrets)

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | MongoDB connection string (required) |
| `SECRET_KEY` | Flask session secret key (required) |
| `DATABASE_NAME` | MongoDB database name (default: `skyline`) |
| `DB_DRIVER` | Database driver (default: `mongo`) |
| `DISCORD_WEBHOOK_URL` | Global system log Discord webhook (optional) |
| `DISCORD_BOT_TOKEN` | Discord bot token (optional) |
| `DISCORD_OWNER_ID` | Discord owner user ID (optional) |
| `MGMT_SECRET` | Shared secret for bot↔Flask API (optional) |

## Workflow

- **Development**: `python app.py` — runs Flask dev server on port 5000
- **Production**: `gunicorn --worker-class=eventlet -w 1 --bind=0.0.0.0:5000 --reuse-port --timeout=120 app:application`

## Notes

- MongoDB database name must match the case of the existing Atlas database (lowercase `skyline`)
- The `KeyAuth-Source-Code-main/` directory is the original PHP source for reference only
- Discord bot integration is optional and separate from the main web app
- Profile pictures are stored in `static/uploads/` and referenced by filename in MongoDB
