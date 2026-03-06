# SKYLINE Authentication System

## Overview
SKYLINE is an open-source authentication/licensing management system built with Python and Flask, using MongoDB as its database. It provides a dashboard for managing applications, users, licenses, packages, and resellers.

## Architecture

- **Framework**: Flask (Python 3.12)
- **Database**: MongoDB via PyMongo
- **WSGI Server**: Gunicorn (production), Flask dev server (development)
- **Port**: 5000

## Project Structure

- `app.py` - Flask application factory, blueprint registration, entry point
- `config.py` - Configuration via environment variables
- `models.py` - Database access layer (MongoDB)
- `routes/` - Flask blueprints for each section of the app
  - `auth.py` - Login/logout
  - `dashboard.py` - Main dashboard
  - `apps.py`, `apps_extra.py` - Application management
  - `users.py` - User management
  - `resellers.py` - Reseller management
  - `packages.py` - Package/license management
  - `profile.py` - Admin profile
  - `admins.py` - Admin management
  - `api.py` - REST API endpoints
  - `discord_mgmt.py` - Discord bot management API
- `templates/` - Jinja2 HTML templates
- `static/` - CSS, JS, images
- `discord_bot.py` - Optional Discord bot integration
- `wsgi.py` - WSGI entry point

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | MongoDB connection string (secret) |
| `SECRET_KEY` | Flask session secret key |
| `DATABASE_NAME` | MongoDB database name (default: `skyline`) |
| `DB_DRIVER` | Database driver (default: `mongo`) |
| `DISCORD_BOT_TOKEN` | Discord bot token (optional) |
| `DISCORD_OWNER_ID` | Discord owner user ID (optional) |
| `MGMT_SECRET` | Shared secret for bot<->Flask API (optional) |

## Workflow

- **Development**: `python app.py` — runs Flask dev server on port 5000
- **Production**: `gunicorn --bind=0.0.0.0:5000 --reuse-port --workers=2 --timeout=120 app:application`

## Notes

- The MongoDB database name must match the case of the existing Atlas database (lowercase `skyline`)
- The `KeyAuth-Source-Code-main/` directory is the original PHP source for reference only
- Discord bot integration is optional and separate from the main web app
