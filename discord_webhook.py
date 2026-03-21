"""
Per-App Discord Event Webhook
Sends structured embed notifications to a Discord webhook URL configured
per application. Covers login, register, license, and error events.
Runs in a background thread so API responses are never slowed down.
"""
import threading
import requests
from datetime import datetime


# ── Colour map per event type ──────────────────────────────────────────────
COLOURS = {
    'login':    0x2ecc71,   # green
    'register': 0x3498db,   # blue
    'license':  0x9b59b6,   # purple
    'upgrade':  0xf39c12,   # orange
    'ban':      0xe74c3c,   # red
    'error':    0xe74c3c,   # red
}

EMOJIS = {
    'login':    '🔑',
    'register': '📝',
    'license':  '🎫',
    'upgrade':  '⬆️',
    'ban':      '🔨',
    'error':    '❌',
}

TITLES = {
    'login':    'User Login',
    'register': 'New Registration',
    'license':  'License Authentication',
    'upgrade':  'Subscription Upgrade',
    'ban':      'User Banned',
    'error':    'API Error',
}


def _send(webhook_url: str, event: str, username: str, ip: str,
          app_name: str, extra: dict = None):
    """
    Internal: build a Discord embed and POST it to webhook_url.
    Called in a daemon thread — never raises.
    """
    if not webhook_url or not webhook_url.startswith('http'):
        return
    try:
        colour = COLOURS.get(event, 0x95a5a6)
        emoji  = EMOJIS.get(event, '📋')
        title  = TITLES.get(event, event.title())
        ts     = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        fields = [
            {'name': '👤 User',        'value': f'`{username}`',  'inline': True},
            {'name': '🌐 IP Address',  'value': f'`{ip}`',        'inline': True},
            {'name': '🕐 Timestamp',   'value': f'`{ts}`',        'inline': False},
        ]

        # Append any extra fields (e.g. license key, error message)
        if extra:
            for k, v in extra.items():
                fields.append({'name': k, 'value': f'`{str(v)[:200]}`', 'inline': True})

        embed = {
            'title':       f'{emoji}  {title}',
            'description': f'**App:** `{app_name}`',
            'color':       colour,
            'fields':      fields[:25],
            'timestamp':   datetime.utcnow().isoformat(),
            'footer':      {'text': 'SKYLINE Auth • Event Logger'},
        }

        requests.post(
            webhook_url,
            json={'embeds': [embed], 'username': 'SKYLINE Events'},
            timeout=8,
        )
    except Exception:
        pass


def send_event(webhook_url: str, event: str, username: str, ip: str,
               app_name: str, extra: dict = None):
    """
    Fire-and-forget: send a Discord event embed without blocking the caller.
    
    Args:
        webhook_url: Discord webhook URL stored on the app document.
        event:       Event key — 'login', 'register', 'license', 'upgrade',
                     'ban', or 'error'.
        username:    The end-user's username or license key.
        ip:          Client IP address.
        app_name:    The name of the application.
        extra:       Optional dict of extra fields to include in the embed.
    """
    if not webhook_url:
        return
    t = threading.Thread(
        target=_send,
        args=(webhook_url, event, username, ip, app_name, extra),
        daemon=True,
    )
    t.start()
