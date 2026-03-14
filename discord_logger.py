"""
Discord Webhook Logger
Captures ALL Flask/Werkzeug logs and ships them to Discord in batched embeds.
"""
import logging
import os
import queue
import threading
import time
import traceback
from datetime import datetime

import requests

WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')

# ── Colours per level ──────────────────────────────────────
COLOURS = {
    'DEBUG':    0x95a5a6,
    'INFO':     0x3498db,
    'WARNING':  0xf39c12,
    'ERROR':    0xe74c3c,
    'CRITICAL': 0x922b21,
    'ACCESS':   0x2ecc71,
}

EMOJIS = {
    'DEBUG':    '🔍',
    'INFO':     'ℹ️',
    'WARNING':  '⚠️',
    'ERROR':    '❌',
    'CRITICAL': '🚨',
    'ACCESS':   '🌐',
}


def _send_embed(title: str, description: str, colour: int, fields: list = None):
    if not WEBHOOK_URL:
        return
    embed = {
        'title': title,
        'description': description[:4000] if description else '',
        'color': colour,
        'timestamp': datetime.utcnow().isoformat(),
        'footer': {'text': 'SKYLINE • Log System'},
    }
    if fields:
        embed['fields'] = fields[:25]
    try:
        requests.post(
            WEBHOOK_URL,
            json={'embeds': [embed], 'username': 'SKYLINE Logs'},
            timeout=8,
        )
    except Exception:
        pass


# ── Batch queue ────────────────────────────────────────────
_log_queue: queue.Queue = queue.Queue()
_BATCH_SIZE = 10       # flush when this many entries accumulate
_BATCH_DELAY = 3.0     # or after this many seconds


def _flush_worker():
    """Background thread: drain the queue and send batched embeds."""
    pending = []
    last_flush = time.time()

    while True:
        try:
            item = _log_queue.get(timeout=1.0)
            pending.append(item)
        except queue.Empty:
            pass

        should_flush = (
            len(pending) >= _BATCH_SIZE
            or (pending and time.time() - last_flush >= _BATCH_DELAY)
        )

        if should_flush and pending:
            # Group by level
            by_level: dict[str, list] = {}
            for entry in pending:
                by_level.setdefault(entry['level'], []).append(entry)

            for level, entries in by_level.items():
                colour = COLOURS.get(level, 0x7f8c8d)
                emoji  = EMOJIS.get(level, '📋')
                fields = []
                for e in entries:
                    name = f"{emoji} `{e['time']}` — {e['logger']}"
                    val  = e['message'][:1024] or '—'
                    fields.append({'name': name, 'value': val, 'inline': False})

                _send_embed(
                    title=f"{emoji} {level} — {len(entries)} event(s)",
                    description=f"**{len(entries)}** `{level}` log(s) from SKYLINE panel",
                    colour=colour,
                    fields=fields[:25],
                )
                time.sleep(0.5)   # small pause to respect rate limit

            pending.clear()
            last_flush = time.time()


_worker_thread = threading.Thread(target=_flush_worker, daemon=True)
_worker_thread.start()


# ── Custom Handler ─────────────────────────────────────────
class DiscordHandler(logging.Handler):
    def __init__(self, level=logging.DEBUG):
        super().__init__(level)

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            # Strip ANSI colour codes from werkzeug output
            import re
            msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)

            _log_queue.put({
                'level':   record.levelname,
                'logger':  record.name,
                'time':    datetime.utcnow().strftime('%H:%M:%S'),
                'message': msg,
            })
        except Exception:
            pass


# ── Access log interceptor ─────────────────────────────────
class AccessLogHandler(logging.Handler):
    """Intercepts Werkzeug HTTP access lines and enqueues them."""
    def emit(self, record: logging.LogRecord):
        try:
            import re
            msg = record.getMessage()
            msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)

            # Parse: 127.0.0.1 - - [timestamp] "METHOD /path HTTP/1.1" status size
            m = re.search(r'"(\w+) ([^\s]+)[^"]*" (\d+)', msg)
            if m:
                method, path, status = m.group(1), m.group(2), m.group(3)
                code = int(status)
                level = 'ERROR' if code >= 500 else ('WARNING' if code >= 400 else 'ACCESS')
                emoji = EMOJIS.get(level, '🌐')
                _log_queue.put({
                    'level':   level,
                    'logger':  'HTTP',
                    'time':    datetime.utcnow().strftime('%H:%M:%S'),
                    'message': f"`{method}` `{path}` → **{status}**",
                })
            else:
                _log_queue.put({
                    'level':   'ACCESS',
                    'logger':  'HTTP',
                    'time':    datetime.utcnow().strftime('%H:%M:%S'),
                    'message': msg,
                })
        except Exception:
            pass


def setup(app):
    """
    Call once from create_app().
    Attaches Discord handlers to Flask + Werkzeug + root loggers.
    """
    if not WEBHOOK_URL:
        app.logger.warning('DISCORD_WEBHOOK_URL not set — Discord logging disabled')
        return

    fmt = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s',
                            datefmt='%H:%M:%S')

    discord_handler = DiscordHandler(level=logging.DEBUG)
    discord_handler.setFormatter(fmt)

    access_handler = AccessLogHandler(level=logging.DEBUG)

    # Root logger (catches everything)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(discord_handler)

    # Flask app logger
    app.logger.setLevel(logging.DEBUG)
    app.logger.addHandler(discord_handler)

    # Werkzeug access logger
    wz = logging.getLogger('werkzeug')
    wz.setLevel(logging.DEBUG)
    wz.addHandler(access_handler)

    # Socket.IO / engineio loggers
    for name in ('socketio', 'engineio'):
        lg = logging.getLogger(name)
        lg.setLevel(logging.WARNING)   # only warnings+ from socket layer
        lg.addHandler(discord_handler)

    app.logger.info('✅ Discord webhook logging active — all logs will be forwarded')

    # Send a startup embed immediately
    _send_embed(
        title='🚀 SKYLINE Panel Started',
        description='The server has started successfully. Log forwarding is **active**.',
        colour=0x2ecc71,
        fields=[
            {'name': 'Time', 'value': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), 'inline': True},
            {'name': 'Status', 'value': '✅ Online', 'inline': True},
        ],
    )
