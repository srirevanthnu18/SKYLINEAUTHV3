import hmac
import hashlib
import json
import secrets
import base64
import time
import threading
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, make_response
from models import db
import discord_webhook as dw   # per-app event webhook helper

api_bp = Blueprint('api', __name__, url_prefix='/api/1.2')

# ── In-memory rate limiter (200 req/min per ownerid) ─────────────────────────
_rate_store = {}
_rate_lock  = threading.Lock()

def _is_rate_limited(ownerid, limit=200, window=60):
    """Return True if ownerid has exceeded `limit` requests in the last `window` seconds."""
    now = time.time()
    with _rate_lock:
        bucket = _rate_store.get(ownerid)
        if bucket is None:
            _rate_store[ownerid] = {'count': 1, 'reset': now + window}
            return False
        if now > bucket['reset']:
            _rate_store[ownerid] = {'count': 1, 'reset': now + window}
            return False
        bucket['count'] += 1
        return bucket['count'] > limit


# ── VPN / proxy detection (ip-api.com, free, 45 req/min) ─────────────────────
_vpn_cache = {}
_vpn_lock  = threading.Lock()

def _is_vpn(ip):
    """Return True if ip is detected as a proxy/VPN/hosting provider."""
    if ip in ('127.0.0.1', '::1') or ip.startswith('192.168.') or ip.startswith('10.'):
        return False
    with _vpn_lock:
        cached = _vpn_cache.get(ip)
    if cached is not None:
        ts, result = cached
        if time.time() - ts < 3600:
            return result
    try:
        import urllib.request as ureq
        url = f"http://ip-api.com/json/{ip}?fields=proxy,hosting,mobile"
        with ureq.urlopen(url, timeout=3) as r:
            payload = json.loads(r.read())
        result = bool(payload.get('proxy') or payload.get('hosting'))
    except Exception:
        result = False
    with _vpn_lock:
        _vpn_cache[ip] = (time.time(), result)
    return result


# ── Token system verification ─────────────────────────────────────────────────
def _verify_token(token, thash, secret):
    """
    Verify KeyAuth token system.
    token  = HMAC-SHA256(secret, token_data) provided by seller
    thash  = SHA256 of client binary provided by client at init
    The seller signs tokens with the app secret; thash binds them to a specific build.
    Returns: 'success' | 'invalid_token' | 'hash_mismatch'
    """
    if not token or not thash:
        return 'invalid_token'
    try:
        # Token format: base64( HMAC-SHA256(secret, thash) )
        expected = hmac.new(
            secret.encode() if isinstance(secret, str) else secret,
            thash.encode()  if isinstance(thash, str)  else thash,
            hashlib.sha256
        ).hexdigest()
        try:
            decoded = base64.b64decode(token).decode()
        except Exception:
            decoded = token
        if hmac.compare_digest(decoded, expected):
            return 'success'
        # Second form: token IS the expected hexdigest directly
        if hmac.compare_digest(token, expected):
            return 'success'
        return 'invalid_token'
    except Exception:
        return 'invalid_token'


# ── Custom message helper ─────────────────────────────────────────────────────
def _msgs(app):
    """
    Build a dict of all custom error/success messages for this app,
    with KeyAuth-identical defaults for every field.
    """
    g = app.get   # convenience
    return {
        'usernametaken':    g('msg_usernametaken',  'Username already taken.'),
        'keynotfound':      g('msg_keynotfound',    'License key not found.'),
        'keyused':          g('msg_keyused',         'License key already used.'),
        'nosublevel':       g('msg_nosublevel',      'User has no subscription.'),
        'usernamenotfound': g('msg_usernamenotfound','Username not found.'),
        'passmismatch':     g('msg_passmismatch',    'Password does not match.'),
        'hwidmismatch':     g('msg_hwidmismatch',    'Hardware ID mismatch.'),
        'noactivesubs':     g('msg_noactivesubs',    'No active subscriptions.'),
        'hwidblacked':      g('msg_hwidblacked',     'Your hardware ID is blacklisted.'),
        'pausedsub':        g('msg_pausedsub',       'Subscription is paused.'),
        'vpnblocked':       g('msg_vpnblocked',      'VPN/proxy detected. Please disable and try again.'),
        'keybanned':        g('msg_keybanned',       'Your license key has been banned.'),
        'userbanned':       g('msg_userbanned',      'Your account has been banned.'),
        'sessionunauthed':  g('msg_sessionunauthed', 'Session is not authenticated.'),
        'hashcheckfail':    g('msg_hashcheckfail',   'File on your disk is modified. Please re-download.'),
        'tokeninvalid':     g('msg_tokeninvalid',    'Invalid token supplied.'),
        'tokenhash':        g('msg_tokenhash',       'Token file hashes must be the same.'),
        'loggedin':         g('msg_loggedin',        'Logged in!'),
        'pausedapp':        g('msg_pausedapp',       app.get('paused_msg', 'Application is currently paused, please wait for the developer to say otherwise.')),
        'appdisabled':      g('msg_appdisabled',     app.get('app_disabled_msg', 'Application is currently disabled.')),
        'untershort':       g('msg_untershort',      'Username too short, try longer one.'),
        'chatdelay':        g('msg_chatdelay',       "Chat slower, you've hit the delay limit."),
    }


def _map_error(raw_error, msgs):
    """
    Map raw model error strings → custom app messages.
    This allows per-app error message customisation exactly like KeyAuth.
    """
    e = (raw_error or '').lower()
    if 'username already taken' in e or 'username taken' in e:
        return msgs['usernametaken']
    if 'invalid license key' in e or 'license key not found' in e:
        return msgs['keynotfound']
    if 'license key already used' in e or 'key already used' in e:
        return msgs['keyused']
    if 'invalid username or password' in e and 'user' not in e:
        return msgs['usernamenotfound']
    if 'invalid username or password' in e:
        return msgs['passmismatch']
    if 'hardware id mismatch' in e or 'hwid mismatch' in e:
        return msgs['hwidmismatch']
    if 'blacklisted' in e and 'hwid' in e:
        return msgs['hwidblacked']
    if 'ban' in e and ('account' in e or 'user' in e):
        return msgs['userbanned']
    if 'ban' in e and ('key' in e or 'license' in e):
        return msgs['keybanned']
    if 'subscription' in e and 'no' in e:
        return msgs['noactivesubs']
    if 'username too short' in e:
        return msgs['untershort']
    # Fallback: return raw message unchanged
    return raw_error


# ── Signing ───────────────────────────────────────────────────────────────────
def sign_response(data_json, key):
    if not key:
        return "No encryption key supplied"
    if isinstance(key, str):
        key = key.encode()
    return hmac.new(key, data_json.encode(), hashlib.sha256).hexdigest()


def signed_response(data, key=""):
    json_resp = json.dumps(data, separators=(',', ':'))
    sig = sign_response(json_resp, key) if key else "No encryption key supplied"
    resp = make_response(json_resp)
    resp.headers['signature'] = sig
    resp.headers['Content-Type'] = 'application/json'
    return resp


def error_response(message):
    return signed_response({"success": False, "message": message})


def get_ip():
    forwarded = request.headers.get('HTTP_CF_CONNECTING_IP',
                request.headers.get('X-Forwarded-For', ''))
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or "0.0.0.0"


def make_nonce():
    return secrets.token_hex(16)


def get_enckey(session):
    """Return the signing key: enckey from init if provided, else empty string."""
    return session.get('sent_key') or ''


def format_user_info(user, ip):
    """
    Build KeyAuth-compatible 'info' block.
    CRITICAL: subscriptions must ALWAYS contain at least one entry.
    All official KeyAuth SDKs do subscriptions[0]["expiry"] and will crash
    if the array is empty.
    """
    try:
        now = datetime.utcnow()

        if user.get('expiry') and hasattr(user['expiry'], 'timestamp'):
            exp = user['expiry']
            if exp.tzinfo:
                from datetime import timezone
                now_aware = now.replace(tzinfo=timezone.utc)
                timeleft = max(0, int((exp - now_aware).total_seconds()))
            else:
                timeleft = max(0, int((exp - now).total_seconds()))
            expiry_ts = str(int(exp.timestamp()))
            timeleft_str = str(timeleft)
        else:
            expiry_ts    = "9999999999"
            timeleft_str = "9999999999"

        created_ts = "0"
        if user.get('created_at') and hasattr(user['created_at'], 'timestamp'):
            created_ts = str(int(user['created_at'].timestamp()))

        sub_name = user.get('subscription_name')
        if not sub_name and user.get('package_id'):
            try:
                pkg = db.db.packages.find_one({'_id': user['package_id']})
                sub_name = pkg.get('name', 'default') if pkg else 'default'
            except Exception:
                sub_name = 'default'
        sub_name = sub_name or 'default'

        subs = [{
            "subscription": sub_name,
            "expiry": expiry_ts,
            "timeleft": timeleft_str
        }]

        username = user.get('username') or user.get('key') or "Unknown"

        return {
            "username":     username,
            "ip":           ip or "0.0.0.0",
            "hwid":         user.get('hwid') or '',
            "createdate":   created_ts,
            "lastlogin":    str(int(now.timestamp())),
            "subscriptions": subs
        }
    except Exception:
        return {
            "username":     user.get('username') or user.get('key') or "Unknown",
            "ip":           ip or "0.0.0.0",
            "hwid":         user.get('hwid') or '',
            "createdate":   "0",
            "lastlogin":    "0",
            "subscriptions": [{
                "subscription": "default",
                "expiry":       "9999999999",
                "timeleft":     "9999999999"
            }]
        }


@api_bp.route('/', methods=['POST', 'GET'])
def handle_api():
    try:
        data     = request.form if request.method == 'POST' else request.args
        app_type = data.get('type', '').strip()
        ownerid  = data.get('ownerid', '').strip()
        name     = data.get('name', '').strip()

        if not ownerid:
            return error_response("No OwnerID specified. Select app & copy code snippet from dashboard.")
        if not name:
            return error_response("No app name specified. Select app & copy code snippet from dashboard.")

        # ── Rate limiting (200 req / min per ownerid) ─────────────────────────
        if _is_rate_limited(ownerid):
            return error_response("This application has sent too many requests. Try again in a minute.")

        # ── App lookup ────────────────────────────────────────────────────────
        oid = db._to_id(ownerid)
        or_clauses = [{'owner_id': ownerid}]
        if oid:
            or_clauses.append({'owner_mongo_id': oid})
            or_clauses.append({'owner_id': oid})
            or_clauses.append({'owner_id': str(oid)})

        app = db.db.apps.find_one({'name': name, '$or': or_clauses})
        if not app:
            return error_response("KeyAuth_Invalid")

        secret = app.get('secret_key', '')
        msgs   = _msgs(app)

        # ── Global app ban (ToS violation flag) ───────────────────────────────
        if app.get('banned', False):
            return error_response("This application has been banned for violating terms of service.")

        # ── Init ──────────────────────────────────────────────────────────────
        if app_type == 'init':
            enckey    = data.get('enckey', '')
            ver       = data.get('ver', '').strip()
            file_hash = data.get('hash', '')
            ip        = get_ip()

            # enckey length guard (KeyAuth enforces <= 35 chars)
            if enckey and len(enckey) > 35:
                return signed_response({
                    "success": False,
                    "message": 'The parameter "enckey" is too long. Must be 35 characters or less.'
                }, enckey or secret)

            # Force encryption check
            if app.get('force_encryption', False) and not enckey:
                return signed_response({
                    "success": False,
                    "message": "No encryption key supplied, encryption is forced."
                }, secret)

            # VPN / proxy block
            if app.get('vpn_block', False):
                if _is_vpn(ip):
                    if not db.check_ip_whitelisted(app['_id'], ip):
                        return signed_response({
                            "success": False,
                            "message": msgs['vpnblocked']
                        }, enckey or secret)

            # App disabled
            if not app.get('is_active', True):
                return signed_response({
                    "success": False,
                    "message": msgs['appdisabled']
                }, enckey or secret)

            # App paused
            if app.get('is_paused', False):
                return signed_response({
                    "success": False,
                    "message": msgs['pausedapp']
                }, enckey or secret)

            # Token system
            if app.get('tokensystem', False):
                token = data.get('token', '').strip()
                thash = data.get('thash', '').strip()
                if not token:
                    return signed_response({"success": False, "message": "Token must be provided."}, enckey or secret)
                if not thash:
                    return signed_response({"success": False, "message": "Hash must be provided."}, enckey or secret)
                result = _verify_token(token, thash, secret)
                if result == 'invalid_token':
                    return signed_response({"success": False, "message": msgs['tokeninvalid']}, enckey or secret)
                if result == 'hash_mismatch':
                    return signed_response({"success": False, "message": msgs['tokenhash']}, enckey or secret)

            # Version check
            if ver and ver != str(app.get('version', '')):
                return signed_response({
                    "success": False,
                    "message": "invalidver",
                    "download": app.get('download_link', '')
                }, enckey or secret)

            # Hash check
            if app.get('hash_check') and app.get('server_hash') and file_hash:
                if file_hash not in app['server_hash']:
                    return signed_response({
                        "success": False,
                        "message": msgs['hashcheckfail']
                    }, enckey or secret)

            sessionid = db.create_session(app['_id'], enckey)
            stats     = db.get_app_stats(app['_id'])
            domain    = request.host_url.rstrip('/')

            return signed_response({
                "success": True,
                "message": "Initialized",
                "sessionid": sessionid,
                "appinfo": {
                    "numUsers":          str(stats.get('numUsers', 0)),
                    "numOnlineUsers":    str(stats.get('numOnlineUsers', 0)),
                    "numKeys":           str(stats.get('numKeys', 0)),
                    "version":           str(app.get('version', '1.0')),
                    "customerPanelLink": domain
                },
                "newSession": True,
                "nonce": make_nonce()
            }, enckey or secret)

        # ── All other actions require a valid session ──────────────────────────
        sessionid = data.get('sessionid', '').strip()
        session   = db.get_session(sessionid)
        if not session:
            return signed_response({"success": False, "message": "Invalid session ID."}, secret)

        enckey   = get_enckey(session)
        resp_key = enckey if enckey else secret

        # Session expiry check
        expiry_secs = int(app.get('session_expiry', 3600))
        age = (datetime.utcnow() - session['created_at']).total_seconds()
        if age > expiry_secs:
            return signed_response({
                "success": False,
                "message": "Session timed out. Please re-initiate."
            }, resp_key)

        hwid = data.get('hwid', '').strip()
        ip   = get_ip()

        # ── Blacklist check ───────────────────────────────────────────────────
        if db.check_blacklisted(app['_id'], hwid=hwid or None, ip=ip or None):
            return signed_response({"success": False, "message": msgs['hwidblacked']}, resp_key)

        # ── HWID minimum length (forceHwid + minHwid) ────────────────────────
        min_hwid = int(app.get('minHwid', 0))
        force_hwid = app.get('force_hwid', False)

        if force_hwid and not hwid:
            return signed_response({
                "success": False,
                "message": "Hardware ID is required for this application."
            }, resp_key)

        if min_hwid and hwid and len(hwid) < min_hwid:
            return signed_response({
                "success": False,
                "message": f"Hardware ID is too short. Minimum length is {min_hwid} characters."
            }, resp_key)

        # ── Login ─────────────────────────────────────────────────────────────
        if app_type == 'login':
            username = data.get('username', '').strip()
            password = data.get('pass', '')
            user, error = db.api_login(secret, username, password, hwid)
            if error:
                mapped = _map_error(error, msgs)
                dw.send_event(
                    app.get('discord_webhook_url', ''), 'error',
                    username or 'Unknown', ip, app['name'],
                    {'Reason': error, 'Action': 'Login Failed'}
                )
                return signed_response({"success": False, "message": mapped}, resp_key)
            db.set_session_validated(sessionid, username)
            db.add_log(app['_id'], username, f"Logged in from {ip}", ip)
            dw.send_event(
                app.get('discord_webhook_url', ''), 'login',
                username, ip, app['name'],
                {'HWID': hwid or 'N/A'}
            )
            return signed_response({
                "success": True,
                "message": msgs['loggedin'],
                "info": format_user_info(user, ip),
                "sessionid": sessionid,
                "nonce": make_nonce()
            }, resp_key)

        # ── Register ──────────────────────────────────────────────────────────
        if app_type == 'register':
            username    = data.get('username', '').strip()
            password    = data.get('pass', '')
            license_key = data.get('key', '').strip()
            email       = data.get('email', '').strip()
            user, error = db.api_register(secret, username, password, license_key, hwid, email)
            if error:
                mapped = _map_error(error, msgs)
                dw.send_event(
                    app.get('discord_webhook_url', ''), 'error',
                    username or 'Unknown', ip, app['name'],
                    {'Reason': error, 'Action': 'Register Failed', 'Key': license_key or 'N/A'}
                )
                return signed_response({"success": False, "message": mapped}, resp_key)
            db.set_session_validated(sessionid, username)
            db.add_log(app['_id'], username, f"Registered with key {license_key} from {ip}", ip)
            dw.send_event(
                app.get('discord_webhook_url', ''), 'register',
                username, ip, app['name'],
                {'License Key': license_key, 'HWID': hwid or 'N/A'}
            )
            return signed_response({
                "success": True,
                "message": msgs['loggedin'],
                "info": format_user_info(user, ip),
                "sessionid": sessionid,
                "nonce": make_nonce()
            }, resp_key)

        # ── License ───────────────────────────────────────────────────────────
        if app_type == 'license':
            license_key = data.get('key', '').strip()
            user, error = db.api_license(secret, license_key, hwid)
            if error:
                mapped = _map_error(error, msgs)
                dw.send_event(
                    app.get('discord_webhook_url', ''), 'error',
                    license_key or 'Unknown', ip, app['name'],
                    {'Reason': error, 'Action': 'License Auth Failed'}
                )
                return signed_response({"success": False, "message": mapped}, resp_key)
            db.set_session_validated(sessionid, license_key)
            db.add_log(app['_id'], license_key, f"License auth from {ip}", ip)
            dw.send_event(
                app.get('discord_webhook_url', ''), 'license',
                license_key, ip, app['name'],
                {'HWID': hwid or 'N/A'}
            )
            return signed_response({
                "success": True,
                "message": msgs['loggedin'],
                "info": format_user_info(user, ip),
                "sessionid": sessionid,
                "nonce": make_nonce()
            }, resp_key)

        # ── Upgrade ───────────────────────────────────────────────────────────
        if app_type == 'upgrade':
            username    = data.get('username', '').strip()
            license_key = data.get('key', '').strip()
            upgrade_key = db.db.app_users.find_one({
                'app_id': app['_id'],
                'key': license_key,
                'is_active': True,
                'username': None
            })
            if not upgrade_key:
                upgrade_key = db.db.app_users.find_one({
                    'app_id': app['_id'],
                    'key': license_key,
                    'is_active': True,
                    '$or': [{'username': {'$exists': False}}, {'username': ''}]
                })
            if not upgrade_key:
                return signed_response({"success": False, "message": msgs['keynotfound']}, resp_key)
            existing = db.db.app_users.find_one({'app_id': app['_id'], 'username': username, 'is_active': True})
            if not existing:
                return signed_response({"success": False, "message": msgs['usernamenotfound']}, resp_key)
            base = existing.get('expiry') or datetime.utcnow()
            if base < datetime.utcnow():
                base = datetime.utcnow()
            pkg  = db.db.packages.find_one({'_id': upgrade_key.get('package_id')})
            days = int(pkg.get('duration_days', 30)) if pkg else 30
            new_expiry = base + timedelta(days=days)
            db.db.app_users.update_one({'_id': existing['_id']}, {'$set': {'expiry': new_expiry}})
            db.db.app_users.update_one({'_id': upgrade_key['_id']}, {'$set': {'username': f'__used__{username}', 'is_active': False}})
            db.add_log(app['_id'], username, f"Upgraded subscription with key {license_key}", ip)
            return signed_response({"success": True, "message": "Upgraded successfully", "nonce": make_nonce()}, resp_key)

        # ── Forgot password ───────────────────────────────────────────────────
        if app_type == 'forgot':
            username = data.get('username', '').strip()
            email    = data.get('email', '').strip()
            new_pass, error = db.api_forgot_password(secret, username, email)
            if error:
                return signed_response({"success": False, "message": error}, resp_key)
            return signed_response({
                "success": True,
                "message": new_pass,
                "nonce": make_nonce()
            }, resp_key)

        # ── Remaining actions need an authenticated session ───────────────────
        if not session.get('validated'):
            return signed_response({
                "success": False,
                "message": msgs['sessionunauthed']
            }, resp_key)

        credential = session.get('credential', '')

        # ── Check ─────────────────────────────────────────────────────────────
        if app_type == 'check':
            return signed_response({"success": True, "message": "Session is validated.", "nonce": make_nonce()}, resp_key)

        # ── Log ───────────────────────────────────────────────────────────────
        if app_type == 'log':
            pcname = data.get('pcuser') or data.get('pcname', 'Unknown')
            msg    = data.get('message', '')
            db.add_log(app['_id'], credential, f"[{pcname}] {msg}", ip)
            return signed_response({"success": True, "message": "Logged!"}, resp_key)

        # ── Var (app variable) ────────────────────────────────────────────────
        if app_type == 'var':
            varid   = data.get('varid', '').strip()
            vardata = db.get_app_var(app['_id'], varid)
            if vardata is not None:
                return signed_response({"success": True, "message": vardata, "nonce": make_nonce()}, resp_key)
            return signed_response({"success": False, "message": "Variable not found."}, resp_key)

        # ── SetVar (user variable) ────────────────────────────────────────────
        if app_type == 'setvar':
            var  = data.get('var', '').strip()
            vdat = data.get('data', '').strip()
            if not var:
                return signed_response({"success": True, "message": "No variable name provided"}, resp_key)
            if not vdat:
                return signed_response({"success": True, "message": "No variable data provided"}, resp_key)
            if len(vdat) > 500:
                return signed_response({"success": True, "message": "Variable data must be 500 characters or less"}, resp_key)
            db.set_user_var(app['_id'], credential, var, vdat)
            return signed_response({"success": True, "message": "Successfully set variable", "nonce": make_nonce()}, resp_key)

        # ── GetVar (user variable) ────────────────────────────────────────────
        if app_type == 'getvar':
            var = data.get('var', '').strip()
            val = db.get_user_var(app['_id'], credential, var)
            if val is None:
                return signed_response({"success": False, "message": "Variable not found for user"}, resp_key)
            return signed_response({
                "success": True,
                "message": "Successfully retrieved variable",
                "response": val,
                "nonce": make_nonce()
            }, resp_key)

        # ── Check Blacklist ───────────────────────────────────────────────────
        if app_type == 'checkblacklist':
            is_banned = db.check_blacklisted(app['_id'], hwid=hwid or None, ip=ip or None)
            if is_banned:
                return signed_response({"success": True,  "message": "Client is blacklisted",     "nonce": make_nonce()}, resp_key)
            return signed_response(    {"success": False, "message": "Client is not blacklisted"}, resp_key)

        # ── Fetch Online Users ────────────────────────────────────────────────
        if app_type == 'fetchOnline':
            online = db.get_online_users(app['_id'])
            users  = [{"credential": u} for u in online]
            if not users:
                return signed_response({"success": False, "message": "No online users found!", "nonce": make_nonce()}, resp_key)
            return signed_response({"success": True, "message": "Successfully fetched online users.", "users": users, "nonce": make_nonce()}, resp_key)

        # ── Fetch Stats ───────────────────────────────────────────────────────
        if app_type == 'fetchStats':
            stats  = db.get_app_stats(app['_id'])
            domain = request.host_url.rstrip('/')
            return signed_response({
                "success": True,
                "message": "Successfully fetched stats",
                "appinfo": {
                    "numUsers":          str(stats.get('numUsers', 0)),
                    "numOnlineUsers":    str(stats.get('numOnlineUsers', 0)),
                    "numKeys":           str(stats.get('numKeys', 0)),
                    "version":           str(app.get('version', '1.0')),
                    "customerPanelLink": domain
                },
                "nonce": make_nonce()
            }, resp_key)

        # ── Ban ───────────────────────────────────────────────────────────────
        if app_type == 'ban':
            reason = data.get('reason', 'Banned via client') or 'Banned via client'
            db.db.app_users.update_one(
                {'app_id': app['_id'], 'username': credential},
                {'$set': {'is_active': False, 'ban_reason': reason}}
            )
            db.add_log(app['_id'], credential, f"Self-banned: {reason}", ip)
            return signed_response({"success": True, "message": "Successfully Banned User", "nonce": make_nonce()}, resp_key)

        # ── Logout ────────────────────────────────────────────────────────────
        if app_type == 'logout':
            db.delete_session(sessionid)
            return signed_response({"success": True, "message": "Successfully logged out.", "nonce": make_nonce()}, resp_key)

        # ── Change Username ───────────────────────────────────────────────────
        if app_type == 'changeUsername':
            new_username = (data.get('newUsername') or data.get('newusername', '')).strip()
            if not new_username:
                return signed_response({"success": False, "message": "New username is required."}, resp_key)
            ok, result = db.api_change_username(app['_id'], credential, new_username)
            if result == 'already_used':
                return signed_response({"success": False, "message": msgs['usernametaken']}, resp_key)
            elif result == 'success':
                db.delete_session(sessionid)
                return signed_response({"success": True, "message": "Successfully changed username, user logged out.", "nonce": make_nonce()}, resp_key)
            else:
                return signed_response({"success": False, "message": "Failed to change username!"}, resp_key)

        # ── Webhook (proxy) ───────────────────────────────────────────────────
        if app_type == 'webhook':
            webid = data.get('webid', '').strip()
            webhook_doc = db.get_webhook_by_webid(app['_id'], webid)
            if not webhook_doc:
                return signed_response({"success": False, "message": "Webhook Not Found."}, resp_key)
            if webhook_doc.get('authed') and not session.get('validated'):
                return signed_response({"success": False, "message": msgs['sessionunauthed']}, resp_key)
            baselink = webhook_doc.get('url', '')
            params   = data.get('params', '')
            body     = data.get('body', '')
            conttype = data.get('conttype', '')
            url = baselink + (params or '')
            try:
                import requests as req_lib
                headers = {}
                if webhook_doc.get('useragent'):
                    headers['User-Agent'] = webhook_doc['useragent']
                if body:
                    if conttype:
                        headers['Content-Type'] = conttype
                    r = req_lib.post(url, data=body, headers=headers, timeout=10)
                else:
                    r = req_lib.get(url, headers=headers, timeout=10)
                return signed_response({
                    "success": True,
                    "message": r.text,
                    "nonce": make_nonce()
                }, resp_key)
            except Exception as e:
                return signed_response({"success": False, "message": f"Webhook request failed: {str(e)}"}, resp_key)

        # ── File (download) ───────────────────────────────────────────────────
        if app_type == 'file':
            fileid   = data.get('fileid', '').strip()
            file_doc = db.get_file_by_fileid(app['_id'], fileid)
            if not file_doc:
                return signed_response({"success": False, "message": "File not Found"}, resp_key)
            if file_doc.get('authed') and not session.get('validated'):
                return signed_response({"success": False, "message": msgs['sessionunauthed']}, resp_key)
            try:
                import requests as req_lib
                r = req_lib.get(file_doc['url'], timeout=30, allow_redirects=True)
                if r.status_code in (403, 404):
                    return signed_response({"success": False, "message": "File not found at URL."}, resp_key)
                encoded = base64.b64encode(r.content).decode('utf-8')
                return signed_response({
                    "success": True,
                    "message": "File retrieved",
                    "contents": encoded,
                    "nonce": make_nonce()
                }, resp_key)
            except Exception as e:
                return signed_response({"success": False, "message": f"Failed to retrieve file: {str(e)}"}, resp_key)

        # ── Chat: Get ─────────────────────────────────────────────────────────
        if app_type == 'chatget':
            channel = data.get('channel', 'global')
            msgs_list = db.get_chat_messages(app['_id'], channel)
            formatted = []
            for m in msgs_list:
                try:
                    ts = str(int(m['timestamp'].timestamp())) if hasattr(m.get('timestamp'), 'timestamp') else "0"
                except Exception:
                    ts = "0"
                formatted.append({
                    "author":    m.get('author', 'Unknown'),
                    "message":   m.get('message', ''),
                    "timestamp": ts
                })
            return signed_response({
                "success": True,
                "message": "Successfully retrieved chat messages",
                "messages": formatted,
                "nonce": make_nonce()
            }, resp_key)

        # ── Chat: Send ────────────────────────────────────────────────────────
        if app_type == 'chatsend':
            channel = data.get('channel', 'global')
            message = data.get('message', '').strip()
            if not message:
                return signed_response({"success": False, "message": "Message can't be blank"}, resp_key)
            if db.send_chat_message(app['_id'], channel, credential, message):
                return signed_response({"success": True, "message": "Successfully sent chat message", "nonce": make_nonce()}, resp_key)
            return signed_response({"success": False, "message": msgs['chatdelay']}, resp_key)

        return signed_response({"success": False, "message": "The value inputted for type parameter was not found"}, resp_key)

    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            secret_val = locals().get('secret', '')
            return signed_response({"success": False, "message": f"Server error: {str(e)}"}, secret_val)
        except Exception:
            resp = make_response(json.dumps({"success": False, "message": f"Server error: {str(e)}"}, separators=(',', ':')))
            resp.headers['Content-Type'] = 'application/json'
            resp.headers['signature'] = ''
            return resp
