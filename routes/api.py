import hmac
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, make_response
from models import db

api_bp = Blueprint('api', __name__, url_prefix='/api/1.2')


def sign_response(data_json, key):
    if not key:
        return ""
    if isinstance(key, str):
        key = key.encode()
    return hmac.new(key, data_json.encode(), hashlib.sha256).hexdigest()


def signed_response(data, key):
    json_resp = json.dumps(data, separators=(',', ':'))
    sig = sign_response(json_resp, key)
    resp = make_response(json_resp)
    resp.headers['signature'] = sig
    resp.headers['Content-Type'] = 'application/json'
    return resp


def get_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def nonce():
    return secrets.token_hex(16)


def format_user_info(user, ip):
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
            expiry_ts = "0"
            timeleft_str = "0"

        created_ts = "0"
        if user.get('created_at') and hasattr(user['created_at'], 'timestamp'):
            created_ts = str(int(user['created_at'].timestamp()))

        return {
            "username": user.get('username') or user.get('key') or "Unknown",
            "ip": ip or "0.0.0.0",
            "hwid": user.get('hwid') or '',
            "createdate": created_ts,
            "lastlogin": str(int(now.timestamp())),
            "subscriptions": [
                {
                    "subscription": user.get('subscription_name', 'default'),
                    "expiry": expiry_ts,
                    "timeleft": timeleft_str
                }
            ] if expiry_ts != "0" else []
        }
    except Exception:
        return {
            "username": user.get('username') or user.get('key') or "Unknown",
            "ip": ip or "0.0.0.0",
            "hwid": user.get('hwid') or '',
            "createdate": "0",
            "lastlogin": "0",
            "subscriptions": []
        }


@api_bp.route('/', methods=['POST', 'GET'])
def handle_api():
    try:
        data = request.form if request.method == 'POST' else request.args
        app_type = data.get('type', '').strip()
        ownerid = data.get('ownerid', '').strip()
        name = data.get('name', '').strip()

        if not ownerid or not name:
            return jsonify({"success": False, "message": "OwnerID and name are required."})

        # Look up by name + ownerid using a 3-way $or to support:
        #   1. New format: owner_id stored as plain username string
        #   2. owner_mongo_id stored as ObjectId (apps created after the fix, internal ref)
        #   3. Legacy format: owner_id stored as ObjectId string (apps created before the fix)
        oid = db._to_id(ownerid)
        or_clauses = [{'owner_id': ownerid}]
        if oid:
            or_clauses.append({'owner_mongo_id': oid})
            or_clauses.append({'owner_id': oid})
        app = db.db.apps.find_one({'name': name, '$or': or_clauses})
        if not app:
            resp = make_response(json.dumps({"success": False, "message": "KeyAuth_Invalid"}, separators=(',', ':')))
            resp.headers['Content-Type'] = 'application/json'
            return resp

        secret = app['secret_key']

        # ── Init ─────────────────────────────────────────────────────────────
        if app_type == 'init':
            ver = data.get('ver', '').strip()
            enckey = data.get('enckey', '')
            file_hash = data.get('hash', '')

            if not app.get('is_active', True):
                return signed_response({"success": False, "message": app.get('app_disabled_msg', 'Application disabled.')}, secret)

            if app.get('is_paused', False):
                return signed_response({"success": False, "message": app.get('paused_msg', 'Application is currently paused, please wait for the developer to say otherwise.')}, secret)

            if ver and ver != str(app.get('version', '')):
                return signed_response({
                    "success": False,
                    "message": "invalidver",
                    "download": app.get('download_link', '')
                }, secret)

            if app.get('hash_check') and app.get('server_hash') and file_hash:
                if file_hash != app['server_hash']:
                    return signed_response({"success": False, "message": app.get('hash_check_fail_msg', 'File on your disk is modifed. Please re-download.')}, secret)

            sessionid = db.create_session(app['_id'], enckey)
            stats = db.get_app_stats(app['_id'])
            domain = request.host_url.rstrip('/')

            return signed_response({
                "success": True,
                "message": "Initialized",
                "sessionid": sessionid,
                "appinfo": {
                    "numUsers": str(stats.get('numUsers', 0)),
                    "numOnlineUsers": str(stats.get('numOnlineUsers', 0)),
                    "numKeys": str(stats.get('numKeys', 0)),
                    "version": str(app.get('version', '1.0')),
                    "customerPanelLink": domain
                },
                "newSession": True,
                "nonce": nonce()
            }, secret)

        # ── All other actions require a valid session ─────────────────────────
        sessionid = data.get('sessionid', '').strip()
        session = db.get_session(sessionid)
        if not session:
            return signed_response({"success": False, "message": "Invalid session ID."}, secret)

        # Build the per-session signing key (enckey + "-" + app_secret)
        sent_key = session.get('sent_key') or ''
        resp_key = f"{sent_key}-{secret}" if sent_key else secret

        # Session expiry
        expiry_secs = int(app.get('session_expiry', 3600))
        age = (datetime.utcnow() - session['created_at']).total_seconds()
        if age > expiry_secs:
            return signed_response({"success": False, "message": "Session timed out. Please re-initiate."}, resp_key)

        hwid = data.get('hwid', '').strip()
        ip = get_ip()

        # ── Blacklist check ───────────────────────────────────────────────────
        if db.check_blacklisted(app['_id'], hwid=hwid or None, ip=ip or None):
            return signed_response({"success": False, "message": "You are blacklisted."}, resp_key)

        # ── Login (username + password) ───────────────────────────────────────
        if app_type == 'login':
            username = data.get('username', '').strip()
            password = data.get('pass', '')
            user, error = db.api_login(secret, username, password, hwid)
            if error:
                return signed_response({"success": False, "message": error}, resp_key)
            db.set_session_validated(sessionid, username)
            db.add_log(app['_id'], username, f"Logged in from {ip}", ip)
            return signed_response({
                "success": True,
                "message": "Logged in!",
                "info": format_user_info(user, ip),
                "nonce": nonce()
            }, resp_key)

        # ── Register (license key → new account) ─────────────────────────────
        if app_type == 'register':
            username = data.get('username', '').strip()
            password = data.get('pass', '')
            license_key = data.get('key', '').strip()
            user, error = db.api_register(secret, username, password, license_key, hwid)
            if error:
                return signed_response({"success": False, "message": error}, resp_key)
            db.set_session_validated(sessionid, username)
            db.add_log(app['_id'], username, f"Registered with key {license_key} from {ip}", ip)
            return signed_response({
                "success": True,
                "message": "Logged in!",
                "info": format_user_info(user, ip),
                "nonce": nonce()
            }, resp_key)

        # ── License (key-only auth, no username/password) ─────────────────────
        if app_type == 'license':
            license_key = data.get('key', '').strip()
            user, error = db.api_license(secret, license_key, hwid)
            if error:
                return signed_response({"success": False, "message": error}, resp_key)
            db.set_session_validated(sessionid, license_key)
            db.add_log(app['_id'], license_key, f"License auth from {ip}", ip)
            return signed_response({
                "success": True,
                "message": "Logged in!",
                "info": format_user_info(user, ip),
                "nonce": nonce()
            }, resp_key)

        # ── Upgrade (use a new key to extend existing account) ────────────────
        if app_type == 'upgrade':
            username = data.get('username', '').strip()
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
                return signed_response({"success": False, "message": "Upgrade key not found or already used."}, resp_key)
            existing = db.db.app_users.find_one({'app_id': app['_id'], 'username': username, 'is_active': True})
            if not existing:
                return signed_response({"success": False, "message": "User not found."}, resp_key)
            base = existing.get('expiry') or datetime.utcnow()
            if base < datetime.utcnow():
                base = datetime.utcnow()
            pkg = db.db.packages.find_one({'_id': upgrade_key.get('package_id')})
            days = int(pkg.get('duration_days', 30)) if pkg else 30
            new_expiry = base + timedelta(days=days)
            db.db.app_users.update_one({'_id': existing['_id']}, {'$set': {'expiry': new_expiry}})
            db.db.app_users.update_one({'_id': upgrade_key['_id']}, {'$set': {'username': f'__used__{username}', 'is_active': False}})
            db.add_log(app['_id'], username, f"Upgraded subscription with key {license_key}", ip)
            return signed_response({"success": True, "message": "Upgraded successfully", "nonce": nonce()}, resp_key)

        # ── The remaining actions require an authenticated session ─────────────
        if not session.get('validated'):
            return signed_response({"success": False, "message": "Session is not authenticated. Please use the login or license endpoint first."}, resp_key)

        credential = session.get('credential', '')

        # ── Check (session still valid?) ──────────────────────────────────────
        if app_type == 'check':
            return signed_response({"success": True, "message": "Session is validated.", "nonce": nonce()}, resp_key)

        # ── Log (write a custom log entry) ────────────────────────────────────
        if app_type == 'log':
            pcname = data.get('pcuser') or data.get('pcname', 'Unknown')
            msg = data.get('message', '')
            db.add_log(app['_id'], credential, f"[{pcname}] {msg}", ip)
            resp = make_response('')
            resp.headers['Content-Type'] = 'application/json'
            return resp

        # ── Var (get a remote variable) ───────────────────────────────────────
        if app_type == 'var':
            varid = data.get('varid', '').strip()
            vardata = db.get_app_var(app['_id'], varid)
            if vardata is not None:
                return signed_response({"success": True, "message": vardata, "nonce": nonce()}, resp_key)
            return signed_response({"success": False, "message": "Variable not found."}, resp_key)

        # ── Check Blacklist ───────────────────────────────────────────────────
        if app_type == 'checkblacklist':
            is_banned = db.check_blacklisted(app['_id'], hwid=hwid or None, ip=ip or None)
            if is_banned:
                return signed_response({"success": True, "message": "Client is blacklisted", "nonce": nonce()}, resp_key)
            return signed_response({"success": False, "message": "Client is not blacklisted"}, resp_key)

        # ── Fetch Online Users ────────────────────────────────────────────────
        if app_type == 'fetchOnline':
            online = db.get_online_users(app['_id'])
            users = [{"credential": u} for u in online]
            if not users:
                return signed_response({"success": False, "message": "No online users found!"}, resp_key)
            return signed_response({"success": True, "message": "Successfully fetched online users.", "users": users, "nonce": nonce()}, resp_key)

        # ── Fetch Stats ───────────────────────────────────────────────────────
        if app_type == 'fetchStats':
            stats = db.get_app_stats(app['_id'])
            domain = request.host_url.rstrip('/')
            return signed_response({
                "success": True,
                "message": "Successfully fetched stats",
                "appinfo": {
                    "numUsers": str(stats.get('numUsers', 0)),
                    "numOnlineUsers": str(stats.get('numOnlineUsers', 0)),
                    "numKeys": str(stats.get('numKeys', 0)),
                    "version": str(app.get('version', '1.0')),
                    "customerPanelLink": domain
                },
                "nonce": nonce()
            }, resp_key)

        # ── Ban (ban current user) ────────────────────────────────────────────
        if app_type == 'ban':
            reason = data.get('reason', 'Banned via client') or 'Banned via client'
            db.db.app_users.update_one(
                {'app_id': app['_id'], 'username': credential},
                {'$set': {'is_active': False, 'ban_reason': reason}}
            )
            db.add_log(app['_id'], credential, f"Self-banned: {reason}", ip)
            return signed_response({"success": True, "message": "Successfully Banned User", "nonce": nonce()}, resp_key)

        # ── Logout ────────────────────────────────────────────────────────────
        if app_type == 'logout':
            db.delete_session(sessionid)
            return signed_response({"success": True, "message": "Successfully logged out.", "nonce": nonce()}, resp_key)

        # ── Chat: Get messages ────────────────────────────────────────────────
        if app_type == 'chatget':
            channel = data.get('channel', 'global')
            msgs = db.get_chat_messages(app['_id'], channel)
            formatted = []
            for m in msgs:
                try:
                    ts = str(int(m['timestamp'].timestamp())) if hasattr(m.get('timestamp'), 'timestamp') else "0"
                except Exception:
                    ts = "0"
                formatted.append({
                    "author": m.get('author', 'Unknown'),
                    "message": m.get('message', ''),
                    "timestamp": ts
                })
            return signed_response({"success": True, "message": "Successfully retrieved chat messages", "messages": formatted, "nonce": nonce()}, resp_key)

        # ── Chat: Send message ────────────────────────────────────────────────
        if app_type == 'chatsend':
            channel = data.get('channel', 'global')
            message = data.get('message', '').strip()
            if not message:
                return signed_response({"success": False, "message": "Message can't be blank"}, resp_key)
            if db.send_chat_message(app['_id'], channel, credential, message):
                return signed_response({"success": True, "message": "Successfully sent chat message", "nonce": nonce()}, resp_key)
            return signed_response({"success": False, "message": "Failed to send message."}, resp_key)

        return signed_response({"success": False, "message": f"Unknown action: {app_type}"}, resp_key)

    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            return signed_response({"success": False, "message": f"Server error: {str(e)}"}, secret)
        except Exception:
            return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500
