import hmac
import hashlib
import json
import secrets
import base64
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, make_response
from models import db
import discord_webhook as dw   # per-app event webhook helper

api_bp = Blueprint('api', __name__, url_prefix='/api/1.2')


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
    forwarded = request.headers.get('X-Forwarded-For', '')
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
            # No expiry = Lifetime access. Use a far-future unix timestamp
            # so SDKs that try to parse the date don't error.
            expiry_ts = "9999999999"
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

        # Always include at least one subscription — SDKs index [0] directly
        subs = [{
            "subscription": sub_name,
            "expiry": expiry_ts,
            "timeleft": timeleft_str
        }]

        # Use username if set, otherwise fall back to the key (license-only auth)
        username = user.get('username') or user.get('key') or "Unknown"

        return {
            "username": username,
            "ip": ip or "0.0.0.0",
            "hwid": user.get('hwid') or '',
            "createdate": created_ts,
            "lastlogin": str(int(now.timestamp())),
            "subscriptions": subs
        }
    except Exception:
        return {
            "username": user.get('username') or user.get('key') or "Unknown",
            "ip": ip or "0.0.0.0",
            "hwid": user.get('hwid') or '',
            "createdate": "0",
            "lastlogin": "0",
            "subscriptions": [{
                "subscription": "default",
                "expiry": "9999999999",
                "timeleft": "9999999999"
            }]
        }


@api_bp.route('/', methods=['POST', 'GET'])
def handle_api():
    try:
        data = request.form if request.method == 'POST' else request.args
        app_type = data.get('type', '').strip()
        ownerid  = data.get('ownerid', '').strip()
        name     = data.get('name', '').strip()

        if not ownerid or not name:
            return error_response("OwnerID and name are required.")

        oid = db._to_id(ownerid)
        or_clauses = [{'owner_id': ownerid}]
        if oid:
            or_clauses.append({'owner_mongo_id': oid})
            or_clauses.append({'owner_id': oid})
            or_clauses.append({'owner_id': str(oid)})

        app = db.db.apps.find_one({'name': name, '$or': or_clauses})
        if not app:
            return error_response("Application not found. Check your ownerid, name, and secret.")

        secret = app.get('secret_key', '')

        # ── Init ──────────────────────────────────────────────────────────────
        if app_type == 'init':
            ver       = data.get('ver', '').strip()
            enckey    = data.get('enckey', '')
            file_hash = data.get('hash', '')

            if not app.get('is_active', True):
                return signed_response({
                    "success": False,
                    "message": app.get('app_disabled_msg', 'Application disabled.')
                }, enckey or secret)

            if app.get('is_paused', False):
                return signed_response({
                    "success": False,
                    "message": app.get('paused_msg', 'Application is currently paused, please wait for the developer to say otherwise.')
                }, enckey or secret)

            if ver and ver != str(app.get('version', '')):
                return signed_response({
                    "success": False,
                    "message": "invalidver",
                    "download": app.get('download_link', '')
                }, enckey or secret)

            if app.get('hash_check') and app.get('server_hash') and file_hash:
                if file_hash != app['server_hash']:
                    return signed_response({
                        "success": False,
                        "message": app.get('hash_check_fail_msg', 'File on your disk is modified. Please re-download.')
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

        # ── All other actions require a valid session ─────────────────────────
        sessionid = data.get('sessionid', '').strip()
        session   = db.get_session(sessionid)
        if not session:
            return signed_response({"success": False, "message": "Invalid session ID."}, secret)

        # Signing key: use enckey from init if client sent one, else app secret
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
            return signed_response({"success": False, "message": "You are blacklisted."}, resp_key)

        # ── Login ─────────────────────────────────────────────────────────────
        if app_type == 'login':
            username = data.get('username', '').strip()
            password = data.get('pass', '')
            user, error = db.api_login(secret, username, password, hwid)
            if error:
                dw.send_event(
                    app.get('discord_webhook_url', ''), 'error',
                    username or 'Unknown', ip, app['name'],
                    {'Reason': error, 'Action': 'Login Failed'}
                )
                return signed_response({"success": False, "message": error}, resp_key)
            db.set_session_validated(sessionid, username)
            db.add_log(app['_id'], username, f"Logged in from {ip}", ip)
            dw.send_event(
                app.get('discord_webhook_url', ''), 'login',
                username, ip, app['name'],
                {'HWID': hwid or 'N/A'}
            )
            return signed_response({
                "success": True,
                "message": "Logged in!",
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
                dw.send_event(
                    app.get('discord_webhook_url', ''), 'error',
                    username or 'Unknown', ip, app['name'],
                    {'Reason': error, 'Action': 'Register Failed', 'Key': license_key or 'N/A'}
                )
                return signed_response({"success": False, "message": error}, resp_key)
            db.set_session_validated(sessionid, username)
            db.add_log(app['_id'], username, f"Registered with key {license_key} from {ip}", ip)
            dw.send_event(
                app.get('discord_webhook_url', ''), 'register',
                username, ip, app['name'],
                {'License Key': license_key, 'HWID': hwid or 'N/A'}
            )
            return signed_response({
                "success": True,
                "message": "Logged in!",
                "info": format_user_info(user, ip),
                "sessionid": sessionid,
                "nonce": make_nonce()
            }, resp_key)

        # ── License ───────────────────────────────────────────────────────────
        if app_type == 'license':
            license_key = data.get('key', '').strip()
            user, error = db.api_license(secret, license_key, hwid)
            if error:
                dw.send_event(
                    app.get('discord_webhook_url', ''), 'error',
                    license_key or 'Unknown', ip, app['name'],
                    {'Reason': error, 'Action': 'License Auth Failed'}
                )
                return signed_response({"success": False, "message": error}, resp_key)
            db.set_session_validated(sessionid, license_key)
            db.add_log(app['_id'], license_key, f"License auth from {ip}", ip)
            dw.send_event(
                app.get('discord_webhook_url', ''), 'license',
                license_key, ip, app['name'],
                {'HWID': hwid or 'N/A'}
            )
            return signed_response({
                "success": True,
                "message": "Logged in!",
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
                return signed_response({"success": False, "message": "Upgrade key not found or already used."}, resp_key)
            existing = db.db.app_users.find_one({'app_id': app['_id'], 'username': username, 'is_active': True})
            if not existing:
                return signed_response({"success": False, "message": "User not found."}, resp_key)
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
                "message": "Session is not authenticated. Please login or use a license first."
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
                return signed_response({"success": False, "message": "Username already used!"}, resp_key)
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
                return signed_response({"success": False, "message": "Session is not authenticated."}, resp_key)
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
                return signed_response({"success": False, "message": "Session is not authenticated."}, resp_key)
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
            msgs    = db.get_chat_messages(app['_id'], channel)
            formatted = []
            for m in msgs:
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
            return signed_response({"success": False, "message": "Failed to send message."}, resp_key)

        return signed_response({"success": False, "message": f"The value inputted for type paramater was not found"}, resp_key)

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
            return resp, 500
