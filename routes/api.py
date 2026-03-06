import hmac
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, make_response
from models import db

api_bp = Blueprint('api', __name__, url_prefix='/api/1.2') # Standard KeyAuth API 1.2 path

def sign_response(data_json, key):
    """Sign the JSON response body using HMAC-SHA256."""
    if not key:
        return ""
    if isinstance(key, str):
        key = key.encode()
    signature = hmac.new(key, data_json.encode(), hashlib.sha256).hexdigest()
    return signature

def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

@api_bp.route('/', methods=['POST', 'GET']) # Single entry point as per PHP source
@api_bp.route('/', methods=['POST', 'GET']) # Single entry point as per PHP source
def handle_api():
    try:
        data = request.form if request.method == 'POST' else request.args
        app_type = data.get('type')
        ownerid = data.get('ownerid')
        name = data.get('name')
        
        if not ownerid or not name:
            return jsonify({"success": False, "message": "OwnerID and name are required."})

        # Fetch app
        app = db.db.apps.find_one({'name': name, 'owner_id': db._to_id(ownerid)})
        if not app:
            return "KeyAuth_Invalid" # Specific SDK error string (Note: SDKs might crash without signature)
        
        secret = app['secret_key']
        
        # ── Init Flow ───────────────────────────────────────────────────
        if app_type == 'init':
            ver = data.get('ver')
            enckey_sent = data.get('enckey')
            hash_sent = data.get('hash')
            
            # Maintenance check
            if not app.get('is_active', True):
                resp = {"success": False, "message": app.get('app_disabled_msg', "Application disabled.")}
                return signed_response(resp, secret)
            
            if app.get('is_paused', False):
                resp = {"success": False, "message": "Application is currently paused."}
                return signed_response(resp, secret)
                
            # Version check
            if ver and ver != app.get('version'):
                resp = {
                    "success": False, 
                    "message": "invalidver", 
                    "download": app.get('download_link', "")
                }
                return signed_response(resp, secret)
                
            # Hash check
            if app.get('hash_check') and app.get('server_hash'):
                if hash_sent != app['server_hash']:
                    resp = {"success": False, "message": "Hash check failed! Checksum mismatch."}
                    return signed_response(resp, secret)
            
            # Session creation
            sessionid = db.create_session(app['_id'], enckey_sent)
            stats = db.get_app_stats(app['_id'])
            
            resp = {
                "success": True,
                "message": "Initialized",
                "sessionid": sessionid,
                "appinfo": {
                    "numUsers": str(stats['numUsers']),
                    "numOnlineUsers": str(stats['numOnlineUsers']),
                    "numKeys": str(stats['numKeys']),
                    "version": app['version'],
                    "customerPanelLink": "https://skylineauthv-2--keyauth-server.replit.app"
                },
                "newsession": True, # For standard SDKs
                "newSession": True, # For AotForms and others
            }
            return signed_response(resp, secret)

        # ── Actions requiring session ────────────────────────────────────
        sessionid = data.get('sessionid')
        session = db.get_session(sessionid)
        if not session:
            return signed_response({"success": False, "message": "Session not found."}, secret)
        
        # Session enckey (sentKey + "-" + secret)
        sent_key = session.get('sent_key')
        resp_signing_key = f"{sent_key}-{secret}" if sent_key else secret

        # Check if session expired
        expiry = app.get('session_expiry', 3600)
        if (datetime.utcnow() - session['created_at']).total_seconds() > expiry:
            return signed_response({"success": False, "message": "Session expired."}, resp_signing_key)
        
        # IP/HWID Blacklist Check for all actions
        hwid = data.get('hwid')
        ip = get_ip()
        if db.check_blacklisted(app['_id'], hwid=hwid, ip=ip):
            resp = {"success": False, "message": "Client is blacklisted."}
            return signed_response(resp, resp_signing_key)

        if app_type == 'login':
            username = data.get('username')
            password = data.get('pass')
            user, error = db.api_login(secret, username, password, hwid)
            if error:
                resp = {"success": False, "message": error}
            else:
                db.set_session_validated(sessionid, username)
                db.add_log(app['_id'], username, "Logged in", ip)
                resp = {
                    "success": True,
                    "message": "Logged in!",
                    "info": format_user_info(user, ip),
                    "nonce": secrets.token_hex(16)
                }
            return signed_response(resp, resp_signing_key)

        if app_type == 'register':
            username = data.get('username')
            password = data.get('pass')
            key = data.get('key')
            user, error = db.api_register(secret, username, password, key, hwid)
            if error:
                resp = {"success": False, "message": error}
            else:
                db.set_session_validated(sessionid, username)
                db.add_log(app['_id'], username, f"Registered with key {key}", ip)
                resp = {
                    "success": True,
                    "message": "Successfully registered!",
                    "info": format_user_info(user, ip),
                    "nonce": secrets.token_hex(16)
                }
            return signed_response(resp, resp_signing_key)

        if app_type == 'license':
            key = data.get('key')
            # License-only login
            user, error = db.api_login(secret, key, key, hwid)
            if error:
                # Try to auto-register if it's the first time
                user, error = db.api_register(secret, key, key, key, hwid)
                
            if error:
                resp = {"success": False, "message": error}
            else:
                db.set_session_validated(sessionid, key)
                db.add_log(app['_id'], key, "Logged in via key", ip)
                resp = {
                    "success": True,
                    "message": "Logged in!",
                    "info": format_user_info(user, ip),
                    "nonce": secrets.token_hex(16)
                }
            return signed_response(resp, resp_signing_key)

        if app_type == 'upgrade':
            username = data.get('username')
            key = data.get('key')
            # Simplified upgrade logic
            res = db.db.app_users.find_one({'app_id': app['_id'], 'username': key, 'status': 'Active'})
            if not res:
                resp = {"success": False, "message": "Upgrade key not found or used."}
            else:
                resp = {"success": True, "message": "Upgraded successfully!"}
            return signed_response(resp, resp_signing_key)

        # ── Authenticated Required Actions ────────────────────────────────
        if not session.get('validated'):
            resp = {"success": False, "message": "Session unauthenticated."}
            return signed_response(resp, resp_signing_key)
        
        credential = session.get('credential')

        if app_type == 'check':
            resp = {"success": True, "message": "Session is valid."}
            return signed_response(resp, resp_signing_key)

        if app_type == 'log':
            pcname = data.get('pcname', 'Unknown')
            msg = data.get('message', '')
            db.add_log(app['_id'], credential, f"[{pcname}] {msg}", ip)
            resp = {"success": True, "message": "Logged successfully."}
            return signed_response(resp, resp_signing_key)

        if app_type == 'var':
            varid = data.get('varid')
            vardata = db.get_app_var(app['_id'], varid)
            if vardata:
                resp = {"success": True, "message": vardata}
            else:
                resp = {"success": False, "message": "Variable not found."}
            return signed_response(resp, resp_signing_key)

        if app_type == 'checkblacklist':
            is_banned = db.check_blacklisted(app['_id'], hwid=hwid, ip=ip)
            resp = {"success": is_banned, "message": "Client is blacklisted" if is_banned else "Client is not blacklisted"}
            return signed_response(resp, resp_signing_key)

        if app_type == 'chatget':
            channel = data.get('channel')
            msgs = db.get_chat_messages(app['_id'], channel)
            formatted = []
            for m in msgs:
                try:
                    ts = str(int(m['timestamp'].timestamp())) if hasattr(m['timestamp'], 'timestamp') else "0"
                except:
                    ts = "0"
                formatted.append({"author": m.get('author', 'Unknown'), "message": m.get('message', ''), "timestamp": ts})
            resp = {"success": True, "message": "Retrieved chat.", "messages": formatted}
            return signed_response(resp, resp_signing_key)

        if app_type == 'chatsend':
            channel = data.get('channel')
            message = data.get('message')
            if db.send_chat_message(app['_id'], channel, credential, message):
                resp = {"success": True, "message": "Sent message."}
            else:
                resp = {"success": False, "message": "Failed to send message."}
            return signed_response(resp, resp_signing_key)

        return jsonify({"success": False, "message": f"Action {app_type} not implemented."})
    except Exception as e:
        try:
            return signed_response({"success": False, "message": f"Server Error: {str(e)}"}, secret)
        except:
            return jsonify({"success": False, "message": f"Server Error: {str(e)}"}), 500

def signed_response(data, key):
    json_resp = json.dumps(data, separators=(',', ':'))
    signature = sign_response(json_resp, key)
    response = make_response(json_resp)
    response.headers['signature'] = signature
    return response

def format_user_info(user, ip):
    try:
        if user.get('expiry') and hasattr(user['expiry'], 'timestamp'):
            expiry_ts = str(int(user['expiry'].timestamp()))
            now = datetime.utcnow()
            # Handle potential offset issues by making naive if needed
            if user['expiry'].tzinfo:
                now = now.replace(tzinfo=user['expiry'].tzinfo)
            timeleft_sec = str(int((user['expiry'] - now).total_seconds()))
        else:
            expiry_ts = "0"
            timeleft_sec = "0"
            
        created_at_ts = str(int(user['created_at'].timestamp())) if user.get('created_at') and hasattr(user['created_at'], 'timestamp') else "0"
        
        return {
            "username": user.get('username') or user.get('key') or "Unknown",
            "ip": ip or "0.0.0.0",
            "hwid": user.get('hwid', ''),
            "createdate": created_at_ts,
            "lastlogin": str(int(datetime.utcnow().timestamp())),
            "subscriptions": [
                {
                    "subscription": "default", 
                    "expiry": expiry_ts, 
                    "timeleft": timeleft_sec
                }
            ] if user.get('expiry') else []
        }
    except Exception:
        # Fallback for unexpected data types
        return {
            "username": user.get('username') or user.get('key') or "Unknown",
            "ip": ip or "0.0.0.0",
            "hwid": user.get('hwid', ''),
            "createdate": "0",
            "lastlogin": "0",
            "subscriptions": []
        }

