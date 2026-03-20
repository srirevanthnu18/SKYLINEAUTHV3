from flask import session, request
from flask_socketio import emit, join_room
import hmac, hashlib

_online_users = {}
_user_roles   = {}
_secret_key   = ''


def _verify_token(username: str, token: str) -> bool:
    if not username or not token or not _secret_key:
        return False
    try:
        expected = hmac.new(_secret_key.encode(), username.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(token, expected)
    except Exception:
        return False


def register_events(socketio, db, secret_key=''):
    global _secret_key
    _secret_key = secret_key

    def _sid_user():
        sid = request.sid
        return _online_users.get(sid), _user_roles.get(sid, 'user')

    def _session_user():
        try:
            if 'admin_id' in session:
                return session.get('username'), session.get('role', 'admin')
            if 'user_id' in session:
                return session.get('username'), 'user'
        except Exception:
            pass
        return None, None

    def _resolve_user(auth=None):
        """Resolve user from cached sid, session, or auth token — in that order."""
        # 1. Already cached from a previous event
        username, role = _sid_user()
        if username:
            return username, role

        # 2. Flask session (works when cookies travel with the WS handshake)
        username, role = _session_user()
        if username:
            return username, role

        # 3. Auth dict (from connect handshake or per-event payload)
        if auth and isinstance(auth, dict):
            claimed_user = (auth.get('user') or '').strip()
            claimed_role = (auth.get('role') or 'user').strip()
            token        = (auth.get('token') or '').strip()
            if claimed_user and _verify_token(claimed_user, token):
                return claimed_user, claimed_role

        return None, None

    @socketio.on('connect')
    def on_connect(auth=None):
        username, role = _resolve_user(auth)

        if username:
            _online_users[request.sid] = username
            _user_roles[request.sid]   = role
            join_room(f'user_{username}')
            emit('online_status', {'username': username, 'online': True}, broadcast=True)
            print(f'[SOCKET] connect ok: {username} ({role}) sid={request.sid}')
        else:
            # Do NOT reject — allow connection so polling still works.
            # Identity will be resolved when the client emits 'auth' or sends a message.
            print(f'[SOCKET] connect: user unknown, allowing anyway. auth={auth}')

    @socketio.on('auth')
    def on_auth(data):
        """Client emits 'auth' right after connect to register themselves."""
        username, role = _resolve_user(data)
        if username:
            _online_users[request.sid] = username
            _user_roles[request.sid]   = role
            join_room(f'user_{username}')
            emit('online_status', {'username': username, 'online': True}, broadcast=True)
            emit('auth_ok', {'username': username})
            print(f'[SOCKET] auth event ok: {username}')
        else:
            print(f'[SOCKET] auth event FAILED, data={data}')

    @socketio.on('disconnect')
    def on_disconnect():
        username = _online_users.pop(request.sid, None)
        _user_roles.pop(request.sid, None)
        if username:
            still_online = username in _online_users.values()
            if not still_online:
                emit('online_status', {'username': username, 'online': False}, broadcast=True)
            print(f'[SOCKET] disconnect: {username}')

    @socketio.on('join_chat')
    def on_join_chat(data):
        room = data.get('room_id')
        if room:
            join_room(room)

    @socketio.on('send_message')
    def on_send_message(data):
        username, role = _resolve_user(data)
        if not username:
            print('[SOCKET] send_message: no user, dropping')
            return

        # Cache it for future events on this sid
        if not _online_users.get(request.sid):
            _online_users[request.sid] = username
            _user_roles[request.sid]   = role

        room    = data.get('room_id')
        to_user = data.get('to_user')
        text    = (data.get('message') or '').strip()
        if not text or not room or not to_user:
            return

        print(f'[SOCKET] msg {username} -> {to_user}: {text[:40]}')
        msg = db.save_chat_message(
            room_id=room,
            from_username=username,
            from_role=role,
            to_username=to_user,
            message=text,
        )

        sender_admin    = db.db.admins.find_one({'username': username}, {'profile_pic': 1})
        profile_pic     = sender_admin.get('profile_pic') if sender_admin else None
        profile_pic_url = f'/static/uploads/{profile_pic}' if profile_pic else None

        payload = {
            'id':             str(msg['_id']),
            'from_username':  username,
            'from_role':      role,
            'to_username':    to_user,
            'message':        text,
            'timestamp':      msg['timestamp'].strftime('%H:%M'),
            'timestamp_full': msg['timestamp'].isoformat(),
            'room_id':        room,
            'profile_pic_url': profile_pic_url,
        }
        emit('new_message',          payload, room=room)
        emit('message_notification', payload, room=f'user_{to_user}')

    @socketio.on('typing')
    def on_typing(data):
        username, _ = _resolve_user()
        if not username:
            return
        room    = data.get('room_id')
        to_user = data.get('to_user')
        if room and to_user:
            emit('user_typing', {'username': username}, room=room, include_self=False)

    @socketio.on('stop_typing')
    def on_stop_typing(data):
        username, _ = _resolve_user()
        if not username:
            return
        room = data.get('room_id')
        if room:
            emit('user_stop_typing', {'username': username}, room=room, include_self=False)

    @socketio.on('get_online_status')
    def on_get_status(data):
        target = data.get('username')
        online = target in _online_users.values()
        emit('online_status', {'username': target, 'online': online})

    @socketio.on('mark_read')
    def on_mark_read(data):
        username, _ = _resolve_user()
        room = data.get('room_id')
        if username and room:
            db.mark_messages_read(room, username)
