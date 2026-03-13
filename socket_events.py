from flask import session, request
from flask_socketio import emit, join_room, leave_room
from datetime import datetime

_online_users = {}


def register_events(socketio, db):

    def _current_user():
        if 'admin_id' in session:
            return session.get('username'), session.get('role', 'admin')
        if 'user_id' in session:
            return session.get('username'), 'user'
        return None, None

    @socketio.on('connect')
    def on_connect():
        username, role = _current_user()
        if not username:
            return False
        _online_users[request.sid] = username
        join_room(f'user_{username}')
        emit('online_status', {'username': username, 'online': True}, broadcast=True)

    @socketio.on('disconnect')
    def on_disconnect():
        username = _online_users.pop(request.sid, None)
        if username:
            still_online = username in _online_users.values()
            if not still_online:
                emit('online_status', {'username': username, 'online': False}, broadcast=True)

    @socketio.on('join_chat')
    def on_join_chat(data):
        room = data.get('room_id')
        if room:
            join_room(room)

    @socketio.on('send_message')
    def on_send_message(data):
        username, role = _current_user()
        if not username:
            return
        room = data.get('room_id')
        to_user = data.get('to_user')
        text = (data.get('message') or '').strip()
        if not text or not room or not to_user:
            return

        msg = db.save_chat_message(
            room_id=room,
            from_username=username,
            from_role=role,
            to_username=to_user,
            message=text,
        )

        payload = {
            'id': str(msg['_id']),
            'from_username': username,
            'from_role': role,
            'to_username': to_user,
            'message': text,
            'timestamp': msg['timestamp'].strftime('%H:%M'),
            'timestamp_full': msg['timestamp'].isoformat(),
            'room_id': room,
        }
        emit('new_message', payload, room=room)
        emit('message_notification', payload, room=f'user_{to_user}')

    @socketio.on('typing')
    def on_typing(data):
        username, _ = _current_user()
        if not username:
            return
        room = data.get('room_id')
        to_user = data.get('to_user')
        if room and to_user:
            emit('user_typing', {'username': username}, room=room, include_self=False)

    @socketio.on('stop_typing')
    def on_stop_typing(data):
        username, _ = _current_user()
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
        username, _ = _current_user()
        room = data.get('room_id')
        if username and room:
            db.mark_messages_read(room, username)
