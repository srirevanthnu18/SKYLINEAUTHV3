from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify
from models import db
from functools import wraps

chat_bp = Blueprint('chat', __name__, url_prefix='/chat')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session and 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def _current_user():
    if 'admin_id' in session:
        return {
            'id': session['admin_id'],
            'username': session['username'],
            'role': session['role'],
        }
    if 'user_id' in session:
        return {
            'id': session['user_id'],
            'username': session['username'],
            'role': 'user',
        }
    return None


def _role_color(role):
    return {
        'superadmin': 'admin',
        'admin': 'admin',
        'reseller': 'reseller',
        'user': 'user',
    }.get(role, 'user')


def _role_label(role):
    return {
        'superadmin': 'Super Admin',
        'admin': 'Admin',
        'reseller': 'Reseller',
        'user': 'User',
    }.get(role, role.title())


def _build_contacts(me):
    """Build full contact list with unread count + last message preview."""
    members = db.get_all_panel_members(exclude_username=me['username'])
    contacts = []
    for m in members:
        uname = m['username']
        room = '_'.join(sorted([me['username'], uname]))
        unread = db.get_unread_count(room, me['username'])
        last_msg = db.get_last_message(room)
        preview = ''
        last_ts = None
        if last_msg:
            preview = last_msg.get('message', '')
            preview = preview[:40] + '…' if len(preview) > 40 else preview
            last_ts = last_msg.get('timestamp')
        contacts.append({
            'username': uname,
            'display_name': m.get('display_name', uname),
            'role': m['role'],
            'display_role': m['display_role'],
            'color': m['color'],
            'initial': m['initial'],
            'type': m.get('type', 'admin'),
            'unread': unread,
            'preview': preview,
            'last_ts': last_ts.strftime('%H:%M') if last_ts else '',
            'has_history': bool(last_msg),
        })
    contacts.sort(key=lambda c: (-(c['unread'] > 0), -(c['has_history']), c['display_name'].lower()))
    return contacts


@chat_bp.route('/')
@login_required
def index():
    me = _current_user()
    contacts = _build_contacts(me)
    total_unread = sum(c['unread'] for c in contacts)
    return render_template(
        'chat.html',
        me=me,
        contacts=contacts,
        active_contact=None,
        messages=[],
        room_id=None,
        total_unread=total_unread,
        role_label=_role_label(me['role']),
        role_color=_role_color(me['role']),
    )


@chat_bp.route('/<target_username>')
@login_required
def conversation(target_username):
    me = _current_user()
    contacts = _build_contacts(me)

    active = None
    for c in contacts:
        if c['username'] == target_username:
            active = c
            break

    if not active:
        admin = db.db.admins.find_one({'username': target_username})
        if admin:
            active = {
                'username': admin['username'],
                'display_name': admin['username'],
                'role': admin['role'],
                'display_role': _role_label(admin['role']),
                'color': _role_color(admin['role']),
                'initial': admin['username'][0].upper(),
                'type': 'admin',
                'unread': 0,
                'preview': '',
                'last_ts': '',
            }
        else:
            app_user = db.db.app_users.find_one({'$or': [
                {'username': target_username},
                {'key': target_username},
            ]})
            if app_user:
                uname = app_user.get('username') or app_user.get('key', '')
                active = {
                    'username': uname,
                    'display_name': uname[:16] + '…' if len(uname) > 16 else uname,
                    'role': 'user',
                    'display_role': 'User',
                    'color': 'user',
                    'initial': uname[0].upper() if uname else '?',
                    'type': 'user',
                    'unread': 0,
                    'preview': '',
                    'last_ts': '',
                }

    if not active:
        return redirect(url_for('chat.index'))

    room = '_'.join(sorted([me['username'], target_username]))
    db.mark_messages_read(room, me['username'])
    messages = db.get_chat_history(room)
    total_unread = sum(c['unread'] for c in contacts)

    return render_template(
        'chat.html',
        me=me,
        contacts=contacts,
        active_contact=active,
        messages=messages,
        room_id=room,
        total_unread=total_unread,
        role_label=_role_label(me['role']),
        role_color=_role_color(me['role']),
    )


@chat_bp.route('/api/unread')
@login_required
def api_unread():
    me = _current_user()
    total = db.get_total_unread(me['username'])
    return jsonify({'unread': total})
