from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, current_app
from models import db
from functools import wraps
import hmac, hashlib


def _make_chat_token(username: str, secret_key: str) -> str:
    return hmac.new(secret_key.encode(), username.encode(), hashlib.sha256).hexdigest()

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
        admin = db.get_admin_by_id(session['admin_id'])
        return {
            'id': session['admin_id'],
            'username': session['username'],
            'role': session['role'],
            'profile_pic': admin.get('profile_pic') if admin else None,
        }
    if 'user_id' in session:
        return {
            'id': session['user_id'],
            'username': session['username'],
            'role': 'user',
            'profile_pic': None,
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
        'superadmin': 'Admin',
        'admin': 'Admin',
        'reseller': 'Reseller',
        'user': 'User',
    }.get(role, role.title())


def _pic_url(profile_pic):
    """Convert a stored profile_pic filename into a URL path, or return None."""
    if profile_pic:
        return f'/static/uploads/{profile_pic}'
    return None


def _get_contacts(me):
    contacts = []
    all_admins = db.get_admins()
    for a in all_admins:
        uname = a['username']
        if uname == me['username']:
            continue
        contacts.append({
            'username': uname,
            'role': a['role'],
            'display_role': _role_label(a['role']),
            'color': _role_color(a['role']),
            'initial': uname[0].upper(),
            'profile_pic_url': _pic_url(a.get('profile_pic')),
        })
    return contacts


@chat_bp.route('/')
@login_required
def index():
    me = _current_user()
    contacts = _get_contacts(me)
    for c in contacts:
        room = '_'.join(sorted([me['username'], c['username']]))
        c['unread'] = db.get_unread_count(room, me['username'])
    total_unread = sum(c['unread'] for c in contacts)
    chat_token = _make_chat_token(me['username'], current_app.config['SECRET_KEY'])
    return render_template(
        'chat.html',
        me=me,
        me_pic_url=_pic_url(me.get('profile_pic')),
        contacts=contacts,
        active_contact=None,
        messages=[],
        room_id=None,
        total_unread=total_unread,
        role_label=_role_label(me['role']),
        role_color=_role_color(me['role']),
        chat_token=chat_token,
    )


@chat_bp.route('/<target_username>')
@login_required
def conversation(target_username):
    me = _current_user()
    contacts = _get_contacts(me)

    active = None
    for c in contacts:
        room = '_'.join(sorted([me['username'], c['username']]))
        c['unread'] = db.get_unread_count(room, me['username'])
        if c['username'] == target_username:
            active = c

    if not active:
        admin = db.db.admins.find_one({'username': target_username})
        if admin:
            active = {
                'username': admin['username'],
                'role': admin['role'],
                'display_role': _role_label(admin['role']),
                'color': _role_color(admin['role']),
                'initial': admin['username'][0].upper(),
                'profile_pic_url': _pic_url(admin.get('profile_pic')),
            }

    if not active:
        return redirect(url_for('chat.index'))

    room = '_'.join(sorted([me['username'], target_username]))
    db.mark_messages_read(room, me['username'])
    messages = db.get_chat_history(room)

    # Attach profile pic URLs to each message's author
    author_pics = {}
    for msg in messages:
        sender = msg.get('from_username', '')
        if sender not in author_pics:
            a = db.db.admins.find_one({'username': sender}, {'profile_pic': 1})
            author_pics[sender] = _pic_url(a.get('profile_pic')) if a else None
        msg['author_pic_url'] = author_pics[sender]

    total_unread = sum(c['unread'] for c in contacts)
    chat_token = _make_chat_token(me['username'], current_app.config['SECRET_KEY'])

    return render_template(
        'chat.html',
        me=me,
        me_pic_url=_pic_url(me.get('profile_pic')),
        contacts=contacts,
        active_contact=active,
        messages=messages,
        room_id=room,
        total_unread=total_unread,
        role_label=_role_label(me['role']),
        role_color=_role_color(me['role']),
        chat_token=chat_token,
    )


@chat_bp.route('/api/unread')
@login_required
def api_unread():
    me = _current_user()
    contacts = _get_contacts(me)
    total = 0
    for c in contacts:
        room = '_'.join(sorted([me['username'], c['username']]))
        total += db.get_unread_count(room, me['username'])
    return jsonify({'unread': total})
