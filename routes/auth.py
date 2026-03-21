from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from models import db
from functools import wraps

auth_bp = Blueprint('auth', __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            if 'user_id' in session:
                return redirect(url_for('auth.user_dashboard'))
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'admin_id' not in session:
                if 'user_id' in session:
                    return redirect(url_for('auth.user_dashboard'))
                return redirect(url_for('auth.login'))
            admin = db.get_admin_by_id(session['admin_id'])
            if not admin or admin['role'] not in roles:
                flash('Access denied.', 'error')
                return redirect(url_for('dashboard.index'))
            return f(*args, **kwargs)
        return decorated
    return decorator


def get_current_admin():
    if 'admin_id' in session:
        admin = db.get_admin_by_id(session['admin_id'])
        if admin:
            session['credits'] = '∞' if admin['role'] == 'superadmin' else admin.get('credits', 0)
            session['profile_pic'] = admin.get('profile_pic') or ''
        return admin
    return None



def user_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if 'admin_id' in session:
                return redirect(url_for('dashboard.index'))
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    if 'user_id' in session:
        return db.get_app_user_by_id(session['user_id'])
    return None


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'admin_id' in session:
        return redirect(url_for('dashboard.index'))
    if 'user_id' in session:
        return redirect(url_for('auth.user_dashboard'))

    if db.count_admins() == 0:
        return redirect(url_for('auth.setup'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        admin = db.verify_admin(username, password)
        if admin:
            login_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if login_ip:
                login_ip = login_ip.split(',')[0].strip()
            db.update_login_ip(str(admin['_id']), login_ip)

            session['admin_id'] = str(admin['_id'])
            session['username'] = admin['username']
            session['role'] = admin['role']
            session['credits'] = '∞' if admin['role'] == 'superadmin' else admin.get('credits', 0)
            session['profile_pic'] = admin.get('profile_pic') or ''
            flash('Login successfully.', 'login-success')
            return redirect(url_for('announcements.index'))
        user = db.verify_app_user(username, password)
        if user:
            session['user_id'] = str(user['_id'])
            session['username'] = user['key']
            session['role'] = 'user'
            session['credits'] = 0
            return redirect(url_for('auth.user_dashboard'))
        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if db.count_admins() > 0:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()

        if not username or not password:
            flash('Username and password are required.', 'error')
        else:
            admin_id = db.create_admin(username, password, email, 'superadmin')
            if admin_id:
                session['admin_id'] = str(admin_id)
                session['username'] = username
                session['role'] = 'superadmin'
                session['credits'] = '∞'
                flash('Super Admin account created!', 'success')
                return redirect(url_for('dashboard.index'))
            else:
                flash('Failed to create account.', 'error')

    return render_template('setup.html')


@auth_bp.route('/user')
@user_login_required
def user_dashboard():
    from models import db as _db
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    announcements = _db.get_announcements()
    return render_template('user_dashboard.html', user=user, announcements=announcements)


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
