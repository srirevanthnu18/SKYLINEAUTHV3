from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db
from routes.auth import login_required, user_login_required, get_current_admin, get_current_user

files_bp = Blueprint('files', __name__, url_prefix='/files')


def _any_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session and 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


@files_bp.route('/')
@_any_login_required
def index():
    files = db.get_global_files()
    admin = get_current_admin() if 'admin_id' in session else None
    user = get_current_user() if 'user_id' in session else None
    seen = set()
    categories = []
    for f in files:
        cat = f.get('category', 'general')
        if cat not in seen:
            seen.add(cat)
            categories.append(cat)
    return render_template('files.html', files=files, admin=admin, user=user, categories=categories)


@files_bp.route('/add', methods=['POST'])
@login_required
def add():
    admin = get_current_admin()
    if not admin or admin['role'] not in ('superadmin', 'admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('files.index'))

    name = request.form.get('name', '').strip()
    url = request.form.get('url', '').strip()
    description = request.form.get('description', '').strip()
    category = request.form.get('category', 'general').strip()

    if not name or not url:
        flash('File name and URL are required.', 'error')
        return redirect(url_for('files.index'))

    db.create_global_file(name, url, description, admin['username'], category)
    flash(f'File "{name}" added successfully.', 'success')
    return redirect(url_for('files.index'))


@files_bp.route('/<file_id>/delete', methods=['POST'])
@login_required
def delete(file_id):
    admin = get_current_admin()
    if not admin or admin['role'] not in ('superadmin', 'admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('files.index'))

    f = db.get_global_file_by_id(file_id)
    if not f:
        flash('File not found.', 'error')
        return redirect(url_for('files.index'))

    db.delete_global_file(file_id)
    flash('File removed.', 'success')
    return redirect(url_for('files.index'))
