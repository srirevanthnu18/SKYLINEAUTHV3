from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db
from routes.auth import login_required, get_current_admin, get_current_user

announcements_bp = Blueprint('announcements', __name__, url_prefix='/announcements')


def _any_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session and 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


@announcements_bp.route('/')
@_any_login_required
def index():
    admin = get_current_admin() if 'admin_id' in session else None
    user = get_current_user() if 'user_id' in session else None
    announcements = db.get_announcements()
    return render_template('announcements.html', admin=admin, user=user, announcements=announcements)


@announcements_bp.route('/create', methods=['POST'])
@login_required
def create():
    admin = get_current_admin()
    if admin['role'] not in ('superadmin', 'admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('announcements.index'))

    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
    pinned = request.form.get('pinned') == 'on'
    tag = request.form.get('tag', 'announcement').strip()

    if not title or not message:
        flash('Title and message are required.', 'error')
        return redirect(url_for('announcements.index'))

    db.create_announcement(title, message, admin['username'], pinned, tag)
    flash('Announcement posted.', 'success')
    return redirect(url_for('announcements.index'))


@announcements_bp.route('/<ann_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(ann_id):
    admin = get_current_admin()
    if admin['role'] not in ('superadmin', 'admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('announcements.index'))

    ann = db.get_announcement_by_id(ann_id)
    if not ann:
        flash('Announcement not found.', 'error')
        return redirect(url_for('announcements.index'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        message = request.form.get('message', '').strip()
        pinned = request.form.get('pinned') == 'on'
        tag = request.form.get('tag', 'announcement').strip()

        if not title or not message:
            flash('Title and message are required.', 'error')
            return redirect(url_for('announcements.edit', ann_id=ann_id))

        db.update_announcement(ann_id, title, message, pinned, tag)
        flash('Announcement updated.', 'success')
        return redirect(url_for('announcements.index'))

    return render_template('announcements.html', admin=admin,
                           announcements=db.get_announcements(), edit_ann=ann)


@announcements_bp.route('/<ann_id>/delete', methods=['POST'])
@login_required
def delete(ann_id):
    admin = get_current_admin()
    if admin['role'] not in ('superadmin', 'admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('announcements.index'))

    db.delete_announcement(ann_id)
    flash('Announcement deleted.', 'success')
    return redirect(url_for('announcements.index'))
