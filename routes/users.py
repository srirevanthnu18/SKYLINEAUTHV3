from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import db
from routes.auth import login_required, role_required, get_current_admin

users_bp = Blueprint('users', __name__)


@users_bp.route('/users')
@login_required
def index():
    admin = get_current_admin()
    app_id = request.args.get('app_id')
    apps = db.get_apps()

    if admin['role'] == 'reseller':
        users = db.get_app_users(app_id=app_id, created_by=str(admin['_id']))
        packages = db.get_reseller_packages(str(admin['_id']))
    else:
        users = db.get_app_users(app_id=app_id)
        packages = db.get_packages(app_id=app_id)

    # Enrich users with creator username
    for user in users:
        creator = db.get_admin_by_id(user.get('created_by'))
        user['creator_username'] = creator['username'] if creator else 'Unknown'

    return render_template('users.html', admin=admin, users=users, apps=apps,
                           packages=packages, selected_app=app_id)


@users_bp.route('/licenses')
@login_required
def licenses():
    admin = get_current_admin()
    app_id = request.args.get('app_id')
    apps = db.get_apps()

    if admin['role'] == 'reseller':
        users = db.get_app_users(app_id=app_id, created_by=str(admin['_id']))
        packages = db.get_reseller_packages(str(admin['_id']))
    else:
        users = db.get_app_users(app_id=app_id)
        packages = db.get_packages(app_id=app_id)

    # Enrich users with names
    for user in users:
        creator = db.get_admin_by_id(user.get('created_by'))
        user['creator_username'] = creator['username'] if creator else 'Unknown'
        app = db.get_app_by_id(user.get('app_id'))
        user['app_name'] = app['name'] if app else 'N/A'
        pkg = db.get_package_by_id(user.get('package_id'))
        user['package_name'] = pkg['name'] if pkg else 'N/A'

    return render_template('licenses.html', admin=admin, users=users, apps=apps,
                           packages=packages, selected_app=app_id)


@users_bp.route('/users/create', methods=['POST'])
@login_required
def create():
    from flask import session
    admin = get_current_admin()
    app_id = request.form.get('app_id')
    package_id = request.form.get('package_id')
    count = request.form.get('count', 1)
    custom_days = request.form.get('custom_days', '').strip()
    hwid_lock = request.form.get('hwid_lock') == 'on'
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not app_id or not package_id:
        flash('Application and package are required.', 'error')
        return redirect(url_for('users.index'))

    # Resellers can only use assigned packages
    if admin['role'] == 'reseller':
        from bson.objectid import ObjectId
        assigned = admin.get('assigned_packages', [])
        if ObjectId(package_id) not in assigned:
            flash('You do not have access to this package.', 'error')
            return redirect(url_for('users.index'))

    # Get package and app info for modal
    pkg = db.get_package_by_id(package_id)
    app = db.get_app_by_id(app_id)
    days_val = int(custom_days) if custom_days else None
    create_type = request.form.get('create_type', 'license')

    if create_type == 'user_account':
        created_users, error = db.create_user_direct(
            app_id, package_id, str(admin['_id']),
            count=count, custom_days=days_val, hwid_lock=hwid_lock,
            username=username if username else None,
            password=password if password else None,
            force_user_account=True,
        )
    else:
        custom_key = request.form.get('custom_key', '').strip()
        created_users, error = db.create_user_direct(
            app_id, package_id, str(admin['_id']),
            count=count, custom_days=days_val, hwid_lock=hwid_lock,
            custom_key=custom_key if custom_key else None,
        )

    if error:
        flash(error, 'error')
    else:
        # Calculate expiry for display
        from datetime import datetime, timedelta
        if days_val:
            expiry_date = (datetime.utcnow() + timedelta(days=days_val)).strftime('%Y-%m-%d')
        else:
            expiry_date = (datetime.utcnow() + timedelta(days=pkg['duration_days'])).strftime('%Y-%m-%d')
        
        # Store credentials in session for popup modal
        session['created_credentials'] = {
            'users': created_users,
            'package': pkg['name'],
            'app': app['name'],
            'expiry': expiry_date,
            'created_by': admin['username']
        }
        flash(f'Created {len(created_users)} user(s) successfully!', 'success')

    return redirect(request.referrer or url_for('users.index'))


@users_bp.route('/users/delete/<user_id>', methods=['POST'])
@login_required
def delete(user_id):
    admin = get_current_admin()
    if admin['role'] == 'reseller':
        user = db.get_app_user_by_id(user_id)
        if not user or str(user.get('created_by')) != str(admin['_id']):
            flash('Access denied.', 'error')
            return redirect(url_for('users.index'))
    db.delete_app_user(user_id)
    flash('User deleted.', 'success')
    return redirect(request.referrer or url_for('users.index'))


@users_bp.route('/users/toggle/<user_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def toggle(user_id):
    db.toggle_app_user(user_id)
    flash('User status updated.', 'success')
    return redirect(request.referrer or url_for('users.index'))


@users_bp.route('/users/reset-hwid/<user_id>', methods=['POST'])
@login_required
def reset_hwid(user_id):
    admin = get_current_admin()
    if admin['role'] == 'reseller':
        user = db.get_app_user_by_id(user_id)
        if not user or str(user.get('created_by')) != str(admin['_id']):
            flash('Access denied.', 'error')
            return redirect(url_for('users.index'))
    db.reset_hwid(user_id)
    flash('HWID reset successfully.', 'success')
    return redirect(request.referrer or url_for('users.index'))


@users_bp.route('/users/extend/<user_id>', methods=['POST'])
@login_required
def extend_license(user_id):
    admin = get_current_admin()
    days = request.form.get('days', 30)
    if admin['role'] == 'reseller':
        user = db.get_app_user_by_id(user_id)
        if not user or str(user.get('created_by')) != str(admin['_id']):
            flash('Access denied.', 'error')
            return redirect(url_for('users.index'))
    db.extend_license(user_id, days)
    flash(f'Key extended by {days} days.', 'success')
    return redirect(request.referrer or url_for('users.index'))


@users_bp.route('/users/ban/<user_id>', methods=['POST'])
@login_required
def ban_license(user_id):
    admin = get_current_admin()
    if admin['role'] == 'reseller':
        user = db.get_app_user_by_id(user_id)
        if not user or str(user.get('created_by')) != str(admin['_id']):
            flash('Access denied.', 'error')
            return redirect(url_for('users.index'))
    user = db.get_app_user_by_id(user_id)
    if user and user.get('is_active'):
        db.ban_license(user_id)
        flash('Key banned.', 'success')
    else:
        db.unban_license(user_id)
        flash('Key unbanned.', 'success')
    return redirect(request.referrer or url_for('users.index'))
