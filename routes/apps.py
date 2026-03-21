from flask import Blueprint, render_template, request, redirect, url_for, flash, Response
from models import db
from routes.auth import login_required, role_required, get_current_admin
import os
import secrets

apps_bp = Blueprint('apps', __name__)


@apps_bp.route('/apps')
@login_required
@role_required('superadmin', 'admin')
def index():
    admin = get_current_admin()
    if admin['role'] == 'superadmin':
        apps = db.get_apps()
    else:
        apps = db.get_apps()
    return render_template('apps.html', admin=admin, apps=apps)


@apps_bp.route('/apps/create', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def create():
    admin = get_current_admin()
    name = request.form.get('name', '').strip()
    if not name:
        flash('App name is required.', 'error')
    else:
        app_id = db.create_app(name, str(admin['_id']))
        flash(f'Application "{name}" created!', 'success')
    return redirect(url_for('apps.index'))


@apps_bp.route('/apps/delete/<app_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def delete(app_id):
    db.delete_app(app_id)
    flash('Application deleted.', 'success')
    return redirect(url_for('apps.index'))


@apps_bp.route('/apps/toggle/<app_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def toggle(app_id):
    db.toggle_app(app_id)
    flash('Application status updated.', 'success')
    return redirect(url_for('apps.index'))


@apps_bp.route('/apps/update_version/<app_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def update_version(app_id):
    version = request.form.get('version', '').strip()
    if version:
        db.update_app_version(app_id, version)
        flash('Application version updated.', 'success')
    else:
        flash('Version cannot be empty.', 'error')
    return redirect(url_for('apps.manage', app_id=app_id))


@apps_bp.route('/apps/regenerate-secret/<app_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def regenerate_secret(app_id):
    """Generate a brand-new 64-char secret key for this app."""
    app = db.get_app_by_id(app_id)
    if not app:
        flash('Application not found.', 'error')
        return redirect(url_for('apps.index'))
    new_secret = secrets.token_hex(32)  # 64 hex chars
    db.db.apps.update_one({'_id': app['_id']}, {'$set': {'secret_key': new_secret}})
    flash('Secret key regenerated! Download the SDK again to get updated credentials.', 'success')
    return redirect(url_for('apps.manage', app_id=app_id))


@apps_bp.route('/apps/manage/<app_id>')
@login_required
@role_required('superadmin', 'admin')
def manage(app_id):
    """Display detailed app management page with SDK download options."""
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    if not app:
        flash('Application not found.', 'error')
        return redirect(url_for('apps.index'))
    
    # Get owner info via owner_mongo_id (owner_id is now the owner_key string)
    owner_ref = str(app.get('owner_mongo_id') or app.get('owner_id', ''))
    owner = db.get_admin_by_id(owner_ref)
    
    # Build API URL from request - Point to 1.2
    api_url = f"{request.scheme}://{request.host}/api/1.2"
    
    return render_template('manage_app.html', 
                         admin=admin, 
                         app=app, 
                         owner=owner,
                         api_url=api_url)

@apps_bp.route('/apps/update_settings/<app_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def update_settings(app_id):
    data = {
        'version': request.form.get('version'),
        'is_active': request.form.get('is_active') == 'on',
        'is_paused': request.form.get('is_paused') == 'on',
        'hwid_check': request.form.get('hwid_check') == 'on',
        'vpn_block': request.form.get('vpn_block') == 'on',
        'hash_check': request.form.get('hash_check') == 'on',
        'force_encryption': request.form.get('force_encryption') == 'on',
        'app_disabled_msg': request.form.get('app_disabled_msg'),
        'paused_msg': request.form.get('paused_msg'),
        'download_link': request.form.get('download_link'),
        'session_expiry': int(request.form.get('session_expiry', 3600)),
        'server_hash': request.form.get('server_hash'),
        'minHwid': int(request.form.get('min_hwid', 0)),
        'discord_webhook_url': request.form.get('discord_webhook_url', '').strip(),
    }
    db.update_app_settings(app_id, data)
    flash('Application settings updated.', 'success')
    return redirect(url_for('apps.manage', app_id=app_id))


@apps_bp.route('/apps/download-sdk/<app_id>/<language>')
@login_required
@role_required('superadmin', 'admin')
def download_sdk(app_id, language):
    """Generate and download SDK file with pre-filled credentials."""
    app = db.get_app_by_id(app_id)
    if not app:
        flash('Application not found.', 'error')
        return redirect(url_for('apps.index'))
    
    # Build API URL
    api_url = f"{request.scheme}://{request.host}/api/1.2"
    version = app.get('version', '1.0.0')
    
    # SDK templates directory
    sdk_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'sdk')
    
    # Map language to file info
    sdk_files = {
        'python': ('neutron_sdk.py', 'text/x-python', f'{app["name"]}_sdk.py'),
        'csharp': ('KeyAuth.cs', 'text/plain', 'KeyAuth.cs'),
        'cpp': ('KeyAuth.hpp', 'text/plain', 'KeyAuth.hpp'),
    }
    
    if language not in sdk_files:
        flash('Invalid SDK language.', 'error')
        return redirect(url_for('apps.manage', app_id=app_id))
    
    template_file, content_type, download_name = sdk_files[language]
    template_path = os.path.join(sdk_dir, template_file)
    
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace placeholders with actual values
        content = content.replace('{{API_URL}}', api_url)
        content = content.replace('{{APP_SECRET}}', app['secret_key'])
        content = content.replace('{{APP_NAME}}', app['name'])
        content = content.replace('{{OWNER_ID}}', str(app['owner_id']))
        content = content.replace('{{VERSION}}', version)
        
        return Response(
            content,
            mimetype=content_type,
            headers={'Content-Disposition': f'attachment; filename={download_name}'}
        )
    except Exception as e:
        flash(f'Error generating SDK: {str(e)}', 'error')
        return redirect(url_for('apps.manage', app_id=app_id))

