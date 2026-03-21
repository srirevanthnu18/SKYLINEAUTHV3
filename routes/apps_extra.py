from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db
from routes.auth import login_required, role_required, get_current_admin

apps_extra_bp = Blueprint('apps_extra', __name__)

@apps_extra_bp.route('/apps/<app_id>/variables')
@login_required
@role_required('superadmin', 'admin')
def variables(app_id):
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    if not app:
        flash('App not found.', 'error')
        return redirect(url_for('apps.index'))
    
    vars_dict = db.get_app_vars(app_id)
    return render_template('app_variables.html', admin=admin, app=app, variables=vars_dict)

@apps_extra_bp.route('/apps/<app_id>/variables/create', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def create_variable(app_id):
    varid = request.form.get('varid')
    vardata = request.form.get('vardata')
    if not varid or not vardata:
        flash('Variable ID and Data are required.', 'error')
    else:
        db.set_app_var(app_id, varid, vardata)
        flash('Variable created/updated.', 'success')
    return redirect(url_for('apps_extra.variables', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/variables/delete/<varid>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def delete_variable(app_id, varid):
    db.delete_app_var(app_id, varid)
    flash('Variable deleted.', 'success')
    return redirect(url_for('apps_extra.variables', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/webhooks')
@login_required
@role_required('superadmin', 'admin')
def webhooks(app_id):
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    webhooks = db.get_webhooks(app_id)
    return render_template('app_webhooks.html', admin=admin, app=app, webhooks=webhooks)

@apps_extra_bp.route('/apps/<app_id>/webhooks/create', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def create_webhook(app_id):
    name = request.form.get('name')
    url = request.form.get('url')
    authed = request.form.get('authed') == 'on'
    db.create_webhook(app_id, name, url, authed)
    flash('Webhook created.', 'success')
    return redirect(url_for('apps_extra.webhooks', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/webhooks/delete/<webhook_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def delete_webhook(app_id, webhook_id):
    db.delete_webhook(webhook_id)
    flash('Webhook deleted.', 'success')
    return redirect(url_for('apps_extra.webhooks', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/files')
@login_required
@role_required('superadmin', 'admin')
def files(app_id):
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    files = db.get_files(app_id)
    return render_template('app_files.html', admin=admin, app=app, files=files)

@apps_extra_bp.route('/apps/<app_id>/files/create', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def create_file(app_id):
    name = request.form.get('name')
    url = request.form.get('url')
    authed = request.form.get('authed') == 'on'
    db.create_file(app_id, name, url, authed=authed)
    flash('File entry created.', 'success')
    return redirect(url_for('apps_extra.files', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/files/delete/<file_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def delete_file(app_id, file_id):
    db.delete_file(file_id)
    flash('File deleted.', 'success')
    return redirect(url_for('apps_extra.files', app_id=app_id))

# ── Blacklists ───────────────────────────────────────────────────

@apps_extra_bp.route('/apps/<app_id>/blacklists')
@login_required
@role_required('superadmin', 'admin')
def blacklists(app_id):
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    bls = db.get_blacklists(app_id)
    return render_template('app_blacklists.html', admin=admin, app=app, blacklists=bls)

@apps_extra_bp.route('/apps/<app_id>/blacklists/add', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def add_blacklist(app_id):
    item = request.form.get('item')
    bl_type = request.form.get('type')
    db.add_blacklist(app_id, item, bl_type)
    flash(f'{bl_type.upper()} blacklisted.', 'success')
    return redirect(url_for('apps_extra.blacklists', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/blacklists/delete/<blacklist_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def delete_blacklist(app_id, blacklist_id):
    db.delete_blacklist(blacklist_id)
    flash('Blacklist removed.', 'success')
    return redirect(url_for('apps_extra.blacklists', app_id=app_id))

# ── Logs ─────────────────────────────────────────────────────────

@apps_extra_bp.route('/apps/<app_id>/logs')
@login_required
@role_required('superadmin', 'admin')
def logs(app_id):
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    app_logs = db.get_logs(app_id)
    return render_template('app_logs.html', admin=admin, app=app, logs=app_logs)

@apps_extra_bp.route('/apps/<app_id>/logs/clear', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def clear_logs(app_id):
    db.clear_logs(app_id)
    flash('All logs cleared.', 'success')
    return redirect(url_for('apps_extra.logs', app_id=app_id))

# ── Chat ─────────────────────────────────────────────────────────

@apps_extra_bp.route('/apps/<app_id>/chats')
@login_required
@role_required('superadmin', 'admin')
def chats(app_id):
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    channels = db.get_chat_channels(app_id)
    return render_template('app_chats.html', admin=admin, app=app, channels=channels)

@apps_extra_bp.route('/apps/<app_id>/chats/create', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def create_chat(app_id):
    name = request.form.get('name')
    delay = request.form.get('delay', 1)
    db.create_chat_channel(app_id, name, delay)
    flash('Chat channel created.', 'success')
    return redirect(url_for('apps_extra.chats', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/chats/delete/<channel_id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def delete_chat(app_id, channel_id):
    db.delete_chat_channel(channel_id)
    flash('Channel and messages deleted.', 'success')
    return redirect(url_for('apps_extra.chats', app_id=app_id))

@apps_extra_bp.route('/apps/<app_id>/chats/view/<channel_name>')
@login_required
@role_required('superadmin', 'admin')
def view_chat(app_id, channel_name):
    # This would need a separate template if we want a dedicated view, 
    # but for now we can just show messages.
    admin = get_current_admin()
    app = db.get_app_by_id(app_id)
    messages = db.get_chat_messages(app_id, channel_name)
    return render_template('app_chat_messages.html', admin=admin, app=app, channel_name=channel_name, messages=messages)
