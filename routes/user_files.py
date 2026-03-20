from flask import Blueprint, render_template, session, redirect, url_for
from models import db
from routes.auth import user_login_required, get_current_user

user_files_bp = Blueprint('user_files', __name__)


@user_files_bp.route('/user/files')
@user_login_required
def index():
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    app_id = str(user.get('app_id', ''))
    files = db.get_files(app_id) if app_id else []
    return render_template('user_files.html', user=user, files=files)
