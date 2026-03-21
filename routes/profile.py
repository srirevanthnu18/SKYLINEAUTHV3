from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from models import db
from routes.auth import login_required, get_current_admin
from werkzeug.utils import secure_filename
import os
import uuid

profile_bp = Blueprint('profile', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@profile_bp.route('/profile')
@login_required
def index():
    admin = get_current_admin()
    return render_template('profile.html', admin=admin)


@profile_bp.route('/profile/update', methods=['POST'])
@login_required
def update():
    admin = get_current_admin()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm = request.form.get('confirm_password', '')
    username = request.form.get('username', '').strip()

    if password and password != confirm:
        flash('Passwords do not match.', 'error')
    else:
        data = {'email': email}
        if password:
            data['password'] = password
        # Only superadmin can change username
        if admin['role'] == 'superadmin' and username:
            data['username'] = username
        
        success, error = db.update_admin(str(admin['_id']), data)
        if success:
            # Update session username if changed
            if username and admin['role'] == 'superadmin':
                session['username'] = username
            flash('Profile updated!', 'success')
        else:
            flash(error, 'error')

    return redirect(url_for('profile.index'))


@profile_bp.route('/profile/upload-pic', methods=['POST'])
@login_required
def upload_pic():
    admin = get_current_admin()
    
    if 'profile_pic' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('profile.index'))
    
    file = request.files['profile_pic']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('profile.index'))
    
    if file and allowed_file(file.filename):
        # Create unique filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{str(admin['_id'])}_{uuid.uuid4().hex[:8]}.{ext}"
        
        # Ensure upload folder exists
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        # Delete old profile pic if exists
        old_pic = admin.get('profile_pic')
        if old_pic:
            old_path = os.path.join(upload_folder, old_pic)
            if os.path.exists(old_path):
                os.remove(old_path)
        
        # Save new file
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)
        
        db.update_admin(str(admin['_id']), {'profile_pic': filename})
        session['profile_pic'] = filename
        flash('Profile picture updated!', 'success')
    else:
        flash('Invalid file type. Use PNG, JPG, GIF or WebP.', 'error')

    return redirect(url_for('profile.index'))
