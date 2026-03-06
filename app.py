# Updated for GitHub sync
from flask import Flask

from config import Config
from models import db


def create_app():
    print("Initializing Flask app...")
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.route('/')
    def index():
        from flask import redirect, url_for
        return redirect(url_for('auth.login'))

    @app.route('/health')
    def health():
        return "OK", 200

    print("Initializing database...")
    db.init_app(app)

    try:
        print("Registering blueprints...")
        from routes.auth import auth_bp
        from routes.dashboard import dashboard_bp
        from routes.apps import apps_bp
        from routes.users import users_bp
        from routes.resellers import resellers_bp
        from routes.packages import packages_bp
        from routes.profile import profile_bp
        from routes.admins import admins_bp
        from routes.api import api_bp
        from routes.discord_mgmt import discord_mgmt_bp
        from routes.apps_extra import apps_extra_bp

        app.register_blueprint(auth_bp)
        app.register_blueprint(dashboard_bp)
        app.register_blueprint(apps_bp)
        app.register_blueprint(users_bp)
        app.register_blueprint(resellers_bp)
        app.register_blueprint(packages_bp)
        app.register_blueprint(profile_bp)
        app.register_blueprint(admins_bp)
        app.register_blueprint(api_bp)
        app.register_blueprint(discord_mgmt_bp)
        app.register_blueprint(apps_extra_bp)

        print("App created successfully.")
        return app
    except Exception as e:
        print(f"CRITICAL ERROR DURING APP CREATION: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


application = create_app()

if __name__ == '__main__':
    application.run(debug=True, host='0.0.0.0', port=5000)
