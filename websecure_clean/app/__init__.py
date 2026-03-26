"""
WebSecure - Web Vulnerability Scanning and Monitoring Tool
Main application factory
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_apscheduler import APScheduler
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
scheduler = APScheduler()


def create_app():
    """Application factory pattern."""
    app = Flask(__name__,
                template_folder='templates',
                static_folder='app/static')

    # ── Configuration ─────────────────────────────────────────────────────────
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///websecure.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Mail config
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', '')

    # Scheduler config
    app.config['SCHEDULER_API_ENABLED'] = False

    # ── Initialize extensions ─────────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access your dashboard.'
    login_manager.login_message_category = 'info'

    # ── Inject unread alert count into every template ─────────────────────────
    from flask_login import current_user

    @app.context_processor
    def inject_alert_count():
        if current_user.is_authenticated:
            from app.models.models import Alert
            count = Alert.query.filter_by(
                user_id=current_user.id, is_read=False).count()
            return {'unread_alert_count': count}
        return {'unread_alert_count': 0}

    # ── Register blueprints ───────────────────────────────────────────────────
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.websites import websites_bp
    from app.routes.scans import scans_bp
    from app.routes.reports import reports_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(websites_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    # ── Create database tables ────────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    # ── Start scheduler ───────────────────────────────────────────────────────
    if not scheduler.running:
        from app.utils.scheduler import register_jobs
        scheduler.init_app(app)
        register_jobs(scheduler)
        scheduler.start()

    return app
