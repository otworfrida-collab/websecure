"""
WebSecure - Web Vulnerability Scanning and Monitoring Tool
Main application factory
"""

import os
from urllib.parse import urlparse

from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from flask_apscheduler import APScheduler
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# Initialize extensions
login_manager = LoginManager()
mail = Mail()
scheduler = APScheduler()
mongo_client = None
mongo_db = None


def _get_default_db_name(mongo_uri: str) -> str:
    parsed = urlparse(mongo_uri)
    if parsed.path and parsed.path != '/':
        return parsed.path.lstrip('/')
    return os.getenv('MONGODB_DB', 'websecure')


def init_mongo(app: Flask):
    global mongo_client, mongo_db

    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/websecure')
    db_name = os.getenv('MONGODB_DB') or _get_default_db_name(mongo_uri)

    mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000)
    mongo_db = mongo_client[db_name]


def create_app():
    """Application factory pattern."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    app = Flask(
        __name__,
        template_folder=os.path.join(project_root, 'templates'),
        static_folder=os.path.join(os.path.dirname(__file__), 'static')
    )

    # ── Configuration ─────────────────────────────────────────────────────────
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
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
    init_mongo(app)
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
            count = Alert.count_unread(current_user.id)
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

    # ── Ensure database indexes ───────────────────────────────────────────────
    with app.app_context():
        from app.models.models import ensure_indexes
        ensure_indexes()

    # ── Start scheduler ───────────────────────────────────────────────────────
    if not scheduler.running:
        from app.utils.scheduler import register_jobs
        scheduler.init_app(app)
        register_jobs(scheduler)
        scheduler.start()

    return app
