"""
WebSecure Database Models
Defines Users, Websites, Scans, Vulnerabilities, and Alerts tables.
"""

from datetime import datetime
from flask_login import UserMixin
from app import db, login_manager


# ── User loader for Flask-Login ───────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ═════════════════════════════════════════════════════════════════════════════
# USER MODEL
# ═════════════════════════════════════════════════════════════════════════════
class User(UserMixin, db.Model):
    """Registered user account."""
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    is_active     = db.Column(db.Boolean, default=True)

    # Relationships
    websites = db.relationship('Website', backref='owner', lazy=True,
                               cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'


# ═════════════════════════════════════════════════════════════════════════════
# WEBSITE MODEL
# ═════════════════════════════════════════════════════════════════════════════
class Website(db.Model):
    """A website URL added by a user for monitoring."""
    __tablename__ = 'websites'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    url        = db.Column(db.String(512), nullable=False)
    label      = db.Column(db.String(128), nullable=True)   # friendly name
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    auto_scan  = db.Column(db.Boolean, default=True)        # enable scheduled scans

    # Relationships
    scans = db.relationship('Scan', backref='website', lazy=True,
                            cascade='all, delete-orphan')

    def latest_scan(self):
        return Scan.query.filter_by(website_id=self.id)\
                         .order_by(Scan.scan_date.desc()).first()

    def __repr__(self):
        return f'<Website {self.url}>'


# ═════════════════════════════════════════════════════════════════════════════
# SCAN MODEL
# ═════════════════════════════════════════════════════════════════════════════
class Scan(db.Model):
    """A single vulnerability scan run against a website."""
    __tablename__ = 'scans'

    id             = db.Column(db.Integer, primary_key=True)
    website_id     = db.Column(db.Integer, db.ForeignKey('websites.id'), nullable=False)
    scan_date      = db.Column(db.DateTime, default=datetime.utcnow)
    status         = db.Column(db.String(20), default='pending')   # pending|running|done|failed
    result_summary = db.Column(db.Text, nullable=True)
    total_vulns    = db.Column(db.Integer, default=0)
    risk_score     = db.Column(db.Float,   default=0.0)   # 0–100 composite score
    duration_secs  = db.Column(db.Float,   default=0.0)

    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True,
                                      cascade='all, delete-orphan')

    def vuln_counts(self):
        """Return dict with counts per risk level."""
        counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for v in self.vulnerabilities:
            counts[v.risk_level] = counts.get(v.risk_level, 0) + 1
        return counts

    def __repr__(self):
        return f'<Scan {self.id} website={self.website_id} {self.status}>'


# ═════════════════════════════════════════════════════════════════════════════
# VULNERABILITY MODEL
# ═════════════════════════════════════════════════════════════════════════════
class Vulnerability(db.Model):
    """A single vulnerability finding within a scan."""
    __tablename__ = 'vulnerabilities'

    id               = db.Column(db.Integer, primary_key=True)
    scan_id          = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vulnerability_type = db.Column(db.String(128), nullable=False)
    risk_level       = db.Column(db.String(20),  nullable=False)   # Low|Medium|High
    description      = db.Column(db.Text,         nullable=False)
    recommendation   = db.Column(db.Text,         nullable=True)
    evidence         = db.Column(db.Text,         nullable=True)   # raw detail / header value
    severity_score   = db.Column(db.Float,        default=0.0)     # 1–10

    def __repr__(self):
        return f'<Vulnerability {self.vulnerability_type} [{self.risk_level}]>'


# ═════════════════════════════════════════════════════════════════════════════
# ALERT MODEL
# ═════════════════════════════════════════════════════════════════════════════
class Alert(db.Model):
    """Notification record sent to a user about a vulnerability finding."""
    __tablename__ = 'alerts'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_id    = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    message    = db.Column(db.Text,    nullable=False)
    is_read    = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    alert_type = db.Column(db.String(20), default='dashboard')  # dashboard|email

    user = db.relationship('User',  backref='alerts')
    scan = db.relationship('Scan',  backref='alerts')

    def __repr__(self):
        return f'<Alert user={self.user_id} scan={self.scan_id}>'
