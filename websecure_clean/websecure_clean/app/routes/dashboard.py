"""
WebSecure Dashboard Routes
Main dashboard showing summary statistics, recent scans, and alerts.
"""

from flask import Blueprint, render_template
from flask_login import login_required, current_user
from sqlalchemy import func
from app.models.models import Website, Scan, Vulnerability, Alert

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
@login_required
def home():
    websites = Website.query.filter_by(user_id=current_user.id).all()

    # Aggregate stats across all user websites
    website_ids = [w.id for w in websites]
    scan_ids = []
    for w in websites:
        scans = Scan.query.filter_by(website_id=w.id).all()
        scan_ids.extend([s.id for s in scans])

    total_scans  = len(scan_ids)
    total_vulns  = Vulnerability.query.filter(
        Vulnerability.scan_id.in_(scan_ids)).count() if scan_ids else 0
    high_vulns   = Vulnerability.query.filter(
        Vulnerability.scan_id.in_(scan_ids),
        Vulnerability.risk_level == 'High').count() if scan_ids else 0

    # Unread alerts
    unread_alerts = Alert.query.filter_by(
        user_id=current_user.id, is_read=False).count()

    # Recent scans across all sites (last 10)
    recent_scans = []
    if website_ids:
        recent_scans = Scan.query.filter(
            Scan.website_id.in_(website_ids)
        ).order_by(Scan.scan_date.desc()).limit(10).all()

    # Risk distribution for chart
    counts = {'High': 0, 'Medium': 0, 'Low': 0}
    if scan_ids:
        rows = Vulnerability.query\
            .filter(Vulnerability.scan_id.in_(scan_ids))\
            .with_entities(Vulnerability.risk_level, func.count())\
            .group_by(Vulnerability.risk_level).all()
        for level, cnt in rows:
            counts[level] = cnt

    # Alerts for notification panel
    alerts = Alert.query.filter_by(user_id=current_user.id)\
                        .order_by(Alert.created_at.desc()).limit(5).all()

    return render_template('dashboard/home.html',
                           websites=websites,
                           total_scans=total_scans,
                           total_vulns=total_vulns,
                           high_vulns=high_vulns,
                           unread_alerts=unread_alerts,
                           recent_scans=recent_scans,
                           vuln_counts=counts,
                           alerts=alerts)
