"""
WebSecure Dashboard Routes
Main dashboard showing summary statistics, recent scans, and alerts.
"""

from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.models import Website, Scan, Vulnerability, Alert

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
@login_required
def home():
    websites = Website.for_user(current_user.id)

    # Aggregate stats across all user websites
    website_ids = [w.id for w in websites]
    all_scans = Scan.for_websites(website_ids)
    scan_ids = [s.id for s in all_scans]

    total_scans  = len(scan_ids)
    total_vulns = Vulnerability.count_for_scans(scan_ids)
    high_vulns = Vulnerability.count_by_risk_for_scans(scan_ids, 'High')

    # Unread alerts
    unread_alerts = Alert.count_unread(current_user.id)

    # Recent scans across all sites (last 10)
    recent_scans = []
    if website_ids:
        recent_scans = Scan.for_websites(website_ids, limit=10)

    # Risk distribution for chart
    counts = Vulnerability.counts_for_scans(scan_ids)

    # Alerts for notification panel
    alerts = Alert.recent_for_user(current_user.id, limit=5)

    return render_template('dashboard/home.html',
                           websites=websites,
                           total_scans=total_scans,
                           total_vulns=total_vulns,
                           high_vulns=high_vulns,
                           unread_alerts=unread_alerts,
                           recent_scans=recent_scans,
                           vuln_counts=counts,
                           alerts=alerts)
