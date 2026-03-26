"""
WebSecure Scan Routes
Trigger manual scans and view scan results.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models.models import Website, Scan, Vulnerability
from app.scanner.runner import run_scan

scans_bp = Blueprint('scans', __name__)


@scans_bp.route('/websites/<int:site_id>/scan', methods=['POST'])
@login_required
def trigger_scan(site_id):
    """Manually trigger a scan for a website."""
    site = Website.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    flash(f'Scan started for {site.url} — this may take a moment…', 'info')
    scan = run_scan(site)
    flash(f'Scan complete: {scan.result_summary}', 'success')
    return redirect(url_for('scans.view_scan', scan_id=scan.id))


@scans_bp.route('/scans/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """Display detailed results for a single scan."""
    scan = Scan.query.get_or_404(scan_id)
    # Security: ensure user owns the website
    site = Website.query.filter_by(id=scan.website_id,
                                    user_id=current_user.id).first_or_404()
    vulns = Vulnerability.query.filter_by(scan_id=scan_id)\
                               .order_by(Vulnerability.severity_score.desc()).all()
    counts = scan.vuln_counts()
    return render_template('scans/detail.html', scan=scan, site=site,
                           vulns=vulns, counts=counts)


@scans_bp.route('/websites/<int:site_id>/scans')
@login_required
def scan_history(site_id):
    """Show full scan history for a website."""
    site = Website.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    scans = Scan.query.filter_by(website_id=site_id)\
                      .order_by(Scan.scan_date.desc()).all()
    return render_template('scans/history.html', site=site, scans=scans)


@scans_bp.route('/alerts/mark-read', methods=['POST'])
@login_required
def mark_alerts_read():
    from app import db
    from app.models.models import Alert
    Alert.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return redirect(url_for('dashboard.home'))
