"""
WebSecure Scan Routes
Trigger manual scans and view scan results.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.models.models import Website, Scan, Vulnerability
from app.scanner.runner import run_scan

scans_bp = Blueprint('scans', __name__)


@scans_bp.route('/websites/<int:site_id>/scan', methods=['POST'])
@login_required
def trigger_scan(site_id):
    """Manually trigger a scan for a website."""
    site = Website.find_by_user_and_id(current_user.id, site_id)
    if not site:
        abort(404)
    flash(f'Scan started for {site.url} — this may take a moment…', 'info')
    scan = run_scan(site)
    flash(f'Scan complete: {scan.result_summary}', 'success')
    return redirect(url_for('scans.view_scan', scan_id=scan.id))


@scans_bp.route('/scans/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """Display detailed results for a single scan."""
    scan = Scan.find_by_id(scan_id)
    if not scan:
        abort(404)
    # Security: ensure user owns the website
    site = Website.find_by_user_and_id(current_user.id, scan.website_id)
    if not site:
        abort(404)
    vulns = Vulnerability.for_scan(scan_id)
    counts = scan.vuln_counts()
    return render_template('scans/detail.html', scan=scan, site=site,
                           vulns=vulns, counts=counts)


@scans_bp.route('/websites/<int:site_id>/scans')
@login_required
def scan_history(site_id):
    """Show full scan history for a website."""
    site = Website.find_by_user_and_id(current_user.id, site_id)
    if not site:
        abort(404)
    scans = Scan.for_website(site_id)
    return render_template('scans/history.html', site=site, scans=scans)


@scans_bp.route('/alerts/mark-read', methods=['POST'])
@login_required
def mark_alerts_read():
    from app.models.models import Alert
    Alert.mark_all_read(current_user.id)
    return redirect(url_for('dashboard.home'))
