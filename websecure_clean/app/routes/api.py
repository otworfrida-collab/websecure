"""
WebSecure REST API
Provides JSON endpoints for programmatic access to scan data.
All endpoints require authentication via session cookie.
"""

from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from app.models.models import Website, Scan, Vulnerability, Alert

api_bp = Blueprint('api', __name__)


def _error(msg, code=400):
    return jsonify({'error': msg}), code


def _iso(dt):
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


# ── Websites ──────────────────────────────────────────────────────────────────

@api_bp.route('/websites', methods=['GET'])
@login_required
def api_websites():
    sites = Website.for_user(current_user.id)
    return jsonify([{
        'id': s.id, 'url': s.url, 'label': s.label,
        'date_added': _iso(s.date_added),
        'auto_scan': s.auto_scan,
    } for s in sites])


# ── Scans ─────────────────────────────────────────────────────────────────────

@api_bp.route('/websites/<int:site_id>/scans', methods=['GET'])
@login_required
def api_scans(site_id):
    site = Website.find_by_user_and_id(current_user.id, site_id)
    if not site:
        return _error('Website not found.', 404)
    scans = Scan.for_website(site_id, limit=20)
    return jsonify([{
        'id': s.id, 'scan_date': _iso(s.scan_date),
        'status': s.status, 'total_vulns': s.total_vulns,
        'risk_score': s.risk_score, 'result_summary': s.result_summary,
    } for s in scans])


@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
@login_required
def api_scan_detail(scan_id):
    scan = Scan.find_by_id(scan_id)
    if not scan:
        return _error('Scan not found.', 404)
    site = Website.find_by_user_and_id(current_user.id, scan.website_id)
    if not site:
        return _error('Scan not found.', 404)
    vulns = Vulnerability.for_scan(scan_id)
    return jsonify({
        'id': scan.id, 'status': scan.status,
        'scan_date': _iso(scan.scan_date),
        'risk_score': scan.risk_score,
        'total_vulns': scan.total_vulns,
        'vulnerabilities': [{
            'type': v.vulnerability_type,
            'risk_level': v.risk_level,
            'description': v.description,
            'recommendation': v.recommendation,
            'severity_score': v.severity_score,
        } for v in vulns]
    })


# ── Alerts ────────────────────────────────────────────────────────────────────

@api_bp.route('/alerts', methods=['GET'])
@login_required
def api_alerts():
    alerts = Alert.recent_for_user(current_user.id, limit=20)
    return jsonify([{
        'id': a.id, 'message': a.message,
        'is_read': a.is_read, 'created_at': _iso(a.created_at),
    } for a in alerts])


@api_bp.route('/alerts/<int:alert_id>/read', methods=['POST'])
@login_required
def api_mark_read(alert_id):
    ok = Alert.mark_read(current_user.id, alert_id)
    if not ok:
        return _error('Alert not found.', 404)
    return jsonify({'status': 'ok'})
