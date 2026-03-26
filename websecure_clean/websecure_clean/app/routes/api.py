"""
WebSecure REST API
Provides JSON endpoints for programmatic access to scan data.
All endpoints require authentication via session cookie.
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app.models.models import Website, Scan, Vulnerability, Alert

api_bp = Blueprint('api', __name__)


def _error(msg, code=400):
    return jsonify({'error': msg}), code


# ── Websites ──────────────────────────────────────────────────────────────────

@api_bp.route('/websites', methods=['GET'])
@login_required
def api_websites():
    sites = Website.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': s.id, 'url': s.url, 'label': s.label,
        'date_added': s.date_added.isoformat(),
        'auto_scan': s.auto_scan,
    } for s in sites])


# ── Scans ─────────────────────────────────────────────────────────────────────

@api_bp.route('/websites/<int:site_id>/scans', methods=['GET'])
@login_required
def api_scans(site_id):
    site = Website.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    scans = Scan.query.filter_by(website_id=site_id)\
                      .order_by(Scan.scan_date.desc()).limit(20).all()
    return jsonify([{
        'id': s.id, 'scan_date': s.scan_date.isoformat(),
        'status': s.status, 'total_vulns': s.total_vulns,
        'risk_score': s.risk_score, 'result_summary': s.result_summary,
    } for s in scans])


@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
@login_required
def api_scan_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    Website.query.filter_by(id=scan.website_id, user_id=current_user.id).first_or_404()
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    return jsonify({
        'id': scan.id, 'status': scan.status,
        'scan_date': scan.scan_date.isoformat(),
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
    alerts = Alert.query.filter_by(user_id=current_user.id)\
                        .order_by(Alert.created_at.desc()).limit(20).all()
    return jsonify([{
        'id': a.id, 'message': a.message,
        'is_read': a.is_read, 'created_at': a.created_at.isoformat(),
    } for a in alerts])


@api_bp.route('/alerts/<int:alert_id>/read', methods=['POST'])
@login_required
def api_mark_read(alert_id):
    from app import db
    alert = Alert.query.filter_by(id=alert_id, user_id=current_user.id).first_or_404()
    alert.is_read = True
    db.session.commit()
    return jsonify({'status': 'ok'})
