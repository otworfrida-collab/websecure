"""
WebSecure Scanner Runner
Ties the scanner engine to the database — runs a scan, persists findings,
creates alerts, and triggers email notifications.
"""

import logging
from datetime import datetime
from app import db, mail
from app.models.models import Scan, Vulnerability, Alert, Website, User
from app.scanner.engine import VulnerabilityScanner
from flask_mail import Message
from flask import current_app

logger = logging.getLogger(__name__)


def run_scan(website: Website) -> Scan:
    """
    Execute a full vulnerability scan for a website and persist results.
    Returns the completed Scan record.
    """
    # Create scan record (status=running)
    scan = Scan(
        website_id=website.id,
        scan_date=datetime.utcnow(),
        status='running'
    )
    db.session.add(scan)
    db.session.commit()

    try:
        # Run the scanner engine
        scanner = VulnerabilityScanner(website.url)
        result = scanner.run()

        # Persist vulnerability findings
        for finding in result['findings']:
            vuln = Vulnerability(
                scan_id=scan.id,
                vulnerability_type=finding['vulnerability_type'],
                risk_level=finding['risk_level'],
                description=finding['description'],
                recommendation=finding['recommendation'],
                evidence=finding['evidence'],
                severity_score=finding['severity_score'],
            )
            db.session.add(vuln)

        # Update scan record
        scan.status         = 'done'
        scan.result_summary = result['summary']
        scan.total_vulns    = result['total_vulns']
        scan.risk_score     = result['risk_score']
        scan.duration_secs  = result['duration']
        db.session.commit()

        # Create alerts for high and medium findings
        _create_alerts(scan, website, result['findings'])

    except Exception as e:
        logger.error(f'Scan failed for {website.url}: {e}')
        scan.status = 'failed'
        scan.result_summary = f'Scan failed: {str(e)}'
        db.session.commit()

    return scan


def _create_alerts(scan: Scan, website: Website, findings: list):
    """Create dashboard alert records and send email notifications."""
    high_findings = [f for f in findings if f['risk_level'] == 'High']
    if not high_findings:
        return

    user = User.query.get(website.user_id)
    if not user:
        return

    # Dashboard alert (one per scan)
    message = (
        f'Security scan of {website.url} found {len(findings)} issue(s), '
        f'including {len(high_findings)} HIGH severity finding(s). '
        f'Please review your scan report.'
    )
    alert = Alert(
        user_id=user.id,
        scan_id=scan.id,
        message=message,
        alert_type='dashboard'
    )
    db.session.add(alert)
    db.session.commit()

    # Email alert (best-effort)
    try:
        _send_email_alert(user, website, scan, findings)
    except Exception as e:
        logger.warning(f'Email alert failed: {e}')


def _send_email_alert(user: User, website: Website, scan: Scan, findings: list):
    """Send an email summarising the scan findings."""
    if not current_app.config.get('MAIL_USERNAME'):
        logger.debug('Email not configured — skipping email alert.')
        return

    counts = {'High': 0, 'Medium': 0, 'Low': 0}
    for f in findings:
        counts[f['risk_level']] = counts.get(f['risk_level'], 0) + 1

    high_list = '\n'.join(
        f"  • {f['vulnerability_type']}" for f in findings if f['risk_level'] == 'High'
    )

    body = f"""Hello {user.username},

WebSecure has completed a vulnerability scan of your website:

  URL: {website.url}
  Scan Date: {scan.scan_date.strftime('%Y-%m-%d %H:%M UTC')}
  Risk Score: {scan.risk_score:.1f} / 100

Findings Summary:
  🔴 High:   {counts['High']}
  🟡 Medium: {counts['Medium']}
  🟢 Low:    {counts['Low']}

High Severity Issues:
{high_list or '  None'}

Log in to your WebSecure dashboard to view the full report and recommended actions.

---
This is an automated alert from WebSecure.
"""
    msg = Message(
        subject=f'[WebSecure] Security Alert: {website.url}',
        recipients=[user.email],
        body=body
    )
    mail.send(msg)
    logger.info(f'Email alert sent to {user.email}')
