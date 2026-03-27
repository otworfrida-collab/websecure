"""
WebSecure Scanner Runner
Ties the scanner engine to the database — runs a scan, persists findings,
creates alerts, and triggers email notifications.
"""

import logging
from app import mail
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
    scan = Scan.create_running(website.id)

    try:
        # Run the scanner engine
        scanner = VulnerabilityScanner(website.url)
        result = scanner.run()

        # Persist vulnerability findings
        Vulnerability.create_many(scan.id, result['findings'])

        # Update scan record
        scan.update_result(result)

        # Create alerts for high and medium findings
        _create_alerts(scan, website, result['findings'])

    except Exception as e:
        logger.error(f'Scan failed for {website.url}: {e}')
        scan.mark_failed(f'Scan failed: {str(e)}')

    return scan


def _create_alerts(scan: Scan, website: Website, findings: list):
    """Create dashboard alert records and send email notifications."""
    high_findings = [f for f in findings if f['risk_level'] == 'High']
    if not high_findings:
        return

    user = User.find_by_id(website.user_id)
    if not user:
        return

    # Dashboard alert (one per scan)
    message = (
        f'Security scan of {website.url} found {len(findings)} issue(s), '
        f'including {len(high_findings)} HIGH severity finding(s). '
        f'Please review your scan report.'
    )
    Alert.create(
        user_id=user.id,
        scan_id=scan.id,
        message=message,
        alert_type='dashboard',
    )

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
