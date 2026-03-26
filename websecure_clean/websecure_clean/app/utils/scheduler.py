"""
WebSecure Scheduler
Registers APScheduler jobs to run automatic scans every 24 hours.
"""

import logging
import os
from app.models.models import Website

logger = logging.getLogger(__name__)


def register_jobs(scheduler):
    """Register all scheduled jobs."""
    interval_hours = int(os.getenv('SCAN_INTERVAL_HOURS', 24))

    scheduler.add_job(
        id='auto_scan_all',
        func=auto_scan_all_websites,
        trigger='interval',
        hours=interval_hours,
        replace_existing=True
    )
    logger.info(f'Scheduled auto-scan every {interval_hours} hour(s).')


def auto_scan_all_websites():
    """Scan every website that has auto_scan enabled."""
    from app import create_app
    app = create_app()
    with app.app_context():
        from app.scanner.runner import run_scan
        sites = Website.query.filter_by(auto_scan=True).all()
        logger.info(f'Auto-scan: processing {len(sites)} website(s).')
        for site in sites:
            try:
                scan = run_scan(site)
                logger.info(f'Auto-scan done for {site.url}: {scan.result_summary}')
            except Exception as e:
                logger.error(f'Auto-scan failed for {site.url}: {e}')
