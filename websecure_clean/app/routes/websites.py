"""
WebSecure Website Management Routes
Add, view, and delete monitored websites.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.models.models import Website

websites_bp = Blueprint('websites', __name__)


@websites_bp.route('/websites')
@login_required
def list_websites():
    websites = Website.for_user(current_user.id)
    return render_template('websites/list.html', websites=websites)


@websites_bp.route('/websites/add', methods=['GET', 'POST'])
@login_required
def add_website():
    if request.method == 'POST':
        url   = request.form.get('url', '').strip()
        label = request.form.get('label', '').strip()
        auto  = bool(request.form.get('auto_scan'))

        if not url:
            flash('Please enter a URL.', 'danger')
            return render_template('websites/add.html')

        # Normalise
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Prevent duplicates per user
        existing = Website.find_by_user_and_url(current_user.id, url)
        if existing:
            flash('You are already monitoring that URL.', 'warning')
            return redirect(url_for('websites.list_websites'))

        Website.create(
            user_id=current_user.id,
            url=url,
            label=label or url,
            auto_scan=auto,
        )
        flash(f'Website "{url}" added successfully.', 'success')
        return redirect(url_for('websites.list_websites'))

    return render_template('websites/add.html')


@websites_bp.route('/websites/<int:site_id>/delete', methods=['POST'])
@login_required
def delete_website(site_id):
    site = Website.find_by_user_and_id(current_user.id, site_id)
    if not site:
        abort(404)
    site.delete()
    flash('Website removed.', 'info')
    return redirect(url_for('websites.list_websites'))


@websites_bp.route('/websites/<int:site_id>/toggle-auto', methods=['POST'])
@login_required
def toggle_auto_scan(site_id):
    site = Website.find_by_user_and_id(current_user.id, site_id)
    if not site:
        abort(404)
    site.auto_scan = not site.auto_scan
    site.save()
    state = 'enabled' if site.auto_scan else 'disabled'
    flash(f'Automatic scanning {state} for {site.url}.', 'info')
    return redirect(url_for('websites.list_websites'))
