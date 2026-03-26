"""
WebSecure Website Management Routes
Add, view, and delete monitored websites.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.models import Website

websites_bp = Blueprint('websites', __name__)


@websites_bp.route('/websites')
@login_required
def list_websites():
    websites = Website.query.filter_by(user_id=current_user.id)\
                            .order_by(Website.date_added.desc()).all()
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
        existing = Website.query.filter_by(user_id=current_user.id, url=url).first()
        if existing:
            flash('You are already monitoring that URL.', 'warning')
            return redirect(url_for('websites.list_websites'))

        site = Website(
            user_id=current_user.id,
            url=url,
            label=label or url,
            auto_scan=auto
        )
        db.session.add(site)
        db.session.commit()
        flash(f'Website "{url}" added successfully.', 'success')
        return redirect(url_for('websites.list_websites'))

    return render_template('websites/add.html')


@websites_bp.route('/websites/<int:site_id>/delete', methods=['POST'])
@login_required
def delete_website(site_id):
    site = Website.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    db.session.delete(site)
    db.session.commit()
    flash('Website removed.', 'info')
    return redirect(url_for('websites.list_websites'))


@websites_bp.route('/websites/<int:site_id>/toggle-auto', methods=['POST'])
@login_required
def toggle_auto_scan(site_id):
    site = Website.query.filter_by(id=site_id, user_id=current_user.id).first_or_404()
    site.auto_scan = not site.auto_scan
    db.session.commit()
    state = 'enabled' if site.auto_scan else 'disabled'
    flash(f'Automatic scanning {state} for {site.url}.', 'info')
    return redirect(url_for('websites.list_websites'))
