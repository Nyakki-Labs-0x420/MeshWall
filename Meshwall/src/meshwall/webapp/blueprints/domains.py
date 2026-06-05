from flask import Blueprint, render_template, request, redirect
from urllib.parse import urlparse
from meshwall.models import BlockedDomain               
from meshwall.webapp.domain_checker import check_domain, detect_typosquat
from meshwall.webapp.extensions import db

domains_bp = Blueprint('domains', __name__)

@domains_bp.route('/')
def index():
    domains = BlockedDomain.query.order_by(BlockedDomain.blocked_at.desc()).all()
    return render_template('domains.html', domains=domains)

@domains_bp.route('/check', methods=['POST'])
def check():
    url = request.form.get('url', '').strip()
    if not url:
        return redirect('/domains/')
    domain = urlparse(url).netloc or url
    result = check_domain(domain)
    typosquat, similar = detect_typosquat(domain)
    if typosquat:
        result['passed'] = False
        result['issues'].append(f'Possible typosquat of {similar}')
    if not result['passed']:
        existing = BlockedDomain.query.filter_by(domain=domain).first()
        if not existing:
            db.session.add(BlockedDomain(domain=domain, reason=', '.join(result['issues'])))
            db.session.commit()
    domains = BlockedDomain.query.order_by(BlockedDomain.blocked_at.desc()).all()
    return render_template('domains.html', domains=domains, result=result, domain=domain)