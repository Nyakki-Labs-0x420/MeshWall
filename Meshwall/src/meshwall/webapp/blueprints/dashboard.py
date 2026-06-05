from flask import Blueprint, render_template, jsonify
from meshwall.models import BlockedIP, FeedBlock         
from meshwall.webapp.extensions import db

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    total_blocked = db.session.query(FeedBlock).count()
    recent_ips = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).limit(100).all()
    return render_template('dashboard.html', total_blocked=total_blocked, blocked_ips=recent_ips)

@dashboard_bp.route('/api/map-data')
def map_data():
    ips = BlockedIP.query.all()
    markers = []
    for ip in ips:
        if ip.lat and ip.lng:
            markers.append({
                'ip': ip.ip,
                'lat': ip.lat,
                'lng': ip.lng,
                'country': ip.geo_country,
                'city': ip.geo_city,
                'reason': ip.reason,
                'asn': ip.asn,
                'provider': ip.provider,
                'blocked_at': ip.blocked_at.strftime('%Y-%m-%d %H:%M:%S') if ip.blocked_at else ''
            })
    return jsonify(markers)