import os
from flask import Flask
from .extensions import init_extensions
from .blueprints.dashboard import dashboard_bp
from .blueprints.domains import domains_bp
from .blueprints.ai_chat import chat_bp
from meshwall.db import get_database_url 

def create_app(config_file=None):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    app.config['MESHWALL_CONFIG'] = config_file or os.environ.get('MESHWALL_CONFIG', '/etc/meshwall/meshwall.conf')
    app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()

    init_extensions(app)

    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(domains_bp, url_prefix='/domains')
    app.register_blueprint(chat_bp, url_prefix='/chat')

    return app