import os
import sys
# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from flask_migrate import Migrate
from src.models import db, Device, Vulnerability, ScanResult, Report
from src.routes.scanner import scanner_bp

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
app.config['SECRET_KEY'] = 'iot_security_scanner_secret_key_2024'

# Enable CORS for all routes
CORS(app, origins="*")

# Register blueprints
app.register_blueprint(scanner_bp, url_prefix='/api')

# Database configuration - PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://hussein:IoT_123456@localhost/iot_scanner_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

# Create tables
with app.app_context():
    db.create_all()

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return "Static folder not configured", 404

    if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, 'index.html')
        else:
            return "Frontend not built yet. Please build the React frontend first.", 404

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'message': 'IoT Security Scanner API is running',
        'version': '1.0.0'
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

