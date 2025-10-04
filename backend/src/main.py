#!/usr/bin/env python3
"""
IoT Security Scanner - Main Application
Advanced IoT Device Security Scanning Tool
Graduation Project - 2024
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Load environment variables
env_path = Path(os.path.dirname(os.path.dirname(__file__))) / '.env'
load_dotenv(dotenv_path=env_path)

from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from src.models import db, User, Device, Vulnerability, ScanResult, Report
from src.routes.scanner import scanner_bp
from src.routes.auth import auth_bp
from src.routes.user import user_bp
# Firmware routes removed - not needed for IoT device scanning
# from src.routes.firmware import firmware_bp
from src.routes.reporting import reporting_bp 

# Create Flask application
app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))

# Load configuration from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'iot_security_scanner_secret_key_2024')
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['SESSION_COOKIE_NAME'] = 'iot_scanner_session'
app.config['REMEMBER_COOKIE_SECURE'] = False
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'

# Enable CORS with credentials support for frontend
CORS(app, 
     origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:5000"],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     expose_headers=['Set-Cookie'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     max_age=3600)

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'يرجى تسجيل الدخول للوصول لهذه الصفحة'
login_manager.login_message_category = 'info'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(scanner_bp, url_prefix='/api')
app.register_blueprint(user_bp, url_prefix='/api')
# Firmware blueprint removed - not needed for IoT scanning
# app.register_blueprint(firmware_bp, url_prefix='/api')
app.register_blueprint(reporting_bp, url_prefix='/api')

# Database configuration from environment
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(os.path.dirname(os.path.dirname(__file__)), 'iot_scanner.db')
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

# Ensure required directories exist
os.makedirs(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads', 'firmware'), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports'), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs'), exist_ok=True)

# Create database tables
with app.app_context():
    try:
        db.create_all()
        print("✓ Database tables created/verified successfully")
    except Exception as e:
        print(f"✗ Error creating database tables: {e}")

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
    try:
        # Test database connection
        with app.app_context():
            db.session.execute(db.text('SELECT 1'))
        db_status = 'connected'
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'message': 'IoT Security Scanner API is running',
        'version': '1.0.0',
        'database': db_status
    })

@app.route('/api', methods=['GET'])
def api_info():
    """API information endpoint"""
    return jsonify({
        'message': 'IoT Security Scanner API',
        'version': '1.0.0',
        'endpoints': {
            'health': '/api/health',
            'auth': '/api/auth',
            'devices': '/api/devices',
            'vulnerabilities': '/api/vulnerabilities',
            'scan': '/api/scan',
            'reports': '/api/reports',
            'firmware': '/api/firmware'
        }
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'message': 'Endpoint not found'
        }), 404
    # Serve frontend for client-side routing
    return serve('')

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500

if __name__ == '__main__':
    print("=" * 80)
    print("🛡️  IoT Security Scanner - Starting Application".center(80))
    print("=" * 80)
    print()
    print("📍 Application Information:")
    print(f"   • Backend URL:  http://localhost:5000")
    print(f"   • API Endpoint: http://localhost:5000/api")
    print(f"   • Frontend:     http://localhost:5173 (run separately)")
    print()
    print("🔧 Configuration:")
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    if 'sqlite' in db_uri:
        print(f"   • Database: SQLite (Development)")
    else:
        print(f"   • Database: {db_uri.split('@')[1] if '@' in db_uri else 'Configured'}")
    print(f"   • Debug Mode: {app.config['DEBUG']}")
    print()
    print("📡 Registered Blueprints:")
    for bp_name in sorted(app.blueprints.keys()):
        print(f"   • {bp_name}")
    print()
    print("=" * 80)
    print("✓ Server is running - Press CTRL+C to stop")
    print("=" * 80)
    print()
    
    # Run the application
    app.run(
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true',
        threaded=True
    )

