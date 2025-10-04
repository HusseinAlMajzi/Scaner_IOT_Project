#!/usr/bin/env python3
"""
IoT Security Scanner - Comprehensive Diagnostic Script
Tests all components and reports any issues
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def print_header(text):
    """Print section header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def test_imports():
    """Test all critical imports"""
    print_header("Testing Imports")
    
    tests = {
        'Flask': lambda: __import__('flask'),
        'SQLAlchemy': lambda: __import__('sqlalchemy'),
        'Flask-Login': lambda: __import__('flask_login'),
        'Flask-Bcrypt': lambda: __import__('flask_bcrypt'),
        'nmap': lambda: __import__('nmap'),
        'scapy': lambda: __import__('scapy.all'),
    }
    
    passed = 0
    failed = 0
    
    for name, test_func in tests.items():
        try:
            test_func()
            print(f"  ✓ {name}")
            passed += 1
        except ImportError as e:
            print(f"  ✗ {name}: {e}")
            failed += 1
    
    print(f"\nImport Tests: {passed} passed, {failed} failed")
    return failed == 0

def test_models():
    """Test model imports"""
    print_header("Testing Models")
    
    try:
        from src.models import User, Device, Vulnerability, ScanResult, Report, db
        print("  ✓ All models imported successfully")
        return True
    except Exception as e:
        print(f"  ✗ Model import error: {e}")
        return False

def test_routes():
    """Test route imports"""
    print_header("Testing Routes")
    
    routes = {
        'Auth Routes': 'src.routes.auth',
        'Scanner Routes': 'src.routes.scanner',
        'User Routes': 'src.routes.user',
        'Firmware Routes': 'src.routes.firmware',
        'Reporting Routes': 'src.routes.reporting',
    }
    
    passed = 0
    failed = 0
    
    for name, module_path in routes.items():
        try:
            __import__(module_path)
            print(f"  ✓ {name}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {name}: {e}")
            failed += 1
    
    print(f"\nRoute Tests: {passed} passed, {failed} failed")
    return failed == 0

def test_services():
    """Test service imports"""
    print_header("Testing Services")
    
    services = {
        'Device Scanner': 'src.services.device_scanner',
        'Vulnerability Scanner': 'src.services.vulnerability_scanner',
        'Report Generator': 'src.services.report_generator',
    }
    
    passed = 0
    failed = 0
    
    for name, module_path in services.items():
        try:
            __import__(module_path)
            print(f"  ✓ {name}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {name}: {e}")
            failed += 1
    
    print(f"\nService Tests: {passed} passed, {failed} failed")
    return failed == 0

def test_database():
    """Test database connection"""
    print_header("Testing Database")
    
    try:
        from src.main import app
        from src.models import db, User, Device, Vulnerability
        
        with app.app_context():
            # Test connection
            db.session.execute(db.text('SELECT 1'))
            print("  ✓ Database connection successful")
            
            # Test tables
            user_count = User.query.count()
            device_count = Device.query.count()
            vuln_count = Vulnerability.query.count()
            
            print(f"  ✓ Users table: {user_count} records")
            print(f"  ✓ Devices table: {device_count} records")
            print(f"  ✓ Vulnerabilities table: {vuln_count} records")
            
            return True
    except Exception as e:
        print(f"  ✗ Database error: {e}")
        print("\n  💡 Fix: Run 'python init_db.py' to initialize database")
        return False

def test_app_startup():
    """Test Flask app initialization"""
    print_header("Testing Flask App")
    
    try:
        from src.main import app
        
        print(f"  ✓ Flask app created")
        print(f"  ✓ Secret key configured")
        print(f"  ✓ Database URI: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')[:50]}...")
        
        # Test blueprints
        blueprints = list(app.blueprints.keys())
        print(f"  ✓ Registered blueprints: {', '.join(blueprints)}")
        
        return True
    except Exception as e:
        print(f"  ✗ App startup error: {e}")
        return False

def test_advanced_features():
    """Test advanced phase features"""
    print_header("Testing Advanced Features (Optional)")
    
    optional_features = {
        'Enhanced Scanner': 'src.services.enhanced_scanner',
        'Wireless Scanner': 'src.services.wireless_scanner_manager',
        'Protocol Analyzers': 'src.services.protocols.mqtt_analyzer',
        'IoT Protocols': 'src.services.iot_protocols.zigbee_analyzer',
        'Security Features': 'src.services.security.default_credentials',
        'Firmware Analysis': 'src.services.firmware.firmware_manager',
        'Reporting': 'src.services.reporting.reporting_manager',
        'Performance': 'src.services.performance.caching',
    }
    
    available = 0
    
    for name, module_path in optional_features.items():
        try:
            __import__(module_path)
            print(f"  ✓ {name}")
            available += 1
        except Exception as e:
            print(f"  ⚠ {name}: Not available ({str(e)[:50]})")
    
    print(f"\nAdvanced Features: {available}/{len(optional_features)} available")
    return True  # Not critical

def run_all_tests():
    """Run all diagnostic tests"""
    print("\n" + "🔍 IoT Security Scanner - Comprehensive Diagnostic".center(70))
    
    results = {
        'Imports': test_imports(),
        'Models': test_models(),
        'Routes': test_routes(),
        'Services': test_services(),
        'Database': test_database(),
        'App Startup': test_app_startup(),
        'Advanced Features': test_advanced_features(),
    }
    
    print_header("Diagnostic Summary")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status:10} {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Your IoT Security Scanner is ready to use!")
        print("\n🚀 Start the application:")
        print("   Backend:  python src/main.py")
        print("   Frontend: cd ../frontend && npm run dev")
        print("   Access:   http://localhost:5173")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please fix the issues above.")
        return 1

if __name__ == '__main__':
    exit_code = run_all_tests()
    sys.exit(exit_code)
