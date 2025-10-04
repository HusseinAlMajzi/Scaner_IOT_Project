#!/usr/bin/env python3
"""
Initialize database with new schema for Phase 1
This script will:
1. Create all tables
2. Create a default admin user for testing
"""

import os
import sys

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.main import app
from src.models import db, User

def init_database():
    """Initialize the database"""
    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("✓ Tables created successfully!")
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("\nCreating default admin user...")
            admin = User(
                username='admin',
                email='admin@iot-scanner.local'
            )
            admin.set_password('Admin123')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin user created successfully!")
            print("  Username: admin")
            print("  Password: Admin123")
            print("  ⚠️  Please change the password after first login!")
        else:
            print("\n✓ Admin user already exists")
        
        print("\n" + "="*50)
        print("Database initialization complete!")
        print("="*50)

if __name__ == '__main__':
    init_database()
