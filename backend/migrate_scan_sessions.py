#!/usr/bin/env python3
"""
Migrate database to add scan_sessions table
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.main import app
from src.models import db

def migrate():
    """Add scan_sessions table"""
    with app.app_context():
        print("Creating scan_sessions table...")
        try:
            db.create_all()
            print("✓ Scan sessions table created successfully!")
            print("\nDatabase is ready for scan session management.")
            return True
        except Exception as e:
            print(f"✗ Error: {e}")
            return False

if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)
