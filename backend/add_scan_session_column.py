#!/usr/bin/env python3
"""
Add scan_session_id column to devices table
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.main import app
from src.models import db

def add_column():
    """Add scan_session_id column to devices table"""
    with app.app_context():
        try:
            print("Adding scan_session_id column to devices table...")
            
            # Add the column using raw SQL
            db.session.execute(db.text(
                'ALTER TABLE devices ADD COLUMN IF NOT EXISTS scan_session_id VARCHAR(36)'
            ))
            
            # Add foreign key constraint
            db.session.execute(db.text(
                '''
                ALTER TABLE devices 
                ADD CONSTRAINT fk_devices_scan_session 
                FOREIGN KEY (scan_session_id) 
                REFERENCES scan_sessions(id) 
                ON DELETE CASCADE
                '''
            ))
            
            db.session.commit()
            print("✓ Column added successfully!")
            print("\nYour database is now ready for scan sessions!")
            return True
        except Exception as e:
            # Check if it's because constraint already exists
            if 'already exists' in str(e) or 'duplicate' in str(e).lower():
                print("✓ Column already exists, skipping...")
                db.session.rollback()
                return True
            else:
                print(f"✗ Error: {e}")
                db.session.rollback()
                return False

if __name__ == '__main__':
    success = add_column()
    sys.exit(0 if success else 1)
