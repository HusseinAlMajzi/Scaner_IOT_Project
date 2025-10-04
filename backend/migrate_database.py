#!/usr/bin/env python3
"""
Database Migration Script
Adds user_id columns and updates schema for multi-user support
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.main import app
from src.models import db, User
from sqlalchemy import text

def migrate_database():
    """Run database migrations"""
    
    print("🔧 IoT Security Scanner - Database Migration")
    print("="*70)
    
    with app.app_context():
        try:
            # Check if user_id column exists in devices
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='devices' AND column_name='user_id'
            """))
            
            if result.fetchone() is None:
                print("\n📝 Adding user_id column to devices table...")
                
                # Add user_id column
                db.session.execute(text("""
                    ALTER TABLE devices 
                    ADD COLUMN user_id INTEGER REFERENCES users(id)
                """))
                
                print("  ✓ user_id column added to devices")
                
                # Get default user (admin) or create one
                admin_user = User.query.filter_by(username='admin').first()
                
                if not admin_user:
                    print("\n📝 Creating default admin user...")
                    admin_user = User(username='admin', email='admin@iotsec.local')
                    admin_user.set_password('Admin123')
                    db.session.add(admin_user)
                    db.session.flush()
                    print("  ✓ Admin user created")
                
                # Assign existing devices to admin user
                print("\n📝 Assigning existing devices to admin user...")
                db.session.execute(text(f"""
                    UPDATE devices 
                    SET user_id = {admin_user.id} 
                    WHERE user_id IS NULL
                """))
                
                db.session.commit()
                print("  ✓ Existing devices assigned to admin")
            else:
                print("\n✓ user_id column already exists in devices table")
            
            # Check reports table
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='reports' AND column_name='user_id'
            """))
            
            if result.fetchone() is None:
                print("\n📝 Adding user_id column to reports table...")
                
                db.session.execute(text("""
                    ALTER TABLE reports 
                    ADD COLUMN user_id INTEGER REFERENCES users(id)
                """))
                
                print("  ✓ user_id column added to reports")
                
                # Get admin user
                admin_user = User.query.filter_by(username='admin').first()
                
                if admin_user:
                    # Assign existing reports to admin
                    db.session.execute(text(f"""
                        UPDATE reports 
                        SET user_id = {admin_user.id} 
                        WHERE user_id IS NULL
                    """))
                    
                    db.session.commit()
                    print("  ✓ Existing reports assigned to admin")
            else:
                print("\n✓ user_id column already exists in reports table")
            
            print("\n" + "="*70)
            print("✅ Database migration completed successfully!")
            print("="*70)
            print("\nYou can now start the application:")
            print("  python src/main.py")
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            print("\nTrying alternative approach...")
            
            # Alternative: Drop and recreate
            try:
                print("\n⚠️  Recreating all tables (existing data will be preserved)...")
                
                # This will add missing columns
                db.create_all()
                
                print("  ✓ Tables updated")
                
                # Ensure admin user exists
                admin_user = User.query.filter_by(username='admin').first()
                if not admin_user:
                    admin_user = User(username='admin', email='admin@iotsec.local')
                    admin_user.set_password('Admin123')
                    db.session.add(admin_user)
                    db.session.commit()
                    print("  ✓ Admin user created")
                
                print("\n✅ Migration completed!")
                
            except Exception as e2:
                print(f"\n❌ Alternative migration also failed: {e2}")
                print("\n💡 Manual fix required:")
                print("   1. Backup your database")
                print("   2. Run: python init_db.py")
                print("   3. Restart the application")
                return False
        
        return True

if __name__ == '__main__':
    success = migrate_database()
    sys.exit(0 if success else 1)
