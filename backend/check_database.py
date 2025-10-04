#!/usr/bin/env python3
"""
Database Diagnostic Script
Checks if data is being saved and retrieved correctly
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.main import app
from src.models import db, User, Device, Vulnerability, ScanResult, Report

def check_database():
    """Check database contents"""
    with app.app_context():
        print("=" * 60)
        print("DATABASE DIAGNOSTIC REPORT")
        print("=" * 60)
        
        # Check Users
        print("\n📋 USERS:")
        users = User.query.all()
        print(f"Total Users: {len(users)}")
        for user in users:
            print(f"  ├─ ID: {user.id}")
            print(f"  ├─ Username: {user.username}")
            print(f"  ├─ Email: {user.email}")
            print(f"  ├─ Active: {user.is_active}")
            print(f"  └─ Last Login: {user.last_login}")
            print()
        
        # Check Devices per user
        print("\n🖥️  DEVICES:")
        devices = Device.query.all()
        print(f"Total Devices: {len(devices)}")
        
        devices_by_user = {}
        for device in devices:
            if device.user_id not in devices_by_user:
                devices_by_user[device.user_id] = []
            devices_by_user[device.user_id].append(device)
        
        for user_id, user_devices in devices_by_user.items():
            user = User.query.get(user_id)
            username = user.username if user else "Unknown"
            print(f"\n  User: {username} (ID: {user_id})")
            print(f"  Devices: {len(user_devices)}")
            for device in user_devices[:5]:  # Show first 5
                print(f"    ├─ {device.ip_address} ({device.device_type or 'Unknown'})")
                print(f"    │  ├─ MAC: {device.mac_address or 'N/A'}")
                print(f"    │  ├─ Hostname: {device.hostname or 'N/A'}")
                print(f"    │  ├─ Manufacturer: {device.manufacturer or 'N/A'}")
                print(f"    │  └─ Open Ports: {len(device.open_ports) if device.open_ports else 0}")
            if len(user_devices) > 5:
                print(f"    └─ ... and {len(user_devices) - 5} more devices")
        
        # Check Vulnerabilities
        print("\n⚠️  VULNERABILITIES:")
        vulns = Vulnerability.query.all()
        print(f"Total Vulnerabilities: {len(vulns)}")
        
        severity_counts = {}
        for vuln in vulns:
            severity = vuln.severity or 'Unknown'
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            print(f"  ├─ {severity}: {count}")
        
        # Show sample vulnerabilities
        if vulns:
            print("\n  Sample Vulnerabilities:")
            for vuln in vulns[:3]:
                print(f"    ├─ {vuln.cve_id or 'Custom'}: {vuln.severity}")
                print(f"    │  └─ {vuln.description[:80]}...")
        
        # Check Scan Results (links devices to vulnerabilities)
        print("\n🔗 SCAN RESULTS:")
        scan_results = ScanResult.query.all()
        print(f"Total Scan Results: {len(scan_results)}")
        
        results_by_user = {}
        for result in scan_results:
            device = Device.query.get(result.device_id)
            if device:
                user_id = device.user_id
                if user_id not in results_by_user:
                    results_by_user[user_id] = []
                results_by_user[user_id].append(result)
        
        for user_id, user_results in results_by_user.items():
            user = User.query.get(user_id)
            username = user.username if user else "Unknown"
            print(f"\n  User: {username} (ID: {user_id})")
            print(f"  Scan Results: {len(user_results)}")
            for result in user_results[:3]:
                device = Device.query.get(result.device_id)
                vuln = Vulnerability.query.get(result.vulnerability_id)
                if device and vuln:
                    print(f"    ├─ {device.ip_address} → {vuln.severity} vulnerability")
        
        # Check Reports
        print("\n📄 REPORTS:")
        reports = Report.query.all()
        print(f"Total Reports: {len(reports)}")
        
        reports_by_user = {}
        for report in reports:
            if report.user_id not in reports_by_user:
                reports_by_user[report.user_id] = []
            reports_by_user[report.user_id].append(report)
        
        for user_id, user_reports in reports_by_user.items():
            user = User.query.get(user_id)
            username = user.username if user else "Unknown"
            print(f"\n  User: {username} (ID: {user_id})")
            print(f"  Reports: {len(user_reports)}")
            for report in user_reports:
                print(f"    ├─ {report.title}")
                print(f"    │  ├─ Devices: {report.total_devices}")
                print(f"    │  ├─ Vulnerabilities: {report.total_vulnerabilities}")
                print(f"    │  └─ Generated: {report.generated_at}")
        
        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"✓ Total Users: {len(users)}")
        print(f"✓ Total Devices: {len(devices)}")
        print(f"✓ Total Vulnerabilities: {len(vulns)}")
        print(f"✓ Total Scan Results: {len(scan_results)}")
        print(f"✓ Total Reports: {len(reports)}")
        
        # Warnings
        print("\n⚠️  WARNINGS:")
        if len(users) == 0:
            print("  ⚠ No users found! Register a user first.")
        if len(devices) == 0:
            print("  ⚠ No devices found! Run a scan to discover devices.")
        if len(vulns) == 0:
            print("  ⚠ No vulnerabilities found! Devices may be secure or no scan completed.")
        if len(scan_results) == 0:
            print("  ⚠ No scan results! Vulnerabilities are not linked to devices.")
        if len(reports) == 0:
            print("  ⚠ No reports generated! Generate a report from the UI.")
        
        if all([len(users) > 0, len(devices) > 0, len(vulns) > 0, len(scan_results) > 0]):
            print("\n✅ DATABASE LOOKS HEALTHY!")
        else:
            print("\n❌ DATABASE HAS ISSUES - Check warnings above")
        
        print("=" * 60)

if __name__ == '__main__':
    try:
        check_database()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
