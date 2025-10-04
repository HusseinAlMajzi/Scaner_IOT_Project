# 🎯 Scan Sessions Implementation Guide

## Overview
Implement separate scan sessions so each user can have multiple named scans and switch between them.

## ✅ Phase 1: Database Changes (COMPLETED)

1. ✅ Created `ScanSession` model
2. ✅ Added `scan_session_id` to `Device` model
3. ✅ Updated models `__init__.py`

## 🔧 Phase 2: Backend API Changes (TODO)

### New API Endpoints Needed:

1. **GET `/api/scan-sessions`** - List all scan sessions for current user
2. **POST `/api/scan-sessions`** - Create a new scan session
3. **GET `/api/scan-sessions/<id>`** - Get specific scan session details
4. **DELETE `/api/scan-sessions/<id>`** - Delete a scan session
5. **POST `/api/scan-sessions/<id>/start`** - Start scanning for a specific session

### Modified Endpoints:

1. **POST `/api/scan/start`** - Now requires `scan_session_id` parameter
2. **GET `/api/devices`** - Now requires `scan_session_id` query parameter
3. **GET `/api/vulnerabilities`** - Now requires `scan_session_id` query parameter  
4. **GET `/api/vulnerabilities/stats`** - Now requires `scan_session_id` query parameter

## 🎨 Phase 3: Frontend Changes (TODO)

### New Components:

1. **ScanSessionSelector** - Dropdown to select active scan session
2. **NewScanDialog** - Modal to create new named scan
3. **ScanHistoryPanel** - List of past scans in sidebar

### Modified Components:

1. **Dashboard** - Shows data only for selected scan session
2. **DeviceList** - Filters by scan session
3. **VulnerabilityList** - Filters by scan session
4. **MainApp** - Manages active scan session state

## 📋 Implementation Steps

### Step 1: Run Database Migration
```bash
cd backend
source iot_env/bin/activate
python
```

```python
from src.main import app
from src.models import db

with app.app_context():
    db.create_all()
    print("✓ Scan sessions table created!")
```

### Step 2: Update Scanner Routes
- Modify `backend/src/routes/scanner.py`
- Add scan session management
- Update existing routes to filter by session

### Step 3: Create Frontend Components
- Create `ScanSessionSelector.jsx`
- Create `NewScanDialog.jsx`  
- Update `Dashboard.jsx` to use sessions
- Update `MainApp.jsx` to track active session

### Step 4: Update Context
- Add `activeScanSession` to `AuthContext`
- Add `setActiveScanSession` function
- Store in localStorage for persistence

## 🎯 User Experience Flow

1. **First Login**: User sees empty dashboard with "Create New Scan" button
2. **Click "Create New Scan"**: Dialog appears asking for scan name
3. **Enter Name & Start**: Scan begins for that named session
4. **View Results**: All data (devices, vulnerabilities) tied to that scan
5. **New Scan**: User can create another named scan
6. **Switch Scans**: Dropdown in sidebar to switch between past scans
7. **Scan History**: List of all past scans with stats

## 📊 UI Mockup

```
┌─────────────────────────────────────────┐
│ أداة فحص IoT                            │
├─────────────────────────────────────────┤
│ 👤 Username                       ▼    │
├─────────────────────────────────────────┤
│                                         │
│ 📂 الفحوصات:                          │
│   ┌───────────────────────────────┐   │
│   │ ⚡ فحص الشبكة المنزلية  ✓    │ ← Active
│   ├───────────────────────────────┤   │
│   │ 📅 فحص المكتب - 2025/01/03   │
│   ├───────────────────────────────┤   │
│   │ 🏢 فحص الشركة - 2025/01/02   │
│   └───────────────────────────────┘   │
│   [+ إنشاء فحص جديد]                  │
│                                         │
├─────────────────────────────────────────┤
│ 🏠 لوحة التحكم                        │
│ 💻 الأجهزة                            │
│ ⚠️  الثغرات                           │
│ 📄 التقارير                           │
└─────────────────────────────────────────┘
```

## 🚀 Benefits

1. ✅ **Isolation**: Each scan is separate and independent
2. ✅ **History**: Users can review past scans
3. ✅ **Comparison**: Compare results between scans
4. ✅ **Organization**: Name scans meaningfully
5. ✅ **Professional**: Much more enterprise-ready
6. ✅ **Clean Start**: New users see empty dashboard

## ⚠️ Important Notes

- Existing data will need migration (optional - can start fresh)
- Session IDs are UUIDs for security
- Deleted sessions cascade delete their devices/vulnerabilities
- Active session stored in localStorage for persistence

---

**Status**: Database models ready. Next: Implement backend API routes.
