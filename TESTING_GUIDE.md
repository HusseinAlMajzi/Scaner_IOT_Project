# 🧪 IoT Security Scanner - Testing & Debugging Guide

## Understanding the 401 Error (This is NORMAL!)

When you first load the application, you'll see this in the backend logs:
```
INFO:werkzeug:127.0.0.1 - - [04/Oct/2025 02:26:03] "GET /api/auth/me HTTP/1.1" 401 -
```

**This is expected behavior!** It means:
- ✅ Frontend is working correctly
- ✅ Backend is responding
- ✅ The frontend is checking if you're already logged in
- ✅ Since you're not logged in yet, it returns 401 (which is correct!)

This is NOT an error - it's the authentication system working as designed.

---

## 🔍 Step-by-Step Testing Guide

### Test 1: Check Backend is Running

1. **Check backend logs** - You should see:
```
===============================================================================
🛡️  IoT Security Scanner - Starting Application
===============================================================================
...
✓ Database tables created/verified successfully
✓ Server is running - Press CTRL+C to stop
```

2. **Test health endpoint** in your browser:
```
http://localhost:5000/api/health
```

You should see:
```json
{
  "status": "healthy",
  "message": "IoT Security Scanner API is running",
  "version": "1.0.0",
  "database": "connected"
}
```

✅ **If you see this, backend is working perfectly!**

### Test 2: Check Frontend is Running

1. Open browser to: `http://localhost:5173`
2. You should see the **login page** with:
   - 🛡️ Shield icon
   - "أداة فحص أمان IoT" title
   - Login form

✅ **If you see the login page, frontend is working!**

### Test 3: Test User Registration

1. Click **"إنشاء حساب جديد"** (Create New Account)
2. Fill in the form:
   - Username: `testuser`
   - Email: `test@example.com`
   - Password: `Test@123456`
   - Confirm Password: `Test@123456`
3. Click **"إنشاء الحساب"**

**Watch backend logs** - You should see:
```
INFO:werkzeug:127.0.0.1 - - [Date] "POST /api/auth/register HTTP/1.1" 201 -
```

✅ **Status 201 = User created successfully!**

❌ **If you see 400/500** - Check the error message in the browser alert.

### Test 4: Test User Login

1. On login page, enter:
   - Username: `testuser`
   - Password: `Test@123456`
2. Click **"تسجيل الدخول"**

**Watch backend logs** - You should see:
```
INFO:werkzeug:127.0.0.1 - - [Date] "POST /api/auth/login HTTP/1.1" 200 -
INFO:werkzeug:127.0.0.1 - - [Date] "GET /api/auth/me HTTP/1.1" 200 -
```

✅ **Status 200 = Login successful! You should be redirected to dashboard.**

❌ **If login fails** - See troubleshooting below.

### Test 5: Check Database

```bash  
# In backend directory
python check_database.py
```

You should see:
```
📋 USERS:    
Total Users: 1
  ├─ ID: 1
  ├─ Username: testuser
  ├─ Email: test@example.com
  └─ Active: True
```

✅ **If you see your user, database is working!**

---

## 🔧 Common Issues and Solutions

### Issue 1: "خطأ في الاتصال بالخادم" (Server Connection Error)

**Symptoms:**  
- Alert shows "خطأ في الاتصال بالخادم"
- No backend logs appear

**Solutions:**

1. **Check if backend is actually running:**
   ```bash
   # In new terminal
   lsof -i :5000
   ```
   Should show python process on port 5000

2. **Check backend URL in browser console:**
   Open browser DevTools (F12) → Console → Look for API requests
   
   If you see errors to `http://localhost:5000`, backend is down.

3. **Restart backend:**
   ```bash
   cd backend
   source iot_env/bin/activate
   python src/main.py       
   ```

### Issue 2: "اسم المستخدم أو كلمة المرور غير صحيحة"

**Symptoms:**
- You enter correct credentials but get "wrong username/password" error

**Solutions:**

1. **Check if user exists in database:**
   ```bash
   cd backend
   python check_database.py
   ```

2. **Try registering again** (maybe registration failed)

3. **Check PostgreSQL connection:**
   ```bash
   psql -h localhost -U hussein -d iot_scanner_db -c "SELECT * FROM users;"
   ```

4. **Reset password in database:**
   ```bash
   cd backend
   python
   ```
   Then in Python:
   ```python
   from src.main import app
   from src.models import db, User
   
   with app.app_context():
       user = User.query.filter_by(username='testuser').first()
       if user:
           user.set_password('Test@123456')
           db.session.commit()
           print("Password reset!")
   ```

### Issue 3: Login Succeeds but Redirects to Login Again

**Symptoms:**
- Login returns success
- You're redirected but immediately see login page again

**Solutions:**

1. **Check browser console for errors**
   - Open DevTools (F12) → Console
   - Look for JavaScript errors

2. **Check cookies:**
   - DevTools → Application → Cookies
   - Look for `iot_scanner_session`
   - If missing, session isn't being saved

3. **Try different browser** (Chrome, Firefox, Edge)

4. **Clear browser cache and cookies:**
   ```
   CTRL+SHIFT+DELETE → Clear browsing data
   ```

5. **Check CORS settings** - The backend logs should NOT show:
   ```
   CORS error
   ```

### Issue 4: 500 Internal Server Error

**Symptoms:**
- Backend logs show:
  ```
  ERROR: ... (some error message)
  ```

**Solutions:**

1. **Read the full error** in backend terminal

2. **Common causes:**
   - Database connection failed
   - Missing table in database
   - Python package missing

3. **Reinitialize database:**
   ```bash
   cd backend
   python init_db.py
   ```

4. **Check database connection:**
   ```bash
   psql -h localhost -U hussein -d iot_scanner_db
   ```

### Issue 5: Frontend Shows White Screen

**Symptoms:**
- Browser shows blank white page
- No login form visible

**Solutions:**

1. **Check browser console** (F12) for errors

2. **Check if Vite dev server is running:**
   ```bash
   cd frontend
   npm run dev
   ```

3. **Reinstall dependencies:**
   ```bash
   cd frontend
   rm -rf node_modules package-lock.json
   npm install
   npm run dev
   ```

4. **Check if port 5173 is available:**
   ```bash
   lsof -i :5173
   ```

---

## 🐛 Advanced Debugging

### Enable Verbose Logging

**Backend:**

Edit `backend/src/main.py` - Add at the top:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Frontend:**

The API config already has console.log statements. Check browser console (F12).

### Test API Endpoints Directly

Use `curl` to test backend:

1. **Test registration:**
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "curltest",
    "email": "curl@test.com",
    "password": "Test@123456",
    "confirmPassword": "Test@123456"
  }'
```

Should return:
```json
{
  "success": true,
  "message": "تم إنشاء الحساب بنجاح"
}
```

2. **Test login:**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "username": "curltest",
    "password": "Test@123456"
  }'
```

Should return:
```json
{
  "success": true,
  "message": "تم تسجيل الدخول بنجاح",
  "user": {...}
}
```

3. **Test authenticated endpoint:**
```bash
curl -X GET http://localhost:5000/api/auth/me \
  -b cookies.txt
```

Should return user data (not 401).

### Check Database Connection

```bash
cd backend
python -c "
from src.main import app
from src.models import db

with app.app_context():
    try:
        result = db.session.execute(db.text('SELECT 1')).scalar()
        print('✓ Database connected! Result:', result)
    except Exception as e:
        print('✗ Database error:', e)
"
```

### Check All Tables Exist

```bash
cd backend
python -c "
from src.main import app
from src.models import db
from sqlalchemy import inspect

with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print('Database tables:', tables)
    
    expected = ['users', 'devices', 'vulnerabilities', 'scan_results', 'reports']
    for table in expected:
        if table in tables:
            print(f'✓ {table}')
        else:
            print(f'✗ {table} MISSING!')
"
```

---

## ✅ Complete Test Checklist

Run through this checklist to verify everything works:

### Backend Tests:
- [ ] Backend starts without errors
- [ ] Health endpoint returns success: `http://localhost:5000/api/health`
- [ ] API info endpoint works: `http://localhost:5000/api`
- [ ] Database connection works
- [ ] All tables exist (users, devices, vulnerabilities, scan_results, reports)

### Frontend Tests:
- [ ] Frontend dev server starts
- [ ] Login page loads at `http://localhost:5173`
- [ ] No JavaScript errors in console
- [ ] Arabic text displays correctly (RTL)

### Authentication Tests:
- [ ] Can register new user
- [ ] Registration creates user in database
- [ ] Can login with registered user
- [ ] After login, redirected to dashboard
- [ ] Session persists (refresh page, still logged in)
- [ ] Can logout successfully

### Navigation Tests:
- [ ] Dashboard page loads
- [ ] Devices page loads (shows "لا توجد أجهزة" initially)
- [ ] Vulnerabilities page loads (shows statistics)
- [ ] Reports page loads (shows "لا توجد تقارير" initially)
- [ ] Sidebar navigation works
- [ ] Active tab highlights correctly

### Scanning Tests:
- [ ] Can start a scan from dashboard
- [ ] Scan progress shows in real-time
- [ ] Scan completes successfully
- [ ] Devices appear in database
- [ ] Devices show in Devices page
- [ ] Vulnerabilities appear in database
- [ ] Vulnerabilities show in Vulnerabilities page

### Report Tests:
- [ ] Can generate report
- [ ] Report shows in Reports list
- [ ] Can view report details
- [ ] Can download report

---

## 🎯 Quick Health Check Script

Save this as `backend/health_check.py`:

```python
#!/usr/bin/env python3
import sys
import requests

def check_health():
    print("🔍 IoT Scanner Health Check\n")
    
    # Test backend
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        if response.status_code == 200:
            print("✓ Backend is running")
            data = response.json()
            print(f"  Database: {data.get('database', 'unknown')}")
        else:
            print(f"✗ Backend returned {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Cannot connect to backend: {e}")
        return False
    
    # Test database
    from src.main import app
    from src.models import db
    
    with app.app_context():
        try:
            db.session.execute(db.text('SELECT 1'))
            print("✓ Database connection OK")
        except Exception as e:
            print(f"✗ Database error: {e}")
            return False
    
    # Test tables
    from sqlalchemy import inspect
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        required = ['users', 'devices', 'vulnerabilities', 'scan_results', 'reports']
        
        all_exist = True
        for table in required:
            if table in tables:
                print(f"✓ Table '{table}' exists")
            else:
                print(f"✗ Table '{table}' missing!")
                all_exist = False
        
        if not all_exist:
            return False
    
    print("\n🎉 All health checks passed!")
    return True

if __name__ == '__main__':
    success = check_health()
    sys.exit(0 if success else 1)
```

Run it:
```bash
cd backend
source iot_env/bin/activate
python health_check.py
```

---

## 📞 Still Having Issues?

If you've tried everything above and still have problems:

1. **Capture full error logs:**
   ```bash
   # Backend
   python src/main.py 2>&1 | tee backend.log
   ```

2. **Check PostgreSQL logs:**
   ```bash
   sudo tail -f /var/log/postgresql/postgresql-*.log
   ```

3. **Double-check .env file:**
   ```bash
   cat backend/.env
   ```
   Make sure DATABASE_URL is correct.

4. **Try with a fresh database:**
   ```bash
   ./backend/setup_postgresql.sh
   python backend/init_db.py
   ```

5. **Restart everything from scratch:**
   ```bash
   # Kill all processes
   pkill -f "python src/main.py"
   pkill -f "npm run dev"
   
   # Restart backend
   cd backend && source iot_env/bin/activate && python src/main.py
   
   # Restart frontend (new terminal)
   cd frontend && npm run dev
   ```

---

**Remember:** The 401 error on first load is NORMAL! Don't worry about it. Focus on whether you can successfully register and login. 

Good luck! 🚀
