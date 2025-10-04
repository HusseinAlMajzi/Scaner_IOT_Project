# 🚀 IoT Security Scanner - Startup Guide
## Quick Start Instructions for Your Graduation Project

---

## 📋 Prerequisites Check

Before starting, ensure you have:
- ✅ Python 3.11+ installed
- ✅ Node.js 18+ installed  
- ✅ PostgreSQL 12+ installed
- ✅ nmap installed (`sudo apt install nmap` on Linux)
- ✅ Git installed
- ✅ Terminal/Command Line access

---

## 🔧 STEP 1: Setup PostgreSQL Database

### 1.1 Run PostgreSQL Setup Script

```bash
cd backend

# Make script executable
chmod +x setup_postgresql.sh

# Run the setup script
./setup_postgresql.sh
```

This will:
- Create database: `iot_scanner_db`
- Create user: `hussein` with password `IoT_123456`
- Grant all necessary permissions
- Test the connection

**Alternative Manual Setup:**

If the script doesn't work, you can setup manually:

```bash
# Login to PostgreSQL
sudo -u postgres psql

# In PostgreSQL prompt, run:
CREATE DATABASE iot_scanner_db;
CREATE USER hussein WITH PASSWORD 'IoT_123456';
GRANT ALL PRIVILEGES ON DATABASE iot_scanner_db TO hussein;
\c iot_scanner_db
GRANT ALL ON SCHEMA public TO hussein;
\q
```

### 1.2 Verify .env File

Check that `backend/.env` contains:
```
DATABASE_URL=postgresql://hussein:IoT_123456@localhost:5432/iot_scanner_db
```

---

## 🔧 STEP 2: Backend Setup

### 2.1 Navigate to Backend Directory
```bash
cd backend  
```

### 2.2 Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv iot_env

# Activate it
source iot_env/bin/activate  # On Linux/Mac
# OR
iot_env\Scripts\activate     # On Windows
```

### 2.3 Install Dependencies
```bash
# Upgrade pip first
pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt
```

**Note**: Some packages might fail (binwalk, pybluez). This is OK - core functionality will still work.

### 2.4 Initialize Database
```bash
# Run database initialization
python init_db.py
```

This will:
- Create database tables
- Set up initial schema
- Verify database connection

### 2.5 Test Backend
```bash
# Run diagnostic to check everything
python diagnostic.py
```

All critical tests should pass!

---                                

## 🎨 STEP 3: Frontend Setup

### 3.1 Navigate to Frontend Directory
```bash
cd ../frontend
```

### 3.2 Install Dependencies
```bash
# Install Node packages
npm install
```

### 3.3 Build Frontend (Optional for Development)
```bash
# Build production version
npm run build

# Copy to backend static folder
cp -r dist/* ../backend/src/static/
```

---

## 🚀 STEP 4: Start the Application

### 4.1 Start Backend Server

In the backend directory:
```bash
# Make sure virtual environment is activated
source iot_env/bin/activate  # Linux/Mac
# OR
iot_env\Scripts\activate     # Windows

# Start the Flask server
python src/main.py
```

You should see:
```
===============================================================================
🛡️  IoT Security Scanner - Starting Application
===============================================================================

📍 Application Information:
   • Backend URL:  http://localhost:5000
   • API Endpoint: http://localhost:5000/api
   • Frontend:     http://localhost:5173 (run separately)

✓ Database tables created/verified successfully
✓ Server is running - Press CTRL+C to stop
===============================================================================
```

### 4.2 Start Frontend (Development Mode)

Open a **NEW terminal** and:
```bash
cd frontend 
npm run dev 
```

You should see:
```
  VITE v6.x.x  ready in xxx ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

---

## 🌐 STEP 5: Access the Application

1. **Open your browser**
2. **Navigate to**: `http://localhost:5173`
3. **You should see** the login page

### 5.1 Create First User Account

1. Click "إنشاء حساب جديد" (Create New Account)
2. Fill in:
   - Username: `admin`
   - Email: `admin@iotscan.local`
   - Password: `Admin@123456`
   - Confirm Password: `Admin@123456`
3. Click "إنشاء الحساب"

### 5.2 Login

1. Login with your credentials
2. You'll see the main dashboard

---

## 🔍 STEP 6: Run Your First Scan

### 6.1 Start a Comprehensive Scan

1. On the dashboard, click **"بدء الفحص"** (Start Scan)
2. Wait for the scan to complete (progress will show)
3. Watch as:
   - 📡 Devices are discovered
   - 🔒 Vulnerabilities are detected
   - 📊 Statistics update in real-time

### 6.2 View Results

Navigate through the sidebar:
- **لوحة التحكم** (Dashboard) - Overview
- **الأجهزة** (Devices) - Discovered devices
- **الثغرات** (Vulnerabilities) - Security issues
- **التقارير** (Reports) - Generate reports

---

## 📊 STEP 7: Generate a Report

1. Go to **التقارير** (Reports) page
2. Click **"إنشاء تقرير جديد"** (Create New Report)
3. Wait for generation
4. Click **"تحميل"** (Download) to save the report

---

## 🐛 Troubleshooting

### Issue: Backend won't start
**Solution**:
```bash
# Check if port 5000 is already in use
lsof -i :5000  # Linux/Mac
netstat -ano | findstr :5000  # Windows

# If busy, kill the process or change port in .env
```

### Issue: Frontend won't start  
**Solution**:
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### Issue: Database errors
**Solution**:
```bash
# PostgreSQL: Drop and recreate
sudo -u postgres psql -c "DROP DATABASE IF EXISTS iot_scanner_db;"
sudo -u postgres psql -c "CREATE DATABASE iot_scanner_db;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE iot_scanner_db TO hussein;"

# Then reinitialize
cd backend
python init_db.py
```

### Issue: PostgreSQL connection refused
**Solution**:
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# If not running, start it
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Check if you can connect
psql -h localhost -U hussein -d iot_scanner_db
```

### Issue: Scan finds no devices
**Solution**:
- Make sure you're on the same network as IoT devices
- Try running backend with sudo for network scanning:
  ```bash
  sudo python src/main.py
  ```
- Check firewall settings

### Issue: Permission denied for nmap
**Solution**:
```bash
# Give nmap special permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
```

---

## 📝 Development Mode vs Production

### Development (Current Setup)
- Frontend: `http://localhost:5173` (Vite dev server)
- Backend: `http://localhost:5000` (Flask debug mode)
- Hot reload enabled
- Debug messages visible

### Production Deployment
1. Build frontend:
   ```bash
   cd frontend
   npm run build
   cp -r dist/* ../backend/src/static/
   ```

2. Run backend only:
   ```bash
   cd backend
   source iot_env/bin/activate
   python src/main.py
   ```

3. Access at: `http://localhost:5000`

---

## 🎓 For Your Graduation Presentation

### Preparation Checklist:
- [ ] Test all scanning modes
- [ ] Generate sample reports
- [ ] Prepare demo network with IoT devices
- [ ] Test on different browsers
- [ ] Prepare screenshots
- [ ] Document any known limitations

### Demo Flow:
1. Show login/registration
2. Start a scan and explain phases
3. Show discovered devices
4. Show vulnerability detection  
5. Generate and show report
6. Explain technical architecture
7. Highlight free vs paid tools comparison

### Key Points to Emphasize:
- ✨ **Free & Open Source** - Unlike paid alternatives
- 🔍 **Comprehensive Scanning** - Multiple protocols
- 🚀 **Modern Tech Stack** - React + Flask
- 🛡️ **Security Focused** - IoT-specific vulnerabilities
- 📊 **Professional Reports** - Detailed and actionable
- 🌐 **Multi-Language** - Arabic interface (unique!)

---

## 💡 Tips for Success

1. **Run scan on actual network**: The tool is more impressive with real devices
2. **Keep logs**: `backend/logs/app.log` shows detailed operation
3. **Test before presentation**: Do a full run-through 24 hours before
4. **Have backup**: Take screenshots of successful scans
5. **Know your code**: Be ready to explain key components

---

## 📞 Quick Reference

### Start Everything:
```bash
# Terminal 1 - Backend
cd backend && source iot_env/bin/activate && python src/main.py

# Terminal 2 - Frontend  
cd frontend && npm run dev
```

### Stop Everything:
- Press `CTRL+C` in each terminal

### Reset Everything:
```bash
# Backend
cd backend
rm iot_scanner.db
python init_db.py

# Frontend
cd frontend
rm -rf node_modules
npm install
```

---

## ✅ Final Checklist Before Presentation

- [ ] Backend starts without errors
- [ ] Frontend loads correctly
- [ ] Can create user account
- [ ] Can login successfully
- [ ] Scan discovers devices
- [ ] Vulnerabilities are detected
- [ ] Can generate reports
- [ ] Reports can be downloaded
- [ ] All pages navigate correctly
- [ ] Arabic text displays properly (RTL)

---

**🎉 You're Ready! Good Luck with Your Graduation Project! 🎓**

---

## 📚 Additional Resources

- **Backend Code**: `backend/src/`
- **Frontend Code**: `frontend/src/`
- **Database Models**: `backend/src/models/`
- **Scanner Services**: `backend/src/services/`
- **API Routes**: `backend/src/routes/`

**Remember**: This is a graduation project you can be proud of! It demonstrates:
- Full-stack development skills
- Security knowledge
- Modern architecture
- Professional UI/UX
- Real-world problem solving

**Show it with confidence!** 💪
