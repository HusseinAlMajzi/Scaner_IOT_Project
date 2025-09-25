# دليل التثبيت المفصل - أداة فحص أمان أجهزة IoT

## متطلبات النظام

### الحد الأدنى من المتطلبات
- **نظام التشغيل**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / macOS 11+
- **المعالج**: Intel/AMD x64 أو ARM64
- **الذاكرة**: 4 GB RAM (8 GB مُوصى به)
- **التخزين**: 2 GB مساحة فارغة
- **الشبكة**: اتصال إنترنت لتحميل التحديثات

### البرامج المطلوبة
- **Python**: 3.11 أو أحدث
- **Node.js**: 18.0 أو أحدث
- **PostgreSQL**: 12.0 أو أحدث
- **Git**: لتحميل المشروع
- **nmap**: أداة فحص الشبكة

## التثبيت على Ubuntu/Debian

### الخطوة 1: تحديث النظام
```bash
sudo apt update && sudo apt upgrade -y
```

### الخطوة 2: تثبيت المتطلبات الأساسية
```bash
# تثبيت Python و pip
sudo apt install python3.11 python3.11-venv python3-pip -y

# تثبيت Node.js و npm
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y

# تثبيت PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# تثبيت Git و nmap
sudo apt install git nmap -y

# تثبيت مكتبات التطوير
sudo apt install build-essential libpq-dev python3.11-dev -y
```

### الخطوة 3: إعداد PostgreSQL
```bash
# بدء خدمة PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# إنشاء قاعدة البيانات والمستخدم
sudo -u postgres psql << EOF
CREATE DATABASE iot_scanner_db;
CREATE USER hussein WITH PASSWORD 'IoT_123456';
GRANT ALL PRIVILEGES ON DATABASE iot_scanner_db TO iot_scanner;
ALTER USER hussein CREATEDB;
\q
EOFcdl
```

### الخطوة 4: تحميل المشروع
```bash
# تحميل المشروع (إذا كان متوفراً على Git)
# git clone https://github.com/your-repo/iot-security-scanner.git
# cd iot-security-scanner

# أو استخراج من ملف ZIP
unzip iot_security_scanner.zip
cd iot_security_scanner
```

### الخطوة 5: إعداد Backend
```bash
cd backend

# إنشاء البيئة الافتراضية
python3.11 -m venv venv

# تفعيل البيئة الافتراضية
source venv/bin/activate

# تثبيت المتطلبات
pip install --upgrade pip
pip install -r requirements.txt

# إعداد متغيرات البيئة
cat > .env << EOF
DATABASE_URL=postgresql://iot_scanner:IoT_Scanner_2025!@localhost/iot_scanner_db
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
EOF
```

### الخطوة 6: إعداد Frontend
```bash
cd ../frontend

# تثبيت المتطلبات
npm install

# بناء المشروع
npm run build

# نسخ الملفات إلى Backend
cp -r dist/* ../backend/src/static/
```

### الخطوة 7: إعداد قاعدة البيانات
```bash
cd ../backend
source venv/bin/activate

# تشغيل migrations (إذا كانت متوفرة)
python src/create_tables.py
```

### الخطوة 8: إعداد صلاحيات nmap
```bash
# إعطاء صلاحيات خاصة لـ nmap
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)

# أو تشغيل التطبيق بصلاحيات sudo (غير مُوصى به للإنتاج)
```

### الخطوة 9: اختبار التثبيت
```bash
cd backend
source venv/bin/activate
python src/main.py
```

افتح المتصفح وانتقل إلى: `http://localhost:5000`

## التثبيت على CentOS/RHEL/Fedora

### الخطوة 1: تحديث النظام
```bash
sudo dnf update -y  # Fedora
# أو
sudo yum update -y  # CentOS/RHEL
```

### الخطوة 2: تثبيت المتطلبات
```bash
# تثبيت Python
sudo dnf install python3.11 python3.11-pip python3.11-devel -y

# تثبيت Node.js
sudo dnf install nodejs npm -y

# تثبيت PostgreSQL
sudo dnf install postgresql postgresql-server postgresql-contrib -y

# تثبيت أدوات التطوير
sudo dnf groupinstall "Development Tools" -y
sudo dnf install git nmap -y
```

### الخطوة 3: إعداد PostgreSQL
```bash
# تهيئة قاعدة البيانات
sudo postgresql-setup --initdb

# بدء الخدمة
sudo systemctl start postgresql
sudo systemctl enable postgresql

# إعداد المصادقة
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" /var/lib/pgsql/data/postgresql.conf
sudo sed -i "s/ident/md5/g" /var/lib/pgsql/data/pg_hba.conf

# إعادة تشغيل الخدمة
sudo systemctl restart postgresql

# إنشاء قاعدة البيانات
sudo -u postgres psql << EOF
CREATE DATABASE iot_scanner_db;
CREATE USER iot_scanner WITH PASSWORD 'IoT_Scanner_2025!';
GRANT ALL PRIVILEGES ON DATABASE iot_scanner_db TO iot_scanner;
\q
EOF
```

## التثبيت على macOS

### الخطوة 1: تثبيت Homebrew
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### الخطوة 2: تثبيت المتطلبات
```bash
# تثبيت Python
brew install python@3.11

# تثبيت Node.js
brew install node

# تثبيت PostgreSQL
brew install postgresql@14

# تثبيت nmap
brew install nmap

# تثبيت Git
brew install git
```

### الخطوة 3: إعداد PostgreSQL
```bash
# بدء خدمة PostgreSQL
brew services start postgresql@14

# إنشاء قاعدة البيانات
createdb iot_scanner_db
psql iot_scanner_db << EOF
CREATE USER iot_scanner WITH PASSWORD 'IoT_Scanner_2025!';
GRANT ALL PRIVILEGES ON DATABASE iot_scanner_db TO iot_scanner;
\q
EOF
```

## إعداد الإنتاج

### استخدام Gunicorn (مُوصى به)
```bash
cd backend
source venv/bin/activate

# تثبيت Gunicorn
pip install gunicorn

# إنشاء ملف إعداد Gunicorn
cat > gunicorn.conf.py << EOF
bind = "0.0.0.0:5000"
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
preload_app = True
EOF

# تشغيل التطبيق
gunicorn --config gunicorn.conf.py src.main:app
```

### إعداد Nginx (اختياري)
```bash
# تثبيت Nginx
sudo apt install nginx -y

# إنشاء إعداد الموقع
sudo cat > /etc/nginx/sites-available/iot-scanner << EOF
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static {
        alias /path/to/iot_security_scanner/backend/src/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# تفعيل الموقع
sudo ln -s /etc/nginx/sites-available/iot-scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### إعداد خدمة systemd
```bash
# إنشاء ملف الخدمة
sudo cat > /etc/systemd/system/iot-scanner.service << EOF
[Unit]
Description=IoT Security Scanner
After=network.target postgresql.service

[Service]
Type=exec
User=www-data
Group=www-data
WorkingDirectory=/path/to/iot_security_scanner/backend
Environment=PATH=/path/to/iot_security_scanner/backend/venv/bin
ExecStart=/path/to/iot_security_scanner/backend/venv/bin/gunicorn --config gunicorn.conf.py src.main:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# تفعيل وبدء الخدمة
sudo systemctl daemon-reload
sudo systemctl enable iot-scanner
sudo systemctl start iot-scanner
```

## إعداد الأمان

### 1. إعداد جدار الحماية
```bash
# Ubuntu/Debian
sudo ufw enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 5000/tcp  # التطبيق (للتطوير فقط)

# CentOS/RHEL
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 2. تأمين PostgreSQL
```bash
# تغيير كلمة مرور postgres
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'strong_password_here';"

# تقييد الاتصالات
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" /etc/postgresql/*/main/postgresql.conf
```

### 3. إعداد SSL/HTTPS (للإنتاج)
```bash
# تثبيت Certbot
sudo apt install certbot python3-certbot-nginx -y

# الحصول على شهادة SSL
sudo certbot --nginx -d your-domain.com
```

## استكشاف الأخطاء

### مشاكل شائعة

#### 1. خطأ في الاتصال بقاعدة البيانات
```bash
# تحقق من حالة PostgreSQL
sudo systemctl status postgresql

# اختبار الاتصال
psql -h localhost -U iot_scanner -d iot_scanner_db

# إعادة تعيين كلمة المرور
sudo -u postgres psql -c "ALTER USER iot_scanner PASSWORD 'new_password';"
```

#### 2. مشاكل صلاحيات nmap
```bash
# تحقق من الصلاحيات
getcap $(which nmap)

# إعادة تعيين الصلاحيات
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)

# أو تشغيل بـ sudo
sudo python src/main.py
```

#### 3. مشاكل في Frontend
```bash
# تنظيف وإعادة البناء
cd frontend
rm -rf node_modules dist
npm install
npm run build
cp -r dist/* ../backend/src/static/
```

#### 4. مشاكل الذاكرة
```bash
# زيادة swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### سجلات الأخطاء
```bash
# سجلات التطبيق
tail -f /var/log/iot-scanner/app.log

# سجلات PostgreSQL
sudo tail -f /var/log/postgresql/postgresql-*.log

# سجلات Nginx
sudo tail -f /var/log/nginx/error.log
```

## التحديث

### تحديث التطبيق
```bash
# إيقاف الخدمة
sudo systemctl stop iot-scanner

# تحديث الكود
cd /path/to/iot_security_scanner
git pull origin main

# تحديث Backend
cd backend
source venv/bin/activate
pip install -r requirements.txt

# تحديث Frontend
cd ../frontend
npm install
npm run build
cp -r dist/* ../backend/src/static/

# إعادة تشغيل الخدمة
sudo systemctl start iot-scanner
```

## النسخ الاحتياطي

### نسخ احتياطي لقاعدة البيانات
```bash
# إنشاء نسخة احتياطية
pg_dump -h localhost -U iot_scanner iot_scanner_db > backup_$(date +%Y%m%d_%H%M%S).sql

# استعادة النسخة الاحتياطية
psql -h localhost -U iot_scanner iot_scanner_db < backup_file.sql
```

### نسخ احتياطي للتطبيق
```bash
# إنشاء أرشيف كامل
tar -czf iot_scanner_backup_$(date +%Y%m%d).tar.gz /path/to/iot_security_scanner
```

## الدعم الفني

إذا واجهت أي مشاكل أثناء التثبيت:

1. **تحقق من السجلات** للحصول على تفاصيل الخطأ
2. **راجع الوثائق** للتأكد من اتباع الخطوات بشكل صحيح
3. **تحقق من المتطلبات** والتأكد من توفر جميع المتطلبات
4. **أبلغ عن المشكلة** مع تفاصيل النظام ورسالة الخطأ

---

**ملاحظة**: هذا الدليل يغطي معظم السيناريوهات الشائعة. قد تحتاج إلى تعديلات إضافية حسب بيئة النظام المحددة.

