# أداة فحص أمان أجهزة IoT المتقدمة

## نظرة عامة

أداة متقدمة وشاملة لاكتشاف وتحليل الثغرات الأمنية في أجهزة إنترنت الأشياء (IoT). تم تطوير هذه الأداة باستخدام أحدث التقنيات لتوفير فحص دقيق ومتعمق للبروتوكولات والخدمات المختلفة.

## المميزات الرئيسية

### 🔍 فحص شامل ومتقدم
- **اكتشاف الأجهزة**: فحص تلقائي للشبكة لاكتشاف جميع أجهزة IoT المتصلة
- **تحليل البروتوكولات**: فحص متعمق لأكثر من 15 بروتوكول IoT مختلف
- **اكتشاف الثغرات**: تحديد الثغرات الأمنية الحديثة والمعروفة
- **تحليل SSL/TLS**: فحص شامل لإعدادات التشفير والشهادات

### 🛡️ البروتوكولات المدعومة
- **MQTT** (Message Queuing Telemetry Transport)
- **CoAP** (Constrained Application Protocol)
- **Modbus TCP/IP** (Industrial Protocol)
- **BACnet** (Building Automation)
- **DNP3** (Distributed Network Protocol)
- **UPnP** (Universal Plug and Play)
- **SNMP** (Simple Network Management Protocol)
- **Zigbee Protocol**
- **LoRaWAN Protocol**
- **HTTP/HTTPS Web Interfaces**
- **SSH, Telnet, FTP**
- **Custom IoT Protocols**

### 🔐 أنواع الفحص الأمني
- **اختبار كلمات المرور الافتراضية**
- **تحليل أمان SSL/TLS**
- **فحص رؤوس الأمان**
- **اكتشاف الثغرات الحرجة**
- **تحليل إعدادات المصادقة**
- **فحص الخدمات الخطيرة**
- **اختبار Directory Traversal**
- **تحليل واجهات الويب**

### 📊 التقارير والتحليل
- **تقارير تفصيلية بصيغة HTML و PDF**
- **تصنيف الثغرات حسب الخطورة**
- **توصيات أمنية مخصصة**
- **إحصائيات شاملة**
- **تصدير البيانات**

## التقنيات المستخدمة

### Backend
- **Flask** - إطار عمل Python للخادم
- **PostgreSQL** - قاعدة بيانات متقدمة
- **SQLAlchemy** - ORM للتعامل مع قاعدة البيانات
- **Nmap** - فحص الشبكة والمنافذ
- **Scapy** - تحليل حزم الشبكة
- **aiohttp** - طلبات HTTP غير متزامنة
- **python-nmap** - واجهة Python لـ Nmap

### Frontend
- **React 18** - مكتبة واجهة المستخدم
- **Vite** - أداة البناء السريعة
- **Tailwind CSS** - إطار عمل CSS
- **Lucide React** - أيقونات حديثة
- **Responsive Design** - تصميم متجاوب

### قاعدة البيانات
- **PostgreSQL** - قاعدة بيانات علائقية متقدمة
- **جداول محسنة** للأجهزة والثغرات والتقارير
- **فهرسة متقدمة** لتحسين الأداء

## متطلبات النظام

### متطلبات أساسية
- **Python 3.11+**
- **Node.js 18+**
- **PostgreSQL 12+**
- **nmap** (مثبت على النظام)
- **نظام Linux/Unix** (مُوصى به)

### المكتبات المطلوبة
```bash
# Backend Dependencies
Flask==3.1.0
SQLAlchemy==2.0.36
psycopg2-binary==2.9.10
python-nmap==0.7.1
scapy==2.6.1
aiohttp==3.12.15
netaddr==1.3.0
jinja2==3.1.6
markdown==3.8.2

# Frontend Dependencies
React 18
Vite 6
Tailwind CSS 3
```

## التثبيت والإعداد

### 1. إعداد قاعدة البيانات
```bash
# تثبيت PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# إنشاء قاعدة البيانات والمستخدم
sudo -u postgres psql
CREATE DATABASE iot_scanner_db;
CREATE USER iot_scanner WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE iot_scanner_db TO iot_scanner;
\q
```

### 2. إعداد Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
# أو
venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

### 3. إعداد Frontend
```bash
cd frontend
npm install
npm run build
```

### 4. تشغيل التطبيق
```bash
# تشغيل Backend
cd backend
source venv/bin/activate
python src/main.py

# الوصول للتطبيق
http://localhost:5000
```

## الاستخدام

### 1. بدء فحص جديد
1. افتح التطبيق في المتصفح
2. انقر على "بدء الفحص" في لوحة التحكم
3. انتظر اكتمال عملية الفحص

### 2. عرض النتائج
- **الأجهزة**: عرض جميع الأجهزة المكتشفة مع تفاصيلها
- **الثغرات**: قائمة بجميع الثغرات المكتشفة مع تصنيفها
- **التقارير**: إنشاء وتحميل التقارير التفصيلية

### 3. إنشاء التقارير
1. انتقل إلى صفحة "التقارير"
2. انقر على "إنشاء تقرير جديد"
3. انتظر إنشاء التقرير
4. حمل التقرير بصيغة HTML أو PDF

## هيكل المشروع

```
iot_security_scanner/
├── backend/
│   ├── src/
│   │   ├── main.py              # نقطة دخول التطبيق
│   │   ├── models/              # نماذج قاعدة البيانات
│   │   │   ├── device.py
│   │   │   ├── vulnerability.py
│   │   │   ├── scan_result.py
│   │   │   └── report.py
│   │   ├── services/            # خدمات الفحص
│   │   │   ├── device_scanner.py
│   │   │   ├── vulnerability_scanner.py
│   │   │   ├── protocol_scanner.py
│   │   │   ├── advanced_scanner.py
│   │   │   └── report_generator.py
│   │   ├── routes/              # مسارات API
│   │   │   └── scanner.py
│   │   └── static/              # ملفات Frontend المبنية
│   ├── venv/                    # البيئة الافتراضية
│   └── requirements.txt    
│   │   
│   │   
│   │      
│   │   
│   │   
│   │   
│   │   
│   ├── dist/                    # ملفات البناء
│   ├── package.json             # متطلبات Node.js
│   └── vite.config.js           # إعدادات Vite
├── system_design.md             # وثيقة تصميم النظام
└── README.md                    # هذا الملف     # متطلبات Python
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # المكون الرئيسي
│   │   ├── components/          # مكونات React
│   │   │   ├── Dashboard.jsx
│   │   │   ├── DeviceList.jsx
│   │   │   ├── VulnerabilityList.jsx
│   │   │   └── ReportsList.jsx
│   │   └── App.css              # أنماط CSS
│   ├── dist/                    # ملفات البناء
│   ├── package.json             # متطلبات Node.js
│   └── vite.config.js           # إعدادات Vite
├── system_design.md             # وثيقة تصميم النظام
└── README.md                    # هذا الملف
```

## الأمان والخصوصية

### إجراءات الأمان
- **فحص آمن**: جميع عمليات الفحص تتم بطريقة آمنة دون إلحاق ضرر
- **عدم التخزين الحساس**: لا يتم تخزين كلمات مرور أو بيانات حساسة
- **تشفير الاتصالات**: دعم HTTPS و SSL/TLS
- **صلاحيات محدودة**: التطبيق يعمل بصلاحيات محدودة

### الخصوصية
- **البيانات المحلية**: جميع البيانات تُحفظ محلياً
- **عدم الإرسال الخارجي**: لا يتم إرسال أي بيانات لخوادم خارجية
- **شفافية كاملة**: الكود مفتوح المصدر وقابل للمراجعة

## الميزات المتقدمة

### 1. فحص البروتوكولات المتقدم
- **تحليل عميق** لحزم البيانات
- **اكتشاف البروتوكولات المخصصة**
- **فحص التشفير والمصادقة**
- **تحليل الأمان للبروتوكولات الصناعية**

### 2. اكتشاف الثغرات الحديثة
- **قاعدة بيانات محدثة** للثغرات
- **فحص CVE الحديثة**
- **تحليل الثغرات المخصصة لـ IoT**
- **اكتشاف الثغرات Zero-Day المحتملة**

### 3. التحليل الذكي
- **تصنيف تلقائي** للأجهزة
- **تحليل المخاطر المتقدم**
- **توصيات مخصصة**
- **تنبؤ بالتهديدات المحتملة**

## استكشاف الأخطاء

### مشاكل شائعة وحلولها

#### 1. خطأ في الاتصال بقاعدة البيانات
```bash
# تأكد من تشغيل PostgreSQL
sudo systemctl status postgresql
sudo systemctl start postgresql

# تحقق من إعدادات الاتصال
psql -h localhost -U iot_scanner -d iot_scanner_db
```

#### 2. خطأ في صلاحيات nmap
```bash
# إعطاء صلاحيات لـ nmap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
```

#### 3. مشاكل في Frontend
```bash
# إعادة بناء Frontend
cd frontend
npm run build
cp -r dist/* ../backend/src/static/
```

## المساهمة في التطوير

### إرشادات المساهمة
1. **Fork** المشروع
2. إنشاء **branch** جديد للميزة
3. **Commit** التغييرات مع وصف واضح
4. **Push** إلى الـ branch
5. إنشاء **Pull Request**

### معايير الكود
- **PEP 8** لكود Python
- **ESLint** لكود JavaScript
- **تعليقات واضحة** باللغة العربية
- **اختبارات شاملة** للميزات الجديدة

## الترخيص

هذا المشروع مرخص تحت رخصة MIT. راجع ملف LICENSE للتفاصيل.

## الدعم والمساعدة

### الحصول على المساعدة
- **الوثائق**: راجع ملفات الوثائق في المشروع
- **المشاكل**: أبلغ عن المشاكل عبر GitHub Issues
- **المناقشات**: شارك في المناقشات عبر GitHub Discussions

### معلومات الاتصال
- **المطور**: فريق تطوير أمان IoT
- **الإصدار**: 1.0.0
- **تاريخ الإصدار**: أغسطس 2025

## الشكر والتقدير

نشكر جميع المساهمين في تطوير هذه الأداة والمجتمع المفتوح المصدر لأدوات الأمان.

---

**ملاحظة مهمة**: هذه الأداة مخصصة للاستخدام الأخلاقي فقط. يُرجى استخدامها فقط على الشبكات والأجهزة التي تملك الصلاحية لفحصها.

