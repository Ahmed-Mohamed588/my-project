# SentraOS: Smart Operations & Security Platform
<!-- عنوان المشروع الرئيسي -->

## 🎓 Graduation Project
<!-- قسم معلومات مشروع التخرج -->
**Student:** Mohamed Ahmed  
<!-- اسم الطالب - غيّره باسمك -->
**University:** Cairo University  
<!-- اسم الجامعة - غيّره بجامعتك -->
**Department:** Computer Science  
<!-- القسم - غيّره بقسمك -->
**Project ID:** GPJ2517  
<!-- رقم المشروع -->
**Academic Year:** 2024/2025  
<!-- السنة الأكاديمية -->

---

## 📖 Project Overview
<!-- نظرة عامة على المشروع -->

SentraOS is a **comprehensive security monitoring and operations platform** built with Python. The system provides real-time monitoring of server infrastructure, automated security scanning, intelligent alerting, and a modern web-based dashboard for visualization and management.

<!-- شرح: المشروع ده منصة شاملة لمراقبة الأمن والعمليات، بيوفر مراقبة لحظية للسيرفرات، فحص أمني تلقائي، تنبيهات ذكية، ولوحة تحكم ويب حديثة -->

This project demonstrates the integration of multiple technologies to create a production-ready monitoring solution suitable for:
<!-- المشروع بيوضح دمج تقنيات متعددة لإنشاء حل مراقبة جاهز للإنتاج مناسب لـ: -->
- **DevOps Teams**: System health monitoring and alerting
  <!-- فرق DevOps: مراقبة صحة النظام والتنبيهات -->
- **Security Teams**: Vulnerability detection and network scanning
  <!-- فرق الأمن: اكتشاف الثغرات ومسح الشبكات -->
- **IT Administrators**: Infrastructure management and analysis
  <!-- مسؤولي IT: إدارة وتحليل البنية التحتية -->

---

## ✨ Key Features
<!-- المميزات الرئيسية -->

### 1. Real-time System Monitoring
<!-- 1. مراقبة النظام في الوقت الفعلي -->
- **CPU Monitoring**: Track processor usage and load
  <!-- مراقبة المعالج: تتبع استخدام وحمل المعالج -->
- **Memory Tracking**: Monitor RAM usage and availability
  <!-- تتبع الذاكرة: مراقبة استخدام RAM وتوافرها -->
- **Disk Usage**: Track storage utilization across partitions
  <!-- استخدام القرص: تتبع استخدام التخزين عبر الأقسام -->
- **Network Metrics**: Monitor bandwidth, traffic, and active connections
  <!-- مقاييس الشبكة: مراقبة النطاق الترددي، حركة المرور، والاتصالات النشطة -->

### 2. Security Scanning
<!-- 2. الفحص الأمني -->
- **Port Scanning**: Detect open ports using nmap integration
  <!-- فحص المنافذ: اكتشاف المنافذ المفتوحة باستخدام nmap -->
- **Vulnerability Detection**: Identify common security risks
  <!-- كشف الثغرات: تحديد مخاطر الأمان الشائعة -->
- **Risk Assessment**: Automatic risk level calculation
  <!-- تقييم المخاطر: حساب تلقائي لمستوى المخاطر -->
- **Service Detection**: Identify running services and versions
  <!-- كشف الخدمات: تحديد الخدمات قيد التشغيل وإصداراتها -->

### 3. Intelligent Alert System
<!-- 3. نظام التنبيهات الذكي -->
- **Performance Alerts**: CPU, memory, and disk threshold violations
  <!-- تنبيهات الأداء: تجاوزات عتبات المعالج، الذاكرة، والقرص -->
- **Security Alerts**: Vulnerability and threat notifications
  <!-- تنبيهات الأمن: إشعارات الثغرات والتهديدات -->
- **Severity Levels**: Low, medium, high, and critical classifications
  <!-- مستويات الخطورة: تصنيفات منخفضة، متوسطة، عالية، وحرجة -->
- **Alert Acknowledgment**: Track and manage alert lifecycle
  <!-- إقرار التنبيهات: تتبع وإدارة دورة حياة التنبيهات -->

### 4. Task Automation
<!-- 4. أتمتة المهام -->
- **Scheduled Monitoring**: System checks every 30 seconds
  <!-- المراقبة المجدولة: فحوصات النظام كل 30 ثانية -->
- **Periodic Scans**: Security scans every 5 minutes
  <!-- الفحوصات الدورية: فحوصات أمنية كل 5 دقائق -->
- **Auto-Response**: Automated actions based on severity
  <!-- الاستجابة التلقائية: إجراءات تلقائية بناءً على الخطورة -->

### 5. Web Dashboard
<!-- 5. لوحة التحكم الويب -->
- **Real-time Charts**: CPU, memory, and network visualizations
  <!-- رسوم بيانية فورية: تصورات للمعالج، الذاكرة، والشبكة -->
- **Responsive Design**: Bootstrap 5 modern interface
  <!-- تصميم متجاوب: واجهة Bootstrap 5 حديثة -->
- **Interactive Tables**: Network connections and scan results
  <!-- جداول تفاعلية: اتصالات الشبكة ونتائج الفحص -->
- **RESTful API**: JSON endpoints for external integrations
  <!-- API RESTful: نقاط نهاية JSON للتكاملات الخارجية -->

---

## 🛠️ Technologies Used
<!-- التقنيات المستخدمة -->

### Backend Technologies
<!-- تقنيات Backend -->
| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Core programming language |
<!-- لغة البرمجة الأساسية -->
| Flask | 3.1.2 | Web framework for API and dashboard |
<!-- إطار عمل الويب للـ API ولوحة التحكم -->
| SQLAlchemy | 2.0.44 | ORM for database operations |
<!-- ORM لعمليات قاعدة البيانات -->
| psutil | 7.1.0 | System and process monitoring |
<!-- مراقبة النظام والعمليات -->
| python-nmap | 0.7.1 | Network security scanning |
<!-- فحص أمن الشبكة -->
| APScheduler | 3.11.0 | Task scheduling and automation |
<!-- جدولة المهام والأتمتة -->
| Gunicorn | 22.0.0 | Production WSGI server |
<!-- خادم WSGI للإنتاج -->

### Frontend Technologies
<!-- تقنيات Frontend -->
- **Bootstrap 5**: Responsive UI framework
  <!-- إطار عمل واجهة مستخدم متجاوب -->
- **Chart.js**: Data visualization library
  <!-- مكتبة تصور البيانات -->
- **Vanilla JavaScript**: Real-time updates and AJAX
  <!-- JavaScript الأصلي: تحديثات فورية وAJAX -->
- **Font Awesome 6**: Icon library
  <!-- مكتبة الأيقونات -->

### Database
<!-- قاعدة البيانات -->
- **SQLite**: Lightweight relational database
  <!-- قاعدة بيانات علائقية خفيفة -->
- **Tables**: system_metrics, scan_results, alerts, activity_logs
  <!-- الجداول: مقاييس النظام، نتائج الفحص، التنبيهات، سجلات النشاط -->

### Infrastructure
<!-- البنية التحتية -->
- **Nginx**: Reverse proxy and load balancer
  <!-- وكيل عكسي وموازن تحميل -->
- **Systemd**: Service management for auto-start
  <!-- إدارة الخدمات للتشغيل التلقائي -->
- **Let's Encrypt**: Free SSL/TLS certificates
  <!-- شهادات SSL/TLS مجانية -->

---

## 📁 Project Structure
<!-- بنية المشروع -->
```
SentraOS/
│
├── main.py                      # Application entry point - نقطة دخول التطبيق
├── requirements.txt             # Python dependencies - تبعيات Python
├── .env                         # Environment configuration - تكوين البيئة
├── .env.example                 # Example environment file - ملف بيئة نموذجي
├── .gitignore                   # Git ignore rules - قواعد تجاهل Git
├── README.md                    # Project documentation - وثائق المشروع
├── INSTALLATION.md              # Installation guide - دليل التثبيت
├── models.py                    # SQLAlchemy database models - نماذج قاعدة البيانات
├── sentra.db                    # SQLite database file - ملف قاعدة بيانات SQLite
│
├── network_monitor/             # System monitoring module - وحدة مراقبة النظام
│   ├── __init__.py              # Module initializer - مُهيئ الوحدة
│   └── monitor.py               # System metrics collection - جمع مقاييس النظام
│
├── security_scanner/            # Security scanning module - وحدة الفحص الأمني
│   ├── __init__.py              # Module initializer - مُهيئ الوحدة
│   └── scanner.py               # Port and vulnerability scanning - فحص المنافذ والثغرات
│
├── automation/                  # Task automation module - وحدة أتمتة المهام
│   ├── __init__.py              # Module initializer - مُهيئ الوحدة
│   └── auto_responder.py        # Scheduled tasks and alerts - المهام المجدولة والتنبيهات
│
└── dashboard/                   # Web application - تطبيق الويب
    ├── app.py                   # Flask main application - تطبيق Flask الرئيسي
    ├── templates/               # HTML templates - قوالب HTML
    │   └── index.html           # Dashboard UI - واجهة لوحة التحكم
    └── static/                  # Static files - ملفات ثابتة
        ├── css/
        │   └── style.css        # Custom styles - أنماط مخصصة
        └── js/
            └── dashboard.js      # Frontend logic - منطق الواجهة الأمامية
```

---

## 🚀 Installation & Setup
<!-- التثبيت والإعداد -->

### Prerequisites
<!-- المتطلبات الأساسية -->
```bash
# Operating System - نظام التشغيل
Ubuntu 20.04+ or Debian 11+

# Python - بايثون
Python 3.11 or higher

# System Tools - أدوات النظام
nmap (for security scanning)  # للفحص الأمني
```

### Quick Installation
<!-- التثبيت السريع -->
```bash
# 1. Update system packages - تحديث حزم النظام
sudo apt update && sudo apt upgrade -y

# 2. Install Python and dependencies - تثبيت Python والتبعيات
sudo apt install -y python3 python3-pip python3-venv nmap

# 3. Create project directory - إنشاء دليل المشروع
sudo mkdir -p /var/www/sentraos
cd /var/www/sentraos

# 4. Create virtual environment - إنشاء بيئة افتراضية
python3 -m venv venv
source venv/bin/activate

# 5. Install Python packages - تثبيت حزم Python
pip install --upgrade pip
pip install -r requirements.txt

# 6. Configure environment - تكوين البيئة
cp .env.example .env
nano .env  # Edit configuration - تحرير التكوين

# 7. Initialize database - تهيئة قاعدة البيانات
python3 main.py
# Press CTRL+C after "Database initialized" message
# اضغط CTRL+C بعد رسالة "تم تهيئة قاعدة البيانات"

# 8. Run application - تشغيل التطبيق
python3 main.py
```

### Access Dashboard
<!-- الوصول إلى لوحة التحكم -->
Open your browser and navigate to:
<!-- افتح المتصفح وانتقل إلى: -->
```
http://your-server-ip:8080
```

---

## 📊 System Architecture
<!-- معمارية النظام -->

### Application Flow
<!-- تدفق التطبيق -->
```
User Request (Browser) → Nginx (Port 80/443) → Gunicorn (Port 8080) → Flask App
                                                                              ↓
                                                                    ┌─────────┴──────────┐
                                                                    ↓                    ↓
                                                            Network Monitor      Security Scanner
                                                                    ↓                    ↓
                                                            System Metrics      Vulnerability Data
                                                                    ↓                    ↓
                                                            ┌───────┴────────────────────┘
                                                            ↓
                                                    SQLite Database
                                                            ↓
                                                    Auto Responder (Alerts)
                                                            ↓
                                                    Dashboard Display
```

### Module Interactions
<!-- تفاعلات الوحدات -->

1. **Network Monitor** → Collects system metrics every 30 seconds
   <!-- جامع مقاييس النظام: يجمع مقاييس النظام كل 30 ثانية -->
2. **Security Scanner** → Performs vulnerability scans every 5 minutes
   <!-- ماسح الأمان: يجري فحوصات ثغرات كل 5 دقائق -->
3. **Auto Responder** → Creates alerts based on thresholds
   <!-- المستجيب التلقائي: ينشئ تنبيهات بناءً على العتبات -->
4. **Database** → Stores all metrics, scans, and alerts
   <!-- قاعدة البيانات: تخزن جميع المقاييس، الفحوصات، والتنبيهات -->
5. **Dashboard** → Displays data with real-time updates
   <!-- لوحة التحكم: تعرض البيانات مع تحديثات فورية -->

---

## 🎯 Project Objectives & Learning Outcomes
<!-- أهداف المشروع ونتائج التعلم -->

### Technical Skills Demonstrated
<!-- المهارات التقنية المُظهَرة -->

1. **Backend Development**
   <!-- تطوير Backend -->
   - RESTful API design and implementation
     <!-- تصميم وتنفيذ RESTful API -->
   - Database modeling with SQLAlchemy ORM
     <!-- نمذجة قاعدة البيانات باستخدام SQLAlchemy ORM -->
   - Asynchronous task scheduling
     <!-- جدولة المهام غير المتزامنة -->

2. **System Administration**
   <!-- إدارة الأنظمة -->
   - Linux server configuration and management
     <!-- تكوين وإدارة خادم Linux -->
   - Process monitoring using psutil
     <!-- مراقبة العمليات باستخدام psutil -->
   - Service deployment with Systemd
     <!-- نشر الخدمات باستخدام Systemd -->

3. **Security Knowledge**
   <!-- معرفة الأمان -->
   - Network scanning with nmap
     <!-- فحص الشبكة باستخدام nmap -->
   - Vulnerability assessment techniques
     <!-- تقنيات تقييم الثغرات -->
   - Security best practices implementation
     <!-- تنفيذ أفضل ممارسات الأمان -->

4. **DevOps Practices**
   <!-- ممارسات DevOps -->
   - Automation and monitoring
     <!-- الأتمتة والمراقبة -->
   - Logging and alerting systems
     <!-- أنظمة التسجيل والتنبيه -->
   - Production deployment strategies
     <!-- استراتيجيات النشر في الإنتاج -->

5. **Frontend Development**
   <!-- تطوير Frontend -->
   - Responsive web design
     <!-- تصميم ويب متجاوب -->
   - Real-time data visualization
     <!-- تصور البيانات في الوقت الفعلي -->
   - AJAX and asynchronous updates
     <!-- AJAX والتحديثات غير المتزامنة -->

---

## 📈 Use Cases
<!-- حالات الاستخدام -->

### 1. IT Infrastructure Monitoring
<!-- 1. مراقبة البنية التحتية لتكنولوجيا المعلومات -->
- Track server performance in real-time
  <!-- تتبع أداء الخادم في الوقت الفعلي -->
- Receive alerts when resources exceed thresholds
  <!-- تلقي تنبيهات عند تجاوز الموارد للعتبات -->
- Historical data analysis for capacity planning
  <!-- تحليل البيانات التاريخية لتخطيط السعة -->

### 2. Security Auditing
<!-- 2. التدقيق الأمني -->
- Regular vulnerability assessments
  <!-- تقييمات ثغرات منتظمة -->
- Open port detection and service identification
  <!-- كشف المنافذ المفتوحة وتحديد الخدمات -->
- Compliance monitoring and reporting
  <!-- مراقبة الامتثال وإعداد التقارير -->

### 3. DevOps Automation
<!-- 3. أتمتة DevOps -->
- Automated health checks
  <!-- فحوصات صحة تلقائية -->
- Integration with CI/CD pipelines
  <!-- التكامل مع خطوط CI/CD -->
- Alert notifications to Slack/Email (extensible)
  <!-- إشعارات التنبيه إلى Slack/البريد الإلكتروني (قابلة للتوسع) -->

---

## 🔒 Security Considerations
<!-- اعتبارات الأمان -->

### Implemented Security Measures
<!-- تدابير الأمان المُنفَّذة -->

1. **Input Validation**
   <!-- التحقق من صحة الإدخال -->
   - Scan target validation to prevent SSRF attacks
     <!-- التحقق من صحة هدف الفحص لمنع هجمات SSRF -->
   - Only localhost scanning allowed by default
     <!-- السماح بفحص localhost فقط افتراضيًا -->

2. **Environment Variables**
   <!-- متغيرات البيئة -->
   - Sensitive data stored in .env file
     <!-- البيانات الحساسة مخزنة في ملف .env -->
   - Secret keys not hardcoded in source
     <!-- المفاتيح السرية غير مُدمجة في المصدر -->

3. **Database Security**
   <!-- أمان قاعدة البيانات -->
   - SQLAlchemy ORM prevents SQL injection
     <!-- SQLAlchemy ORM يمنع حقن SQL -->
   - Session management for safe database operations
     <!-- إدارة الجلسات لعمليات قاعدة بيانات آمنة -->

4. **Production Deployment**
   <!-- النشر في الإنتاج -->
   - Nginx reverse proxy hides backend
     <!-- وكيل Nginx العكسي يخفي Backend -->
   - SSL/TLS encryption for HTTPS
     <!-- تشفير SSL/TLS لـ HTTPS -->
   - Firewall rules restrict access
     <!-- قواعد جدار الحماية تقيد الوصول -->

---

## 🧪 Testing
<!-- الاختبار -->

### Manual Testing Procedures
<!-- إجراءات الاختبار اليدوي -->
```bash
# Test system monitoring - اختبار مراقبة النظام
curl http://localhost:8080/api/metrics/current

# Test security scanning - اختبار الفحص الأمني
curl -X POST http://localhost:8080/api/security/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"localhost","type":"quick"}'

# Test alerts retrieval - اختبار استرجاع التنبيهات
curl http://localhost:8080/api/alerts?limit=10

# Check database connectivity - التحقق من اتصال قاعدة البيانات
python3 -c "from models import get_session; session = get_session(); print('Database OK')"
```

---

## 📚 API Documentation
<!-- وثائق API -->

### Available Endpoints
<!-- نقاط النهاية المتاحة -->

#### System Metrics
<!-- مقاييس النظام -->
```
GET /api/metrics/current
<!-- الحصول على المقاييس الحالية -->
Response: { cpu: {...}, memory: {...}, disk: {...}, network: {...} }

GET /api/metrics/history?type=cpu&limit=20
<!-- الحصول على تاريخ المقاييس -->
Response: [{ timestamp, value, unit, details }, ...]
```

#### Security Scanning
<!-- الفحص الأمني -->
```
POST /api/security/scan
<!-- إطلاق فحص أمني -->
Body: { target: "localhost", type: "quick" }
Response: { target, status, open_ports, vulnerabilities, risk_level }

GET /api/security/scans?limit=10
<!-- الحصول على تاريخ الفحوصات -->
Response: [{ id, target, timestamp, risk_level, ... }, ...]
```

#### Alerts
<!-- التنبيهات -->
```
GET /api/alerts?limit=20&severity=high
<!-- الحصول على التنبيهات -->
Response: [{ id, type, severity, message, timestamp }, ...]

POST /api/alerts/<id>/acknowledge
<!-- إقرار تنبيه -->
Response: { success: true }
```

#### Network
<!-- الشبكة -->
```
GET /api/network/connections
<!-- الحصول على الاتصالات النشطة -->
Response: [{ local_address, remote_address, status, pid }, ...]
```

#### Statistics
<!-- الإحصائيات -->
```
GET /api/stats
<!-- الحصول على إحصائيات لوحة التحكم -->
Response: { total_scans, critical_alerts, high_risk_scans, current_cpu, ... }
```

---

## 🚀 Future Enhancements
<!-- التحسينات المستقبلية -->

### Planned Features
<!-- الميزات المخططة -->

1. **Multi-Server Monitoring**
   <!-- مراقبة متعددة الخوادم -->
   - Add remote server monitoring capability
     <!-- إضافة قدرة مراقبة الخوادم البعيدة -->
   - Agent-based or agentless monitoring
     <!-- مراقبة قائمة على وكيل أو بدون وكيل -->

2. **Advanced Alerting**
   <!-- تنبيه متقدم -->
   - Email notifications via SMTP
     <!-- إشعارات البريد الإلكتروني عبر SMTP -->
   - Slack/Discord webhook integration
     <!-- تكامل webhook لـ Slack/Discord -->
   - SMS alerts for critical events
     <!-- تنبيهات SMS للأحداث الحرجة -->

3. **Enhanced Security Features**
   <!-- ميزات أمان محسّنة -->
   - CVE database integration
     <!-- تكامل قاعدة بيانات CVE -->
   - Custom vulnerability rules
     <!-- قواعد ثغرات مخصصة -->
   - Compliance reports (PCI-DSS, HIPAA)
     <!-- تقارير الامتثال (PCI-DSS، HIPAA) -->

4. **Data Analytics**
   <!-- تحليلات البيانات -->
   - Machine learning for anomaly detection
     <!-- التعلم الآلي لكشف الشذوذ -->
   - Predictive maintenance alerts
     <!-- تنبيهات الصيانة التنبؤية -->
   - Historical trend analysis
     <!-- تحليل الاتجاهات التاريخية -->

5. **User Management**
   <!-- إدارة المستخدمين -->
   - Multi-user authentication
     <!-- مصادقة متعددة المستخدمين -->
   - Role-based access control (RBAC)
     <!-- التحكم في الوصول القائم على الأدوار -->
   - Audit logs for user actions
     <!-- سجلات تدقيق لإجراءات المستخدمين -->

---

## 🐛 Known Issues & Limitations
<!-- المشكلات المعروفة والقيود -->

1. **Security Scanning**
   - Requires root privileges for SYN scans
     <!-- يتطلب امتيازات root لفحوصات SYN -->
   - Currently limited to localhost by default
     <!-- محدود حاليًا بـ localhost افتراضيًا -->

2. **Database**
   - SQLite not recommended for high-traffic production
    
   - Consider PostgreSQL/MySQL for scaling
     

3. **Monitoring**
   - Network metrics may vary based on system load
     <!-- قد تختلف مقاييس الشبكة بناءً على حمل النظام -->
   - 30-second intervals may miss brief spikes
     <!-- فترات 30 ثانية قد تفوت الارتفاعات المؤقتة -->

---

## 📝 License & Usage
<!-- الترخيص والاستخدام -->

This project is developed as an educational graduation project for [اسم حمعتك هنا].


**Usage Rights:**
<!-- حقوق الاستخدام: -->
- Educational and research purposes ✅
  <!-- الأغراض التعليمية والبحثية -->
- Personal learning and portfolio ✅
  <!-- التعلم الشخصي والمحفظة -->
- Commercial use requires permission ⚠️
  <!-- الاستخدام التجاري يتطلب إذنًا -->

---

## 👨‍💻 Author & Contact
<!-- المؤلف والاتصال -->

**Student:**الاسامي بتاعتكم 

**Email:** حط هنا البريد

**University:** الجامعة 

**Department:** حط هنا القسم بتاعك 

**Supervisor:** حط هنا اسم الدكتور

**Project Year:** حط هنا 


---

## 🙏 Acknowledgments
<!-- شكر وتقدير -->

- **Flask Community**: For the excellent web framework
  <!-- مجتمع Flask: لإطار العمل الممتاز -->
- **nmap Project**: For the powerful scanning tool
  <!-- مشروع nmap: للأداة القوية للفحص -->
- **Bootstrap Team**: For the responsive UI framework
  <!-- فريق Bootstrap: لإطار واجهة المستخدم المتجاوب -->
- **Chart.js**: For beautiful data visualization
  <!-- Chart.js: للتصور الجميل للبيانات -->
- **My Supervisor**: For guidance and support
  <!-- مشرفي: للتوجيه والدعم -->

---

## 📅 Project Timeline
<!-- الجدول الزمني للمشروع -->

- **Phase 1** (Week 1-2): Requirements analysis and design
  <!-- المرحلة 1: تحليل المتطلبات والتصميم -->
- **Phase 2** (Week 3-4): Backend development (monitoring, scanning)
  <!-- المرحلة 2: تطوير Backend (المراقبة، الفحص) -->
- **Phase 3** (Week 5-6): Frontend development (dashboard, charts)
  <!-- المرحلة 3: تطوير Frontend (لوحة التحكم، الرسوم البيانية) -->
- **Phase 4** (Week 7-8): Integration and automation
  <!-- المرحلة 4: التكامل والأتمتة -->
- **Phase 5** (Week 9-10): Testing and deployment
  <!-- المرحلة 5: الاختبار والنشر -->
- **Phase 6** (Week 11-12): Documentation and presentation
  <!-- المرحلة 6: التوثيق والعرض -->

---

**Last Updated:** November 2024  
<!-- آخر تحديث: نوفمبر 2024 -->
**Version:** 1.0.0  
<!-- الإصدار: 1.0.0 -->