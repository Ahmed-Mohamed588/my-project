"""
SentraOS Dashboard - Updated with Authentication
Main Flask application with login/registration system
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_cors import CORS
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from network_monitor.monitor import SystemMonitor
from security_scanner.scanner import SecurityScanner
from automation.auto_responder import AutoResponder
from models import get_session, SystemMetric, ScanResult, Alert, log_activity, User
from dashboard.auth import login_required, authenticate_user, register_user, logout_user, get_current_user

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'sentra-dev-secret-key-change-in-production')

# Initialize modules
system_monitor = SystemMonitor()
security_scanner = SecurityScanner()
auto_responder = AutoResponder()


# ===== Authentication Routes =====

@app.route('/login', methods=['GET', 'POST'])
def login():
    """صفحة تسجيل الدخول"""
    # لو المستخدم مسجل دخول، ارجعه للـ Dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user, error = authenticate_user(username, password)
        
        if user:
            # حفظ بيانات المستخدم في الـ session
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error=error)
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """صفحة إنشاء حساب جديد"""
    # لو المستخدم مسجل دخول، ارجعه للـ Dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        
        # التحقق من تطابق كلمات المرور
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        # التحقق من طول كلمة المرور
        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters')
        
        # تسجيل المستخدم
        user, error = register_user(
            username=username,
            email=email,
            password=password,
            full_name=full_name
        )
        
        if user:
            # تسجيل دخول تلقائي بعد التسجيل
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            
            return redirect(url_for('dashboard'))
        else:
            return render_template('register.html', error=error)
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    """تسجيل الخروج"""
    logout_user()
    return redirect(url_for('login'))


# ===== Dashboard Routes =====

@app.route('/')
@login_required
def dashboard():
    """الصفحة الرئيسية - Dashboard"""
    user = get_current_user()
    return render_template('index.html', user=user)


# ===== API Routes (Protected) =====

@app.route('/api/metrics/current')
@login_required
def get_current_metrics():
    """Get current system metrics - للمستخدم الحالي فقط"""
    try:
        metrics = system_monitor.get_all_metrics()
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics/history')
@login_required
def get_metrics_history():
    """Get historical metrics data - للمستخدم الحالي فقط"""
    db_session = None
    try:
        metric_type = request.args.get('type', 'cpu')
        limit = int(request.args.get('limit', 20))
        user_id = session['user_id']
        
        db_session = get_session()
        metrics = db_session.query(SystemMetric)\
            .filter_by(metric_type=metric_type, user_id=user_id)\
            .order_by(SystemMetric.timestamp.desc())\
            .limit(limit)\
            .all()
        
        data = [{
            'timestamp': m.timestamp.isoformat(),
            'value': m.value,
            'unit': m.unit,
            'details': m.details
        } for m in reversed(metrics)]
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if db_session:
            db_session.close()


@app.route('/api/security/scan', methods=['POST'])
@login_required
def run_security_scan():
    """Trigger a security scan - للمستخدم الحالي"""
    db_session = None
    try:
        data = request.json or {}
        target = data.get('target', 'localhost')
        scan_type = data.get('type', 'quick')
        user_id = session['user_id']
        
        # Security: Validate target to prevent SSRF
        allowed_targets = ['localhost', '127.0.0.1', '::1']
        if target not in allowed_targets:
            return jsonify({
                'error': 'Invalid target. Only localhost scanning is permitted.',
                'allowed_targets': allowed_targets
            }), 403
        
        if scan_type == 'quick':
            result = security_scanner.quick_vulnerability_scan(target)
        else:
            port_range = data.get('port_range', '1-1000')
            result = security_scanner.scan_host(target, port_range)
        
        # Store scan result with user_id
        db_session = get_session()
        scan_record = ScanResult(
            user_id=user_id,
            target=result['target'],
            scan_type=scan_type,
            status=result['status'],
            open_ports=result.get('open_ports', []),
            vulnerabilities=result.get('vulnerabilities', []),
            risk_level=result.get('risk_level', 'low')
        )
        db_session.add(scan_record)
        db_session.commit()
        
        log_activity('security_scan', f'Security scan performed on {target}', user_id=user_id)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if db_session:
            db_session.close()


@app.route('/api/security/scans')
@login_required
def get_scan_history():
    """Get scan history - للمستخدم الحالي فقط"""
    db_session = None
    try:
        limit = int(request.args.get('limit', 10))
        user_id = session['user_id']
        
        db_session = get_session()
        scans = db_session.query(ScanResult)\
            .filter_by(user_id=user_id)\
            .order_by(ScanResult.timestamp.desc())\
            .limit(limit)\
            .all()
        
        data = [{
            'id': s.id,
            'target': s.target,
            'scan_type': s.scan_type,
            'status': s.status,
            'open_ports': s.open_ports,
            'vulnerabilities': s.vulnerabilities,
            'risk_level': s.risk_level,
            'timestamp': s.timestamp.isoformat()
        } for s in scans]
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if db_session:
            db_session.close()


@app.route('/api/alerts')
@login_required
def get_alerts():
    """Get recent alerts - للمستخدم الحالي فقط"""
    try:
        limit = int(request.args.get('limit', 20))
        severity = request.args.get('severity')
        
        # Get alerts from auto_responder (in-memory)
        alerts = auto_responder.get_alerts(limit, severity)
        
        # Filter by user_id if needed (currently auto_responder doesn't track user_id)
        # TODO: Update auto_responder to support multi-user
        
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        success = auto_responder.acknowledge_alert(alert_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network/connections')
@login_required
def get_network_connections():
    """Get active network connections"""
    try:
        connections = system_monitor.get_network_connections()
        return jsonify(connections)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
@login_required
def get_dashboard_stats():
    """Get overall dashboard statistics - للمستخدم الحالي"""
    db_session = None
    try:
        user_id = session['user_id']
        db_session = get_session()
        
        total_scans = db_session.query(ScanResult).filter_by(user_id=user_id).count()
        critical_alerts = db_session.query(Alert).filter_by(user_id=user_id, severity='critical').count()
        
        recent_scans = db_session.query(ScanResult)\
            .filter_by(user_id=user_id)\
            .order_by(ScanResult.timestamp.desc())\
            .limit(5)\
            .all()
        
        high_risk_scans = sum(1 for s in recent_scans if s.risk_level == 'high')
        
        metrics = system_monitor.get_all_metrics()
        
        stats = {
            'total_scans': total_scans,
            'critical_alerts': critical_alerts,
            'high_risk_scans': high_risk_scans,
            'current_cpu': metrics['cpu']['usage_percent'],
            'current_memory': metrics['memory']['percent'],
            'current_disk': metrics['disk']['percent'],
            'system_status': 'healthy' if metrics['cpu']['usage_percent'] < 80 else 'warning'
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if db_session:
            db_session.close()


# ===== Automated Monitoring Tasks =====

def periodic_system_check():
    """Periodic system metrics check - لكل المستخدمين"""
    db_session = None
    try:
        metrics = system_monitor.get_all_metrics()
        
        # Store metrics for all active users
        db_session = get_session()
        active_users = db_session.query(User).filter_by(is_active=True).all()
        
        for user in active_users:
            # Check for performance issues
            if metrics['cpu']['usage_percent'] > 80:
                auto_responder.create_alert(
                    'performance',
                    'high',
                    f"High CPU usage detected: {metrics['cpu']['usage_percent']}%",
                    {'cpu_data': metrics['cpu'], 'user_id': user.id}
                )
            
            if metrics['memory']['percent'] > 85:
                auto_responder.create_alert(
                    'performance',
                    'high',
                    f"High memory usage detected: {metrics['memory']['percent']}%",
                    {'memory_data': metrics['memory'], 'user_id': user.id}
                )
            
            # Store metrics
            db_session.add(SystemMetric(
                user_id=user.id,
                metric_type='cpu',
                value=metrics['cpu']['usage_percent'],
                unit='percent',
                details=metrics['cpu']
            ))
            db_session.add(SystemMetric(
                user_id=user.id,
                metric_type='memory',
                value=metrics['memory']['percent'],
                unit='percent',
                details=metrics['memory']
            ))
        
        db_session.commit()
        
    except Exception as e:
        print(f"Error in periodic system check: {e}")
        if db_session:
            db_session.rollback()
    finally:
        if db_session:
            db_session.close()


def periodic_security_scan():
    """Periodic security scan - لكل المستخدمين"""
    db_session = None
    try:
        db_session = get_session()
        active_users = db_session.query(User).filter_by(is_active=True).all()
        
        for user in active_users:
            scan_result = security_scanner.quick_vulnerability_scan('localhost')
            
            # Store scan result
            db_session.add(ScanResult(
                user_id=user.id,
                target=scan_result['target'],
                scan_type='vulnerability',
                status=scan_result['status'],
                open_ports=scan_result.get('open_ports', []),
                vulnerabilities=scan_result.get('vulnerabilities', []),
                risk_level=scan_result.get('risk_level', 'low')
            ))
            
            # Create alerts for vulnerabilities
            if scan_result.get('vulnerabilities'):
                for vuln in scan_result['vulnerabilities']:
                    auto_responder.create_alert(
                        'security',
                        vuln['severity'],
                        f"Vulnerability detected: {vuln['name']}",
                        {'vulnerability': vuln, 'target': scan_result['target'], 'user_id': user.id}
                    )
        
        db_session.commit()
        
    except Exception as e:
        print(f"Error in periodic security scan: {e}")
        if db_session:
            db_session.rollback()
    finally:
        if db_session:
            db_session.close()


# Start automation tasks
auto_responder.add_periodic_task(periodic_system_check, 30, 'system_check')
auto_responder.add_periodic_task(periodic_security_scan, 300, 'security_scan')
auto_responder.start()


if __name__ == '__main__':
    log_activity('system_start', 'SentraOS Dashboard started')
    app.run(host='0.0.0.0', port=5000, debug=True)