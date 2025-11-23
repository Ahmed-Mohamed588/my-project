"""
Database Models for SentraOS
Updated with User Authentication System
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os

Base = declarative_base()


class User(Base):
    """User accounts for authentication"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120))
    server_ip = Column(String(50))  # للسيرفر الخاص بالمستخدم
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)
    last_login = Column(DateTime)
    
    # العلاقات مع الجداول الأخرى
    metrics = relationship('SystemMetric', back_populates='user', cascade='all, delete-orphan')
    scans = relationship('ScanResult', back_populates='user', cascade='all, delete-orphan')
    alerts = relationship('Alert', back_populates='user', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """تشفير كلمة المرور"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """التحقق من كلمة المرور"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class SystemMetric(Base):
    """Store system performance metrics"""
    __tablename__ = 'system_metrics'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    metric_type = Column(String(50))  # cpu, memory, disk, network
    value = Column(Float)
    unit = Column(String(20))
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.now)
    
    # العلاقة مع User
    user = relationship('User', back_populates='metrics')


class ScanResult(Base):
    """Store security scan results"""
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    target = Column(String(100))
    scan_type = Column(String(50))
    status = Column(String(20))
    open_ports = Column(JSON)
    vulnerabilities = Column(JSON)
    risk_level = Column(String(20))
    timestamp = Column(DateTime, default=datetime.now)
    
    # العلاقة مع User
    user = relationship('User', back_populates='scans')


class Alert(Base):
    """Store security and performance alerts"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    alert_type = Column(String(50))
    severity = Column(String(20))
    message = Column(Text)
    details = Column(JSON)
    acknowledged = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.now)
    
    # العلاقة مع User
    user = relationship('User', back_populates='alerts')


class ActivityLog(Base):
    """Store system activity logs"""
    __tablename__ = 'activity_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(100))
    description = Column(Text)
    ip_address = Column(String(50))
    timestamp = Column(DateTime, default=datetime.now)


# Database setup
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'sentra.db')
engine = create_engine(f'sqlite:///{DATABASE_PATH}', echo=False)

# إنشاء كل الجداول
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)


def get_session():
    """Get a new database session"""
    return Session()


def log_activity(action: str, description: str, user_id: int = None, ip_address: str = None):
    """Helper function to log activities"""
    session = get_session()
    try:
        log = ActivityLog(
            action=action, 
            description=description, 
            user_id=user_id,
            ip_address=ip_address
        )
        session.add(log)
        session.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")
        session.rollback()
    finally:
        session.close()


def create_admin_user():
    """Create default admin user if not exists"""
    session = get_session()
    try:
        # التحقق من وجود admin
        admin = session.query(User).filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@sentraos.local',
                full_name='Administrator',
                is_admin=True,
                is_active=True
            )
            admin.set_password('admin123')  # كلمة مرور افتراضية - غيّرها!
            session.add(admin)
            session.commit()
            print("✅ Admin user created: username=admin, password=admin123")
            return True
        return False
    except Exception as e:
        print(f"Error creating admin user: {e}")
        session.rollback()
        return False
    finally:
        session.close()