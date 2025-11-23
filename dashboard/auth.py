"""
Authentication System for SentraOS
Handles login, registration, and session management
"""

from flask import session, redirect, url_for, request
from functools import wraps
import sys
import os

# إضافة المسار للـ models
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from models import get_session, User, log_activity


def login_required(f):
    """Decorator للتحقق من تسجيل الدخول"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator للتحقق من صلاحيات Admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        db_session = get_session()
        try:
            user = db_session.query(User).get(session['user_id'])
            if not user or not user.is_admin:
                return redirect(url_for('dashboard'))
        finally:
            db_session.close()
        
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """الحصول على المستخدم الحالي من الـ session"""
    if 'user_id' not in session:
        return None
    
    db_session = get_session()
    try:
        user = db_session.query(User).get(session['user_id'])
        return user
    finally:
        db_session.close()


def authenticate_user(username, password):
    """التحقق من بيانات تسجيل الدخول"""
    db_session = get_session()
    try:
        user = db_session.query(User).filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                return None, "Account is disabled"
            
            # تحديث آخر تسجيل دخول
            from datetime import datetime
            user.last_login = datetime.now()
            db_session.commit()
            
            # تسجيل النشاط
            log_activity(
                'user_login',
                f'User {username} logged in',
                user_id=user.id,
                ip_address=request.remote_addr
            )
            
            return user, None
        
        return None, "Invalid username or password"
    
    except Exception as e:
        print(f"Authentication error: {e}")
        return None, "Authentication error"
    finally:
        db_session.close()


def register_user(username, email, password, full_name=None, server_ip=None):
    """تسجيل مستخدم جديد"""
    db_session = get_session()
    try:
        # التحقق من وجود المستخدم
        existing_user = db_session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return None, "Username already exists"
            else:
                return None, "Email already exists"
        
        # إنشاء مستخدم جديد
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            server_ip=server_ip,
            is_admin=False,
            is_active=True
        )
        new_user.set_password(password)
        
        db_session.add(new_user)
        db_session.commit()
        
        # تسجيل النشاط
        log_activity(
            'user_register',
            f'New user registered: {username}',
            user_id=new_user.id,
            ip_address=request.remote_addr
        )
        
        return new_user, None
    
    except Exception as e:
        print(f"Registration error: {e}")
        db_session.rollback()
        return None, f"Registration error: {str(e)}"
    finally:
        db_session.close()


def logout_user():
    """تسجيل خروج المستخدم"""
    if 'user_id' in session:
        log_activity(
            'user_logout',
            f'User logged out',
            user_id=session['user_id'],
            ip_address=request.remote_addr
        )
        session.clear()