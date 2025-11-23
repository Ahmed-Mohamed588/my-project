#!/usr/bin/env python3
"""
SentraOS - Main Entry Point
Smart Operations & Security Platform
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize database
from models import Base, engine, log_activity, create_admin_user

def init_database():
    """Initialize database tables and create admin user"""
    try:
        # إنشاء الجداول
        Base.metadata.create_all(engine)
        print("✅ Database initialized successfully")
        
        # إنشاء مستخدم admin افتراضي
        if create_admin_user():
            print("✅ Default admin user created")
            print("   Username: admin")
            print("   Password: admin123")
            print("   ⚠️  Please change the password after first login!")
        
        log_activity('system_init', 'Database tables created and admin user initialized')
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def main():
    """Main application entry point"""
    print("=" * 60)
    print("🚀 Starting SentraOS - Smart Operations & Security Platform")
    print("=" * 60)
    
    # Initialize database
    if not init_database():
        print("⚠️  Continuing without database initialization...")
    
    # Import and run Flask app
    from dashboard.app import app
    
    # Configuration from .env file
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 8080))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    server_ip = os.getenv('SERVER_IP', '72.61.192.175')
    
    print(f"\n📡 Starting server on http://{host}:{port}")
    print(f"📊 Dashboard available at: http://{server_ip}:{port}")
    print(f"🌐 Access from browser: http://72.61.192.175:{port}")
    print(f"\n🔐 Login Credentials:")
    print(f"   Username: admin")
    print(f"   Password: admin123")
    print("\n⌨️  Press CTRL+C to stop the server\n")
    
    log_activity('system_start', f'SentraOS started on {host}:{port}')
    
    # Run Flask application
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down SentraOS...")
        log_activity('system_stop', 'SentraOS stopped by user')
    except Exception as e:
        print(f"\n❌ Error running application: {e}")
        log_activity('system_error', f'Application error: {str(e)}')
        sys.exit(1)

if __name__ == '__main__':
    main()