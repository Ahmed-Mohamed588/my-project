"""
Automation & Response Module
Handles automated monitoring tasks and response actions
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
from typing import Callable, Dict, List, Optional
import logging


class AutoResponder:
    """Manages automated tasks and scheduled responses"""
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.alerts = []
        self.max_alerts = 100
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start the scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            self.logger.info("Automation scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            self.logger.info("Automation scheduler stopped")
    
    def add_periodic_task(self, task_func: Callable, interval_seconds: int, task_id: str):
        """
        Add a periodic task to run at specified intervals
        
        Args:
            task_func: Function to execute
            interval_seconds: Interval in seconds between executions
            task_id: Unique identifier for the task
        """
        self.scheduler.add_job(
            func=task_func,
            trigger=IntervalTrigger(seconds=interval_seconds),
            id=task_id,
            replace_existing=True
        )
        self.logger.info(f"Added periodic task: {task_id} (every {interval_seconds}s)")
    
    def remove_task(self, task_id: str):
        """Remove a scheduled task"""
        try:
            self.scheduler.remove_job(task_id)
            self.logger.info(f"Removed task: {task_id}")
        except:
            pass
    
    def create_alert(self, alert_type: str, severity: str, message: str, details: Optional[Dict] = None) -> Dict:
        """
        Create a new alert
        
        Args:
            alert_type: Type of alert (e.g., 'security', 'performance', 'network')
            severity: Alert severity ('low', 'medium', 'high', 'critical')
            message: Alert message
            details: Additional details about the alert
        """
        alert = {
            'id': len(self.alerts) + 1,
            'type': alert_type,
            'severity': severity,
            'message': message,
            'details': details or {},
            'timestamp': datetime.now().isoformat(),
            'acknowledged': False
        }
        
        self.alerts.insert(0, alert)  # Add to beginning
        
        # Keep only the most recent alerts
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[:self.max_alerts]
        
        self.logger.warning(f"Alert created: [{severity.upper()}] {alert_type} - {message}")
        
        # Auto-response based on severity
        if severity == 'critical':
            self._handle_critical_alert(alert)
        
        return alert
    
    def get_alerts(self, limit: int = 50, severity_filter: Optional[str] = None) -> List[Dict]:
        """Get recent alerts with optional filtering"""
        alerts = self.alerts[:limit]
        
        if severity_filter:
            alerts = [a for a in alerts if a['severity'] == severity_filter]
        
        return alerts
    
    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                self.logger.info(f"Alert {alert_id} acknowledged")
                return True
        return False
    
    def clear_old_alerts(self, hours: int = 24):
        """Clear alerts older than specified hours"""
        from datetime import timedelta
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        initial_count = len(self.alerts)
        self.alerts = [
            a for a in self.alerts 
            if datetime.fromisoformat(a['timestamp']) > cutoff_time
        ]
        cleared_count = initial_count - len(self.alerts)
        
        if cleared_count > 0:
            self.logger.info(f"Cleared {cleared_count} old alerts")
    
    def _handle_critical_alert(self, alert: Dict):
        """Handle critical alerts with automated response"""
        self.logger.critical(f"CRITICAL ALERT: {alert['message']}")
        
        # Here you could add automated response actions:
        # - Send notifications
        # - Execute security commands
        # - Trigger failover procedures
        # - etc.
    
    def get_task_status(self) -> List[Dict]:
        """Get status of all scheduled tasks"""
        jobs = self.scheduler.get_jobs()
        return [
            {
                'id': job.id,
                'name': job.name,
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                'trigger': str(job.trigger)
            }
            for job in jobs
        ]
