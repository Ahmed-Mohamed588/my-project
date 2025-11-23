"""
Network Monitor Module
Monitors system metrics including CPU, RAM, disk usage, and network statistics
"""

import psutil
import time
from datetime import datetime
from typing import Dict, List


class SystemMonitor:
    """Monitors system performance and network metrics"""
    
    def __init__(self):
        self.network_stats_baseline = psutil.net_io_counters()
        self.last_check_time = time.time()
    
    def get_cpu_metrics(self) -> Dict:
        """Get CPU usage metrics"""
        cpu_percent = psutil.cpu_percent(interval=1, percpu=False)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        return {
            'usage_percent': cpu_percent,
            'core_count': cpu_count,
            'frequency_mhz': cpu_freq.current if cpu_freq else 0,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_memory_metrics(self) -> Dict:
        """Get memory usage metrics"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'total_gb': round(memory.total / (1024**3), 2),
            'used_gb': round(memory.used / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'percent': memory.percent,
            'swap_percent': swap.percent,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_disk_metrics(self) -> Dict:
        """Get disk usage metrics"""
        disk = psutil.disk_usage('/')
        
        return {
            'total_gb': round(disk.total / (1024**3), 2),
            'used_gb': round(disk.used / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'percent': disk.percent,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_network_metrics(self) -> Dict:
        """Get network statistics"""
        current_stats = psutil.net_io_counters()
        current_time = time.time()
        time_delta = current_time - self.last_check_time
        
        bytes_sent_delta = current_stats.bytes_sent - self.network_stats_baseline.bytes_sent
        bytes_recv_delta = current_stats.bytes_recv - self.network_stats_baseline.bytes_recv
        
        # Calculate rates (bytes per second)
        send_rate = bytes_sent_delta / time_delta if time_delta > 0 else 0
        recv_rate = bytes_recv_delta / time_delta if time_delta > 0 else 0
        
        # Update baseline
        self.network_stats_baseline = current_stats
        self.last_check_time = current_time
        
        return {
            'bytes_sent': current_stats.bytes_sent,
            'bytes_recv': current_stats.bytes_recv,
            'packets_sent': current_stats.packets_sent,
            'packets_recv': current_stats.packets_recv,
            'send_rate_mbps': round(send_rate / (1024**2), 2),
            'recv_rate_mbps': round(recv_rate / (1024**2), 2),
            'errors_in': current_stats.errin,
            'errors_out': current_stats.errout,
            'drops_in': current_stats.dropin,
            'drops_out': current_stats.dropout,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_all_metrics(self) -> Dict:
        """Get all system metrics at once"""
        return {
            'cpu': self.get_cpu_metrics(),
            'memory': self.get_memory_metrics(),
            'disk': self.get_disk_metrics(),
            'network': self.get_network_metrics()
        }
    
    def get_network_connections(self) -> List[Dict]:
        """Get active network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid
                    })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        return connections[:20]  # Limit to 20 connections
