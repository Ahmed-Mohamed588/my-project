"""
Security Scanner Module
Performs network security scans using nmap to detect open ports and vulnerabilities
"""

import nmap
from datetime import datetime
from typing import Dict, List
import socket


class SecurityScanner:
    """Scans networks for security vulnerabilities and open ports"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_host(self, target: str, port_range: str = "1-1000") -> Dict:
        """
        Scan a specific host for open ports
        
        Args:
            target: IP address or hostname to scan
            port_range: Range of ports to scan (e.g., "1-1000")
        """
        scan_result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'status': 'success',
            'open_ports': [],
            'vulnerabilities': [],
            'risk_level': 'low'
        }
        
        try:
            # Perform TCP SYN scan (requires root, falls back to TCP connect)
            self.nm.scan(target, port_range, arguments='-T4')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                # Extract open ports
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in sorted(ports):
                        port_info = host_info[proto][port]
                        if port_info['state'] == 'open':
                            service_name = port_info.get('name', 'unknown')
                            service_version = port_info.get('version', '')
                            
                            scan_result['open_ports'].append({
                                'port': port,
                                'protocol': proto,
                                'service': service_name,
                                'version': service_version,
                                'state': port_info['state']
                            })
                            
                            # Check for common vulnerabilities
                            vulnerabilities = self._check_vulnerabilities(port, service_name)
                            scan_result['vulnerabilities'].extend(vulnerabilities)
                
                # Determine risk level
                scan_result['risk_level'] = self._calculate_risk_level(
                    len(scan_result['open_ports']),
                    len(scan_result['vulnerabilities'])
                )
        
        except Exception as e:
            scan_result['status'] = 'error'
            scan_result['error'] = str(e)
        
        return scan_result
    
    def scan_local_network(self) -> Dict:
        """Scan the local network for active hosts"""
        local_ip = self._get_local_ip()
        network_base = '.'.join(local_ip.split('.')[0:3])
        
        scan_result = {
            'network': f"{network_base}.0/24",
            'timestamp': datetime.now().isoformat(),
            'active_hosts': [],
            'total_hosts': 0
        }
        
        try:
            # Quick ping scan to find active hosts
            self.nm.scan(hosts=f"{network_base}.0/24", arguments='-sn -T4')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hostname = self.nm[host].hostname()
                    scan_result['active_hosts'].append({
                        'ip': host,
                        'hostname': hostname if hostname else 'Unknown',
                        'status': 'up'
                    })
            
            scan_result['total_hosts'] = len(scan_result['active_hosts'])
        
        except Exception as e:
            scan_result['error'] = str(e)
        
        return scan_result
    
    def quick_vulnerability_scan(self, target: str = 'localhost') -> Dict:
        """Perform a quick vulnerability assessment"""
        common_ports = "21,22,23,25,53,80,110,143,443,3306,3389,5432,8080,8443"
        return self.scan_host(target, common_ports)
    
    def _check_vulnerabilities(self, port: int, service: str) -> List[Dict]:
        """Check for known vulnerabilities based on port and service"""
        vulnerabilities = []
        
        # Common vulnerability patterns
        vuln_database = {
            21: {'name': 'FTP Open', 'severity': 'medium', 'description': 'FTP service detected - unencrypted data transfer'},
            22: {'name': 'SSH Open', 'severity': 'low', 'description': 'SSH service detected - ensure strong authentication'},
            23: {'name': 'Telnet Open', 'severity': 'high', 'description': 'Telnet detected - unencrypted protocol, use SSH instead'},
            25: {'name': 'SMTP Open', 'severity': 'medium', 'description': 'SMTP service detected - potential spam relay'},
            80: {'name': 'HTTP Open', 'severity': 'low', 'description': 'HTTP service detected - consider using HTTPS'},
            3306: {'name': 'MySQL Open', 'severity': 'high', 'description': 'MySQL database exposed to network'},
            3389: {'name': 'RDP Open', 'severity': 'high', 'description': 'Remote Desktop exposed - high security risk'},
            5432: {'name': 'PostgreSQL Open', 'severity': 'high', 'description': 'PostgreSQL database exposed to network'},
        }
        
        if port in vuln_database:
            vulnerabilities.append(vuln_database[port])
        
        return vulnerabilities
    
    def _calculate_risk_level(self, open_ports_count: int, vulnerabilities_count: int) -> str:
        """Calculate overall risk level"""
        if vulnerabilities_count > 2 or open_ports_count > 10:
            return 'high'
        elif vulnerabilities_count > 0 or open_ports_count > 5:
            return 'medium'
        else:
            return 'low'
    
    def _get_local_ip(self) -> str:
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
