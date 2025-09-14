"""
VAPT (Vulnerability Assessment & Penetration Testing) Agent for SentinelAI v2
Handles network scanning, service fingerprinting, and vulnerability detection
"""

import asyncio
import socket
import subprocess
import json
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import ipaddress
import concurrent.futures

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from agents.base_agent import BaseAgent
from utils.logger import security_audit

class VAPTAgent(BaseAgent):
    """Agent for Vulnerability Assessment and Penetration Testing"""
    
    def __init__(self):
        super().__init__("vapt")
        
        # Initialize scanning tools
        self.nmap_scanner = None
        if NMAP_AVAILABLE:
            try:
                self.nmap_scanner = nmap.PortScanner()
                self.logger.info("Nmap scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Nmap: {e}")
        
        # CVE database (simplified - in production would use proper CVE API)
        self.cve_database = self._load_cve_database()
        
        # Common vulnerable services and their indicators
        self.vulnerable_services = self._load_vulnerable_services()
        
        # Scan statistics
        self.scan_stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'services_detected': 0,
            'vulnerabilities_found': 0,
            'scan_duration': 0
        }
    
    def _load_cve_database(self) -> Dict[str, Any]:
        """Load simplified CVE database"""
        # In production, this would connect to NIST NVD or similar
        return {
            'ssh': {
                'OpenSSH_7.4': ['CVE-2018-15473', 'CVE-2018-15919'],
                'OpenSSH_6.6': ['CVE-2016-0777', 'CVE-2016-0778'],
            },
            'apache': {
                'Apache/2.4.29': ['CVE-2019-0211', 'CVE-2019-0215'],
                'Apache/2.2.15': ['CVE-2017-15710', 'CVE-2017-15715'],
            },
            'nginx': {
                'nginx/1.10.3': ['CVE-2017-7529'],
                'nginx/1.6.2': ['CVE-2016-0742', 'CVE-2016-0746'],
            },
            'mysql': {
                'MySQL 5.7.21': ['CVE-2018-2767', 'CVE-2018-2755'],
                'MySQL 5.5.59': ['CVE-2017-10155', 'CVE-2017-10227'],
            },
            'ftp': {
                'vsftpd 2.3.4': ['CVE-2011-2523'],  # Backdoor
                'ProFTPD 1.3.3c': ['CVE-2010-4221'],
            }
        }
    
    def _load_vulnerable_services(self) -> Dict[str, Any]:
        """Load common vulnerable service patterns"""
        return {
            'telnet': {
                'port': 23,
                'risk': 'high',
                'description': 'Unencrypted remote access protocol',
                'recommendation': 'Replace with SSH'
            },
            'ftp': {
                'port': 21,
                'risk': 'medium',
                'description': 'Unencrypted file transfer protocol',
                'recommendation': 'Use SFTP or FTPS'
            },
            'http': {
                'port': 80,
                'risk': 'medium',
                'description': 'Unencrypted web traffic',
                'recommendation': 'Implement HTTPS'
            },
            'snmp': {
                'port': 161,
                'risk': 'medium',
                'description': 'Network management protocol with weak authentication',
                'recommendation': 'Use SNMPv3 with encryption'
            },
            'rpc': {
                'port': 111,
                'risk': 'high',
                'description': 'Remote Procedure Call service',
                'recommendation': 'Disable if not needed'
            },
            'netbios': {
                'port': 139,
                'risk': 'medium',
                'description': 'NetBIOS session service',
                'recommendation': 'Disable SMBv1, use SMBv3'
            }
        }
    
    async def execute(self, target: str, port_range: str = "1-1000", scan_type: str = "port_scan", scope: str = "host_only") -> Dict[str, Any]:
        """Execute VAPT assessment"""
        self.start_operation(f"vapt_{scan_type}")
        
        try:
            # Validate inputs
            if not self._validate_target(target, scope):
                raise ValueError(f"Invalid target: {target}")
            
            if not self._validate_port_range(port_range):
                raise ValueError(f"Invalid port range: {port_range}")
            
            # Security check - ensure we're not scanning unauthorized targets
            if not self._is_authorized_target(target, scope):
                raise PermissionError(f"Unauthorized scan target: {target}")
            
            # Reset statistics
            self.scan_stats = {
                'hosts_scanned': 0,
                'ports_scanned': 0,
                'services_detected': 0,
                'vulnerabilities_found': 0,
                'scan_duration': 0,
                'start_time': datetime.now().isoformat()
            }
            
            # Execute scan based on type
            if scan_type == "port_scan":
                results = await self._port_scan(target, port_range)
            elif scan_type == "service_fingerprinting":
                results = await self._service_fingerprinting(target, port_range)
            elif scan_type == "vulnerability_scan":
                results = await self._vulnerability_scan(target, port_range)
            elif scan_type == "full_assessment":
                results = await self._full_assessment(target, port_range)
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")
            
            # Add metadata
            results['scan_metadata'] = {
                'target': target,
                'port_range': port_range,
                'scan_type': scan_type,
                'scope': scope,
                'timestamp': datetime.now().isoformat(),
                'tools_used': self._get_available_tools()
            }
            
            results['scan_statistics'] = self.scan_stats
            
            # Log security event
            security_audit.log_event(
                "vapt_scan_completed",
                {
                    'target': target,
                    'scan_type': scan_type,
                    'vulnerabilities_found': self.scan_stats['vulnerabilities_found'],
                    'ports_scanned': self.scan_stats['ports_scanned']
                },
                "INFO"
            )
            
            self.end_operation(f"vapt_{scan_type}", True, results)
            return results
            
        except Exception as e:
            error_result = self.handle_error(e, f"vapt_{scan_type}")
            self.end_operation(f"vapt_{scan_type}", False, error_result)
            return error_result
    
    async def _port_scan(self, target: str, port_range: str) -> Dict[str, Any]:
        """Perform port scanning"""
        results = {
            'hosts': {},
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': []
        }
        
        if self.nmap_scanner:
            results = await self._nmap_port_scan(target, port_range)
        else:
            results = await self._basic_port_scan(target, port_range)
        
        return results
    
    async def _nmap_port_scan(self, target: str, port_range: str) -> Dict[str, Any]:
        """Port scan using Nmap"""
        try:
            # Run Nmap scan in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                scan_result = await loop.run_in_executor(
                    executor,
                    self._run_nmap_scan,
                    target,
                    port_range,
                    "-sS -T4"  # SYN scan, aggressive timing
                )
            
            results = {
                'hosts': {},
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'scan_info': scan_result.get('nmap', {})
            }
            
            # Parse results
            for host in scan_result.all_hosts():
                host_info = {
                    'hostname': scan_result[host].hostname(),
                    'state': scan_result[host].state(),
                    'protocols': list(scan_result[host].all_protocols()),
                    'ports': {}
                }
                
                self.scan_stats['hosts_scanned'] += 1
                
                for protocol in scan_result[host].all_protocols():
                    ports = scan_result[host][protocol].keys()
                    
                    for port in ports:
                        port_info = scan_result[host][protocol][port]
                        state = port_info['state']
                        
                        port_data = {
                            'port': port,
                            'protocol': protocol,
                            'state': state,
                            'reason': port_info.get('reason', ''),
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        
                        host_info['ports'][port] = port_data
                        self.scan_stats['ports_scanned'] += 1
                        
                        if state == 'open':
                            results['open_ports'].append(port_data)
                        elif state == 'closed':
                            results['closed_ports'].append(port_data)
                        elif state == 'filtered':
                            results['filtered_ports'].append(port_data)
                
                results['hosts'][host] = host_info
            
            return results
            
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            # Fallback to basic scan
            return await self._basic_port_scan(target, port_range)
    
    def _run_nmap_scan(self, target: str, port_range: str, arguments: str):
        """Run Nmap scan synchronously"""
        return self.nmap_scanner.scan(target, port_range, arguments)
    
    async def _basic_port_scan(self, target: str, port_range: str) -> Dict[str, Any]:
        """Basic port scan using socket connections"""
        results = {
            'hosts': {target: {'ports': {}}},
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': []
        }
        
        # Parse port range
        ports = self._parse_port_range(port_range)
        
        # Limit concurrent connections
        semaphore = asyncio.Semaphore(50)
        
        # Create scan tasks
        tasks = [
            self._scan_port(semaphore, target, port)
            for port in ports
        ]
        
        # Execute scans
        port_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for port, result in zip(ports, port_results):
            if isinstance(result, Exception):
                continue
            
            port_data = {
                'port': port,
                'protocol': 'tcp',
                'state': result['state'],
                'service': result.get('service', ''),
                'banner': result.get('banner', '')
            }
            
            results['hosts'][target]['ports'][port] = port_data
            self.scan_stats['ports_scanned'] += 1
            
            if result['state'] == 'open':
                results['open_ports'].append(port_data)
            elif result['state'] == 'closed':
                results['closed_ports'].append(port_data)
            else:
                results['filtered_ports'].append(port_data)
        
        self.scan_stats['hosts_scanned'] = 1
        return results
    
    async def _scan_port(self, semaphore: asyncio.Semaphore, host: str, port: int) -> Dict[str, Any]:
        """Scan a single port"""
        async with semaphore:
            try:
                # Try to connect
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=3.0)
                
                # Try to grab banner
                banner = ""
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    banner_data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                writer.close()
                await writer.wait_closed()
                
                # Identify service
                service = self._identify_service(port, banner)
                
                return {
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
                
            except asyncio.TimeoutError:
                return {'state': 'filtered'}
            except ConnectionRefusedError:
                return {'state': 'closed'}
            except Exception:
                return {'state': 'filtered'}
    
    async def _service_fingerprinting(self, target: str, port_range: str) -> Dict[str, Any]:
        """Perform service fingerprinting"""
        # First do port scan
        port_results = await self._port_scan(target, port_range)
        
        # Then fingerprint open services
        fingerprint_results = {
            'services': {},
            'service_versions': {},
            'potential_vulnerabilities': []
        }
        
        for port_data in port_results.get('open_ports', []):
            port = port_data['port']
            service_info = await self._fingerprint_service(target, port, port_data.get('service', ''))
            
            if service_info:
                fingerprint_results['services'][port] = service_info
                self.scan_stats['services_detected'] += 1
                
                # Check for known vulnerabilities
                vulnerabilities = self._check_service_vulnerabilities(service_info)
                fingerprint_results['potential_vulnerabilities'].extend(vulnerabilities)
        
        # Combine results
        combined_results = {**port_results, **fingerprint_results}
        return combined_results
    
    async def _fingerprint_service(self, host: str, port: int, service_hint: str) -> Optional[Dict[str, Any]]:
        """Fingerprint a specific service"""
        try:
            # Connect and grab banner
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=5.0)
            
            service_info = {
                'port': port,
                'service': service_hint,
                'banner': '',
                'version': '',
                'product': '',
                'os': '',
                'fingerprint_confidence': 0
            }
            
            # Service-specific fingerprinting
            if port == 22 or 'ssh' in service_hint.lower():
                service_info = await self._fingerprint_ssh(reader, writer, service_info)
            elif port == 80 or 'http' in service_hint.lower():
                service_info = await self._fingerprint_http(reader, writer, service_info)
            elif port == 21 or 'ftp' in service_hint.lower():
                service_info = await self._fingerprint_ftp(reader, writer, service_info)
            elif port == 25 or 'smtp' in service_hint.lower():
                service_info = await self._fingerprint_smtp(reader, writer, service_info)
            else:
                # Generic banner grab
                try:
                    banner_data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    service_info['banner'] = banner_data.decode('utf-8', errors='ignore').strip()
                except:
                    pass
            
            writer.close()
            await writer.wait_closed()
            
            return service_info
            
        except Exception as e:
            self.logger.debug(f"Service fingerprinting failed for {host}:{port}: {e}")
            return None
    
    async def _fingerprint_ssh(self, reader, writer, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fingerprint SSH service"""
        try:
            banner_data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            
            service_info['banner'] = banner
            service_info['service'] = 'ssh'
            service_info['fingerprint_confidence'] = 90
            
            # Parse SSH version
            if 'SSH-' in banner:
                parts = banner.split()
                if len(parts) > 0:
                    version_part = parts[0]
                    if 'OpenSSH' in banner:
                        service_info['product'] = 'OpenSSH'
                        # Extract version number
                        version_match = re.search(r'OpenSSH_(\d+\.\d+)', banner)
                        if version_match:
                            service_info['version'] = version_match.group(1)
            
        except Exception as e:
            self.logger.debug(f"SSH fingerprinting failed: {e}")
        
        return service_info
    
    async def _fingerprint_http(self, reader, writer, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fingerprint HTTP service"""
        try:
            # Send HTTP request
            http_request = b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: SentinelAI-Scanner\r\n\r\n"
            writer.write(http_request)
            await writer.drain()
            
            response_data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            response = response_data.decode('utf-8', errors='ignore')
            
            service_info['banner'] = response[:500]  # Truncate for storage
            service_info['service'] = 'http'
            service_info['fingerprint_confidence'] = 85
            
            # Parse server header
            server_match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
            if server_match:
                server_header = server_match.group(1)
                service_info['product'] = server_header
                
                # Extract version information
                if 'Apache' in server_header:
                    version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
                    if version_match:
                        service_info['version'] = version_match.group(1)
                elif 'nginx' in server_header:
                    version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header)
                    if version_match:
                        service_info['version'] = version_match.group(1)
            
        except Exception as e:
            self.logger.debug(f"HTTP fingerprinting failed: {e}")
        
        return service_info
    
    async def _fingerprint_ftp(self, reader, writer, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fingerprint FTP service"""
        try:
            banner_data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            
            service_info['banner'] = banner
            service_info['service'] = 'ftp'
            service_info['fingerprint_confidence'] = 80
            
            # Parse FTP banner
            if 'vsftpd' in banner.lower():
                service_info['product'] = 'vsftpd'
                version_match = re.search(r'vsftpd (\d+\.\d+\.\d+)', banner)
                if version_match:
                    service_info['version'] = version_match.group(1)
            elif 'proftpd' in banner.lower():
                service_info['product'] = 'ProFTPD'
                version_match = re.search(r'ProFTPD (\d+\.\d+\.\d+)', banner)
                if version_match:
                    service_info['version'] = version_match.group(1)
            
        except Exception as e:
            self.logger.debug(f"FTP fingerprinting failed: {e}")
        
        return service_info
    
    async def _fingerprint_smtp(self, reader, writer, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fingerprint SMTP service"""
        try:
            banner_data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            
            service_info['banner'] = banner
            service_info['service'] = 'smtp'
            service_info['fingerprint_confidence'] = 75
            
            # Parse SMTP banner
            if 'Postfix' in banner:
                service_info['product'] = 'Postfix'
            elif 'Sendmail' in banner:
                service_info['product'] = 'Sendmail'
            elif 'Exim' in banner:
                service_info['product'] = 'Exim'
            
        except Exception as e:
            self.logger.debug(f"SMTP fingerprinting failed: {e}")
        
        return service_info
    
    async def _vulnerability_scan(self, target: str, port_range: str) -> Dict[str, Any]:
        """Perform vulnerability scanning"""
        # First do service fingerprinting
        service_results = await self._service_fingerprinting(target, port_range)
        
        # Then check for vulnerabilities
        vulnerability_results = {
            'vulnerabilities': [],
            'risk_assessment': {},
            'recommendations': []
        }
        
        # Check each service for vulnerabilities
        for port, service_info in service_results.get('services', {}).items():
            vulnerabilities = self._check_service_vulnerabilities(service_info)
            vulnerability_results['vulnerabilities'].extend(vulnerabilities)
            self.scan_stats['vulnerabilities_found'] += len(vulnerabilities)
        
        # Check for common misconfigurations
        misconfigs = self._check_misconfigurations(service_results)
        vulnerability_results['vulnerabilities'].extend(misconfigs)
        
        # Generate risk assessment
        vulnerability_results['risk_assessment'] = self._assess_risk(vulnerability_results['vulnerabilities'])
        
        # Generate recommendations
        vulnerability_results['recommendations'] = self._generate_recommendations(vulnerability_results['vulnerabilities'])
        
        # Combine results
        combined_results = {**service_results, **vulnerability_results}
        return combined_results
    
    async def _full_assessment(self, target: str, port_range: str) -> Dict[str, Any]:
        """Perform full VAPT assessment"""
        # This combines all scan types
        return await self._vulnerability_scan(target, port_range)
    
    def _check_service_vulnerabilities(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check service for known vulnerabilities"""
        vulnerabilities = []
        
        service = service_info.get('service', '').lower()
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        
        # Check CVE database
        if service in self.cve_database:
            service_cves = self.cve_database[service]
            
            for product_version, cves in service_cves.items():
                if product in product_version and version in product_version:
                    for cve in cves:
                        vulnerability = {
                            'cve_id': cve,
                            'service': service,
                            'product': product,
                            'version': version,
                            'port': service_info.get('port'),
                            'severity': self._get_cve_severity(cve),
                            'description': f'Known vulnerability in {product} {version}',
                            'recommendation': f'Update {product} to latest version'
                        }
                        vulnerabilities.append(vulnerability)
        
        # Check for inherently risky services
        if service in self.vulnerable_services:
            vuln_info = self.vulnerable_services[service]
            vulnerability = {
                'type': 'insecure_service',
                'service': service,
                'port': service_info.get('port'),
                'severity': vuln_info['risk'],
                'description': vuln_info['description'],
                'recommendation': vuln_info['recommendation']
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_misconfigurations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for common misconfigurations"""
        misconfigs = []
        
        open_ports = scan_results.get('open_ports', [])
        
        # Check for unnecessary open ports
        risky_ports = [23, 135, 139, 445, 1433, 3389]  # Telnet, RPC, NetBIOS, SMB, SQL Server, RDP
        
        for port_data in open_ports:
            port = port_data['port']
            
            if port in risky_ports:
                misconfig = {
                    'type': 'risky_port_open',
                    'port': port,
                    'service': port_data.get('service', 'unknown'),
                    'severity': 'medium',
                    'description': f'Potentially risky service on port {port}',
                    'recommendation': f'Consider closing port {port} if not needed'
                }
                misconfigs.append(misconfig)
        
        # Check for default credentials (would require more sophisticated testing)
        # This is a placeholder for demonstration
        
        return misconfigs
    
    def _assess_risk(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk based on vulnerabilities"""
        if not vulnerabilities:
            return {
                'overall_risk': 'low',
                'risk_score': 10,
                'critical_issues': 0,
                'high_issues': 0,
                'medium_issues': 0,
                'low_issues': 0
            }
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score
        risk_score = (
            severity_counts['critical'] * 40 +
            severity_counts['high'] * 20 +
            severity_counts['medium'] * 10 +
            severity_counts['low'] * 5
        )
        
        # Determine overall risk level
        if risk_score >= 80:
            overall_risk = 'critical'
        elif risk_score >= 50:
            overall_risk = 'high'
        elif risk_score >= 20:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': min(100, risk_score),
            'critical_issues': severity_counts['critical'],
            'high_issues': severity_counts['high'],
            'medium_issues': severity_counts['medium'],
            'low_issues': severity_counts['low']
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = set()
        
        for vuln in vulnerabilities:
            if 'recommendation' in vuln:
                recommendations.add(vuln['recommendation'])
        
        # Add general recommendations
        recommendations.add("Regularly update all software and operating systems")
        recommendations.add("Implement network segmentation and firewalls")
        recommendations.add("Use strong authentication mechanisms")
        recommendations.add("Monitor network traffic for suspicious activity")
        recommendations.add("Conduct regular security assessments")
        
        return list(recommendations)
    
    def _validate_target(self, target: str, scope: str) -> bool:
        """Validate scan target"""
        try:
            if scope == "host_only":
                # Single IP or hostname
                try:
                    ipaddress.ip_address(target)
                    return True
                except ValueError:
                    # Try as hostname
                    socket.gethostbyname(target)
                    return True
            
            elif scope == "local_subnet":
                # CIDR notation or IP range
                try:
                    ipaddress.ip_network(target, strict=False)
                    return True
                except ValueError:
                    return False
            
            return False
            
        except Exception:
            return False
    
    def _validate_port_range(self, port_range: str) -> bool:
        """Validate port range format"""
        try:
            if '-' in port_range:
                start, end = port_range.split('-')
                start_port, end_port = int(start), int(end)
                return 1 <= start_port <= end_port <= 65535
            
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
                return all(1 <= p <= 65535 for p in ports)
            
            else:
                port = int(port_range)
                return 1 <= port <= 65535
                
        except ValueError:
            return False
    
    def _is_authorized_target(self, target: str, scope: str) -> bool:
        """Check if target is authorized for scanning"""
        try:
            # Parse target IP
            if scope == "host_only":
                try:
                    target_ip = ipaddress.ip_address(target)
                except ValueError:
                    # Resolve hostname
                    target_ip = ipaddress.ip_address(socket.gethostbyname(target))
            else:
                target_network = ipaddress.ip_network(target, strict=False)
                target_ip = target_network.network_address
            
            # Check if target is in authorized ranges
            authorized_ranges = [
                ipaddress.ip_network('127.0.0.0/8'),    # Localhost
                ipaddress.ip_network('10.0.0.0/8'),     # Private Class A
                ipaddress.ip_network('172.16.0.0/12'),  # Private Class B
                ipaddress.ip_network('192.168.0.0/16'), # Private Class C
            ]
            
            for authorized_range in authorized_ranges:
                if target_ip in authorized_range:
                    return True
            
            # Log unauthorized scan attempt
            security_audit.log_event(
                "unauthorized_scan_attempt",
                {'target': target, 'scope': scope},
                "WARNING"
            )
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error validating target authorization: {e}")
            return False
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        if '-' in port_range:
            start, end = port_range.split('-')
            ports = list(range(int(start), int(end) + 1))
        
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        
        else:
            ports = [int(port_range)]
        
        return ports
    
    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service based on port and banner"""
        # Common port mappings
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s'
        }
        
        # Check banner for service identification
        banner_lower = banner.lower()
        
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'http' in banner_lower:
            return 'http'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower:
            return 'smtp'
        
        # Fall back to common port mapping
        return common_ports.get(port, 'unknown')
    
    def _get_cve_severity(self, cve_id: str) -> str:
        """Get CVE severity (simplified - would use CVSS in production)"""
        # This is a simplified mapping - in production would query CVE database
        high_risk_cves = ['CVE-2017-0144', 'CVE-2019-0708', 'CVE-2020-1472']
        
        if cve_id in high_risk_cves:
            return 'critical'
        elif '2020' in cve_id or '2021' in cve_id or '2022' in cve_id:
            return 'high'
        elif '2018' in cve_id or '2019' in cve_id:
            return 'medium'
        else:
            return 'low'
    
    def _get_available_tools(self) -> List[str]:
        """Get list of available scanning tools"""
        tools = ['socket_scan']
        
        if NMAP_AVAILABLE and self.nmap_scanner:
            tools.append('nmap')
        
        if SCAPY_AVAILABLE:
            tools.append('scapy')
        
        return tools
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get current scan statistics"""
        return self.scan_stats.copy()
