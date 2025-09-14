"""
Local Scan Agent for SentinelAI v2
Handles local file system scanning, hashing, and malware detection using ClamAV and YARA
"""

import os
import hashlib
try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    try:
        import ppdeep
        TLSH_AVAILABLE = False
        PPDEEP_AVAILABLE = True
    except ImportError:
        TLSH_AVAILABLE = False
        PPDEEP_AVAILABLE = False
import magic
import asyncio
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import json
import time
from datetime import datetime

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    
try:
    import pyclamd
    CLAMAV_AVAILABLE = True
except ImportError:
    CLAMAV_AVAILABLE = False

from agents.base_agent import BaseAgent
from utils.logger import security_audit

class LocalScanAgent(BaseAgent):
    """Agent for local file system scanning and malware detection"""
    
    def __init__(self):
        super().__init__("local_scan")
        self.yara_rules = None
        self.clamav_daemon = None
        self.magic_mime = magic.Magic(mime=True)
        
        # Initialize detection engines
        self._initialize_yara()
        self._initialize_clamav()
        
        # Scan statistics
        self.scan_stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'scan_duration': 0,
            'bytes_scanned': 0
        }
    
    def _initialize_yara(self):
        """Initialize YARA rules engine"""
        if not YARA_AVAILABLE:
            self.logger.warning("YARA not available - YARA scanning disabled")
            return
        
        try:
            # Load built-in YARA rules
            rules_dir = Path(__file__).parent.parent / "rules" / "yara"
            
            if rules_dir.exists():
                rule_files = list(rules_dir.glob("*.yar"))
                if rule_files:
                    # Compile multiple rule files
                    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
                    self.yara_rules = yara.compile(filepaths=filepaths)
                    self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
                else:
                    # Create basic rules if none exist
                    self._create_basic_yara_rules()
            else:
                self._create_basic_yara_rules()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize YARA: {e}")
            self.yara_rules = None
    
    def _create_basic_yara_rules(self):
        """Create basic YARA rules for common malware patterns"""
        rules_dir = Path(__file__).parent.parent / "rules" / "yara"
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Basic malware detection rules
        basic_rules = '''
        rule Suspicious_Executable
        {
            meta:
                description = "Detects suspicious executable patterns"
                author = "SentinelAI"
                severity = "medium"
            
            strings:
                $mz = { 4D 5A }
                $pe = "PE"
                $suspicious1 = "cmd.exe" nocase
                $suspicious2 = "powershell" nocase
                $suspicious3 = "rundll32" nocase
                
            condition:
                $mz at 0 and $pe and any of ($suspicious*)
        }
        
        rule Potential_Ransomware
        {
            meta:
                description = "Detects potential ransomware indicators"
                author = "SentinelAI"
                severity = "high"
                
            strings:
                $encrypt1 = "encrypt" nocase
                $encrypt2 = "decrypt" nocase
                $ransom1 = "bitcoin" nocase
                $ransom2 = "payment" nocase
                $ransom3 = "ransom" nocase
                $file_ext1 = ".locked"
                $file_ext2 = ".encrypted"
                
            condition:
                any of ($encrypt*) and any of ($ransom*) or any of ($file_ext*)
        }
        
        rule Suspicious_Script
        {
            meta:
                description = "Detects suspicious script patterns"
                author = "SentinelAI"
                severity = "medium"
                
            strings:
                $powershell1 = "powershell -enc" nocase
                $powershell2 = "powershell -e " nocase
                $download1 = "downloadstring" nocase
                $download2 = "wget" nocase
                $download3 = "curl" nocase
                $exec1 = "invoke-expression" nocase
                $exec2 = "iex" nocase
                
            condition:
                any of them
        }
        
        rule Potential_Keylogger
        {
            meta:
                description = "Detects potential keylogger patterns"
                author = "SentinelAI"
                severity = "high"
                
            strings:
                $key1 = "GetAsyncKeyState" nocase
                $key2 = "SetWindowsHookEx" nocase
                $key3 = "keylogger" nocase
                $key4 = "keystroke" nocase
                $log1 = "log" nocase
                
            condition:
                any of ($key*) and $log1
        }
        '''
        
        try:
            with open(rules_dir / "basic_malware.yar", 'w') as f:
                f.write(basic_rules)
            
            # Compile the basic rules
            self.yara_rules = yara.compile(filepath=str(rules_dir / "basic_malware.yar"))
            self.logger.info("Created and loaded basic YARA rules")
            
        except Exception as e:
            self.logger.error(f"Failed to create basic YARA rules: {e}")
    
    def _initialize_clamav(self):
        """Initialize ClamAV daemon connection"""
        if not CLAMAV_AVAILABLE:
            self.logger.warning("ClamAV not available - ClamAV scanning disabled")
            return
        
        try:
            # Try to connect to ClamAV daemon
            self.clamav_daemon = pyclamd.ClamdUnixSocket()
            
            # Test connection
            if self.clamav_daemon.ping():
                version = self.clamav_daemon.version()
                self.logger.info(f"Connected to ClamAV: {version}")
            else:
                self.logger.warning("ClamAV daemon not responding - trying network socket")
                self.clamav_daemon = pyclamd.ClamdNetworkSocket()
                
                if not self.clamav_daemon.ping():
                    self.logger.warning("ClamAV daemon not available")
                    self.clamav_daemon = None
                    
        except Exception as e:
            self.logger.error(f"Failed to initialize ClamAV: {e}")
            self.clamav_daemon = None
    
    async def execute(self, scan_path: str, recursive: bool = True, exclude_system: bool = True) -> Dict[str, Any]:
        """Execute local scan operation"""
        self.start_operation("local_scan")
        
        try:
            # Validate input
            if not self.validate_input(scan_path, "file_path"):
                raise ValueError("Invalid scan path provided")
            
            scan_path = self.sanitize_path(scan_path)
            
            if not os.path.exists(scan_path):
                raise FileNotFoundError(f"Scan path does not exist: {scan_path}")
            
            # Reset statistics
            self.scan_stats = {
                'files_scanned': 0,
                'threats_detected': 0,
                'scan_duration': 0,
                'bytes_scanned': 0,
                'start_time': datetime.now().isoformat()
            }
            
            # Perform scan
            if os.path.isfile(scan_path):
                results = await self._scan_single_file(scan_path)
            else:
                results = await self._scan_directory(scan_path, recursive, exclude_system)
            
            # Finalize results
            self.scan_stats['scan_duration'] = time.time() - time.mktime(
                datetime.fromisoformat(self.scan_stats['start_time']).timetuple()
            )
            
            results['scan_statistics'] = self.scan_stats
            results['scan_metadata'] = {
                'scan_path': scan_path,
                'scan_type': 'file' if os.path.isfile(scan_path) else 'directory',
                'recursive': recursive,
                'exclude_system': exclude_system,
                'engines_used': self._get_enabled_engines(),
                'timestamp': datetime.now().isoformat()
            }
            
            self.end_operation("local_scan", True, results)
            
            # Cache results
            cache_key = hashlib.md5(f"{scan_path}_{recursive}_{exclude_system}".encode()).hexdigest()
            self.cache_results(cache_key, results, ttl_hours=1)  # Short TTL for file scans
            
            return results
            
        except Exception as e:
            error_result = self.handle_error(e, "local_scan")
            self.end_operation("local_scan", False, error_result)
            return error_result
    
    async def _scan_directory(self, directory_path: str, recursive: bool, exclude_system: bool) -> Dict[str, Any]:
        """Scan a directory for malware"""
        results = {
            'files': [],
            'threats': [],
            'hashes': {},
            'errors': []
        }
        
        # Get list of files to scan
        files_to_scan = self._get_files_to_scan(directory_path, recursive, exclude_system)
        
        self.logger.info(f"Scanning {len(files_to_scan)} files in {directory_path}")
        
        # Use thread pool for concurrent scanning
        max_workers = min(4, os.cpu_count() or 1)  # Limit concurrent scans
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit scan tasks
            future_to_file = {
                executor.submit(self._scan_file_sync, file_path): file_path 
                for file_path in files_to_scan
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                
                try:
                    file_result = future.result()
                    
                    if file_result:
                        results['files'].append(file_result)
                        
                        # Add hashes
                        if 'hashes' in file_result:
                            results['hashes'][file_path] = file_result['hashes']
                        
                        # Add threats
                        if file_result.get('threats'):
                            results['threats'].extend(file_result['threats'])
                        
                        self.scan_stats['files_scanned'] += 1
                        self.scan_stats['bytes_scanned'] += file_result.get('file_size', 0)
                        
                        if file_result.get('threats'):
                            self.scan_stats['threats_detected'] += len(file_result['threats'])
                            
                except Exception as e:
                    error_msg = f"Error scanning {file_path}: {str(e)}"
                    self.logger.error(error_msg)
                    results['errors'].append(error_msg)
        
        return results
    
    async def _scan_single_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a single file"""
        file_result = self._scan_file_sync(file_path)
        
        results = {
            'files': [file_result] if file_result else [],
            'threats': file_result.get('threats', []) if file_result else [],
            'hashes': {file_path: file_result.get('hashes', {})} if file_result else {},
            'errors': []
        }
        
        if file_result:
            self.scan_stats['files_scanned'] = 1
            self.scan_stats['bytes_scanned'] = file_result.get('file_size', 0)
            self.scan_stats['threats_detected'] = len(file_result.get('threats', []))
        
        return results
    
    def _scan_file_sync(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Synchronous file scanning (for use in thread pool)"""
        try:
            if not os.path.isfile(file_path):
                return None
            
            file_info = self._get_file_info(file_path)
            
            # Skip files that are too large (>100MB by default)
            max_file_size = 100 * 1024 * 1024  # 100MB
            if file_info['file_size'] > max_file_size:
                self.logger.warning(f"Skipping large file: {file_path} ({file_info['file_size']} bytes)")
                return None
            
            # Generate hashes
            hashes = self._generate_file_hashes(file_path)
            file_info['hashes'] = hashes
            
            # Scan with available engines
            threats = []
            
            # YARA scan
            if self.yara_rules:
                yara_threats = self._yara_scan_file(file_path)
                threats.extend(yara_threats)
            
            # ClamAV scan
            if self.clamav_daemon:
                clamav_threats = self._clamav_scan_file(file_path)
                threats.extend(clamav_threats)
            
            # Signature-based detection
            signature_threats = self._signature_scan_file(file_path, file_info)
            threats.extend(signature_threats)
            
            file_info['threats'] = threats
            file_info['threat_count'] = len(threats)
            file_info['is_clean'] = len(threats) == 0
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return None
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        try:
            stat = os.stat(file_path)
            
            # Get MIME type
            try:
                mime_type = self.magic_mime.from_file(file_path)
            except Exception:
                mime_type = "unknown"
            
            return {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': stat.st_size,
                'file_extension': Path(file_path).suffix.lower(),
                'mime_type': mime_type,
                'created_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat.st_atime).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting file info for {file_path}: {e}")
            return {'file_path': file_path, 'error': str(e)}
    
    def _generate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Generate multiple hashes for a file"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # SHA256
            hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
            
            # MD5
            hashes['md5'] = hashlib.md5(file_data).hexdigest()
            
            # SHA1
            hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
            
            # Fuzzy hash (TLSH preferred, ppdeep fallback)
            try:
                if TLSH_AVAILABLE:
                    hashes['fuzzy'] = tlsh.hash(file_data)
                elif PPDEEP_AVAILABLE:
                    hashes['fuzzy'] = ppdeep.hash(file_data)
                else:
                    hashes['fuzzy'] = None
            except Exception as e:
                self.logger.debug(f"Fuzzy hash failed for {file_path}: {e}")
                hashes['fuzzy'] = None
            
        except Exception as e:
            self.logger.error(f"Error generating hashes for {file_path}: {e}")
        
        return hashes
    
    def _yara_scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with YARA rules"""
        threats = []
        
        try:
            matches = self.yara_rules.match(file_path)
            
            for match in matches:
                threat = {
                    'engine': 'YARA',
                    'rule_name': match.rule,
                    'threat_name': match.rule,
                    'description': match.meta.get('description', 'YARA rule match'),
                    'severity': match.meta.get('severity', 'medium'),
                    'confidence': 85,  # YARA matches are generally reliable
                    'file_path': file_path,
                    'detection_time': datetime.now().isoformat(),
                    'strings_matched': [str(s) for s in match.strings] if match.strings else []
                }
                threats.append(threat)
                
        except Exception as e:
            self.logger.error(f"YARA scan failed for {file_path}: {e}")
        
        return threats
    
    def _clamav_scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with ClamAV"""
        threats = []
        
        try:
            result = self.clamav_daemon.scan_file(file_path)
            
            if result and file_path in result:
                status, threat_name = result[file_path]
                
                if status == 'FOUND':
                    threat = {
                        'engine': 'ClamAV',
                        'threat_name': threat_name,
                        'description': f'ClamAV detected: {threat_name}',
                        'severity': self._classify_clamav_severity(threat_name),
                        'confidence': 95,  # ClamAV is highly reliable
                        'file_path': file_path,
                        'detection_time': datetime.now().isoformat()
                    }
                    threats.append(threat)
                    
        except Exception as e:
            self.logger.error(f"ClamAV scan failed for {file_path}: {e}")
        
        return threats
    
    def _signature_scan_file(self, file_path: str, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform signature-based detection"""
        threats = []
        
        try:
            # Check for suspicious file extensions
            suspicious_extensions = [
                '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
                '.jar', '.ps1', '.msi', '.dll', '.sys'
            ]
            
            file_ext = file_info.get('file_extension', '').lower()
            
            # Check for double extensions (common in malware)
            if file_path.count('.') > 1:
                parts = file_path.split('.')
                if len(parts) >= 3 and f".{parts[-2]}" in ['.txt', '.pdf', '.doc', '.jpg']:
                    if file_ext in suspicious_extensions:
                        threat = {
                            'engine': 'Signature',
                            'threat_name': 'Suspicious_Double_Extension',
                            'description': 'File has suspicious double extension pattern',
                            'severity': 'medium',
                            'confidence': 70,
                            'file_path': file_path,
                            'detection_time': datetime.now().isoformat()
                        }
                        threats.append(threat)
            
            # Check file size anomalies
            if file_ext in ['.txt', '.log'] and file_info.get('file_size', 0) > 10 * 1024 * 1024:  # >10MB
                threat = {
                    'engine': 'Signature',
                    'threat_name': 'Suspicious_File_Size',
                    'description': 'Text file with unusually large size',
                    'severity': 'low',
                    'confidence': 50,
                    'file_path': file_path,
                    'detection_time': datetime.now().isoformat()
                }
                threats.append(threat)
            
            # Check for executable files in unusual locations
            if file_ext in suspicious_extensions:
                suspicious_paths = ['/tmp/', '/var/tmp/', 'Downloads', 'Temp']
                if any(path in file_path for path in suspicious_paths):
                    threat = {
                        'engine': 'Signature',
                        'threat_name': 'Suspicious_Location',
                        'description': 'Executable file in suspicious location',
                        'severity': 'medium',
                        'confidence': 60,
                        'file_path': file_path,
                        'detection_time': datetime.now().isoformat()
                    }
                    threats.append(threat)
            
        except Exception as e:
            self.logger.error(f"Signature scan failed for {file_path}: {e}")
        
        return threats
    
    def _classify_clamav_severity(self, threat_name: str) -> str:
        """Classify ClamAV threat severity based on name"""
        threat_name_lower = threat_name.lower()
        
        if any(keyword in threat_name_lower for keyword in ['trojan', 'backdoor', 'rootkit', 'ransomware']):
            return 'critical'
        elif any(keyword in threat_name_lower for keyword in ['virus', 'worm', 'malware']):
            return 'high'
        elif any(keyword in threat_name_lower for keyword in ['adware', 'spyware', 'pup']):
            return 'medium'
        else:
            return 'low'
    
    def _get_files_to_scan(self, directory_path: str, recursive: bool, exclude_system: bool) -> List[str]:
        """Get list of files to scan in directory"""
        files_to_scan = []
        
        # System directories to exclude
        system_dirs = {
            '/proc', '/sys', '/dev', '/tmp', '/var/tmp',
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
            'C:\\Program Files', 'C:\\Program Files (x86)',
            '/System', '/Library/System', '/usr/bin', '/usr/sbin'
        }
        
        # File extensions to skip
        skip_extensions = {
            '.tmp', '.log', '.cache', '.lock', '.pid', '.sock',
            '.swp', '.bak', '.old', '.orig'
        }
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    # Skip system directories if requested
                    if exclude_system:
                        dirs[:] = [d for d in dirs if not any(
                            os.path.join(root, d).startswith(sys_dir) for sys_dir in system_dirs
                        )]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Skip files with certain extensions
                        if Path(file_path).suffix.lower() not in skip_extensions:
                            files_to_scan.append(file_path)
            else:
                # Non-recursive scan
                for item in os.listdir(directory_path):
                    item_path = os.path.join(directory_path, item)
                    
                    if os.path.isfile(item_path):
                        if Path(item_path).suffix.lower() not in skip_extensions:
                            files_to_scan.append(item_path)
        
        except Exception as e:
            self.logger.error(f"Error getting files to scan: {e}")
        
        return files_to_scan
    
    def _get_enabled_engines(self) -> List[str]:
        """Get list of enabled scanning engines"""
        engines = []
        
        if self.yara_rules:
            engines.append("YARA")
        
        if self.clamav_daemon:
            engines.append("ClamAV")
        
        engines.append("Signature")  # Always available
        
        return engines
    
    def scan_folder(self, folder_path: str, recursive: bool = True, exclude_system: bool = True) -> Dict[str, Any]:
        """Synchronous wrapper for folder scanning"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            return loop.run_until_complete(
                self.execute(folder_path, recursive, exclude_system)
            )
        finally:
            loop.close()
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get current scan statistics"""
        return self.scan_stats.copy()
    
    def compare_fuzzy_hashes(self, hash1: str, hash2: str) -> Optional[int]:
        """Compare two fuzzy hashes and return similarity score"""
        try:
            if not hash1 or not hash2:
                return None
            
            if TLSH_AVAILABLE:
                # TLSH: lower score = more similar (0-100)
                return tlsh.diff(hash1, hash2)
            elif PPDEEP_AVAILABLE:
                # ppdeep: higher score = more similar (0-100)
                return ppdeep.compare(hash1, hash2)
            else:
                return None
        except Exception as e:
            self.logger.error(f"Fuzzy hash comparison failed: {e}")
            return None
    
    def update_yara_rules(self, rules_content: str) -> bool:
        """Update YARA rules with new content"""
        try:
            # Save new rules to file
            rules_dir = Path(__file__).parent.parent / "rules" / "yara"
            rules_dir.mkdir(parents=True, exist_ok=True)
            
            custom_rules_file = rules_dir / "custom_rules.yar"
            
            with open(custom_rules_file, 'w') as f:
                f.write(rules_content)
            
            # Recompile rules
            rule_files = list(rules_dir.glob("*.yar"))
            filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
            self.yara_rules = yara.compile(filepaths=filepaths)
            
            self.logger.info("YARA rules updated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update YARA rules: {e}")
            return False
