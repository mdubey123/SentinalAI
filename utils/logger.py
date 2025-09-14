"""
Logging utilities for SentinelAI v2
Provides structured logging with security audit capabilities
"""

import logging
import logging.handlers
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

def setup_logger(name: str = "sentinelai", level: str = "INFO") -> logging.Logger:
    """Setup structured logger with file and console handlers"""
    
    # Create logs directory
    log_dir = Path.home() / ".sentinelai" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "sentinelai.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    
    # Security audit handler
    security_handler = logging.handlers.RotatingFileHandler(
        log_dir / "security_audit.log",
        maxBytes=5*1024*1024,  # 5MB
        backupCount=10
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(detailed_formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.addHandler(security_handler)
    
    return logger

class SecurityAuditLogger:
    """Specialized logger for security events"""
    
    def __init__(self):
        self.logger = setup_logger("security_audit", "DEBUG")
        self.audit_file = Path.home() / ".sentinelai" / "logs" / "audit_events.jsonl"
    
    def log_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log a security event with structured data"""
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "session_id": self._get_session_id()
        }
        
        # Log to standard logger
        log_message = f"Security Event: {event_type} - {json.dumps(details)}"
        
        if severity == "CRITICAL":
            self.logger.critical(log_message)
        elif severity == "ERROR":
            self.logger.error(log_message)
        elif severity == "WARNING":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Log to structured audit file
        try:
            with open(self.audit_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write audit event: {e}")
    
    def log_api_access(self, service: str, action: str, success: bool, details: Optional[Dict] = None):
        """Log API access events"""
        self.log_event(
            "api_access",
            {
                "service": service,
                "action": action,
                "success": success,
                "details": details or {}
            },
            "INFO" if success else "WARNING"
        )
    
    def log_scan_event(self, scan_type: str, target: str, results_summary: Dict[str, Any]):
        """Log scan completion events"""
        self.log_event(
            "scan_completed",
            {
                "scan_type": scan_type,
                "target": target,
                "results": results_summary
            },
            "INFO"
        )
    
    def log_threat_detection(self, threat_details: Dict[str, Any]):
        """Log threat detection events"""
        severity = "CRITICAL" if threat_details.get('severity') == 'Critical' else "WARNING"
        
        self.log_event(
            "threat_detected",
            threat_details,
            severity
        )
    
    def log_authentication_event(self, event: str, success: bool, details: Optional[Dict] = None):
        """Log authentication-related events"""
        self.log_event(
            "authentication",
            {
                "event": event,
                "success": success,
                "details": details or {}
            },
            "INFO" if success else "WARNING"
        )
    
    def log_configuration_change(self, setting: str, old_value: Any, new_value: Any):
        """Log configuration changes"""
        self.log_event(
            "config_change",
            {
                "setting": setting,
                "old_value": str(old_value),
                "new_value": str(new_value)
            },
            "INFO"
        )
    
    def _get_session_id(self) -> str:
        """Get or create session ID"""
        # In a real implementation, this would be more sophisticated
        return f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def get_recent_events(self, hours: int = 24, event_type: Optional[str] = None) -> list:
        """Get recent audit events"""
        if not self.audit_file.exists():
            return []
        
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        events = []
        
        try:
            with open(self.audit_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        event_time = datetime.fromisoformat(event['timestamp']).timestamp()
                        
                        if event_time >= cutoff_time:
                            if event_type is None or event['event_type'] == event_type:
                                events.append(event)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except Exception as e:
            self.logger.error(f"Error reading audit events: {e}")
        
        return sorted(events, key=lambda x: x['timestamp'], reverse=True)

# Global instances
security_audit = SecurityAuditLogger()
