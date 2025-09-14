"""
Base Agent class for SentinelAI v2
Provides common functionality for all specialized agents
"""

import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
import json

from core.security_manager import SecurityManager
from utils.logger import security_audit

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """Base class for all SentinelAI agents"""
    
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.security_manager = SecurityManager()
        self.logger = logging.getLogger(f"agents.{agent_name}")
        self.start_time = None
        self.end_time = None
    
    def start_operation(self, operation_name: str):
        """Start timing an operation"""
        self.start_time = datetime.now()
        self.logger.info(f"Starting {operation_name}")
        
        security_audit.log_event(
            "agent_operation_start",
            {
                "agent": self.agent_name,
                "operation": operation_name,
                "start_time": self.start_time.isoformat()
            }
        )
    
    def end_operation(self, operation_name: str, success: bool = True, results: Optional[Dict] = None):
        """End timing an operation"""
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time else 0
        
        self.logger.info(f"Completed {operation_name} in {duration:.2f}s - Success: {success}")
        
        security_audit.log_event(
            "agent_operation_complete",
            {
                "agent": self.agent_name,
                "operation": operation_name,
                "duration_seconds": duration,
                "success": success,
                "results_summary": self._summarize_results(results) if results else None
            }
        )
    
    def _summarize_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of results for logging"""
        if not results:
            return {}
        
        summary = {}
        
        # Count various result types
        if 'threats' in results:
            summary['threats_found'] = len(results['threats'])
        
        if 'files_scanned' in results:
            summary['files_scanned'] = results['files_scanned']
        
        if 'vulnerabilities' in results:
            summary['vulnerabilities_found'] = len(results['vulnerabilities'])
        
        if 'security_score' in results:
            summary['security_score'] = results['security_score']
        
        return summary
    
    def validate_input(self, input_data: Any, input_type: str) -> bool:
        """Validate input data"""
        try:
            if input_type == "file_path":
                return isinstance(input_data, str) and len(input_data) > 0
            elif input_type == "ip_address":
                import ipaddress
                ipaddress.ip_address(input_data)
                return True
            elif input_type == "port_range":
                if isinstance(input_data, str):
                    # Validate port range format
                    if '-' in input_data:
                        start, end = input_data.split('-')
                        return 1 <= int(start) <= int(end) <= 65535
                    elif ',' in input_data:
                        ports = [int(p.strip()) for p in input_data.split(',')]
                        return all(1 <= p <= 65535 for p in ports)
                    else:
                        port = int(input_data)
                        return 1 <= port <= 65535
            elif input_type == "hash":
                return isinstance(input_data, str) and len(input_data) in [32, 40, 64, 128]
            
            return True
            
        except Exception as e:
            self.logger.error(f"Input validation failed for {input_type}: {e}")
            return False
    
    def sanitize_path(self, path: str) -> str:
        """Sanitize file paths to prevent directory traversal"""
        import os
        from pathlib import Path
        
        try:
            # Resolve path and ensure it's absolute
            clean_path = os.path.abspath(path)
            
            # Check for directory traversal attempts
            if '..' in path or path.startswith('/'):
                self.logger.warning(f"Potentially unsafe path detected: {path}")
            
            return clean_path
            
        except Exception as e:
            self.logger.error(f"Path sanitization failed: {e}")
            return path
    
    def handle_error(self, error: Exception, operation: str) -> Dict[str, Any]:
        """Standard error handling"""
        error_details = {
            "agent": self.agent_name,
            "operation": operation,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.error(f"Error in {operation}: {error}")
        
        security_audit.log_event(
            "agent_error",
            error_details,
            "ERROR"
        )
        
        return {
            "success": False,
            "error": error_details,
            "results": {}
        }
    
    async def async_operation_wrapper(self, operation_func, *args, **kwargs):
        """Wrapper for async operations with error handling"""
        try:
            return await operation_func(*args, **kwargs)
        except Exception as e:
            return self.handle_error(e, operation_func.__name__)
    
    def cache_results(self, cache_key: str, results: Dict[str, Any], ttl_hours: int = 24):
        """Cache operation results"""
        try:
            from pathlib import Path
            import json
            
            cache_dir = Path.home() / ".sentinelai" / "cache"
            cache_dir.mkdir(exist_ok=True)
            
            cache_file = cache_dir / f"{self.agent_name}_{cache_key}.json"
            
            cache_data = {
                "timestamp": datetime.now().isoformat(),
                "ttl_hours": ttl_hours,
                "results": results
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to cache results: {e}")
    
    def get_cached_results(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached results if still valid"""
        try:
            from pathlib import Path
            import json
            
            cache_file = Path.home() / ".sentinelai" / "cache" / f"{self.agent_name}_{cache_key}.json"
            
            if not cache_file.exists():
                return None
            
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Check if cache is still valid
            cache_time = datetime.fromisoformat(cache_data['timestamp'])
            ttl_hours = cache_data.get('ttl_hours', 24)
            
            if (datetime.now() - cache_time).total_seconds() > (ttl_hours * 3600):
                # Cache expired
                cache_file.unlink()
                return None
            
            return cache_data['results']
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve cached results: {e}")
            return None
    
    @abstractmethod
    async def execute(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the main agent operation - must be implemented by subclasses"""
        pass
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            "agent_name": self.agent_name,
            "status": "ready",
            "last_operation": self.end_time.isoformat() if self.end_time else None,
            "cache_enabled": True
        }
