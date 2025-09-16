"""
Security Manager for SentinelAI v2
Handles encryption, API key management, and security controls
"""

import os
import json
import base64
import logging
from typing import Dict, Optional, Any
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import streamlit as st

logger = logging.getLogger(__name__)

class SecurityManager:
    """Manages security operations including encryption and key storage"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".sentinelai"
        self.keys_file = self.config_dir / "encrypted_keys.json"
        self.master_key_file = self.config_dir / ".master_key"
        self.audit_log_file = self.config_dir / "logs" / "audit.log"
        
        self.ensure_security_setup()
        self.fernet = self._get_or_create_fernet()
    
    def ensure_security_setup(self):
        """Ensure security infrastructure is set up"""
        self.config_dir.mkdir(exist_ok=True)
        (self.config_dir / "logs").mkdir(exist_ok=True)
        
        # Set restrictive permissions on config directory
        try:
            os.chmod(self.config_dir, 0o700)
        except Exception as e:
            logger.warning(f"Could not set directory permissions: {e}")
    
    def _get_or_create_fernet(self) -> Fernet:
        """Get or create Fernet encryption instance"""
        if self.master_key_file.exists():
            with open(self.master_key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate new master key
            password = self._generate_master_password()
            salt = os.urandom(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Store key securely
            with open(self.master_key_file, 'wb') as f:
                f.write(key)
            
            # Set restrictive permissions
            try:
                os.chmod(self.master_key_file, 0o600)
            except Exception as e:
                logger.warning(f"Could not set key file permissions: {e}")
        
        return Fernet(key)
    
    def _generate_master_password(self) -> str:
        """Generate a master password for encryption"""
        # In production, this should be user-provided or derived from system entropy
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(32))
        return password
    
    def store_encrypted_key(self, service: str, api_key: str) -> bool:
        """Store an API key encrypted"""
        try:
            # Load existing keys
            encrypted_keys = self._load_encrypted_keys()
            
            # Encrypt the new key
            encrypted_key = self.fernet.encrypt(api_key.encode()).decode()
            
            # Store with metadata
            encrypted_keys[service] = {
                'encrypted_key': encrypted_key,
                'created_at': self._get_timestamp(),
                'last_used': None
            }
            
            # Save to file
            self._save_encrypted_keys(encrypted_keys)
            
            # Audit log
            self._audit_log(f"API key stored for service: {service}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error storing encrypted key for {service}: {e}")
            return False
    
    def get_decrypted_key(self, service: str) -> Optional[str]:
        """Retrieve and decrypt an API key"""
        try:
            encrypted_keys = self._load_encrypted_keys()
            
            if service not in encrypted_keys:
                return None
            
            key_data = encrypted_keys[service]
            encrypted_key = key_data['encrypted_key'].encode()
            
            # Decrypt the key
            decrypted_key = self.fernet.decrypt(encrypted_key).decode()
            
            # Update last used timestamp
            key_data['last_used'] = self._get_timestamp()
            self._save_encrypted_keys(encrypted_keys)
            
            # Audit log
            self._audit_log(f"API key retrieved for service: {service}")
            
            return decrypted_key
            
        except Exception as e:
            logger.error(f"Error retrieving key for {service}: {e}")
            return None
    
    def delete_key(self, service: str) -> bool:
        """Delete a stored API key"""
        try:
            encrypted_keys = self._load_encrypted_keys()
            
            if service in encrypted_keys:
                del encrypted_keys[service]
                self._save_encrypted_keys(encrypted_keys)
                self._audit_log(f"API key deleted for service: {service}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting key for {service}: {e}")
            return False
    
    def list_stored_services(self) -> list:
        """List services with stored API keys"""
        try:
            encrypted_keys = self._load_encrypted_keys()
            return list(encrypted_keys.keys())
        except Exception as e:
            logger.error(f"Error listing services: {e}")
            return []
    
    def _load_encrypted_keys(self) -> Dict[str, Any]:
        """Load encrypted keys from file"""
        if not self.keys_file.exists():
            return {}
        
        try:
            with open(self.keys_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading encrypted keys: {e}")
            return {}
    
    def _save_encrypted_keys(self, keys: Dict[str, Any]):
        """Save encrypted keys to file"""
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(keys, f, indent=2)
            
            # Set restrictive permissions
            try:
                os.chmod(self.keys_file, 0o600)
            except Exception as e:
                logger.warning(f"Could not set keys file permissions: {e}")
                
        except Exception as e:
            logger.error(f"Error saving encrypted keys: {e}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _audit_log(self, message: str):
        """Write to audit log"""
        try:
            timestamp = self._get_timestamp()
            log_entry = f"[{timestamp}] {message}\n"
            
            with open(self.audit_log_file, 'a') as f:
                f.write(log_entry)
                
        except Exception as e:
            logger.error(f"Error writing audit log: {e}")
    
    def sanitize_input(self, user_input: str) -> str:
        """Sanitize user input to prevent injection attacks"""
        if not isinstance(user_input, str):
            return str(user_input)
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\n', '\r']
        sanitized = user_input
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Limit length
        max_length = 1000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    def validate_api_key(self, api_key: str, service: str) -> bool:
        """Validate API key format"""
        if not api_key or not isinstance(api_key, str):
            return False
        
        # Service-specific validation
        validation_rules = {
            'openai': lambda k: k.startswith('sk-') and len(k) > 20,
            'anthropic': lambda k: k.startswith('sk-ant-') and len(k) > 20,
            'virustotal': lambda k: len(k) == 64 and k.isalnum(),
            'google': lambda k: len(k) > 20,
            'groq': lambda k: k.startswith('gsk_') and len(k) > 20,
            'cohere': lambda k: len(k) > 20,
            'hugging face': lambda k: k.startswith('hf_') and len(k) > 20,
            'mistral': lambda k: len(k) > 20,
            'llama': lambda k: len(k) > 20,
            'local': lambda k: True  # Local models don't need API keys
        }
        
        validator = validation_rules.get(service.lower())
        if validator:
            return validator(api_key)
        
        # Generic validation
        return len(api_key) > 10 and api_key.isprintable()
    
    def check_prompt_injection(self, prompt: str) -> bool:
        """Check for potential prompt injection attempts"""
        if not isinstance(prompt, str):
            return False
        
        # Common injection patterns
        injection_patterns = [
            'ignore previous instructions',
            'forget everything above',
            'system:',
            'assistant:',
            'human:',
            '\\n\\nHuman:',
            '\\n\\nAssistant:',
            'jailbreak',
            'roleplay',
            'pretend you are',
            'act as if'
        ]
        
        prompt_lower = prompt.lower()
        
        for pattern in injection_patterns:
            if pattern in prompt_lower:
                self._audit_log(f"Potential prompt injection detected: {pattern}")
                return True
        
        return False
    
    def get_audit_logs(self, lines: int = 100) -> list:
        """Get recent audit log entries"""
        try:
            if not self.audit_log_file.exists():
                return []
            
            with open(self.audit_log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:] if len(all_lines) > lines else all_lines
                
        except Exception as e:
            logger.error(f"Error reading audit logs: {e}")
            return []
    
    def clear_audit_logs(self) -> bool:
        """Clear audit log file"""
        try:
            if self.audit_log_file.exists():
                self.audit_log_file.unlink()
            self._audit_log("Audit logs cleared")
            return True
        except Exception as e:
            logger.error(f"Error clearing audit logs: {e}")
            return False
    
    def log_security_event(self, event_type: str, details: Dict[str, Any] = None):
        """Log a security event"""
        try:
            if details is None:
                details = {}
            
            message = f"Security event: {event_type}"
            if details:
                detail_str = ", ".join([f"{k}: {v}" for k, v in details.items()])
                message += f" - {detail_str}"
            
            self._audit_log(message)
            
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
    
    def export_security_report(self) -> Dict[str, Any]:
        """Export security status report"""
        return {
            'stored_services': len(self.list_stored_services()),
            'audit_log_entries': len(self.get_audit_logs()),
            'encryption_enabled': True,
            'last_key_access': self._get_timestamp(),
            'security_features': {
                'encryption': True,
                'audit_logging': True,
                'input_sanitization': True,
                'prompt_injection_protection': True,
                'api_key_validation': True
            }
        }
