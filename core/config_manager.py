"""
Configuration Manager for SentinelAI v2
Handles application configuration, settings, and environment management
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import streamlit as st

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages application configuration and settings"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".sentinelai"
        self.config_file = self.config_dir / "config.json"
        self.ensure_config_directory()
        self.load_config()
    
    def ensure_config_directory(self):
        """Ensure configuration directory exists"""
        self.config_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.config_dir / "logs").mkdir(exist_ok=True)
        (self.config_dir / "reports").mkdir(exist_ok=True)
        (self.config_dir / "profiles").mkdir(exist_ok=True)
        (self.config_dir / "cache").mkdir(exist_ok=True)
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            "version": "2.1.0",
            "llm_settings": {
                "default_provider": "OpenAI",
                "default_model": "gpt-4",
                "max_tokens": 4000,
                "temperature": 0.1
            },
            "scan_settings": {
                "max_file_size_mb": 32,
                "exclude_extensions": [".tmp", ".log", ".cache"],
                "exclude_directories": [
                    "/proc", "/sys", "/dev", "/tmp",
                    "C:\\Windows\\System32", "C:\\Windows\\SysWOW64"
                ],
                "recursive_scan": True,
                "hash_algorithms": ["sha256", "fuzzy"]
            },
            "virustotal_settings": {
                "enabled": True,
                "api_quota_limit": 500,
                "upload_threshold_mb": 32,
                "cache_results": True,
                "cache_duration_hours": 24
            },
            "vapt_settings": {
                "enabled": False,
                "default_scope": "host_only",
                "port_ranges": {
                    "quick": "1-1000",
                    "standard": "1-65535",
                    "custom": "80,443,8080,8443"
                },
                "timeout_seconds": 30
            },
            "security_settings": {
                "audit_logging": True,
                "prompt_injection_protection": True,
                "api_rate_limiting": True,
                "max_requests_per_minute": 60,
                "encryption_enabled": True
            },
            "gamification_settings": {
                "enabled": True,
                "scoring_weights": {
                    "scan_completion": 10,
                    "threat_detection": 25,
                    "clean_scan": 5,
                    "vapt_completion": 15
                },
                "level_thresholds": [0, 100, 250, 500, 1000, 2000, 5000]
            },
            "reporting_settings": {
                "auto_save": True,
                "pdf_template": "executive",
                "include_technical_details": False,
                "export_formats": ["pdf", "json"]
            }
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    self.config = {**default_config, **loaded_config}
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                self.config = default_config
        else:
            self.config = default_config
            self.save_config()
        
        return self.config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()
    
    def get_llm_config(self, provider: str, model: str) -> Dict[str, Any]:
        """Get LLM-specific configuration"""
        base_config = self.get("llm_settings", {})
        
        provider_configs = {
            "OpenAI": {
                "api_base": "https://api.openai.com/v1",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "OPENAI_API_KEY"
            },
            "Anthropic": {
                "api_base": "https://api.anthropic.com",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "ANTHROPIC_API_KEY"
            },
            "Google": {
                "api_base": "https://generativelanguage.googleapis.com",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "GOOGLE_API_KEY"
            },
            "Groq": {
                "api_base": "https://api.groq.com/openai/v1",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "GROQ_API_KEY"
            },
            "Cohere": {
                "api_base": "https://api.cohere.ai/v1",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "COHERE_API_KEY"
            },
            "Hugging Face": {
                "api_base": "https://api-inference.huggingface.co/models",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "HUGGINGFACE_API_KEY"
            },
            "Mistral": {
                "api_base": "https://api.mistral.ai/v1",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "MISTRAL_API_KEY"
            },
            "Llama": {
                "api_base": "https://api.llama.ai/v1",
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": "LLAMA_API_KEY"
            },
            "Local": {
                "api_base": "http://localhost:11434",  # Default Ollama endpoint
                "max_tokens": base_config.get("max_tokens", 4000),
                "temperature": base_config.get("temperature", 0.1),
                "api_key_env": None
            }
        }
        
        return provider_configs.get(provider, base_config)
    
    def initialize_llm(self, provider: str, model: str) -> Dict[str, Any]:
        """Initialize LLM configuration for the workflow"""
        try:
            # Get provider-specific configuration
            llm_config = self.get_llm_config(provider, model)
            
            # Validate provider and model combination
            if not self._validate_llm_combination(provider, model):
                raise ValueError(f"Invalid LLM combination: {provider}/{model}")
            
            # Set up provider-specific parameters
            initialized_config = {
                'provider': provider,
                'model': model,
                'config': llm_config,
                'initialized': True,
                'initialization_time': str(datetime.now()),
                'status': 'ready'
            }
            
            # Store current LLM configuration
            self.set('current_llm.provider', provider)
            self.set('current_llm.model', model)
            self.set('current_llm.initialized_at', initialized_config['initialization_time'])
            
            logger.info(f"LLM initialized: {provider}/{model}")
            return initialized_config
            
        except Exception as e:
            logger.error(f"Failed to initialize LLM {provider}/{model}: {e}")
            return {
                'provider': provider,
                'model': model,
                'initialized': False,
                'error': str(e),
                'status': 'failed'
            }
    
    def _validate_llm_combination(self, provider: str, model: str) -> bool:
        """Validate that the provider/model combination is supported"""
        supported_combinations = {
            "OpenAI": [
                # GPT-5 Series (Latest)
                "gpt-5", "gpt-5-pro", "gpt-5-mini",
                # GPT-4 Series
                "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4",
                # o Series (Reasoning-Focused)
                "o3-pro", "o3", "o3-mini", "o4-mini",
                # GPT-3.5 Series
                "gpt-3.5-turbo",
                # Codex Series (Developer-Focused)
                "codex"
            ],
            "Anthropic": [
                "claude-3.5-sonnet", "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
                "claude-2.1", "claude-2.0", "claude-instant"
            ],
            "Google": [
                # Gemini 2.5 Series (Latest)
                "gemini-2.5-pro-diamond", "gemini-2.5-pro", "gemini-2.5-flash-spark", 
                "gemini-2.5-flash", "gemini-2.5-flash-lite",
                # Gemini 2.0 Series
                "gemini-2.0-pro", "gemini-2.0-flash", "gemini-2.0-flash-lite",
                # Gemini 1.5 Series
                "gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.5-flash-lite",
                # Gemini 1.0 Series
                "gemini-1.0-ultra", "gemini-1.0-pro", "gemini-1.0-nano",
                # Specialized Models
                "gemini-nano-banana", "gemini-veo-3", "gemini-robotics", "gemini-robotics-er"
            ],
            "Groq": [
                # Production Models
                "llama-3.1-8b", "llama-3.3-70b", "llama-guard-4-12b",
                "gpt-oss-20b", "gpt-oss-120b", "whisper-large-v3", "whisper-large-v3-turbo",
                # Groq-Optimized Systems
                "compound", "compound-mini",
                # Tool-Use Models
                "llama-3-groq-70b-tool-use", "llama-3-groq-8b-tool-use"
            ],
            "Cohere": [
                "command-r-plus", "command-r", "command", "command-light",
                "command-nightly", "command-light-nightly"
            ],
            "Hugging Face": [
                "mistral-7b", "llama-2-7b", "llama-2-13b", "llama-2-70b",
                "code-llama", "codellama", "falcon-7b", "falcon-40b",
                "bloom-560m", "bloom-1b7", "bloom-3b", "bloom-7b1"
            ],
            "Mistral": [
                "mistral-large", "mistral-medium", "mistral-small",
                "mixtral-8x7b", "mixtral-8x22b", "codestral"
            ],
            "Llama": [
                "llama-3.1-8b", "llama-3.1-70b", "llama-3.1-405b",
                "llama-3-8b", "llama-3-70b", "llama-3-405b",
                "llama-2-7b", "llama-2-13b", "llama-2-70b",
                "llama-2-7b-chat", "llama-2-13b-chat", "llama-2-70b-chat"
            ],
            "Local": [
                "local-model", "ollama-llama3", "ollama-mistral", "ollama-codellama",
                "local-gpt", "local-claude", "custom-model"
            ]
        }
        
        return provider in supported_combinations and model in supported_combinations[provider]
    
    def get_current_llm_config(self) -> Optional[Dict[str, Any]]:
        """Get currently configured LLM settings"""
        provider = self.get('current_llm.provider')
        model = self.get('current_llm.model')
        
        if provider and model:
            return {
                'provider': provider,
                'model': model,
                'config': self.get_llm_config(provider, model),
                'initialized_at': self.get('current_llm.initialized_at')
            }
        
        return None
    
    def get_workflow_config(self) -> Dict[str, Any]:
        """Get configuration optimized for workflow execution"""
        return {
            'llm_settings': self.get('llm_settings', {}),
            'scan_settings': self.get('scan_settings', {}),
            'virustotal_settings': self.get('virustotal_settings', {}),
            'vapt_settings': self.get('vapt_settings', {}),
            'security_settings': self.get('security_settings', {}),
            'performance_settings': {
                'concurrent_scans': self.get('performance.concurrent_scans', 4),
                'cache_enabled': self.get('performance.cache_enabled', True),
                'timeout_seconds': self.get('performance.timeout_seconds', 300)
            }
        }
    
    def validate_config(self) -> bool:
        """Validate configuration integrity"""
        required_sections = [
            "llm_settings", "scan_settings", "security_settings"
        ]
        
        for section in required_sections:
            if section not in self.config:
                logger.error(f"Missing required config section: {section}")
                return False
        
        return True
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        if self.config_file.exists():
            self.config_file.unlink()
        self.load_config()
    
    def export_config(self) -> str:
        """Export configuration as JSON string"""
        return json.dumps(self.config, indent=2)
    
    def import_config(self, config_json: str) -> bool:
        """Import configuration from JSON string"""
        try:
            imported_config = json.loads(config_json)
            self.config = imported_config
            self.save_config()
            return True
        except Exception as e:
            logger.error(f"Error importing config: {e}")
            return False
