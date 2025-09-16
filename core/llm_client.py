"""
Universal LLM Client for SentinelAI v2
Supports multiple LLM providers with unified interface
"""

import os
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import aiohttp
import openai
from anthropic import Anthropic
import google.generativeai as genai
import cohere
from groq import Groq

logger = logging.getLogger(__name__)

class UniversalLLMClient:
    """Universal client for multiple LLM providers"""
    
    def __init__(self, provider: str, model: str, api_key: Optional[str] = None):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key
        self.client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the appropriate client based on provider"""
        try:
            if self.provider == "openai":
                self.client = openai.OpenAI(api_key=self.api_key)
            elif self.provider == "anthropic":
                self.client = Anthropic(api_key=self.api_key)
            elif self.provider == "google":
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel(self.model)
            elif self.provider == "groq":
                self.client = Groq(api_key=self.api_key)
            elif self.provider == "cohere":
                self.client = cohere.Client(api_key=self.api_key)
            elif self.provider in ["hugging face", "mistral", "llama"]:
                # Use OpenAI-compatible API
                self.client = openai.OpenAI(
                    api_key=self.api_key,
                    base_url=self._get_custom_base_url()
                )
            elif self.provider == "local":
                # Local models (Ollama, etc.)
                self.client = openai.OpenAI(
                    api_key="dummy",  # Local models don't need real API keys
                    base_url="http://localhost:11434/v1"
                )
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
                
            logger.info(f"Initialized {self.provider} client with model {self.model}")
            
        except Exception as e:
            logger.error(f"Failed to initialize {self.provider} client: {e}")
            raise
    
    def _get_custom_base_url(self) -> str:
        """Get custom base URL for providers"""
        base_urls = {
            "hugging face": "https://api-inference.huggingface.co/models",
            "mistral": "https://api.mistral.ai/v1",
            "llama": "https://api.llama.ai/v1"
        }
        return base_urls.get(self.provider, "https://api.openai.com/v1")
    
    async def generate_response(self, prompt: str, max_tokens: int = 4000, temperature: float = 0.1) -> Dict[str, Any]:
        """Generate response from the LLM"""
        try:
            if self.provider == "openai":
                return await self._openai_generate(prompt, max_tokens, temperature)
            elif self.provider == "anthropic":
                return await self._anthropic_generate(prompt, max_tokens, temperature)
            elif self.provider == "google":
                return await self._google_generate(prompt, max_tokens, temperature)
            elif self.provider == "groq":
                return await self._groq_generate(prompt, max_tokens, temperature)
            elif self.provider == "cohere":
                return await self._cohere_generate(prompt, max_tokens, temperature)
            elif self.provider in ["hugging face", "mistral", "llama", "local"]:
                return await self._openai_compatible_generate(prompt, max_tokens, temperature)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
                
        except Exception as e:
            logger.error(f"Error generating response with {self.provider}: {e}")
            return {
                "success": False,
                "error": str(e),
                "provider": self.provider,
                "model": self.model
            }
    
    async def _openai_generate(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Generate response using OpenAI API"""
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            return {
                "success": True,
                "content": response.choices[0].message.content,
                "usage": response.usage.dict() if response.usage else {},
                "provider": self.provider,
                "model": self.model,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise Exception(f"OpenAI API error: {e}")
    
    async def _anthropic_generate(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Generate response using Anthropic API"""
        try:
            response = await asyncio.to_thread(
                self.client.messages.create,
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return {
                "success": True,
                "content": response.content[0].text,
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens
                },
                "provider": self.provider,
                "model": self.model,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise Exception(f"Anthropic API error: {e}")
    
    async def _google_generate(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Generate response using Google Gemini API"""
        try:
            generation_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature
            )
            
            response = await asyncio.to_thread(
                self.client.generate_content,
                prompt,
                generation_config=generation_config
            )
            
            return {
                "success": True,
                "content": response.text,
                "usage": {
                    "input_tokens": len(prompt.split()),
                    "output_tokens": len(response.text.split()) if response.text else 0
                },
                "provider": self.provider,
                "model": self.model,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise Exception(f"Google API error: {e}")
    
    async def _groq_generate(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Generate response using Groq API"""
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            return {
                "success": True,
                "content": response.choices[0].message.content,
                "usage": response.usage.dict() if response.usage else {},
                "provider": self.provider,
                "model": self.model,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise Exception(f"Groq API error: {e}")
    
    async def _cohere_generate(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Generate response using Cohere API"""
        try:
            response = await asyncio.to_thread(
                self.client.generate,
                model=self.model,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            return {
                "success": True,
                "content": response.generations[0].text,
                "usage": {
                    "input_tokens": len(prompt.split()),
                    "output_tokens": len(response.generations[0].text.split())
                },
                "provider": self.provider,
                "model": self.model,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise Exception(f"Cohere API error: {e}")
    
    async def _openai_compatible_generate(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Generate response using OpenAI-compatible API"""
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            return {
                "success": True,
                "content": response.choices[0].message.content,
                "usage": response.usage.dict() if response.usage else {},
                "provider": self.provider,
                "model": self.model,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise Exception(f"OpenAI-compatible API error: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            "provider": self.provider,
            "model": self.model,
            "api_key_configured": self.api_key is not None,
            "client_initialized": self.client is not None
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection to the LLM service"""
        try:
            # Simple test prompt
            test_prompt = "Hello, this is a test. Please respond with 'Connection successful.'"
            
            # Run synchronous test
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    self.generate_response(test_prompt, max_tokens=50, temperature=0.1)
                )
                return {
                    "success": result.get("success", False),
                    "message": "Connection test completed",
                    "response": result.get("content", ""),
                    "provider": self.provider,
                    "model": self.model
                }
            finally:
                loop.close()
                
        except Exception as e:
            return {
                "success": False,
                "message": f"Connection test failed: {str(e)}",
                "provider": self.provider,
                "model": self.model
            }

def create_llm_client(provider: str, model: str, api_key: Optional[str] = None) -> UniversalLLMClient:
    """Factory function to create LLM client"""
    return UniversalLLMClient(provider, model, api_key)

def get_supported_providers() -> List[str]:
    """Get list of supported LLM providers"""
    return [
        "OpenAI", "Anthropic", "Google", "Groq", "Cohere",
        "Hugging Face", "Mistral", "Llama", "Local"
    ]

def get_provider_models(provider: str) -> List[str]:
    """Get available models for a provider"""
    model_map = {
        "OpenAI": [
            "gpt-5", "gpt-5-pro", "gpt-5-mini",
            "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4",
            "o3-pro", "o3", "o3-mini", "o4-mini",
            "gpt-3.5-turbo", "codex"
        ],
        "Anthropic": [
            "claude-3.5-sonnet", "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
            "claude-2.1", "claude-2.0", "claude-instant"
        ],
        "Google": [
            "gemini-2.5-pro-diamond", "gemini-2.5-pro", "gemini-2.5-flash-spark", 
            "gemini-2.5-flash", "gemini-2.5-flash-lite",
            "gemini-2.0-pro", "gemini-2.0-flash", "gemini-2.0-flash-lite",
            "gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.5-flash-lite",
            "gemini-1.0-ultra", "gemini-1.0-pro", "gemini-1.0-nano",
            "gemini-nano-banana", "gemini-veo-3", "gemini-robotics", "gemini-robotics-er"
        ],
        "Groq": [
            "llama-3.1-8b", "llama-3.3-70b", "llama-guard-4-12b",
            "gpt-oss-20b", "gpt-oss-120b", "whisper-large-v3", "whisper-large-v3-turbo",
            "compound", "compound-mini",
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
    return model_map.get(provider, [])
