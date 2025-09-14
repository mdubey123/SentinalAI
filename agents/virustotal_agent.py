"""
VirusTotal Integration Agent for SentinelAI v2
Handles VirusTotal API interactions with intelligent quota management and caching
"""

import asyncio
import aiohttp
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import logging

from agents.base_agent import BaseAgent
from utils.logger import security_audit

class VirusTotalAgent(BaseAgent):
    """Agent for VirusTotal API integration with quota management"""
    
    def __init__(self):
        super().__init__("virustotal")
        
        # API configuration
        self.api_base_url = "https://www.virustotal.com/vtapi/v2"
        self.api_v3_base_url = "https://www.virustotal.com/api/v3"
        self.api_key = None
        self.is_premium = False
        
        # Rate limiting
        self.public_rate_limit = 4  # requests per minute for public API
        self.premium_rate_limit = 1000  # requests per minute for premium API
        self.request_timestamps = []
        
        # Quota tracking
        self.daily_quota_used = 0
        self.daily_quota_limit = 500  # Default for public API
        self.quota_reset_time = None
        
        # File size limits
        self.max_file_size_public = 32 * 1024 * 1024  # 32MB for public API
        self.max_file_size_premium = 650 * 1024 * 1024  # 650MB for premium API
        
        # Initialize API key
        self._load_api_key()
    
    def _load_api_key(self):
        """Load VirusTotal API key from secure storage"""
        try:
            self.api_key = self.security_manager.get_decrypted_key("virustotal")
            
            if self.api_key:
                # Detect if premium key (premium keys are longer and have different format)
                self.is_premium = len(self.api_key) > 64 or self.api_key.startswith("vt-")
                
                if self.is_premium:
                    self.daily_quota_limit = 15000  # Premium quota
                    self.logger.info("VirusTotal Premium API key detected")
                else:
                    self.logger.info("VirusTotal Public API key detected")
            else:
                self.logger.warning("No VirusTotal API key found - using fallback mode")
                
        except Exception as e:
            self.logger.error(f"Error loading VirusTotal API key: {e}")
    
    async def execute(self, hashes: List[str], files_to_upload: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute VirusTotal analysis"""
        self.start_operation("virustotal_analysis")
        
        try:
            if not self.api_key:
                return self._fallback_response("No API key available")
            
            results = {
                'hash_results': {},
                'upload_results': {},
                'quota_info': self._get_quota_info(),
                'api_info': {
                    'is_premium': self.is_premium,
                    'rate_limit': self.premium_rate_limit if self.is_premium else self.public_rate_limit
                },
                'errors': []
            }
            
            # Process hash lookups first (more efficient)
            if hashes:
                hash_results = await self._analyze_hashes(hashes)
                results['hash_results'] = hash_results
            
            # Process file uploads for unknown hashes
            if files_to_upload:
                upload_results = await self._upload_files(files_to_upload)
                results['upload_results'] = upload_results
            
            # Update quota tracking
            self._update_quota_usage(len(hashes) + len(files_to_upload or []))
            
            self.end_operation("virustotal_analysis", True, results)
            return results
            
        except Exception as e:
            error_result = self.handle_error(e, "virustotal_analysis")
            self.end_operation("virustotal_analysis", False, error_result)
            return error_result
    
    async def _analyze_hashes(self, hashes: List[str]) -> Dict[str, Any]:
        """Analyze file hashes using VirusTotal API"""
        results = {}
        
        # Check cache first
        cached_results = {}
        uncached_hashes = []
        
        for file_hash in hashes:
            cached_result = self.get_cached_results(f"hash_{file_hash}")
            if cached_result:
                cached_results[file_hash] = cached_result
                self.logger.debug(f"Using cached result for hash: {file_hash[:8]}...")
            else:
                uncached_hashes.append(file_hash)
        
        results.update(cached_results)
        
        if not uncached_hashes:
            return results
        
        # Check rate limits and quota
        if not self._can_make_requests(len(uncached_hashes)):
            self.logger.warning("Rate limit or quota exceeded - using cached results only")
            return results
        
        # Process uncached hashes
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
            
            tasks = [
                self._analyze_single_hash(session, semaphore, file_hash)
                for file_hash in uncached_hashes
            ]
            
            hash_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for file_hash, result in zip(uncached_hashes, hash_results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error analyzing hash {file_hash}: {result}")
                    results[file_hash] = {'error': str(result)}
                else:
                    results[file_hash] = result
                    
                    # Cache successful results
                    if 'error' not in result:
                        self.cache_results(f"hash_{file_hash}", result, ttl_hours=24)
        
        return results
    
    async def _analyze_single_hash(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, file_hash: str) -> Dict[str, Any]:
        """Analyze a single file hash"""
        async with semaphore:
            # Rate limiting
            await self._wait_for_rate_limit()
            
            try:
                # Use v3 API for better results
                url = f"{self.api_v3_base_url}/files/{file_hash}"
                headers = {
                    'x-apikey': self.api_key,
                    'User-Agent': 'SentinelAI-v2'
                }
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_file_report(data)
                    
                    elif response.status == 404:
                        return {
                            'hash': file_hash,
                            'found': False,
                            'message': 'File not found in VirusTotal database'
                        }
                    
                    elif response.status == 429:
                        # Rate limit exceeded
                        self.logger.warning("VirusTotal rate limit exceeded")
                        raise Exception("Rate limit exceeded")
                    
                    elif response.status == 403:
                        # Quota exceeded or invalid API key
                        error_data = await response.json()
                        error_msg = error_data.get('error', {}).get('message', 'API access denied')
                        self.logger.error(f"VirusTotal API error: {error_msg}")
                        raise Exception(f"API error: {error_msg}")
                    
                    else:
                        error_text = await response.text()
                        raise Exception(f"API request failed: {response.status} - {error_text}")
                        
            except asyncio.TimeoutError:
                raise Exception("Request timeout")
            except Exception as e:
                self.logger.error(f"Error in hash analysis: {e}")
                raise
    
    async def _upload_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """Upload files to VirusTotal for analysis"""
        results = {}
        
        if not self._can_make_requests(len(file_paths)):
            self.logger.warning("Cannot upload files - quota or rate limit exceeded")
            return results
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(2)  # Limit concurrent uploads
            
            tasks = [
                self._upload_single_file(session, semaphore, file_path)
                for file_path in file_paths
            ]
            
            upload_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for file_path, result in zip(file_paths, upload_results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error uploading {file_path}: {result}")
                    results[file_path] = {'error': str(result)}
                else:
                    results[file_path] = result
        
        return results
    
    async def _upload_single_file(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, file_path: str) -> Dict[str, Any]:
        """Upload a single file to VirusTotal"""
        async with semaphore:
            try:
                # Check file size
                file_size = Path(file_path).stat().st_size
                max_size = self.max_file_size_premium if self.is_premium else self.max_file_size_public
                
                if file_size > max_size:
                    return {
                        'file_path': file_path,
                        'error': f'File too large: {file_size} bytes (max: {max_size} bytes)'
                    }
                
                # Rate limiting
                await self._wait_for_rate_limit()
                
                # Get upload URL
                upload_url = await self._get_upload_url(session)
                
                if not upload_url:
                    raise Exception("Failed to get upload URL")
                
                # Upload file
                with open(file_path, 'rb') as f:
                    data = aiohttp.FormData()
                    data.add_field('file', f, filename=Path(file_path).name)
                    
                    async with session.post(upload_url, data=data) as response:
                        if response.status == 200:
                            result = await response.json()
                            
                            # Wait for analysis to complete
                            analysis_id = result.get('data', {}).get('id')
                            if analysis_id:
                                analysis_result = await self._wait_for_analysis(session, analysis_id)
                                return {
                                    'file_path': file_path,
                                    'upload_successful': True,
                                    'analysis_id': analysis_id,
                                    'analysis_result': analysis_result
                                }
                            else:
                                return {
                                    'file_path': file_path,
                                    'upload_successful': True,
                                    'message': 'File uploaded, analysis pending'
                                }
                        else:
                            error_text = await response.text()
                            raise Exception(f"Upload failed: {response.status} - {error_text}")
                            
            except Exception as e:
                self.logger.error(f"Error uploading file {file_path}: {e}")
                return {
                    'file_path': file_path,
                    'error': str(e)
                }
    
    async def _get_upload_url(self, session: aiohttp.ClientSession) -> Optional[str]:
        """Get upload URL from VirusTotal"""
        try:
            url = f"{self.api_v3_base_url}/files/upload_url"
            headers = {
                'x-apikey': self.api_key,
                'User-Agent': 'SentinelAI-v2'
            }
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data')
                else:
                    self.logger.error(f"Failed to get upload URL: {response.status}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"Error getting upload URL: {e}")
            return None
    
    async def _wait_for_analysis(self, session: aiohttp.ClientSession, analysis_id: str, max_wait: int = 300) -> Optional[Dict[str, Any]]:
        """Wait for file analysis to complete"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                await asyncio.sleep(10)  # Wait 10 seconds between checks
                
                url = f"{self.api_v3_base_url}/analyses/{analysis_id}"
                headers = {
                    'x-apikey': self.api_key,
                    'User-Agent': 'SentinelAI-v2'
                }
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        status = data.get('data', {}).get('attributes', {}).get('status')
                        
                        if status == 'completed':
                            return self._parse_analysis_report(data)
                        elif status in ['queued', 'running']:
                            continue  # Keep waiting
                        else:
                            self.logger.warning(f"Analysis failed with status: {status}")
                            return None
                    else:
                        self.logger.error(f"Error checking analysis status: {response.status}")
                        return None
                        
            except Exception as e:
                self.logger.error(f"Error waiting for analysis: {e}")
                return None
        
        self.logger.warning(f"Analysis timeout for {analysis_id}")
        return None
    
    def _parse_file_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal file report"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            # Basic file info
            result = {
                'hash': data.get('data', {}).get('id', ''),
                'found': True,
                'scan_date': attributes.get('last_analysis_date'),
                'total_engines': 0,
                'positive_detections': 0,
                'detection_ratio': '0/0',
                'detections': {},
                'file_info': {
                    'size': attributes.get('size'),
                    'type': attributes.get('type_description'),
                    'md5': attributes.get('md5'),
                    'sha1': attributes.get('sha1'),
                    'sha256': attributes.get('sha256'),
                    'ssdeep': attributes.get('ssdeep'),
                    'tlsh': attributes.get('tlsh'),
                    'names': attributes.get('names', [])
                },
                'reputation': self._calculate_reputation(attributes)
            }
            
            # Parse scan results
            last_analysis_results = attributes.get('last_analysis_results', {})
            
            if last_analysis_results:
                total_engines = len(last_analysis_results)
                positive_detections = 0
                detections = {}
                
                for engine, engine_result in last_analysis_results.items():
                    category = engine_result.get('category', 'undetected')
                    
                    if category in ['malicious', 'suspicious']:
                        positive_detections += 1
                        detections[engine] = {
                            'result': engine_result.get('result', 'Malware'),
                            'category': category,
                            'engine_version': engine_result.get('engine_version'),
                            'engine_update': engine_result.get('engine_update')
                        }
                
                result.update({
                    'total_engines': total_engines,
                    'positive_detections': positive_detections,
                    'detection_ratio': f"{positive_detections}/{total_engines}",
                    'detections': detections
                })
            
            # Add threat classification
            result['threat_classification'] = self._classify_threat(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing file report: {e}")
            return {'error': f'Failed to parse report: {str(e)}'}
    
    def _parse_analysis_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal analysis report"""
        # Similar to _parse_file_report but for analysis results
        return self._parse_file_report(data)
    
    def _calculate_reputation(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate file reputation score"""
        reputation_score = 0
        reputation_factors = []
        
        # Community votes
        votes = attributes.get('total_votes', {})
        harmless_votes = votes.get('harmless', 0)
        malicious_votes = votes.get('malicious', 0)
        
        if malicious_votes > harmless_votes:
            reputation_score -= 20
            reputation_factors.append("Community flagged as malicious")
        elif harmless_votes > malicious_votes:
            reputation_score += 10
            reputation_factors.append("Community flagged as harmless")
        
        # Crowdsourced IDS rules
        crowdsourced_ids = attributes.get('crowdsourced_ids_results', [])
        if crowdsourced_ids:
            reputation_score -= 15
            reputation_factors.append("Triggered IDS rules")
        
        # Sandbox behavior
        sandbox_verdicts = attributes.get('sandbox_verdicts', {})
        for sandbox, verdict in sandbox_verdicts.items():
            if verdict.get('category') == 'malicious':
                reputation_score -= 25
                reputation_factors.append(f"Malicious behavior in {sandbox}")
        
        # Normalize score to 0-100 range
        reputation_score = max(0, min(100, 50 + reputation_score))
        
        return {
            'score': reputation_score,
            'factors': reputation_factors,
            'classification': 'suspicious' if reputation_score < 30 else 'neutral' if reputation_score < 70 else 'trusted'
        }
    
    def _classify_threat(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Classify threat based on VirusTotal results"""
        positive_detections = report.get('positive_detections', 0)
        total_engines = report.get('total_engines', 1)
        detection_ratio = positive_detections / total_engines if total_engines > 0 else 0
        
        # Determine severity
        if detection_ratio >= 0.7:
            severity = 'critical'
        elif detection_ratio >= 0.4:
            severity = 'high'
        elif detection_ratio >= 0.2:
            severity = 'medium'
        elif detection_ratio > 0:
            severity = 'low'
        else:
            severity = 'clean'
        
        # Analyze detection names for threat type
        threat_types = set()
        detections = report.get('detections', {})
        
        for engine, detection in detections.items():
            result = detection.get('result', '').lower()
            
            if any(keyword in result for keyword in ['trojan', 'backdoor']):
                threat_types.add('trojan')
            elif any(keyword in result for keyword in ['virus', 'worm']):
                threat_types.add('virus')
            elif any(keyword in result for keyword in ['ransomware', 'crypto', 'locker']):
                threat_types.add('ransomware')
            elif any(keyword in result for keyword in ['adware', 'pup']):
                threat_types.add('adware')
            elif any(keyword in result for keyword in ['spyware', 'keylog']):
                threat_types.add('spyware')
            elif any(keyword in result for keyword in ['rootkit']):
                threat_types.add('rootkit')
            else:
                threat_types.add('malware')
        
        return {
            'severity': severity,
            'confidence': min(95, int(detection_ratio * 100 + 50)),
            'threat_types': list(threat_types),
            'detection_ratio': detection_ratio,
            'is_malicious': positive_detections > 0
        }
    
    async def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits"""
        current_time = time.time()
        
        # Clean old timestamps (older than 1 minute)
        self.request_timestamps = [
            ts for ts in self.request_timestamps 
            if current_time - ts < 60
        ]
        
        # Check if we need to wait
        rate_limit = self.premium_rate_limit if self.is_premium else self.public_rate_limit
        
        if len(self.request_timestamps) >= rate_limit:
            # Wait until the oldest request is more than 1 minute old
            oldest_request = min(self.request_timestamps)
            wait_time = 60 - (current_time - oldest_request)
            
            if wait_time > 0:
                self.logger.info(f"Rate limiting: waiting {wait_time:.1f} seconds")
                await asyncio.sleep(wait_time)
        
        # Record this request
        self.request_timestamps.append(current_time)
    
    def _can_make_requests(self, num_requests: int) -> bool:
        """Check if we can make the requested number of API calls"""
        # Check daily quota
        if self.daily_quota_used + num_requests > self.daily_quota_limit:
            self.logger.warning(f"Daily quota would be exceeded: {self.daily_quota_used + num_requests}/{self.daily_quota_limit}")
            return False
        
        return True
    
    def _update_quota_usage(self, requests_made: int):
        """Update quota usage tracking"""
        self.daily_quota_used += requests_made
        
        # Reset quota if it's a new day
        now = datetime.now()
        if self.quota_reset_time is None or now.date() > self.quota_reset_time.date():
            self.daily_quota_used = requests_made
            self.quota_reset_time = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    
    def _get_quota_info(self) -> Dict[str, Any]:
        """Get current quota information"""
        return {
            'daily_used': self.daily_quota_used,
            'daily_limit': self.daily_quota_limit,
            'remaining': max(0, self.daily_quota_limit - self.daily_quota_used),
            'reset_time': self.quota_reset_time.isoformat() if self.quota_reset_time else None,
            'is_premium': self.is_premium
        }
    
    def _fallback_response(self, reason: str) -> Dict[str, Any]:
        """Generate fallback response when VirusTotal is unavailable"""
        return {
            'hash_results': {},
            'upload_results': {},
            'quota_info': self._get_quota_info(),
            'api_info': {
                'is_premium': self.is_premium,
                'available': False,
                'reason': reason
            },
            'errors': [f"VirusTotal unavailable: {reason}"]
        }
    
    def analyze_hashes(self, hashes: List[str]) -> Dict[str, Any]:
        """Synchronous wrapper for hash analysis"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            return loop.run_until_complete(self.execute(hashes))
        finally:
            loop.close()
    
    def upload_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """Synchronous wrapper for file uploads"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            return loop.run_until_complete(self.execute([], file_paths))
        finally:
            loop.close()
    
    def get_api_status(self) -> Dict[str, Any]:
        """Get current API status and configuration"""
        return {
            'api_key_configured': self.api_key is not None,
            'is_premium': self.is_premium,
            'quota_info': self._get_quota_info(),
            'rate_limit_info': {
                'requests_per_minute': self.premium_rate_limit if self.is_premium else self.public_rate_limit,
                'recent_requests': len(self.request_timestamps)
            },
            'file_size_limits': {
                'current_limit': self.max_file_size_premium if self.is_premium else self.max_file_size_public,
                'premium_limit': self.max_file_size_premium,
                'public_limit': self.max_file_size_public
            }
        }
    
    def reset_quota(self):
        """Reset daily quota (for testing or manual reset)"""
        self.daily_quota_used = 0
        self.quota_reset_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        self.logger.info("VirusTotal quota reset")
    
    def set_api_key(self, api_key: str) -> bool:
        """Set new API key"""
        try:
            # Validate API key format
            if not self.security_manager.validate_api_key(api_key, "virustotal"):
                return False
            
            # Store encrypted
            success = self.security_manager.store_encrypted_key("virustotal", api_key)
            
            if success:
                self.api_key = api_key
                self.is_premium = len(api_key) > 64 or api_key.startswith("vt-")
                
                if self.is_premium:
                    self.daily_quota_limit = 15000
                else:
                    self.daily_quota_limit = 500
                
                self.logger.info("VirusTotal API key updated")
                
                security_audit.log_api_access(
                    "virustotal", 
                    "api_key_updated", 
                    True, 
                    {"is_premium": self.is_premium}
                )
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error setting API key: {e}")
            return False
