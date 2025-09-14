"""
Gamification Engine for SentinelAI v2
Handles user profiles, scoring, badges, achievements, and progression
"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta
import math

logger = logging.getLogger(__name__)

class GamificationEngine:
    """Manages gamification features including scoring, badges, and achievements"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".sentinelai" / "profiles"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.profile_file = self.config_dir / "user_profile.json"
        self.leaderboard_file = self.config_dir / "leaderboard.json"
        
        # Achievement definitions
        self.achievements = self._define_achievements()
        self.badge_definitions = self._define_badges()
    
    def _define_achievements(self) -> Dict[str, Dict[str, Any]]:
        """Define available achievements"""
        return {
            "first_scan": {
                "name": "First Steps",
                "description": "Complete your first security scan",
                "icon": "🎯",
                "points": 50,
                "condition": lambda profile: profile.get('scans_completed', 0) >= 1
            },
            "threat_hunter": {
                "name": "Threat Hunter",
                "description": "Detect your first malware threat",
                "icon": "🕵️",
                "points": 100,
                "condition": lambda profile: profile.get('threats_detected', 0) >= 1
            },
            "clean_sweep": {
                "name": "Clean Sweep",
                "description": "Complete 5 scans with no threats found",
                "icon": "✨",
                "points": 75,
                "condition": lambda profile: profile.get('clean_scans', 0) >= 5
            },
            "security_expert": {
                "name": "Security Expert",
                "description": "Reach security score of 90+",
                "icon": "🛡️",
                "points": 200,
                "condition": lambda profile: profile.get('highest_security_score', 0) >= 90
            },
            "vapt_specialist": {
                "name": "VAPT Specialist",
                "description": "Complete 10 vulnerability assessments",
                "icon": "🎯",
                "points": 150,
                "condition": lambda profile: profile.get('vapt_scans_completed', 0) >= 10
            },
            "persistent_guardian": {
                "name": "Persistent Guardian",
                "description": "Scan for 7 consecutive days",
                "icon": "🔥",
                "points": 300,
                "condition": self._check_consecutive_days
            },
            "threat_eliminator": {
                "name": "Threat Eliminator",
                "description": "Detect 50+ threats across all scans",
                "icon": "⚔️",
                "points": 500,
                "condition": lambda profile: profile.get('total_threats_detected', 0) >= 50
            },
            "security_master": {
                "name": "Security Master",
                "description": "Reach level 10",
                "icon": "👑",
                "points": 1000,
                "condition": lambda profile: profile.get('level', 1) >= 10
            }
        }
    
    def _define_badges(self) -> Dict[str, Dict[str, Any]]:
        """Define available badges"""
        return {
            "bronze_scanner": {
                "name": "Bronze Scanner",
                "description": "Complete 10 scans",
                "color": "#CD7F32",
                "icon": "🥉",
                "requirement": lambda profile: profile.get('scans_completed', 0) >= 10
            },
            "silver_scanner": {
                "name": "Silver Scanner",
                "description": "Complete 50 scans",
                "color": "#C0C0C0",
                "icon": "🥈",
                "requirement": lambda profile: profile.get('scans_completed', 0) >= 50
            },
            "gold_scanner": {
                "name": "Gold Scanner",
                "description": "Complete 100 scans",
                "color": "#FFD700",
                "icon": "🥇",
                "requirement": lambda profile: profile.get('scans_completed', 0) >= 100
            },
            "threat_detector": {
                "name": "Threat Detector",
                "description": "Detect 25+ threats",
                "color": "#FF4500",
                "icon": "🔍",
                "requirement": lambda profile: profile.get('total_threats_detected', 0) >= 25
            },
            "security_analyst": {
                "name": "Security Analyst",
                "description": "Maintain 80+ average security score",
                "color": "#4169E1",
                "icon": "📊",
                "requirement": lambda profile: profile.get('average_security_score', 0) >= 80
            },
            "vapt_expert": {
                "name": "VAPT Expert",
                "description": "Complete 25 VAPT assessments",
                "color": "#8A2BE2",
                "icon": "🎯",
                "requirement": lambda profile: profile.get('vapt_scans_completed', 0) >= 25
            }
        }
    
    def create_new_profile(self) -> Dict[str, Any]:
        """Create a new user profile"""
        profile = {
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "username": "SecurityAnalyst",
            "level": 1,
            "experience_points": 0,
            "security_score": 0,
            "highest_security_score": 0,
            "average_security_score": 0,
            "scans_completed": 0,
            "threats_detected": 0,
            "total_threats_detected": 0,
            "clean_scans": 0,
            "vapt_scans_completed": 0,
            "vulnerabilities_found": 0,
            "scan_history": [],
            "achievements": [],
            "badges": [],
            "daily_streak": 0,
            "longest_streak": 0,
            "last_scan_date": None,
            "statistics": {
                "total_files_scanned": 0,
                "total_scan_time_minutes": 0,
                "malware_types_detected": {},
                "severity_distribution": {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0
                }
            }
        }
        
        self.save_profile(profile)
        return profile
    
    def load_profile(self) -> Dict[str, Any]:
        """Load user profile from file"""
        if not self.profile_file.exists():
            return self.create_new_profile()
        
        try:
            with open(self.profile_file, 'r') as f:
                profile = json.load(f)
                
            # Ensure all required fields exist
            default_profile = self.create_new_profile()
            for key, value in default_profile.items():
                if key not in profile:
                    profile[key] = value
            
            return profile
            
        except Exception as e:
            logger.error(f"Error loading profile: {e}")
            return self.create_new_profile()
    
    def save_profile(self, profile: Dict[str, Any]):
        """Save user profile to file"""
        try:
            profile["last_updated"] = datetime.now().isoformat()
            
            with open(self.profile_file, 'w') as f:
                json.dump(profile, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving profile: {e}")
    
    def update_profile_after_scan(self, profile: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Update profile after completing a scan"""
        # Basic scan statistics
        profile['scans_completed'] += 1
        profile['last_scan_date'] = datetime.now().isoformat()
        
        # Security score
        new_score = scan_results.get('security_score', 0)
        profile['security_score'] = new_score
        
        if new_score > profile['highest_security_score']:
            profile['highest_security_score'] = new_score
        
        # Calculate average security score
        scan_history = profile.get('scan_history', [])
        if scan_history:
            total_score = sum(scan.get('security_score', 0) for scan in scan_history)
            profile['average_security_score'] = total_score / len(scan_history)
        
        # Threat detection
        threats = scan_results.get('ai_analysis', {}).get('threats', [])
        threats_found = len(threats)
        
        if threats_found > 0:
            profile['threats_detected'] = threats_found
            profile['total_threats_detected'] += threats_found
            
            # Update malware type statistics
            for threat in threats:
                threat_type = threat.get('type', 'Unknown')
                if threat_type not in profile['statistics']['malware_types_detected']:
                    profile['statistics']['malware_types_detected'][threat_type] = 0
                profile['statistics']['malware_types_detected'][threat_type] += 1
                
                # Update severity distribution
                severity = threat.get('severity', 'Unknown')
                if severity in profile['statistics']['severity_distribution']:
                    profile['statistics']['severity_distribution'][severity] += 1
        else:
            profile['clean_scans'] += 1
        
        # Update daily streak
        self._update_daily_streak(profile)
        
        # Calculate experience points
        points_earned = self._calculate_points_earned(scan_results, threats_found)
        profile['experience_points'] += points_earned
        
        # Update level
        new_level = self._calculate_level(profile['experience_points'])
        if new_level > profile['level']:
            profile['level'] = new_level
        
        # Add to scan history
        scan_record = {
            'date': datetime.now().isoformat(),
            'security_score': new_score,
            'threats_found': threats_found,
            'scan_type': scan_results.get('metadata', {}).get('scan_type', 'unknown'),
            'points_earned': points_earned
        }
        profile['scan_history'].append(scan_record)
        
        # Keep only last 100 scan records
        if len(profile['scan_history']) > 100:
            profile['scan_history'] = profile['scan_history'][-100:]
        
        # Check for new achievements and badges
        self._check_achievements(profile)
        self._check_badges(profile)
        
        # Save updated profile
        self.save_profile(profile)
        
        return profile
    
    def _update_daily_streak(self, profile: Dict[str, Any]):
        """Update daily streak counter"""
        today = datetime.now().date()
        last_scan_date = profile.get('last_scan_date')
        
        if last_scan_date:
            last_date = datetime.fromisoformat(last_scan_date).date()
            days_diff = (today - last_date).days
            
            if days_diff == 1:
                # Consecutive day
                profile['daily_streak'] += 1
            elif days_diff > 1:
                # Streak broken
                profile['daily_streak'] = 1
            # Same day scan doesn't change streak
        else:
            # First scan
            profile['daily_streak'] = 1
        
        # Update longest streak
        if profile['daily_streak'] > profile['longest_streak']:
            profile['longest_streak'] = profile['daily_streak']
    
    def _calculate_points_earned(self, scan_results: Dict[str, Any], threats_found: int) -> int:
        """Calculate experience points earned from a scan"""
        base_points = 10  # Base points for completing a scan
        
        # Bonus for threat detection
        threat_bonus = threats_found * 25
        
        # Bonus for high security score
        security_score = scan_results.get('security_score', 0)
        if security_score >= 90:
            score_bonus = 50
        elif security_score >= 75:
            score_bonus = 25
        elif security_score >= 50:
            score_bonus = 10
        else:
            score_bonus = 0
        
        # Bonus for VAPT scans
        vapt_bonus = 15 if scan_results.get('vapt_results') else 0
        
        # Bonus for clean scans (no threats)
        clean_bonus = 5 if threats_found == 0 else 0
        
        total_points = base_points + threat_bonus + score_bonus + vapt_bonus + clean_bonus
        
        return total_points
    
    def _calculate_level(self, experience_points: int) -> int:
        """Calculate user level based on experience points"""
        # Level thresholds: exponential growth
        level_thresholds = [0, 100, 250, 500, 1000, 2000, 3500, 5500, 8000, 12000, 17500]
        
        for level, threshold in enumerate(level_thresholds, 1):
            if experience_points < threshold:
                return level - 1
        
        # For very high XP, use formula
        return len(level_thresholds) + int(math.log2(experience_points / level_thresholds[-1]))
    
    def _check_achievements(self, profile: Dict[str, Any]):
        """Check and award new achievements"""
        current_achievements = set(profile.get('achievements', []))
        
        for achievement_id, achievement in self.achievements.items():
            if achievement_id not in current_achievements:
                if achievement['condition'](profile):
                    profile['achievements'].append(achievement_id)
                    profile['experience_points'] += achievement['points']
                    logger.info(f"Achievement unlocked: {achievement['name']}")
    
    def _check_badges(self, profile: Dict[str, Any]):
        """Check and award new badges"""
        current_badges = set(profile.get('badges', []))
        
        for badge_id, badge in self.badge_definitions.items():
            if badge_id not in current_badges:
                if badge['requirement'](profile):
                    profile['badges'].append(badge_id)
                    logger.info(f"Badge earned: {badge['name']}")
    
    def _check_consecutive_days(self, profile: Dict[str, Any]) -> bool:
        """Check if user has scanned for 7 consecutive days"""
        return profile.get('daily_streak', 0) >= 7
    
    def get_achievement_progress(self, profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Get progress towards achievements"""
        progress = {}
        
        for achievement_id, achievement in self.achievements.items():
            is_unlocked = achievement_id in profile.get('achievements', [])
            
            # Calculate progress percentage (simplified)
            if achievement_id == "first_scan":
                progress_pct = min(100, (profile.get('scans_completed', 0) / 1) * 100)
            elif achievement_id == "threat_hunter":
                progress_pct = min(100, (profile.get('threats_detected', 0) / 1) * 100)
            elif achievement_id == "clean_sweep":
                progress_pct = min(100, (profile.get('clean_scans', 0) / 5) * 100)
            elif achievement_id == "security_expert":
                progress_pct = min(100, (profile.get('highest_security_score', 0) / 90) * 100)
            elif achievement_id == "vapt_specialist":
                progress_pct = min(100, (profile.get('vapt_scans_completed', 0) / 10) * 100)
            elif achievement_id == "persistent_guardian":
                progress_pct = min(100, (profile.get('daily_streak', 0) / 7) * 100)
            elif achievement_id == "threat_eliminator":
                progress_pct = min(100, (profile.get('total_threats_detected', 0) / 50) * 100)
            elif achievement_id == "security_master":
                progress_pct = min(100, (profile.get('level', 1) / 10) * 100)
            else:
                progress_pct = 100 if is_unlocked else 0
            
            progress[achievement_id] = {
                'name': achievement['name'],
                'description': achievement['description'],
                'icon': achievement['icon'],
                'points': achievement['points'],
                'unlocked': is_unlocked,
                'progress_percentage': progress_pct
            }
        
        return progress
    
    def get_leaderboard(self) -> List[Dict[str, Any]]:
        """Get local leaderboard data"""
        try:
            if not self.leaderboard_file.exists():
                return []
            
            with open(self.leaderboard_file, 'r') as f:
                leaderboard = json.load(f)
                
            # Sort by experience points
            return sorted(leaderboard, key=lambda x: x.get('experience_points', 0), reverse=True)
            
        except Exception as e:
            logger.error(f"Error loading leaderboard: {e}")
            return []
    
    def update_leaderboard(self, profile: Dict[str, Any]):
        """Update leaderboard with current profile"""
        try:
            leaderboard = self.get_leaderboard()
            
            # Create leaderboard entry
            entry = {
                'username': profile.get('username', 'Anonymous'),
                'level': profile.get('level', 1),
                'experience_points': profile.get('experience_points', 0),
                'security_score': profile.get('security_score', 0),
                'scans_completed': profile.get('scans_completed', 0),
                'last_updated': datetime.now().isoformat()
            }
            
            # Update or add entry
            updated = False
            for i, existing in enumerate(leaderboard):
                if existing.get('username') == entry['username']:
                    leaderboard[i] = entry
                    updated = True
                    break
            
            if not updated:
                leaderboard.append(entry)
            
            # Keep top 100 entries
            leaderboard = sorted(leaderboard, key=lambda x: x.get('experience_points', 0), reverse=True)[:100]
            
            # Save leaderboard
            with open(self.leaderboard_file, 'w') as f:
                json.dump(leaderboard, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error updating leaderboard: {e}")
    
    def get_next_level_progress(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        """Get progress towards next level"""
        current_level = profile.get('level', 1)
        current_xp = profile.get('experience_points', 0)
        
        # Calculate XP needed for next level
        level_thresholds = [0, 100, 250, 500, 1000, 2000, 3500, 5500, 8000, 12000, 17500]
        
        if current_level < len(level_thresholds):
            next_level_xp = level_thresholds[current_level]
            current_level_xp = level_thresholds[current_level - 1] if current_level > 1 else 0
        else:
            # For high levels, use exponential formula
            base_xp = level_thresholds[-1]
            multiplier = 2 ** (current_level - len(level_thresholds))
            next_level_xp = base_xp * multiplier
            current_level_xp = base_xp * (multiplier // 2)
        
        progress_xp = current_xp - current_level_xp
        needed_xp = next_level_xp - current_level_xp
        progress_percentage = (progress_xp / needed_xp) * 100 if needed_xp > 0 else 100
        
        return {
            'current_level': current_level,
            'next_level': current_level + 1,
            'current_xp': current_xp,
            'progress_xp': progress_xp,
            'needed_xp': needed_xp,
            'progress_percentage': min(100, progress_percentage)
        }
    
    def export_profile(self, profile: Dict[str, Any]) -> str:
        """Export profile as JSON string"""
        return json.dumps(profile, indent=2)
    
    def import_profile(self, profile_json: str) -> bool:
        """Import profile from JSON string"""
        try:
            imported_profile = json.loads(profile_json)
            self.save_profile(imported_profile)
            return True
        except Exception as e:
            logger.error(f"Error importing profile: {e}")
            return False
