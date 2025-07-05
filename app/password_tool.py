#!/usr/bin/env python3
"""
Password Security Tool - Core Implementation
A comprehensive password security checker with generation, strength analysis, and breach detection.
"""

import hashlib
import secrets
import string
import re
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import requests
from dataclasses import dataclass

@dataclass
class PasswordStats:
    """Statistics for password analysis"""
    length: int
    has_upper: bool
    has_lower: bool
    has_digits: bool
    has_special: bool
    strength_score: int
    strength_label: str
    is_common: bool
    breach_count: Optional[int] = None

class PasswordSecurityTool:
    """Main password security tool class"""
    
    def __init__(self):
        self.stats_file = "password_stats.json"
        self.common_passwords = self._load_common_passwords()
        self.stats = self._load_stats()
    
    def _load_common_passwords(self) -> set:
        """Load common passwords from built-in list"""
        common = {
            "123456", "password", "123456789", "12345678", "12345", "1234567",
            "1234567890", "qwerty", "abc123", "password123", "admin", "letmein",
            "welcome", "monkey", "password1", "123123", "111111", "dragon",
            "master", "sunshine", "princess", "football", "charlie", "jordan",
            "baseball", "freedom", "lovely", "buster", "trustno1", "shadow"
        }
        return common
    
    def _load_stats(self) -> Dict:
        """Load statistics from file"""
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            "passwords_checked": 0,
            "passwords_generated": 0,
            "breaches_found": 0,
            "last_used": None
        }
    
    def _save_stats(self):
        """Save statistics to file"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except IOError:
            pass
    
    def generate_password(self, length: int = 16, 
                         include_symbols: bool = True,
                         exclude_ambiguous: bool = True) -> str:
        """Generate a secure password"""
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous = "0O1lI|"
            lowercase = lowercase.translate(str.maketrans('', '', ambiguous))
            uppercase = uppercase.translate(str.maketrans('', '', ambiguous))
            digits = digits.translate(str.maketrans('', '', ambiguous))
            symbols = symbols.translate(str.maketrans('', '', ambiguous))
        
        # Build character pool
        chars = lowercase + uppercase + digits
        if include_symbols:
            chars += symbols
        
        # Ensure at least one character from each category
        password = []
        password.append(secrets.choice(lowercase))
        password.append(secrets.choice(uppercase))
        password.append(secrets.choice(digits))
        if include_symbols:
            password.append(secrets.choice(symbols))
        
        # Fill remaining length
        remaining_length = length - len(password)
        for _ in range(remaining_length):
            password.append(secrets.choice(chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        # Update stats
        self.stats["passwords_generated"] += 1
        self.stats["last_used"] = datetime.now().isoformat()
        self._save_stats()
        
        return ''.join(password)
    
    def check_password_strength(self, password: str) -> PasswordStats:
        """Analyze password strength"""
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Basic checks
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        # Check if it's a common password
        is_common = password.lower() in self.common_passwords
        
        # Calculate strength score (0-100)
        score = 0
        
        # Length scoring
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        
        # Character variety scoring
        if has_upper:
            score += 15
        if has_lower:
            score += 15
        if has_digits:
            score += 15
        if has_special:
            score += 15
        
        # Bonus for good length
        if length >= 16:
            score += 10
        
        # Penalty for common passwords
        if is_common:
            score = max(0, score - 50)
        
        # Penalty for patterns
        if self._has_patterns(password):
            score = max(0, score - 20)
        
        # Determine strength label
        if score >= 80:
            strength_label = "Very Strong"
        elif score >= 60:
            strength_label = "Strong"
        elif score >= 40:
            strength_label = "Moderate"
        elif score >= 20:
            strength_label = "Weak"
        else:
            strength_label = "Very Weak"
        
        # Update stats
        self.stats["passwords_checked"] += 1
        self.stats["last_used"] = datetime.now().isoformat()
        self._save_stats()
        
        return PasswordStats(
            length=length,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digits=has_digits,
            has_special=has_special,
            strength_score=score,
            strength_label=strength_label,
            is_common=is_common
        )
    
    def _has_patterns(self, password: str) -> bool:
        """Check for common patterns in password"""
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            return True
        
        # Check for sequential characters
        for i in range(len(password) - 2):
            if (ord(password[i]) == ord(password[i+1]) - 1 == ord(password[i+2]) - 2):
                return True
        
        # Check for keyboard patterns
        keyboard_patterns = ["qwerty", "asdf", "zxcv", "123456", "abcdef"]
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                return True
        
        return False
    
    def check_breach(self, password: str) -> Tuple[bool, Optional[int]]:
        """Check if password has been breached using HaveIBeenPwned API"""
        try:
            # Hash the password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HaveIBeenPwned API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                hashes = response.text.split('\n')
                for hash_line in hashes:
                    if ':' in hash_line:
                        hash_suffix, count = hash_line.split(':', 1)
                        if hash_suffix.strip() == suffix:
                            breach_count = int(count.strip())
                            self.stats["breaches_found"] += 1
                            self._save_stats()
                            return True, breach_count
                return False, 0
            else:
                return False, None
                
        except (requests.RequestException, ValueError, KeyError):
            return False, None
    
    def get_password_recommendations(self, stats: PasswordStats) -> List[str]:
        """Get recommendations for password improvement"""
        recommendations = []
        
        if stats.length < 12:
            recommendations.append("• Use at least 12 characters (16+ recommended)")
        
        if not stats.has_upper:
            recommendations.append("• Include uppercase letters (A-Z)")
        
        if not stats.has_lower:
            recommendations.append("• Include lowercase letters (a-z)")
        
        if not stats.has_digits:
            recommendations.append("• Include numbers (0-9)")
        
        if not stats.has_special:
            recommendations.append("• Include special characters (!@#$%^&*)")
        
        if stats.is_common:
            recommendations.append("• Avoid common passwords")
        
        if stats.strength_score < 60:
            recommendations.append("• Consider using a password manager")
            recommendations.append("• Try generating a random password")
        
        return recommendations