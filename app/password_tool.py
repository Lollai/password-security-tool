import hashlib
import secrets
import string
import re
import requests
from typing import Optional, Dict, List

class PasswordTool:
    """Simple password security tool with generation, strength checking, and breach detection"""
    
    def __init__(self):
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty', 
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123'
        }
    
    def generate_password(self, length: int = 16, include_symbols: bool = True, exclude_ambiguous: bool = True) -> str:
        """Generate a secure password"""
        if length < 8 or length > 128:
            raise ValueError("Password length must be between 8 and 128 characters")
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous = '0O1lI'
            lowercase = ''.join(c for c in lowercase if c not in ambiguous)
            uppercase = ''.join(c for c in uppercase if c not in ambiguous)
            digits = ''.join(c for c in digits if c not in ambiguous)
        
        # Build character set
        chars = lowercase + uppercase + digits
        if include_symbols:
            chars += symbols
        
        # Generate password ensuring at least one character from each required set
        password = []
        password.append(secrets.choice(lowercase))
        password.append(secrets.choice(uppercase))
        password.append(secrets.choice(digits))
        
        if include_symbols:
            password.append(secrets.choice(symbols))
        
        # Fill remaining length with random characters
        for _ in range(length - len(password)):
            password.append(secrets.choice(chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def check_password_strength(self, password: str) -> Dict:
        """Check password strength and return analysis"""
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Basic checks
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        is_common = password.lower() in self.common_passwords
        
        # Calculate strength score
        score = 0
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        if has_upper:
            score += 1
        if has_lower:
            score += 1
        if has_digits:
            score += 1
        if has_special:
            score += 1
        if not is_common:
            score += 1
        
        # Determine strength label
        if score <= 2:
            strength_label = "very-weak"
        elif score <= 4:
            strength_label = "weak"
        elif score <= 6:
            strength_label = "medium"
        elif score <= 7:
            strength_label = "strong"
        else:
            strength_label = "very-strong"
        
        # Generate recommendations
        recommendations = []
        if length < 8:
            recommendations.append("Use at least 8 characters")
        if length < 12:
            recommendations.append("Consider using 12+ characters for better security")
        if not has_upper:
            recommendations.append("Add uppercase letters")
        if not has_lower:
            recommendations.append("Add lowercase letters")
        if not has_digits:
            recommendations.append("Add numbers")
        if not has_special:
            recommendations.append("Add special characters")
        if is_common:
            recommendations.append("Avoid common passwords")
        
        return {
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digits": has_digits,
            "has_special": has_special,
            "strength_score": score,
            "strength_label": strength_label,
            "is_common": is_common,
            "recommendations": recommendations
        }
    
    def check_breach(self, password: str) -> Optional[int]:
        """Check if password has been in a data breach using HaveIBeenPwned API"""
        if not password:
            return None
        
        try:
            # Hash the password using SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Send first 5 characters to HaveIBeenPwned API
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Make API request
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                # Parse response to find our suffix
                hashes = response.text.splitlines()
                for line in hashes:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
                return 0  # Not found in breaches
            else:
                return None  # API error
                
        except Exception:
            return None  # Network or other error
