#!/usr/bin/env python3
"""
Password Security Tool - Python Implementation (Improved)
A comprehensive password security checker with generation, strength analysis, and breach detection.
"""

import hashlib
import secrets
import string
import re
import json
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import requests
from dataclasses import dataclass
import argparse
import sys

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

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

class ImprovedPasswordBreachChecker:
    """Improved implementation for HaveIBeenPwned API with better error handling"""
    
    def __init__(self):
        self.api_url = "https://api.pwnedpasswords.com/range"
        self.headers = {
            'User-Agent': 'Password-Security-Tool/1.0',
            'Accept': 'text/plain'
        }
        self.timeout = 15
        self.max_retries = 3
        self.retry_delay = 1
    
    def check_breach(self, password: str) -> Tuple[bool, Optional[int]]:
        """
        Check if password has been breached using HaveIBeenPwned API
        
        Returns:
            Tuple[bool, Optional[int]]: (is_breached, count)
            - is_breached: True if password found in breaches
            - count: Number of times found (None if API error)
        """
        if not password:
            return False, None
        
        try:
            # Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Try the API call with retries
            for attempt in range(self.max_retries):
                try:
                    response = self._make_api_request(prefix)
                    if response is not None:
                        return self._parse_response(response, suffix)
                    
                    # If we get here, API request failed
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
                        
                except Exception as e:
                    logging.warning(f"API request attempt {attempt + 1} failed: {e}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
            
            # All retries failed
            return False, None
            
        except Exception as e:
            logging.error(f"Error in breach check: {e}")
            return False, None
    
    def _make_api_request(self, prefix: str) -> Optional[str]:
        """Make API request with proper error handling"""
        try:
            url = f"{self.api_url}/{prefix}"
            response = requests.get(
                url, 
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check status code
            if response.status_code == 200:
                return response.text
            elif response.status_code == 429:
                # Rate limited - wait longer
                logging.warning("Rate limited by API, waiting...")
                time.sleep(5)
                return None
            elif response.status_code == 503:
                # Service unavailable
                logging.warning("API service unavailable")
                return None
            else:
                logging.warning(f"API returned status code: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            logging.warning("API request timed out")
            return None
        except requests.exceptions.ConnectionError:
            logging.warning("Connection error to API")
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request error: {e}")
            return None
    
    def _parse_response(self, response_text: str, suffix: str) -> Tuple[bool, Optional[int]]:
        """Parse API response and find matching hash"""
        try:
            # Split response into lines
            lines = response_text.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Split hash and count
                if ':' not in line:
                    continue
                    
                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue
                    
                hash_suffix = parts[0].strip().upper()
                count_str = parts[1].strip()
                
                # Check if this is our hash
                if hash_suffix == suffix:
                    try:
                        count = int(count_str)
                        return True, count
                    except ValueError:
                        logging.warning(f"Invalid count value: {count_str}")
                        continue
            
            # Hash not found in response
            return False, 0
            
        except Exception as e:
            logging.error(f"Error parsing API response: {e}")
            return False, None
    
    def test_api_connection(self) -> bool:
        """Test API connection with a known hash"""
        try:
            # Use hash for "password" which is definitely breached
            test_prefix = "5E884"  # First 5 chars of SHA1 for "password"
            response = self._make_api_request(test_prefix)
            return response is not None and len(response) > 0
        except Exception:
            return False

class PasswordSecurityTool:
    """Main password security tool class"""
    
    def __init__(self):
        self.stats_file = "password_stats.json"
        self.common_passwords = self._load_common_passwords()
        self.stats = self._load_stats()
        self._breach_checker = ImprovedPasswordBreachChecker()
    
    def _load_common_passwords(self) -> set:
        """Load common passwords from built-in list"""
        common = {
            "123456", "password", "123456789", "12345678", "12345", "1234567",
            "1234567890", "qwerty", "abc123", "password123", "admin", "letmein",
            "welcome", "monkey", "password1", "123123", "111111", "dragon",
            "master", "sunshine", "princess", "football", "charlie", "jordan",
            "baseball", "freedom", "lovely", "buster", "trustno1", "shadow",
            "login", "passw0rd", "000000", "654321", "superman", "qazwsx",
            "michael", "football1", "batman", "trustno1", "hello", "welcome123"
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
            "api_errors": 0,
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
        
        if length > 128:
            raise ValueError("Password length cannot exceed 128 characters")
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous = "0O1lI|"
            lowercase = ''.join(c for c in lowercase if c not in ambiguous)
            uppercase = ''.join(c for c in uppercase if c not in ambiguous)
            digits = ''.join(c for c in digits if c not in ambiguous)
            symbols = ''.join(c for c in symbols if c not in ambiguous)
        
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
        if length >= 16:
            score += 30
        elif length >= 12:
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
        
        # Bonus for excellent length
        if length >= 20:
            score += 10
        
        # Penalty for common passwords
        if is_common:
            score = max(0, score - 60)
        
        # Penalty for patterns
        if self._has_patterns(password):
            score = max(0, score - 25)
        
        # Penalty for dictionary words
        if self._has_dictionary_words(password):
            score = max(0, score - 15)
        
        # Determine strength label
        if score >= 85:
            strength_label = "Very Strong"
        elif score >= 70:
            strength_label = "Strong"
        elif score >= 50:
            strength_label = "Moderate"
        elif score >= 30:
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
        # Check for repeated characters (3+ in a row)
        if re.search(r'(.)\1{2,}', password):
            return True
        
        # Check for sequential characters
        for i in range(len(password) - 2):
            if len(password) > i + 2:
                char1, char2, char3 = password[i:i+3]
                if (ord(char1) == ord(char2) - 1 == ord(char3) - 2):
                    return True
        
        # Check for keyboard patterns
        keyboard_patterns = [
            "qwerty", "qwertyuiop", "asdf", "asdfghjkl", "zxcv", "zxcvbnm",
            "123456", "1234567890", "abcdef", "qazwsx", "wsxedc"
        ]
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True
        
        return False
    
    def _has_dictionary_words(self, password: str) -> bool:
        """Check for common dictionary words"""
        common_words = {
            "password", "admin", "user", "login", "welcome", "hello", "world",
            "computer", "internet", "email", "website", "system", "database",
            "server", "network", "security", "access", "account", "profile"
        }
        
        password_lower = password.lower()
        for word in common_words:
            if word in password_lower:
                return True
        
        return False
    
    def check_breach(self, password: str) -> Tuple[bool, Optional[int]]:
        """Check if password has been breached using improved HaveIBeenPwned API"""
        try:
            is_breached, count = self._breach_checker.check_breach(password)
            
            # Update stats
            if is_breached and count is not None:
                self.stats["breaches_found"] += 1
            elif count is None:
                self.stats["api_errors"] += 1
            
            self.stats["last_used"] = datetime.now().isoformat()
            self._save_stats()
            
            return is_breached, count
            
        except Exception as e:
            logging.error(f"Error checking breach: {e}")
            self.stats["api_errors"] += 1
            self._save_stats()
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
        
        if stats.strength_score < 70:
            recommendations.append("• Consider using a password manager")
            recommendations.append("• Try generating a random password")
        
        if stats.length < 16:
            recommendations.append("• Consider using a longer password (16+ characters)")
        
        return recommendations
    
    def print_stats(self):
        """Print usage statistics"""
        print("\n" + "="*60)
        print("🔐 PASSWORD SECURITY TOOL STATISTICS")
        print("="*60)
        print(f"📊 Passwords checked: {self.stats['passwords_checked']}")
        print(f"🔑 Passwords generated: {self.stats['passwords_generated']}")
        print(f"⚠️  Breaches found: {self.stats['breaches_found']}")
        print(f"❌ API errors: {self.stats['api_errors']}")
        if self.stats['last_used']:
            last_used = datetime.fromisoformat(self.stats['last_used'])
            print(f"🕐 Last used: {last_used.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
    
    def test_api_connection(self) -> bool:
        """Test HaveIBeenPwned API connection"""
        return self._breach_checker.test_api_connection()

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="Password Security Tool - Improved")
    parser.add_argument("--generate", "-g", action="store_true", 
                       help="Generate a secure password")
    parser.add_argument("--length", "-l", type=int, default=16,
                       help="Password length (default: 16)")
    parser.add_argument("--no-symbols", action="store_true",
                       help="Exclude special characters")
    parser.add_argument("--allow-ambiguous", action="store_true",
                       help="Allow ambiguous characters (0,O,1,l,I,|)")
    parser.add_argument("--check", "-c", type=str,
                       help="Check password strength")
    parser.add_argument("--breach", "-b", type=str,
                       help="Check if password has been breached")
    parser.add_argument("--stats", "-s", action="store_true",
                       help="Show usage statistics")
    parser.add_argument("--test-api", action="store_true",
                       help="Test HaveIBeenPwned API connection")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Start interactive mode")
    
    args = parser.parse_args()
    
    tool = PasswordSecurityTool()
    
    # Test API connection
    if args.test_api:
        print("🔍 Testing HaveIBeenPwned API connection...")
        if tool.test_api_connection():
            print("✅ API connection successful!")
        else:
            print("❌ API connection failed!")
        return
    
    # Show stats if requested
    if args.stats:
        tool.print_stats()
        return
    
    # Interactive mode
    if args.interactive or len(sys.argv) == 1:
        interactive_mode(tool)
        return
    
    # Generate password
    if args.generate:
        try:
            password = tool.generate_password(
                length=args.length,
                include_symbols=not args.no_symbols,
                exclude_ambiguous=not args.allow_ambiguous
            )
            print(f"\n🔑 Generated password: {password}")
            
            # Also check its strength
            stats = tool.check_password_strength(password)
            print(f"🔍 Strength: {stats.strength_label} ({stats.strength_score}/100)")
            
        except ValueError as e:
            print(f"❌ Error: {e}")
        return
    
    # Check password strength
    if args.check:
        try:
            stats = tool.check_password_strength(args.check)
            print_password_analysis(stats, tool)
        except ValueError as e:
            print(f"❌ Error: {e}")
        return
    
    # Check breach
    if args.breach:
        print("🔍 Checking against known breaches...")
        is_breached, count = tool.check_breach(args.breach)
        if is_breached and count is not None:
            print(f"⚠️  WARNING: Password found in {count:,} data breaches!")
        elif count == 0:
            print("✅ Password not found in known breaches")
        else:
            print("❓ Could not check breach status (API unavailable)")
        return
    
    # Show help if no arguments
    parser.print_help()

def interactive_mode(tool):
    """Interactive CLI mode"""
    print("\n" + "="*60)
    print("🔐 PASSWORD SECURITY TOOL - Interactive Mode")
    print("="*60)
    
    while True:
        print("\nOptions:")
        print("1. Generate secure password")
        print("2. Check password strength")
        print("3. Check for data breaches")
        print("4. Test API connection")
        print("5. Show statistics")
        print("6. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == "1":
            generate_password_interactive(tool)
        elif choice == "2":
            check_password_interactive(tool)
        elif choice == "3":
            check_breach_interactive(tool)
        elif choice == "4":
            test_api_interactive(tool)
        elif choice == "5":
            tool.print_stats()
        elif choice == "6":
            print("Goodbye! 👋")
            break
        else:
            print("❌ Invalid option. Please try again.")

def generate_password_interactive(tool):
    """Interactive password generation"""
    print("\n" + "-"*50)
    print("🔑 PASSWORD GENERATOR")
    print("-"*50)
    
    try:
        length = int(input("Password length (8-128, default 16): ") or "16")
        if length < 8 or length > 128:
            print("❌ Length must be between 8 and 128")
            return
    except ValueError:
        print("❌ Invalid length")
        return
    
    include_symbols = input("Include symbols? (Y/n): ").lower() != 'n'
    exclude_ambiguous = input("Exclude ambiguous chars (0,O,1,l,I,|)? (Y/n): ").lower() != 'n'
    
    try:
        password = tool.generate_password(length, include_symbols, exclude_ambiguous)
        print(f"\n✅ Generated password: {password}")
        
        # Show strength analysis
        stats = tool.check_password_strength(password)
        print(f"🔍 Strength: {stats.strength_label} ({stats.strength_score}/100)")
        
        # Ask if user wants to check for breaches
        if input("\nCheck for data breaches? (Y/n): ").lower() != 'n':
            print("🔍 Checking against known breaches...")
            is_breached, count = tool.check_breach(password)
            if is_breached and count is not None:
                print(f"⚠️  WARNING: Password found in {count:,} data breaches!")
            elif count == 0:
                print("✅ Password not found in known breaches")
            else:
                print("❓ Could not check breach status")
        
    except ValueError as e:
        print(f"❌ Error: {e}")

def check_password_interactive(tool):
    """Interactive password checking"""
    print("\n" + "-"*50)
    print("🔍 PASSWORD STRENGTH CHECKER")
    print("-"*50)
    
    import getpass
    password = getpass.getpass("Enter password to check (hidden): ")
    
    if not password:
        print("❌ Password cannot be empty")
        return
    
    try:
        stats = tool.check_password_strength(password)
        print_password_analysis(stats, tool)
        
        # Ask if user wants to check for breaches
        if input("\nCheck for data breaches? (Y/n): ").lower() != 'n':
            print("🔍 Checking against known breaches...")
            is_breached, count = tool.check_breach(password)
            if is_breached and count is not None:
                print(f"⚠️  WARNING: Password found in {count:,} data breaches!")
                print("🚨 You should change this password immediately!")
            elif count == 0:
                print("✅ Password not found in known breaches")
            else:
                print("❓ Could not check breach status")
                
    except ValueError as e:
        print(f"❌ Error: {e}")

def check_breach_interactive(tool):
    """Interactive breach checking"""
    print("\n" + "-"*50)
    print("🔍 BREACH CHECKER")
    print("-"*50)
    
    import getpass
    password = getpass.getpass("Enter password to check (hidden): ")
    
    if not password:
        print("❌ Password cannot be empty")
        return
    
    print("🔍 Checking against known breaches...")
    is_breached, count = tool.check_breach(password)
    
    if is_breached and count is not None:
        print(f"⚠️  WARNING: Password found in {count:,} data breaches!")
        print("🚨 You should change this password immediately!")
    elif count == 0:
        print("✅ Good news! Password not found in known breaches")
    else:
        print("❓ Could not check breach status (API unavailable)")

def test_api_interactive(tool):
    """Interactive API testing"""
    print("\n" + "-"*50)
    print("🔍 API CONNECTION TEST")
    print("-"*50)
    
    print("Testing HaveIBeenPwned API connection...")
    if tool.test_api_connection():
        print("✅ API connection successful!")
    else:
        print("❌ API connection failed!")
        print("This could be due to:")
        print("• Network connectivity issues")
        print("• API service temporarily unavailable")
        print("• Rate limiting")

def print_password_analysis(stats: PasswordStats, tool):
    """Print detailed password analysis"""
    print("\n" + "-"*60)
    print("📊 PASSWORD ANALYSIS RESULTS")
    print("-"*60)
    
    # Strength indicator
    strength_colors = {
        "Very Strong": "🟢",
        "Strong": "🟡", 
        "Moderate": "🟠",
        "Weak": "🔴",
        "Very Weak": "🔴"
    }
    
    color = strength_colors.get(stats.strength_label, "⚪")
    print(f"{color} Overall Strength: {stats.strength_label} ({stats.strength_score}/100)")
    
    # Progress bar
    bar_length = 30
    filled_length = int(bar_length * stats.strength_score / 100)
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    print(f"   [{bar}] {stats.strength_score}%")
    
    # Details
    print(f"\n📋 Password Details:")
    print(f"   Length: {stats.length} characters")
    print(f"   Uppercase: {'✅' if stats.has_upper else '❌'}")
    print(f"   Lowercase: {'✅' if stats.has_lower else '❌'}")
    print(f"   Numbers: {'✅' if stats.has_digits else '❌'}")
    print(f"   Symbols: {'✅' if stats.has_special else '❌'}")
    print(f"   Common password: {'⚠️  Yes' if stats.is_common else '✅ No'}")
    
    # Recommendations
    recommendations = tool.get_password_recommendations(stats)
    if recommendations:
        print(f"\n💡 Recommendations:")
        for rec in recommendations:
            print(f"   {rec}")
    else:
        print(f"\n🎉 Excellent! This password meets all security criteria.")
    
    print("-"*60)

if __name__ == "__main__":
    main()