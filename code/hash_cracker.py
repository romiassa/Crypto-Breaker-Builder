import hashlib
import time
import itertools
import string
import re
import json
import os
from typing import List, Dict, Tuple, Optional
from database_orm import CryptoDatabaseORM
from PIL import Image
import io
import wave

class AdvancedHashCracker:
    def __init__(self, db=None):
        self.db = db or CryptoDatabaseORM()
        
        self.json_folder = "json_data" 
        self.learned_passwords_file = os.path.join(self.json_folder, "learned_passwords.json")
        self.rainbow_table_file = os.path.join(self.json_folder, "rainbow_table.json")
        
    
        self.leet_subs = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'l': ['1'],
            'b': ['8']
        }
        
        # Initialize these BEFORE calling load_comprehensive_wordlist
        self.learned_passwords = self.load_learned_passwords()
        self.rainbow_table = self.load_rainbow_table()
        self.common_passwords = self.load_comprehensive_wordlist()
        
        print(f"🚀 Hash Cracker Initialized: {len(self.learned_passwords)} learned passwords, {len(self.rainbow_table)} rainbow entries")
        
    def load_comprehensive_wordlist(self) -> List[str]:
        """Load extensive wordlist with phrases, patterns, and breach data"""
        base_words = [
            # Common passwords
            "password", "123456", "12345678", "1234", "qwerty", "12345", 
            "dragon", "baseball", "football", "letmein", "monkey", "abc123",
            "mustang", "michael", "shadow", "master", "jennifer", "111111",
            "2000", "jordan", "superman", "harley", "1234567", "freedom",
            "hello", "secret", "admin", "test", "welcome", "password1",
            "123", "123abc", "admin123", "qwerty123", "pass123", "access",
            "love", "sunshine", "password123", "admin1", "123qwe", "welcome1",
        ]
        
        # Add number sequences
        number_sequences = [str(i) for i in range(0, 1000)]
        
        # Add common patterns
        patterns = self.generate_common_patterns()
        
        # Add ALL learned passwords from previous sessions
        learned_words = list(self.learned_passwords.keys()) if self.learned_passwords else []
        
        # Combine all sources and remove duplicates
        all_words = base_words + number_sequences + patterns + learned_words
        return list(set(all_words))
    
    def hash_text(self, text: str, hash_type: str = 'md5') -> str:
        """Hash text using specified algorithm AND AUTO-LEARN IT"""
        hash_type = hash_type.lower()
        
        if hash_type == 'md5':
            hash_value = hashlib.md5(text.encode()).hexdigest()
        elif hash_type == 'sha1':
            hash_value = hashlib.sha1(text.encode()).hexdigest()
        elif hash_type == 'sha256':
            hash_value = hashlib.sha256(text.encode()).hexdigest()
        elif hash_type == 'sha512':
            hash_value = hashlib.sha512(text.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        # 🎯 CRITICAL: AUTO-LEARN EVERY HASH YOU CREATE
        self.auto_learn_hash(text, hash_value, hash_type)
        
        return hash_value
    
    def auto_learn_hash(self, password: str, hash_value: str, hash_type: str):
        """AUTOMATICALLY learn every hash that gets created in your app"""
        # Check if we already know this hash
        if hash_value in self.rainbow_table:
            return  # Already learned
        
        print(f"🤖 AUTO-LEARNING: '{password}' → {hash_type.upper()}:{hash_value}")
        
        # Add to learned passwords
        if password not in self.learned_passwords:
            self.learned_passwords[password] = []
        
        # Store hash entry
        hash_entry = f"{hash_type}:{hash_value}"
        if hash_entry not in self.learned_passwords[password]:
            self.learned_passwords[password].append(hash_entry)
        
        # 🎯 CRITICAL: Add to rainbow table for INSTANT lookup
        self.rainbow_table[hash_value] = password
        
        # Also learn in other hash types
        other_types = [t for t in ['md5', 'sha1', 'sha256', 'sha512'] if t != hash_type]
        for other_type in other_types:
            other_hash = self._compute_hash_only(password, other_type)
            self.rainbow_table[other_hash] = password
        
        # Save to disk
        self.save_learned_passwords()
        self.save_rainbow_table()
        
        # Update common passwords
        if password not in self.common_passwords:
            self.common_passwords.append(password)
        
        print(f"✅ Auto-learned: '{password}' → {hash_type.upper()}")
    
    def _compute_hash_only(self, text: str, hash_type: str) -> str:
        """Compute hash without auto-learning (to avoid infinite loops)"""
        hash_type = hash_type.lower()
        
        if hash_type == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(text.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    def manually_learn_password(self, password: str, hash_type: str = "all"):
        """MANUALLY learn a password and its hashes"""
        print(f"🎓 MANUALLY LEARNING: '{password}'")
        
        hash_types_to_learn = ['md5', 'sha1', 'sha256', 'sha512'] if hash_type == "all" else [hash_type]
        
        for h_type in hash_types_to_learn:
            hash_value = self._compute_hash_only(password, h_type)
            self.auto_learn_hash(password, hash_value, h_type)
        
        print(f"✅ Successfully learned '{password}' with all hash types")
        return {
            'success': True,
            'password': password,
            'total_passwords': len(self.learned_passwords),
            'total_hashes': len(self.rainbow_table)
        }
    
    def smart_dictionary_attack(self, target_hash: str, hash_type: str, timeout: int) -> Dict:
        """ADVANCED dictionary attack that CHECKS RAINBOW TABLE FIRST"""
        start_time = time.time()
        attempts = 0
        
        print("🧠 Starting smart dictionary attack...")
        print(f"📊 Rainbow table has {len(self.rainbow_table)} entries")
        print(f"🔍 Looking for: {target_hash}")
        
        # 🎯 CRITICAL: Check rainbow table FIRST (INSTANT lookup)
        if target_hash in self.rainbow_table:
            password = self.rainbow_table[target_hash]
            print(f"🚀 INSTANT FOUND in rainbow table: '{password}'")
            return {
                'success': True,
                'method': 'rainbow_table',
                'password': password,
                'attempts': 1,
                'time_taken': time.time() - start_time
            }
        
        print("❌ Hash not found in rainbow table, trying dictionary...")
        
        # Also check if any learned password has this hash
        for password, hash_list in self.learned_passwords.items():
            for hash_entry in hash_list:
                if hash_entry.endswith(target_hash):
                    print(f"🎯 FOUND in learned passwords: '{password}'")
                    # Add to rainbow table for next time
                    self.rainbow_table[target_hash] = password
                    self.save_rainbow_table()
                    return {
                        'success': True,
                        'method': 'learned_passwords',
                        'password': password,
                        'attempts': 1,
                        'time_taken': time.time() - start_time
                    }
        
        # Test common passwords
        tested_passwords = set()
        for password in self.common_passwords:
            if time.time() - start_time > timeout:
                break
                
            if password not in tested_passwords:
                attempts += 1
                tested_passwords.add(password)
                
                if self._compute_hash_only(password, hash_type) == target_hash:
                    print(f"✅ CRACKED with dictionary: '{password}'")
                    self.auto_learn_hash(password, target_hash, hash_type)
                    return {
                        'success': True,
                        'method': 'dictionary_base',
                        'password': password,
                        'attempts': attempts,
                        'time_taken': time.time() - start_time
                    }
        
        return {
            'success': False,
            'attempts': attempts,
            'time_taken': time.time() - start_time,
            'message': 'Hash not found in rainbow table or dictionary'
        }
  
    def crack_hash(self, target_hash: str, hash_type: str = 'md5', max_length: int = 8, timeout: int = 60) -> Dict:
        """MAIN CRACKING METHOD - Checks rainbow table FIRST"""
        start_time = time.time()
        
        print(f"🔍 Starting hash crack for {hash_type.upper()}: {target_hash}")
        print(f"📊 Database: {len(self.learned_passwords)} passwords, {len(self.rainbow_table)} rainbow entries")
        
        # Method 1: Smart Dictionary Attack (Rainbow table + dictionary)
        result = self.smart_dictionary_attack(target_hash, hash_type, timeout)
        
        if result['success']:
            # 🎯 CRITICAL: Save successful crack to database
            self.save_successful_crack_to_history(
                target_hash=target_hash,
                hash_type=hash_type,
                password=result['password'],
                method=result['method'],
                attempts=result['attempts'],
                time_taken=result['time_taken']
            )
            return result
        
        # Method 2: Brute Force (if time permits)
        if time.time() - start_time < timeout:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time > 10:
                print("💪 Trying brute force...")
                result = self.advanced_brute_force(target_hash, hash_type, max_length, remaining_time)
                if result['success']:
                    # 🎯 CRITICAL: Save successful crack to database
                    self.save_successful_crack_to_history(
                        target_hash=target_hash,
                        hash_type=hash_type,
                        password=result['password'],
                        method=result['method'],
                        attempts=result['attempts'],
                        time_taken=result['time_taken']
                    )
                    return result
        
        total_time = time.time() - start_time
        print(f"❌ FAILED: Hash not cracked after {result.get('attempts', 0)} attempts")
        
        # Also save failed attempts to history
        try:
            if self.db:
                # Check if this hash operation already exists
                existing_ops = self.db.get_hash_operations(hash_type=hash_type, limit=100)
                hash_op_id = None
                
                for op in existing_ops:
                    if op['hash_value'] == target_hash:
                        hash_op_id = op['id']
                        break
                
                if not hash_op_id:
                    # Create new failed hash operation
                    self.db.add_hash_operation(
                        hash_type=hash_type,
                        original_text="",  # Unknown
                        hash_value=target_hash,
                        cracked=False,
                        cracked_text=None,
                        crack_time=total_time,
                        attempts_made=result.get('attempts', 0)
                    )
        except Exception as e:
            print(f"⚠️ Error saving failed attempt: {e}")
        
        return {
            'success': False,
            'method': 'all_methods',
            'attempts': result.get('attempts', 0),
            'time_taken': total_time,
            'message': 'Hash could not be cracked',
            'database_stats': {
                'learned_passwords': len(self.learned_passwords),
                'rainbow_table_entries': len(self.rainbow_table)
            }
        }
    
    def identify_hash_type(self, hash_string: str) -> str:
        """Identify hash type based on length"""
        length = len(hash_string)
        hash_patterns = {
            32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'
        }
        return hash_patterns.get(length, 'unknown')
    
    def auto_crack_hash(self, hash_string: str, timeout: int = 60) -> Dict:
        """Auto-detect hash type and crack it"""
        hash_type = self.identify_hash_type(hash_string)
        
        if hash_type == 'unknown':
            return {'success': False, 'error': 'Unknown hash type'}
        
        print(f"🤖 Auto-detected: {hash_type.upper()}")
        return self.crack_hash(hash_string, hash_type, timeout=timeout)
    
    def load_learned_passwords(self) -> Dict[str, List[str]]:
        """Load learned passwords from file"""
        try:
            if os.path.exists(self.learned_passwords_file):
                with open(self.learned_passwords_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"⚠️ Error loading learned passwords: {e}")
        return {}
    
    def save_learned_passwords(self):
        """Save learned passwords to file"""
        try:
            with open(self.learned_passwords_file, 'w') as f:
                json.dump(self.learned_passwords, f, indent=2)
        except Exception as e:
            print(f"⚠️ Error saving learned passwords: {e}")
    
    def load_rainbow_table(self) -> Dict[str, str]:
        """Load rainbow table from file"""
        try:
            if os.path.exists(self.rainbow_table_file):
                with open(self.rainbow_table_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"⚠️ Error loading rainbow table: {e}")
        return {}
    
    def save_rainbow_table(self):
        """Save rainbow table to file"""
        try:
            with open(self.rainbow_table_file, 'w') as f:
                json.dump(self.rainbow_table, f, indent=2)
        except Exception as e:
            print(f"⚠️ Error saving rainbow table: {e}")
    
    def advanced_brute_force(self, target_hash: str, hash_type: str, max_length: int, timeout: int) -> Dict:
        """Brute force fallback"""
        start_time = time.time()
        attempts = 0
        
        char_sets = [string.digits, string.ascii_lowercase, string.ascii_lowercase + string.digits]
        
        for char_set in char_sets:
            if time.time() - start_time > timeout:
                break
                
            for length in range(1, max_length + 1):
                if time.time() - start_time > timeout:
                    break
                    
                for combo in itertools.product(char_set, repeat=length):
                    if time.time() - start_time > timeout:
                        break
                        
                    password = ''.join(combo)
                    attempts += 1
                    
                    if self._compute_hash_only(password, hash_type) == target_hash:
                        self.auto_learn_hash(password, target_hash, hash_type)
                        return {
                            'success': True,
                            'method': 'brute_force',
                            'password': password,
                            'attempts': attempts,
                            'time_taken': time.time() - start_time
                        }
        
        return {'success': False, 'attempts': attempts, 'time_taken': time.time() - start_time}
    
    def export_database_stats(self):
        """Export database statistics"""
        return {
            'learned_passwords_count': len(self.learned_passwords),
            'rainbow_table_count': len(self.rainbow_table),
            'common_passwords_count': len(self.common_passwords)
        }
    
    def search_database(self, search_term: str):
        """Search the database"""
        results = {'exact_matches': [], 'partial_matches': [], 'hash_matches': []}
        
        for password, hashes in self.learned_passwords.items():
            if search_term.lower() in password.lower():
                if search_term.lower() == password.lower():
                    results['exact_matches'].append({'password': password, 'hashes': hashes})
                else:
                    results['partial_matches'].append({'password': password, 'hashes': hashes})
        
        for hash_val, password in self.rainbow_table.items():
            if search_term.lower() in hash_val.lower():
                results['hash_matches'].append({'hash': hash_val, 'password': password})
        
        return results

    def generate_common_patterns(self) -> List[str]:
        """Generate common patterns"""
        patterns = []
        keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
        
        for row in keyboard_rows:
            for length in [3, 4, 5, 6]:
                for i in range(len(row) - length + 1):
                    patterns.append(row[i:i+length])
        
        sequences = ["123", "1234", "12345", "123456", "111", "1111", "000", "0000"]
        return patterns + sequences

    def debug_database_contents(db: CryptoDatabaseORM):
        """Debug function to check database contents"""
        try:
            print("\n" + "🔍" * 50)
            print("🔍 DEBUG DATABASE STATE")
            print("🔍" * 50)
            
            # Check hash operations
            hash_ops = db.get_hash_operations(limit=10)
            print(f"Hash Operations in DB: {len(hash_ops)}")
            
            for op in hash_ops:
                print(f"  ID: {op['id']}, Hash: {op['hash_value']}, Cracked: {op['cracked']}, Text: '{op['cracked_text']}'")
            
            # Check regular operations
            regular_ops = db.get_history(limit=5)
            print(f"\nRegular Operations in DB: {len(regular_ops)}")
            
            for op in regular_ops:
                print(f"  Type: {op['operation_type']}, Cipher: {op['cipher_type']}, Input: '{op['input_text']}'")
            
            print("🔍" * 50 + "\n")
            
        except Exception as e:
            print(f"❌ Debug error: {e}")

# Call this after crack attempts to see what's in DB

    def save_successful_crack_to_history(self, target_hash: str, hash_type: str, password: str, 
                                    method: str, attempts: int, time_taken: float):
        """Save successful crack to database history"""
        try:
            if self.db:
                print(f"💾 Saving successful crack to database: {target_hash} → '{password}'")
                
                # First, check if this hash operation already exists
                existing_ops = self.db.get_hash_operations(hash_type=hash_type, limit=100)
                hash_op_id = None
                
                for op in existing_ops:
                    if op['hash_value'] == target_hash:
                        hash_op_id = op['id']
                        break
                
                # If exists, update it
                if hash_op_id:
                    self.db.update_hash_crack_result(
                        hash_operation_id=hash_op_id,
                        cracked_text=password,
                        crack_time=time_taken,
                        attempts_made=attempts
                    )
                    print(f"✅ Updated existing hash operation #{hash_op_id}")
                else:
                    # Create new hash operation
                    hash_op_id = self.db.add_hash_operation(
                        hash_type=hash_type,
                        original_text=password,  # The cracked password
                        hash_value=target_hash,  # The original hash
                        cracked=True,
                        cracked_text=password,
                        crack_time=time_taken,
                        attempts_made=attempts
                    )
                    print(f"✅ Created new hash operation #{hash_op_id}")
                
                # Also add to regular operations for history tab
                self.db.add_operation(
                    op_type="hash_crack",
                    cipher_type=f"hash_{hash_type}",
                    input_text=target_hash,
                    output_text=password,
                    key_used=method,
                    score=100,
                    file_name=None,
                    is_file_operation=False,
                    is_image_operation=False,
                    is_audio_operation=False
                )
                
                return True
            else:
                print("⚠️ No database connection to save history")
                return False
        except Exception as e:
            print(f"❌ Error saving to history: {e}")
            return False

             
