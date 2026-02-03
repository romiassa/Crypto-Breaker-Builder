'''brute_force.py'''
import itertools
import string
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64
import time
import os
import threading

class UltimateBruteForce:
    def __init__(self):
        self.common_passwords = [
            '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
            '000000', '111111', '222222', '333333', '444444', '555555', '666666', '777777', '888888', '999999',
            'password', 'Password', 'PASSWORD', 'admin', 'Admin', 'ADMIN', 'test', 'Test', 'TEST',
            'hello', 'Hello', 'HELLO', 'welcome', 'Welcome', 'WELCOME', 'why', 'qsa', 'qzse', 'lmpp', 'letmein'
        ]
        
        self.stop_flag = threading.Event()
        self.found_password = None
        self.batch_size = 10000
        self.max_workers = min(12, os.cpu_count() * 2)
    
    def _derive_key(self, password):
        return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    
    def _test_password_batch(self, ciphertext, passwords_batch):
        if self.stop_flag.is_set():
            return (False, None, None)
            
        encrypted_data = ciphertext.encode('latin1') if isinstance(ciphertext, str) else ciphertext
        
        for password in passwords_batch:
            try:
                key = self._derive_key(password)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted_data)
                decrypted_text = decrypted.decode('utf-8')
                return (True, password, decrypted_text)
            except:
                continue
                
        return (False, None, None)

    # 🚀 PHASE 1: 1-5 CHARACTERS + NUMBERS TO 6 DIGITS (FAST)
    def generate_common_passwords(self):
        for pwd in self.common_passwords:
            if self.stop_flag.is_set():
                return
            yield pwd

    def generate_numbers_0_99999(self):
        """PHASE 1: Numbers 0-999,999 (1-6 digits)"""
        for i in range(100000):
            if self.stop_flag.is_set():
                return
            yield str(i)

    def generate_chars_1_2_lowercase_digits(self):
        chars = string.ascii_lowercase + string.digits
        for c in chars:
            if self.stop_flag.is_set():
                return
            yield c
        for c1 in chars:
            for c2 in chars:
                if self.stop_flag.is_set():
                    return
                yield c1 + c2

    def generate_chars_1_5_lowercase(self):
        """PHASE 1: 1-5 chars lowercase"""
        chars = string.ascii_lowercase
        for length in [3, 4, 5, 2, 1]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_chars_3_5_lowercase_digits(self):
        chars = string.ascii_lowercase + string.digits
        for length in [3, 4, 5]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_lowercase_numbers_1_5(self):
        """PHASE 1: Lowercase+numbers 1-5 chars"""
        chars = string.ascii_lowercase + string.digits
        for length in [3, 4, 5, 2, 1]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_starting_uppercase_2_5(self):
        """PHASE 1: Starting uppercase 2-5 chars"""
        for length in [3, 4, 5, 2]:
            for first_char in string.ascii_uppercase:
                if self.stop_flag.is_set():
                    return
                for rest_combo in itertools.product(string.ascii_lowercase, repeat=length-1):
                    if self.stop_flag.is_set():
                        return
                    yield first_char + ''.join(rest_combo)

    def generate_uppercase_1_5(self):
        """PHASE 1: Uppercase 1-5 chars"""
        chars = string.ascii_uppercase
        for length in [3, 4, 5, 2, 1]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_mixed_case_1_5(self):
        """PHASE 1: Mixed case 1-5 chars"""
        chars = string.ascii_letters
        for length in [3, 4, 5, 2, 1]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_special_combinations_1_5(self):
        """PHASE 1: Special chars 1-5"""
        special_chars = '!@#$%^&*()_-+=[]{}|;:,.<>?'
        chars = string.ascii_lowercase + special_chars
        for length in [3, 4, 5, 2, 1]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_all_chars_1_5(self):
        """PHASE 1: All chars 1-5"""
        chars = string.ascii_letters + string.digits + '!@#$%^&*()_-+=[]{}|;:,.<>?'
        for length in [3, 4, 5, 2, 1]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_uppercase_lowercase_numbers_1_5(self):
        """PHASE 1: Upper+lower+numbers 1-5 chars"""
        chars = string.ascii_letters + string.digits
        for length in [3, 4, 5, 2, 1]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_common_phrases(self):
        common_phrases = [
            'password', 'welcome', 'sunshine', 'dragon', 'monkey', 'qwerty', 'abcdef',
            'letmein', 'master', 'shadow', 'superman', 'iloveyou', 'hello', 'admin',
            'test', 'guest', 'login', 'secret', 'pass', 'user', 'access', 'security'
        ]
        
        for phrase in common_phrases:
            if self.stop_flag.is_set():
                return
            yield phrase
            yield phrase + '1'
            yield phrase + '12'
            yield phrase + '123'
            yield phrase + '!'
            yield phrase.capitalize()
            yield phrase.upper()

    # 🚀 PHASE 2: 6 CHARACTERS + NUMBERS 7-9 DIGITS
    def generate_chars_6_lowercase(self):
        """PHASE 2: 6 chars lowercase"""
        chars = string.ascii_lowercase
        for combo in itertools.product(chars, repeat=6):
            if self.stop_flag.is_set():
                return
            yield ''.join(combo)

    def generate_lowercase_numbers_6(self):
        """PHASE 2: 6 chars lowercase+numbers"""
        chars = string.ascii_lowercase + string.digits
        for combo in itertools.product(chars, repeat=6):
            if self.stop_flag.is_set():
                return
            yield ''.join(combo)

    def generate_starting_uppercase_6(self):
        """PHASE 2: 6 chars starting uppercase"""
        for first_char in string.ascii_uppercase:
            if self.stop_flag.is_set():
                return
            for rest_combo in itertools.product(string.ascii_lowercase, repeat=5):
                if self.stop_flag.is_set():
                    return
                yield first_char + ''.join(rest_combo)

    def generate_uppercase_6(self):
        """PHASE 2: 6 chars uppercase"""
        chars = string.ascii_uppercase
        for combo in itertools.product(chars, repeat=6):
            if self.stop_flag.is_set():
                return
            yield ''.join(combo)

    def generate_mixed_case_6(self):
        """PHASE 2: 6 chars mixed case"""
        chars = string.ascii_letters
        for combo in itertools.product(chars, repeat=6):
            if self.stop_flag.is_set():
                return
            yield ''.join(combo)

    def generate_special_combinations_6(self):
        """PHASE 2: 6 chars with special"""
        special_chars = '!@#$%^&*()_-+=[]{}|;:,.<>?'
        chars = string.ascii_lowercase + special_chars
        for combo in itertools.product(chars, repeat=6):
            if self.stop_flag.is_set():
                return
            yield ''.join(combo)

    def generate_all_chars_6(self):
        """PHASE 2: 6 chars all characters"""
        chars = string.ascii_letters + string.digits + '!@#$%^&*()_-+=[]{}|;:,.<>?'
        for combo in itertools.product(chars, repeat=6):
            if self.stop_flag.is_set():
                return
            yield ''.join(combo)

    def generate_uppercase_lowercase_numbers_6(self):
        """PHASE 2: 6 chars upper+lower+numbers"""
        chars = string.ascii_letters + string.digits
        for combo in itertools.product(chars, repeat=6):
            if self.stop_flag.is_set():
                return
            yield ''.join(combo)

    def generate_numbers_7_9_digits(self):
        """PHASE 2: Numbers 7-9 digits (10M - 1B) - sampled"""
        # Common patterns first
        patterns = [
            '1000000', '10000000', '100000000', '1234567', '12345678', '123456789',
            '9999999', '99999999', '999999999', '1111111', '11111111', '111111111',
            '0000000', '00000000', '000000000'
        ]
        for pattern in patterns:
            if self.stop_flag.is_set():
                return
            yield pattern
        
        # Sample every 100,000th number for performance
        for digits in [6, 7, 8, 9]:
            max_num = 10 ** digits
            for i in range(0, max_num, 100000):
                if self.stop_flag.is_set():
                    return
                yield str(i).zfill(digits)

    # 🚀 PHASE 3: 7-9 CHARACTERS + NUMBERS 10-15 DIGITS
    def generate_chars_7_9_lowercase(self):
        """PHASE 3: 7-9 chars lowercase"""
        chars = string.ascii_lowercase
        for length in [7, 8, 9]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_lowercase_numbers_7_9(self):
        """PHASE 3: 7-9 chars lowercase+numbers"""
        chars = string.ascii_lowercase + string.digits
        for length in [7, 8, 9]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_starting_uppercase_7_9(self):
        """PHASE 3: 7-9 chars starting uppercase"""
        for length in [7, 8, 9]:
            for first_char in string.ascii_uppercase:
                if self.stop_flag.is_set():
                    return
                for rest_combo in itertools.product(string.ascii_lowercase, repeat=length-1):
                    if self.stop_flag.is_set():
                        return
                    yield first_char + ''.join(rest_combo)

    def generate_uppercase_7_9(self):
        """PHASE 3: 7-9 chars uppercase"""
        chars = string.ascii_uppercase
        for length in [7, 8, 9]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_mixed_case_7_9(self):
        """PHASE 3: 7-9 chars mixed case"""
        chars = string.ascii_letters
        for length in [7, 8, 9]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_special_combinations_7_9(self):
        """PHASE 3: 7-9 chars with special"""
        special_chars = '!@#$%^&*()_-+=[]{}|;:,.<>?'
        chars = string.ascii_lowercase + special_chars
        for length in [7, 8, 9]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_all_chars_7_9(self):
        """PHASE 3: 7-9 chars all characters"""
        chars = string.ascii_letters + string.digits + '!@#$%^&*()_-+=[]{}|;:,.<>?'
        for length in [7, 8, 9]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_uppercase_lowercase_numbers_7_9(self):
        """PHASE 3: 7-9 chars upper+lower+numbers"""
        chars = string.ascii_letters + string.digits
        for length in [7, 8, 9]:
            for combo in itertools.product(chars, repeat=length):
                if self.stop_flag.is_set():
                    return
                yield ''.join(combo)

    def generate_numbers_10_15_digits(self):
        """PHASE 3: Numbers 10-15 digits (very large numbers) - sampled heavily"""
        # Common patterns for very large numbers
        patterns = [
            '1000000000', '10000000000', '100000000000', '1000000000000', '10000000000000', '100000000000000',
            '1234567890', '12345678901', '123456789012', '1234567890123', '12345678901234', '123456789012345',
            '9999999999', '99999999999', '999999999999', '9999999999999', '99999999999999', '999999999999999',
            '1111111111', '11111111111', '111111111111', '1111111111111', '11111111111111', '111111111111111',
            '0000000000', '00000000000', '000000000000', '0000000000000', '00000000000000', '000000000000000'
        ]
        for pattern in patterns:
            if self.stop_flag.is_set():
                return
            yield pattern
        
        # Very heavy sampling for huge numbers
        for digits in [10, 11, 12, 13, 14, 15]:
            step_size = 10 ** (digits - 6)  # Sample every 10^(digits-6) numbers
            max_samples = 10000  # Limit to 10,000 samples per digit length
            
            for i in range(0, max_samples):
                if self.stop_flag.is_set():
                    return
                num = i * step_size
                if num < (10 ** digits):
                    yield str(num).zfill(digits)

    def brute_force_aes(self, ciphertext, max_workers=None):
        """ULTIMATE 3-PHASE STRATEGY WITH NUMBERS 6-15 DIGITS"""
        if max_workers is None:
            max_workers = self.max_workers
            
        print(f"🚀 ULTIMATE 3-PHASE BRUTE FORCE")
        print(f"📋 PHASE 1: 1-5 chars + Numbers 0-999,999 (1-6 digits)")
        print(f"📋 PHASE 2: 6 chars + Numbers 7-9 digits") 
        print(f"📋 PHASE 3: 7-9 chars + Numbers 10-15 digits")
        
        # PHASE 1: 1-5 Characters + Numbers to 6 digits
        phase1_strategies = [
            ("🎯 Common passwords", lambda: iter(self.common_passwords)),
            ("1️⃣ Numbers 0-999,99", self.generate_numbers_0_99999),
            ("2️⃣ 1-2 chars (lowercase+digits)", self.generate_chars_1_2_lowercase_digits),
            ("3️⃣ 1-5 chars lowercase", self.generate_chars_1_5_lowercase),
            ("4️⃣ 3-5 chars (lowercase+digits)", self.generate_chars_3_5_lowercase_digits),
            ("5️⃣ Lowercase+numbers 1-5", self.generate_lowercase_numbers_1_5),
            ("6️⃣ Starting uppercase 2-5", self.generate_starting_uppercase_2_5),
            ("7️⃣ Uppercase 1-5", self.generate_uppercase_1_5),
            ("8️⃣ Mixed case 1-5", self.generate_mixed_case_1_5),
            ("9️⃣ Special combos 1-5", self.generate_special_combinations_1_5),
            ("🔟 All chars 1-5", self.generate_all_chars_1_5),
            ("1️⃣1️⃣ Upper+lower+num 1-5", self.generate_uppercase_lowercase_numbers_1_5),
            ("1️⃣2️⃣ Common phrases", self.generate_common_phrases),
        ]
        
        # PHASE 2: 6 Characters + Numbers 7-9 digits
        phase2_strategies = [
            ("🔄 6 chars lowercase", self.generate_chars_6_lowercase),
            ("🔄 Lowercase+numbers 6", self.generate_lowercase_numbers_6),
            ("🔄 Starting uppercase 6", self.generate_starting_uppercase_6),
            ("🔄 Uppercase 6", self.generate_uppercase_6),
            ("🔄 Mixed case 6", self.generate_mixed_case_6),
            ("🔄 Special combos 6", self.generate_special_combinations_6),
            ("🔄 All chars 6", self.generate_all_chars_6),
            ("🔄 Upper+lower+num 6", self.generate_uppercase_lowercase_numbers_6),
            ("🔄 Numbers 6-9 digits", self.generate_numbers_7_9_digits),
        ]
        
        # PHASE 3: 7-9 Characters + Numbers 10-15 digits
        phase3_strategies = [
            ("🐢 7-9 chars lowercase", self.generate_chars_7_9_lowercase),
            ("🐢 Lowercase+numbers 7-9", self.generate_lowercase_numbers_7_9),
            ("🐢 Starting uppercase 7-9", self.generate_starting_uppercase_7_9),
            ("🐢 Uppercase 7-9", self.generate_uppercase_7_9),
            ("🐢 Mixed case 7-9", self.generate_mixed_case_7_9),
            ("🐢 Special combos 7-9", self.generate_special_combinations_7_9),
            ("🐢 All chars 7-9", self.generate_all_chars_7_9),
            ("🐢 Upper+lower+num 7-9", self.generate_uppercase_lowercase_numbers_7_9),
            ("🐢 Numbers 10-15 digits", self.generate_numbers_10_15_digits),
        ]
        
        print(f"⚡ Threads: {max_workers} | Batch: {self.batch_size}")
        print("=" * 60)
        
        self.stop_flag.clear()
        start_time = time.time()
        tested_count = 0
        
        # 🚀 PHASE 1: Execute 1-5 char strategies + numbers to 6 digits
        print(f"\n🎯 STARTING PHASE 1: 1-5 Characters + Numbers 0-999,999")
        for strategy_name, generator_func in phase1_strategies:
            if self.stop_flag.is_set():
                break
                
            print(f"\n{strategy_name}")
            strategy_start = time.time()
            result = self._execute_ultra_fast(ciphertext, generator_func(), max_workers)
            strategy_time = time.time() - strategy_start
            
            if result and 'password' in result:
                total_time = time.time() - start_time
                print("=" * 60)
                print(f"🎉 PASSWORD FOUND: '{result['password']}'")
                print(f"⏱️  Total time: {total_time:.2f}s")
                
                return {
                    'success': True,
                    'password': result['password'],
                    'text': result['text'],
                    'time_elapsed': f"{total_time:.2f}s",
                    'method': strategy_name,
                    'tested_count': result.get('tested', 0)
                }
            
            if result and 'tested' in result:
                tested_count += result['tested']
        
        # 🚀 PHASE 2: Only if Phase 1 didn't find password
        print(f"\n🔄 STARTING PHASE 2: 6 Characters + Numbers 7-9 digits")
        for strategy_name, generator_func in phase2_strategies:
            if self.stop_flag.is_set():
                break
                
            print(f"\n{strategy_name}")
            strategy_start = time.time()
            result = self._execute_ultra_fast(ciphertext, generator_func(), max_workers)
            strategy_time = time.time() - strategy_start
            
            if result and 'password' in result:
                total_time = time.time() - start_time
                print("=" * 60)
                print(f"🎉 PASSWORD FOUND: '{result['password']}'")
                print(f"⏱️  Total time: {total_time:.2f}s")
                
                return {
                    'success': True,
                    'password': result['password'],
                    'text': result['text'],
                    'time_elapsed': f"{total_time:.2f}s",
                    'method': strategy_name,
                    'tested_count': result.get('tested', 0)
                }
            
            if result and 'tested' in result:
                tested_count += result['tested']
        
        # 🚀 PHASE 3: Only if Phase 2 didn't find password
        print(f"\n🐢 STARTING PHASE 3: 7-9 Characters + Numbers 10-15 digits")
        for strategy_name, generator_func in phase3_strategies:
            if self.stop_flag.is_set():
                break
                
            print(f"\n{strategy_name}")
            strategy_start = time.time()
            result = self._execute_ultra_fast(ciphertext, generator_func(), max_workers)
            strategy_time = time.time() - strategy_start
            
            if result and 'password' in result:
                total_time = time.time() - start_time
                print("=" * 60)
                print(f"🎉 PASSWORD FOUND: '{result['password']}'")
                print(f"⏱️  Total time: {total_time:.2f}s")
                
                return {
                    'success': True,
                    'password': result['password'],
                    'text': result['text'],
                    'time_elapsed': f"{total_time:.2f}s",
                    'method': strategy_name,
                    'tested_count': result.get('tested', 0)
                }
            
            if result and 'tested' in result:
                tested_count += result['tested']
        
        total_time = time.time() - start_time
        
        return {
            'success': False,
            'error': f'Password not found ({tested_count:,} tested in {total_time:.2f}s)',
            'time_elapsed': f"{total_time:.2f}s",
            'tested_count': tested_count
        }

    def brute_force_aes_file(self, encrypted_file_data, max_workers=None):
        """ULTRA-FAST FILE BRUTE FORCE - Uses same 3-phase strategy as text brute force"""
        if max_workers is None:
            max_workers = self.max_workers
            
        print(f"🚀 **ULTRA-FAST FILE BRUTE FORCE ACTIVATED**")
        print(f"📋 PHASE 1: 1-5 chars + Numbers 0-999,999 (1-6 digits)")
        print(f"📋 PHASE 2: 6 chars + Numbers 7-9 digits") 
        print(f"📋 PHASE 3: 7-9 chars + Numbers 10-15 digits")
        print(f"⚡ Threads: {max_workers} | Batch: {self.batch_size}")
        print("=" * 60)
        
        self.stop_flag.clear()
        start_time = time.time()
        tested_count = 0
        
        # PHASE 1: 1-5 Characters + Numbers to 6 digits
        phase1_strategies = [
            ("🎯 Common passwords", lambda: iter(self.common_passwords)),
            ("1️⃣ Numbers 0-999,99", self.generate_numbers_0_99999),
            ("2️⃣ 1-2 chars (lowercase+digits)", self.generate_chars_1_2_lowercase_digits),
            ("3️⃣ 1-5 chars lowercase", self.generate_chars_1_5_lowercase),
            ("4️⃣ 3-5 chars (lowercase+digits)", self.generate_chars_3_5_lowercase_digits),
            ("5️⃣ Lowercase+numbers 1-5", self.generate_lowercase_numbers_1_5),
            ("6️⃣ Starting uppercase 2-5", self.generate_starting_uppercase_2_5),
            ("7️⃣ Uppercase 1-5", self.generate_uppercase_1_5),
            ("8️⃣ Mixed case 1-5", self.generate_mixed_case_1_5),
            ("9️⃣ Special combos 1-5", self.generate_special_combinations_1_5),
            ("🔟 All chars 1-5", self.generate_all_chars_1_5),
            ("1️⃣1️⃣ Upper+lower+num 1-5", self.generate_uppercase_lowercase_numbers_1_5),
            ("1️⃣2️⃣ Common phrases", self.generate_common_phrases),
        ]
        
        # PHASE 2: 6 Characters + Numbers 7-9 digits
        phase2_strategies = [
            ("🔄 6 chars lowercase", self.generate_chars_6_lowercase),
            ("🔄 Lowercase+numbers 6", self.generate_lowercase_numbers_6),
            ("🔄 Starting uppercase 6", self.generate_starting_uppercase_6),
            ("🔄 Uppercase 6", self.generate_uppercase_6),
            ("🔄 Mixed case 6", self.generate_mixed_case_6),
            ("🔄 Special combos 6", self.generate_special_combinations_6),
            ("🔄 All chars 6", self.generate_all_chars_6),
            ("🔄 Upper+lower+num 6", self.generate_uppercase_lowercase_numbers_6),
            ("🔄 Numbers 6-9 digits", self.generate_numbers_7_9_digits),
        ]
        
        # PHASE 3: 7-9 Characters + Numbers 10-15 digits
        phase3_strategies = [
            ("🐢 7-9 chars lowercase", self.generate_chars_7_9_lowercase),
            ("🐢 Lowercase+numbers 7-9", self.generate_lowercase_numbers_7_9),
            ("🐢 Starting uppercase 7-9", self.generate_starting_uppercase_7_9),
            ("🐢 Uppercase 7-9", self.generate_uppercase_7_9),
            ("🐢 Mixed case 7-9", self.generate_mixed_case_7_9),
            ("🐢 Special combos 7-9", self.generate_special_combinations_7_9),
            ("🐢 All chars 7-9", self.generate_all_chars_7_9),
            ("🐢 Upper+lower+num 7-9", self.generate_uppercase_lowercase_numbers_7_9),
            ("🐢 Numbers 10-15 digits", self.generate_numbers_10_15_digits),
        ]
        
        # 🚀 PHASE 1: Execute 1-5 char strategies + numbers to 6 digits
        print(f"\n🎯 STARTING PHASE 1: 1-5 Characters + Numbers 0-999,999")
        for strategy_name, generator_func in phase1_strategies:
            if self.stop_flag.is_set():
                break
                
            print(f"\n{strategy_name}")
            strategy_start = time.time()
            result = self._execute_ultra_fast(encrypted_file_data, generator_func(), max_workers)
            strategy_time = time.time() - strategy_start
            
            if result and 'password' in result:
                total_time = time.time() - start_time
                print("=" * 60)
                print(f"🎉 **FILE PASSWORD FOUND**: '{result['password']}'")
                print(f"⏱️  Total time: {total_time:.2f}s")
                
                return {
                    'success': True,
                    'password': result['password'],
                    'time_elapsed': f"{total_time:.2f}s",
                    'method': strategy_name,
                    'tested_count': result.get('tested', 0)
                }
            
            if result and 'tested' in result:
                tested_count += result['tested']
                print(f"✅ {strategy_name}: {result['tested']:,} tested in {strategy_time:.2f}s")
        
        # 🚀 PHASE 2: Only if Phase 1 didn't find password
        print(f"\n🔄 STARTING PHASE 2: 6 Characters + Numbers 7-9 digits")
        for strategy_name, generator_func in phase2_strategies:
            if self.stop_flag.is_set():
                break
                
            print(f"\n{strategy_name}")
            strategy_start = time.time()
            result = self._execute_ultra_fast(encrypted_file_data, generator_func(), max_workers)
            strategy_time = time.time() - strategy_start
            
            if result and 'password' in result:
                total_time = time.time() - start_time
                print("=" * 60)
                print(f"🎉 **FILE PASSWORD FOUND**: '{result['password']}'")
                print(f"⏱️  Total time: {total_time:.2f}s")
                
                return {
                    'success': True,
                    'password': result['password'],
                    'time_elapsed': f"{total_time:.2f}s",
                    'method': strategy_name,
                    'tested_count': result.get('tested', 0)
                }
            
            if result and 'tested' in result:
                tested_count += result['tested']
                print(f"✅ {strategy_name}: {result['tested']:,} tested in {strategy_time:.2f}s")
        
        # 🚀 PHASE 3: Only if Phase 2 didn't find password
        print(f"\n🐢 STARTING PHASE 3: 7-9 Characters + Numbers 10-15 digits")
        for strategy_name, generator_func in phase3_strategies:
            if self.stop_flag.is_set():
                break
                
            print(f"\n{strategy_name}")
            strategy_start = time.time()
            result = self._execute_ultra_fast(encrypted_file_data, generator_func(), max_workers)
            strategy_time = time.time() - strategy_start
            
            if result and 'password' in result:
                total_time = time.time() - start_time
                print("=" * 60)
                print(f"🎉 **FILE PASSWORD FOUND**: '{result['password']}'")
                print(f"⏱️  Total time: {total_time:.2f}s")
                
                return {
                    'success': True,
                    'password': result['password'],
                    'time_elapsed': f"{total_time:.2f}s",
                    'method': strategy_name,
                    'tested_count': result.get('tested', 0)
                }
            
            if result and 'tested' in result:
                tested_count += result['tested']
                print(f"✅ {strategy_name}: {result['tested']:,} tested in {strategy_time:.2f}s")
        
        total_time = time.time() - start_time
        
        print(f"\n❌ File password not found after all 3 phases")
        print(f"📊 Total tested: {tested_count:,} passwords in {total_time:.2f}s")
        
        return {
            'success': False,
            'error': f'File password not found ({tested_count:,} tested in {total_time:.2f}s)',
            'time_elapsed': f"{total_time:.2f}s",
            'tested_count': tested_count
        }

    def _execute_ultra_fast(self, ciphertext, password_generator, max_workers):
        """MAXIMUM SPEED EXECUTION"""
        tested = 0
        batch = []
        start_time = time.time()
        last_report = start_time
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for password in password_generator:
                if self.stop_flag.is_set():
                    break
                    
                batch.append(password)
                tested += 1
                
                if len(batch) >= self.batch_size:
                    future = executor.submit(self._test_password_batch, ciphertext, batch.copy())
                    futures.append(future)
                    batch = []
                
                completed = []
                for f in list(futures):
                    if f.done():
                        completed.append(f)
                
                for f in completed:
                    futures.remove(f)
                    success, found_pwd, decrypted = f.result()
                    if success:
                        elapsed = time.time() - start_time
                        rate = tested / elapsed if elapsed > 0 else 0
                        print(f"✅ FOUND: '{found_pwd}' | {rate:,.0f}/sec")
                        return {'password': found_pwd, 'text': decrypted, 'tested': tested}
                
                current_time = time.time()
                if current_time - last_report >= 3.0:
                    elapsed = current_time - start_time
                    rate = tested / elapsed if elapsed > 0 else 0
                    print(f"⏳ {tested:,} tested | {rate:,.0f}/sec", end='\r')
                    last_report = current_time
            
            if batch:
                success, found_pwd, decrypted = self._test_password_batch(ciphertext, batch)
                if success:
                    elapsed = time.time() - start_time
                    rate = tested / elapsed if elapsed > 0 else 0
                    print(f"✅ FOUND: '{found_pwd}' | {rate:,.0f}/sec")
                    return {'password': found_pwd, 'text': decrypted, 'tested': tested}
            
            for f in futures:
                success, found_pwd, decrypted = f.result()
                if success:
                    elapsed = time.time() - start_time
                    rate = tested / elapsed if elapsed > 0 else 0
                    print(f"✅ FOUND: '{found_pwd}' | {rate:,.0f}/sec")
                    return {'password': found_pwd, 'text': decrypted, 'tested': tested}
        
        elapsed = time.time() - start_time
        rate = tested / elapsed if elapsed > 0 else 0
        print(f"✅ {tested:,} tested | {rate:,.0f}/sec | {elapsed:.1f}s")
        return {'tested': tested}

    def brute_force_with_threading(self, ciphertext, max_workers=None):
        return self.brute_force_aes(ciphertext, max_workers)

    def stop_brute_force(self):
        self.stop_flag.set()
        print("⏹️ Brute force stopped")

    # brute_force.py - ADD THIS METHOD

    def brute_force_aes_phase1_only(self, ciphertext, max_workers=None):
        """
        Phase 1 ONLY brute force - for FAST checking
        Includes ALL Phase 1 strategies
        """
        if max_workers is None:
            max_workers = self.max_workers
            
        print(f"🚀 **PHASE 1 ONLY (FAST CHECK)**")
        print(f"📋 Includes ALL Phase 1 strategies on test data")
        
        self.stop_flag.clear()
        start_time = time.time()
        tested_count = 0
        
        # ALL Phase 1 strategies
        phase1_strategies = [
            ("🎯 Common passwords", lambda: iter(self.common_passwords)),
            ("1️⃣ Numbers 0-999,999", self.generate_numbers_0_99999),
            ("2️⃣ 1-2 chars lowercase+digits", self.generate_chars_1_2_lowercase_digits),
            ("3️⃣ 1-5 chars lowercase", self.generate_chars_1_5_lowercase),
            ("4️⃣ 3-5 chars lowercase+digits", self.generate_chars_3_5_lowercase_digits),
            ("5️⃣ Lowercase+numbers 1-5", self.generate_lowercase_numbers_1_5),
            ("6️⃣ Starting uppercase 2-5", self.generate_starting_uppercase_2_5),
            ("7️⃣ Uppercase 1-5", self.generate_uppercase_1_5),
            ("8️⃣ Mixed case 1-5", self.generate_mixed_case_1_5),
            ("9️⃣ Special combos 1-5", self.generate_special_combinations_1_5),
            ("🔟 All chars 1-5", self.generate_all_chars_1_5),
            ("1️⃣1️⃣ Upper+lower+num 1-5", self.generate_uppercase_lowercase_numbers_1_5),
            ("1️⃣2️⃣ Common phrases", self.generate_common_phrases),
        ]
        
        print(f"⚡ Threads: {max_workers}")
        print("=" * 60)
        
        for strategy_name, generator_func in phase1_strategies:
            if self.stop_flag.is_set():
                break
                
            print(f"\n{strategy_name}")
            strategy_start = time.time()
            result = self._execute_ultra_fast(ciphertext, generator_func(), max_workers)
            strategy_time = time.time() - strategy_start
            
            if result and 'password' in result:
                total_time = time.time() - start_time
                print("=" * 60)
                print(f"✅ PASSWORD FOUND: '{result['password']}'")
                print(f"⏱️  Total time: {total_time:.3f}s")
                
                return {
                    'success': True,
                    'password': result['password'],
                    'text': result.get('text', ''),
                    'time_elapsed': f"{total_time:.3f}s",
                    'method': strategy_name,
                    'tested_count': result.get('tested', 0) + tested_count
                }
            
            if result and 'tested' in result:
                tested_count += result['tested']
                print(f"   Tested: {result['tested']:,} in {strategy_time:.2f}s")
        
        total_time = time.time() - start_time
        
        return {
            'success': False,
            'error': f'Password not found in Phase 1 ({tested_count:,} tested in {total_time:.2f}s)',
            'time_elapsed': f"{total_time:.2f}s",
            'tested_count': tested_count
        }
    # Or use it in your main.py:
    # aes = AESEncryption()
    # result = aes.modern_crack_file(encrypted_file_data, method="bruteforce")

AdvancedBruteForce = UltimateBruteForce