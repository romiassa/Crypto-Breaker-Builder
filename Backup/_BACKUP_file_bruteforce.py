import os
import time
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet, InvalidToken
import threading
from pathlib import Path

class FileBruteForce:
    def __init__(self):
        self.common_passwords = [
            '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
            'password', 'Password', 'PASSWORD', 'admin', 'Admin', 'ADMIN', 'test', 'Test', 'TEST',
            'hello', 'Hello', 'HELLO', 'welcome', 'Welcome', 'WELCOME',
            '000000', '111111', '222222', '333333', '444444', '555555', '666666', '777777', '888888', '999999',
            'qwerty', 'qwerty123', 'abc123', 'monkey', 'dragon', 'sunshine', 'master', 'letmein', 'football',
            'iloveyou', 'password1', 'superman', 'trustno1', 'princess', 'admin123', 'welcome123',
            '123qwe', '1q2w3e', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'password123', 'adminadmin'
        ]
        
        self.stop_flag = threading.Event()
        self.found_password = None
        self.decrypted_data = None
        self.batch_size = 1000
        self.max_workers = min(8, os.cpu_count() * 2)
        
    def _derive_key(self, password):
        """Derive a valid Fernet key from password using SHA256"""
        hash_obj = hashlib.sha256(password.encode())
        return base64.urlsafe_b64encode(hash_obj.digest())
    
    def _test_password_batch(self, encrypted_bytes, passwords_batch, file_extension=None):
        """Test a batch of passwords against encrypted file data"""
        if self.stop_flag.is_set():
            return (False, None, None)
            
        for password in passwords_batch:
            try:
                key = self._derive_key(password)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted_bytes)
                
                # Check if decrypted data looks valid
                if self._is_valid_file_data(decrypted, file_extension):
                    return (True, password, decrypted)
                    
            except InvalidToken:
                continue
            except Exception:
                continue
                
        return (False, None, None)
    
    def _is_valid_file_data(self, data, file_extension=None):
        """Check if decrypted data looks like a valid file"""
        if len(data) == 0:
            return False
            
        # Check for common file signatures
        if len(data) >= 4:
            # PNG
            if data[:8] == b'\x89PNG\r\n\x1a\n':
                return True
            # JPEG
            if data[:3] == b'\xff\xd8\xff':
                return True
            # PDF
            if data[:4] == b'%PDF':
                return True
            # ZIP/RAR
            if data[:2] == b'PK' or data[:4] == b'Rar!':
                return True
            # Windows executable
            if data[:2] == b'MZ':
                return True
            # Text files (check for high percentage of printable ASCII)
            printable_count = sum(1 for b in data[:1000] if 32 <= b <= 126 or b in [9, 10, 13])
            if printable_count > 800:  # 80% printable
                return True
        
        return True  # Accept all data for now
    
    def detect_file_type(self, data):
        """Try to detect file type from decrypted data"""
        if len(data) >= 4:
            if data[:8] == b'\x89PNG\r\n\x1a\n':
                return 'png', '.png'
            if data[:3] == b'\xff\xd8\xff':
                return 'jpeg', '.jpg'
            if data[:4] == b'%PDF':
                return 'pdf', '.pdf'
            if data[:2] == b'PK':
                return 'zip', '.zip'
            if data[:4] == b'Rar!':
                return 'rar', '.rar'
            if data[:2] == b'MZ':
                return 'exe', '.exe'
            
            # Check for text
            printable_count = sum(1 for b in data[:1000] if 32 <= b <= 126 or b in [9, 10, 13])
            if printable_count > 800:
                return 'text', '.txt'
        
        return 'unknown', '.bin'
    
    def generate_common_passwords(self):
        """Generate common passwords"""
        for pwd in self.common_passwords:
            if self.stop_flag.is_set():
                return
            yield pwd
    
    def generate_numbers_0_999999(self):
        """Generate numbers 0-999,999"""
        for i in range(1000000):
            if self.stop_flag.is_set():
                return
            yield str(i)
    
    def generate_simple_words(self):
        """Generate simple dictionary words"""
        words = [
            'love', 'god', 'life', 'work', 'home', 'food', 'water', 'earth', 'fire', 'wind',
            'star', 'moon', 'sun', 'sky', 'sea', 'fish', 'bird', 'cat', 'dog', 'car', 'bus',
            'train', 'plane', 'book', 'pen', 'paper', 'phone', 'computer', 'internet', 'money',
            'bank', 'shop', 'store', 'house', 'room', 'door', 'window', 'chair', 'table', 'bed'
        ]
        
        for word in words:
            if self.stop_flag.is_set():
                return
            yield word
            yield word + '123'
            yield word + '!'
            yield word.capitalize()
            yield word.upper()
    
    def generate_all_combinations_1_4(self):
        """Generate all combinations of lowercase letters 1-4 chars"""
        import string
        chars = string.ascii_lowercase
        
        # 1 character
        for c in chars:
            if self.stop_flag.is_set():
                return
            yield c
        
        # 2 characters
        for c1 in chars:
            for c2 in chars:
                if self.stop_flag.is_set():
                    return
                yield c1 + c2
        
        # 3 characters (common ones first)
        common_3char = ['abc', 'def', 'ghi', 'jkl', 'mno', 'pqr', 'stu', 'vwx', 'yz',
                       'the', 'and', 'for', 'you', 'are', 'but', 'not', 'all', 'can']
        for word in common_3char:
            if self.stop_flag.is_set():
                return
            yield word
        
        # Then generate rest of 3 char combos
        for c1 in chars[:13]:  # Limit to first half of alphabet
            for c2 in chars:
                for c3 in chars:
                    if self.stop_flag.is_set():
                        return
                    yield c1 + c2 + c3
    
    def brute_force_file_fast(self, file_path, max_workers=None):
        """
        FAST FILE BRUTE FORCE - Specialized for file encryption
        Returns actual decrypted file data if successful
        """
        if max_workers is None:
            max_workers = self.max_workers
        
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': f"File not found: {file_path}"
            }
        
        print(f"\n{'='*60}")
        print(f"🚀 **ULTRA-FAST FILE BRUTE FORCE**")
        print(f"📁 File: {os.path.basename(file_path)}")
        print(f"⚡ Threads: {max_workers} | Batch size: {self.batch_size}")
        print(f"{'='*60}")
        
        try:
            # Read the encrypted file
            with open(file_path, 'rb') as f:
                encrypted_bytes = f.read()
            
            file_size = len(encrypted_bytes)
            print(f"📊 File size: {file_size:,} bytes")
            
            if file_size < 10:
                return {
                    'success': False,
                    'error': f"File too small ({file_size} bytes)"
                }
            
            self.stop_flag.clear()
            start_time = time.time()
            tested_count = 0
            
            # PHASE 1: Common passwords (FAST)
            print(f"\n🎯 PHASE 1: Common passwords")
            phase1_strategies = [
                ("Most Common", self.generate_common_passwords),
                ("Numbers 0-999,999", self.generate_numbers_0_999999),
                ("Simple Words", self.generate_simple_words),
            ]
            
            for strategy_name, generator_func in phase1_strategies:
                if self.stop_flag.is_set():
                    break
                    
                print(f"  {strategy_name}...")
                strategy_start = time.time()
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = []
                    batch = []
                    
                    for password in generator_func():
                        if self.stop_flag.is_set():
                            break
                            
                        batch.append(password)
                        tested_count += 1
                        
                        if len(batch) >= self.batch_size:
                            future = executor.submit(
                                self._test_password_batch, 
                                encrypted_bytes, 
                                batch.copy()
                            )
                            futures.append(future)
                            batch = []
                        
                        # Check completed futures
                        for f in list(futures):
                            if f.done():
                                success, found_pwd, decrypted_data = f.result()
                                if success:
                                    self.stop_flag.set()
                                    total_time = time.time() - start_time
                                    
                                    # Determine file type
                                    file_type, extension = self.detect_file_type(decrypted_data)
                                    
                                    # Save the decrypted file
                                    original_name = os.path.basename(file_path)
                                    decrypted_filename = f"decrypted_{original_name}{extension}"
                                    
                                    with open(decrypted_filename, 'wb') as f_out:
                                        f_out.write(decrypted_data)
                                    
                                    print(f"\n{'='*60}")
                                    print(f"🎉 **FILE PASSWORD FOUND!**")
                                    print(f"🔑 Password: '{found_pwd}'")
                                    print(f"📁 File type: {file_type.upper()}")
                                    print(f"💾 Saved as: {decrypted_filename}")
                                    print(f"⏱️  Time: {total_time:.2f}s")
                                    print(f"📊 Tested: {tested_count:,} passwords")
                                    print(f"{'='*60}")
                                    
                                    return {
                                        'success': True,
                                        'password': found_pwd,
                                        'file_data': decrypted_data,
                                        'file_size': len(decrypted_data),
                                        'file_type': file_type,
                                        'file_path': decrypted_filename,
                                        'time_elapsed': f"{total_time:.2f}s",
                                        'tested_count': tested_count,
                                        'method': strategy_name
                                    }
                                
                                futures.remove(f)
                    
                    # Process remaining batch
                    if batch and not self.stop_flag.is_set():
                        success, found_pwd, decrypted_data = self._test_password_batch(
                            encrypted_bytes, batch
                        )
                        if success:
                            self.stop_flag.set()
                            total_time = time.time() - start_time
                            
                            file_type, extension = self.detect_file_type(decrypted_data)
                            decrypted_filename = f"decrypted_{os.path.basename(file_path)}{extension}"
                            
                            with open(decrypted_filename, 'wb') as f_out:
                                f_out.write(decrypted_data)
                            
                            print(f"\n{'='*60}")
                            print(f"🎉 **FILE PASSWORD FOUND!**")
                            print(f"🔑 Password: '{found_pwd}'")
                            print(f"💾 Saved as: {decrypted_filename}")
                            print(f"⏱️  Time: {total_time:.2f}s")
                            print(f"{'='*60}")
                            
                            return {
                                'success': True,
                                'password': found_pwd,
                                'file_data': decrypted_data,
                                'file_size': len(decrypted_data),
                                'file_type': file_type,
                                'file_path': decrypted_filename,
                                'time_elapsed': f"{total_time:.2f}s",
                                'tested_count': tested_count,
                                'method': strategy_name
                            }
                
                strategy_time = time.time() - strategy_start
                print(f"    ⏱️  {strategy_time:.1f}s | Tested: {tested_count:,}")
            
            # If we get here, Phase 1 failed
            print(f"\n❌ Phase 1 failed - password not found")
            print(f"📊 Total tested: {tested_count:,} passwords")
            
            total_time = time.time() - start_time
            
            return {
                'success': False,
                'error': f'Password not found ({tested_count:,} tested in {total_time:.2f}s)',
                'time_elapsed': f"{total_time:.2f}s",
                'tested_count': tested_count
            }
            
        except Exception as e:
            print(f"❌ Error during brute force: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def stop_brute_force(self):
        """Stop the brute force operation"""
        self.stop_flag.set()
        print("⏹️ Brute force stopped")


# For backward compatibility
AdvancedBruteForceFile = FileBruteForce