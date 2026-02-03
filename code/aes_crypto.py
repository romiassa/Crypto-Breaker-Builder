import os
import base64
import hashlib
import logging
import time
import itertools
from multiprocessing import Pool, Manager
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
from tqdm import tqdm #type: ignore

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AESEncryption:
    """
    AES encryption/decryption class using Fernet (AES-128-CBC with HMAC-SHA256).
    Supports both text and file encryption.
    """
    
    def __init__(self):
        pass
    
    def _derive_key(self, password):
        """
        Derive a 32-byte key from password using SHA256.
        IMPORTANT: This matches your specific compatibility requirement.
        """
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest)
    
    def encrypt(self, plaintext, password):
        """Encrypt a plaintext string"""
        key = self._derive_key(password)
        cipher = Fernet(key)
        encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))
        return encrypted_bytes.decode('latin1')
    
    def decrypt(self, encrypted_text, password):
        """Decrypt an encrypted string"""
        try:
            key = self._derive_key(password)
            cipher = Fernet(key)
            encrypted_bytes = encrypted_text.encode('latin1')
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return decrypted_bytes
        except Exception as e:
            return None
    
    def encrypt_file(self, input_path, password, output_path=None):
        """Encrypt a file"""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        if output_path is None:
            output_path = input_path + '.bin'
        
        key = self._derive_key(password)
        cipher = Fernet(key)
        
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        encrypted_bytes = cipher.encrypt(plaintext)
        
        # Return bytes directly (GUI handles saving)
        return encrypted_bytes

    def validate_password(self, encrypted_data, password):
        """Check if password is correct without decoding (Binary Safe)"""
        try:
            key = self._derive_key(password)
            cipher = Fernet(key)
            cipher.decrypt(encrypted_data)
            return True
        except:
            return False


    def brute_force_file_all_phase1(self, file_path, max_workers=8):
        """
        Use the HYBRID brute force for Phase 1
        """
        from hybrid_brute_force import HybridBruteForce
        
        hybrid = HybridBruteForce()
        result = hybrid.brute_force_file_phase1(file_path, max_workers)
        
        if result['success']:
            return {
                'success': True,
                'password': result['password'],
                'method': 'Phase 1 (Hybrid)',
                'tested_count': result['tested_count'],
                'time': result['time_elapsed']
            }
        else:
            return {
                'success': False,
                'error': result.get('error', 'Password not found'),
                'tested_count': result.get('tested_count', 0),
                'time': result.get('time_elapsed', 0)
            }
            
    def decrypt_file(self, encrypted_data_or_path, password, output_path=None):
        """Decrypt file data or a file path."""
        try:
            key = self._derive_key(password)
            cipher = Fernet(key)
            
            # Handle input
            if isinstance(encrypted_data_or_path, bytes):
                encrypted_data = encrypted_data_or_path
            elif isinstance(encrypted_data_or_path, str) and os.path.exists(encrypted_data_or_path):
                with open(encrypted_data_or_path, 'rb') as f:
                    encrypted_data = f.read()
            else:
                raise ValueError("Invalid input - must be bytes or file path")
            
            # Decrypt
            decrypted_bytes = cipher.decrypt(encrypted_data)
            
            # Save if output path provided
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(decrypted_bytes)
            
            return decrypted_bytes
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
        
    def auto_decrypt_with_password(self, encrypted_file_path, password, output_path=None):
        """
        Automatically decrypt file after brute force finds password
        Returns: {'success': bool, 'decrypted_file': str, 'size': int, 'message': str}
        """
        try:
            # Create output filename
            base_name = os.path.basename(encrypted_file_path)
            
            if base_name.endswith('.bin') and base_name.startswith('encrypted_'):
                original_name = base_name[10:-4]  # Remove 'encrypted_' and '.bin'
            else:
                # Generate meaningful name
                name_parts = base_name.split('.')
                if len(name_parts) > 1:
                    original_name = f"decrypted_{name_parts[0]}"
                else:
                    original_name = f"decrypted_{base_name}"
            
            output_file = original_name
            
            # Ensure unique name
            counter = 1
            while os.path.exists(output_file):
                name_parts = original_name.split('.')
                if len(name_parts) > 1:
                    output_file = f"{name_parts[0]}_{counter}.{'.'.join(name_parts[1:])}"
                else:
                    output_file = f"{original_name}_{counter}"
                counter += 1
            
            # Decrypt the file
            result_bytes = self.decrypt_file(encrypted_file_path, password, output_file)
            
            if result_bytes is not None:
                file_size = os.path.getsize(output_file)
                
                return {
                    'success': True,
                    'decrypted_file': output_file,
                    'size': file_size,
                    'message': f"✅ File automatically decrypted!\n📁 Saved as: {output_file}\n📊 Size: {file_size:,} bytes"
                }
            else:
                return {
                    'success': False,
                    'error': 'Auto-decryption failed - wrong password or corrupted file'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Auto-decryption error: {str(e)}"
            }

class UltimateBruteForce:
    
    def __init__(self):
        self._tested_count = 0
        self._lock = None
        self.charset = 'abcdefghijklmnopqrstuvwxyz'
        self.base = len(self.charset)
        self.found_flag = False

    def _derive_key(self, password):
        """Same as AESEncryption"""
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    def _validate_password_fast(self, encrypted_data, password):
        """
        ✅ FIXED: No truncation - decrypt FULL token
        """
        try:
            key = self._derive_key(password)
            cipher = Fernet(key)
            # ✅ FIXED: Full token, NOT [:100]
            cipher.decrypt(encrypted_data)  # DECRYPT FULL DATA
            return True
        except:
            return False  # ✅ FIXED: Was "Fals"

    def calculate_total_combinations_phase1(self):
        """Calculate total combinations for Phase 1 (1-5 chars lowercase)"""
        total = 0
        for length in range(1, 6):
            total += self.base ** length
        return total

    def index_to_password(self, index):
        """Convert index to password"""
        length = 1
        count = self.base
        
        while index >= count:
            index -= count
            length += 1
            count = self.base ** length
            
        password_chars = []
        for _ in range(length):
            password_chars.append(self.charset[index % self.base])
            index //= self.base
            
        return ''.join(reversed(password_chars))

    def _worker_aes_direct(self, encrypted_data, start_idx, end_idx, found_passwords, worker_id):
        """FIXED worker function"""
        tested_local = 0
        BATCH_SIZE = 100
        
        try:
            for current_idx in range(start_idx, end_idx):
                # Check if ANY worker found password
                if len(found_passwords) > 0:
                    return
                
                password = self.index_to_password(current_idx)
                
                # Use FAST validation (FULL token now)
                if self._validate_password_fast(encrypted_data, password):
                    print(f"🎯 Worker {worker_id} found password: {password}")
                    found_passwords.append(password)
                    return

                tested_local += 1
                if tested_local >= BATCH_SIZE:
                    with self._lock:
                        self._tested_count += tested_local
                        # Print progress every 10,000 attempts
                        if self._tested_count % 10000 == 0:
                            print(f"📊 Tested: {self._tested_count:,} passwords")
                    tested_local = 0
                    
        except Exception as e:
            print(f"Worker {worker_id} error: {e}")

        if tested_local > 0 and self._lock is not None:
            with self._lock:
                self._tested_count += tested_local

    def get_tested_count(self):
        """Get total tested count"""
        if self._lock is None:
            return self._tested_count
        with self._lock:
            return self._tested_count

    def brute_force_aes_phase1_only(self, encrypted_data, max_workers=4):
        """FIXED brute force with progress"""
        print(f"🔍 Starting UltimateBruteForce with {max_workers} workers...")
        print(f"📊 Total combos: {self.calculate_total_combinations_phase1():,}")
        print(f"🔑 Charset: {self.charset}")
        print(f"📏 Password length: 1-5 characters lowercase")
        
        total_combinations = self.calculate_total_combinations_phase1()
        
        # Split work
        part_size = total_combinations // max_workers
        ranges = []
        for i in range(max_workers):
            start = i * part_size
            end = total_combinations if i == max_workers - 1 else (i + 1) * part_size
            ranges.append((start, end))
            print(f"  Worker {i}: passwords {start:,} to {end:,}")

        with Manager() as manager:
            found_passwords = manager.list()
            self._lock = manager.Lock()
            self._tested_count = 0
            
            print("🚀 Starting workers...")
            start_time = time.time()
            
            try:
                with Pool(processes=max_workers) as pool:
                    results = []
                    for i, (start, end) in enumerate(ranges):
                        res = pool.apply_async(
                            self._worker_aes_direct,
                            args=(encrypted_data, start, end, found_passwords, i)
                        )
                        results.append(res)
                    
                    # Progress monitoring
                    last_progress = time.time()
                    
                    while True:
                        time.sleep(0.5)  # Check every 0.5 seconds
                        
                        # Check if found
                        if len(found_passwords) > 0:
                            print(f"✅ Password found! Stopping workers...")
                            pool.terminate()
                            pool.join()
                            
                            elapsed = time.time() - start_time
                            tested = self.get_tested_count()
                            print(f"⏱️ Time: {elapsed:.1f}s, Tested: {tested:,}")
                            return found_passwords[0]
                        
                        # Check if all workers are done
                        all_done = all(r.ready() for r in results)
                        if all_done:
                            break
                        
                        # Print progress every 5 seconds
                        current_time = time.time()
                        if current_time - last_progress >= 5:
                            tested = self.get_tested_count()
                            elapsed = current_time - start_time
                            rate = tested / elapsed if elapsed > 0 else 0
                            print(f"⏳ Tested: {tested:,} | Rate: {rate:,.0f}/sec | Time: {elapsed:.1f}s")
                            last_progress = current_time
                    
                    # Clean up if not found
                    pool.close()
                    pool.join()
                
            except KeyboardInterrupt:
                print("\n⚠️ Brute force interrupted by user")
                return None
            except Exception as e:
                print(f"❌ Error: {e}")
                return None
            
            elapsed = time.time() - start_time
            tested = self.get_tested_count()
            print(f"⏱️ Time: {elapsed:.1f}s, Tested: {tested:,}")
            
            if found_passwords:
                return found_passwords[0]
                
        print("❌ Password not found in phase 1")
        return None