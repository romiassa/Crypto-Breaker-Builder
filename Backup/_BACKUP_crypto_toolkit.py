# crypto_toolkit.py
"""
COMPLETE CRYPTO TOOLKIT - FIXED FOR COMPATIBILITY WITH AESEncryption
"""

from brute_force import UltimateBruteForce
import hashlib
import base64
from cryptography.fernet import Fernet
import os
import time
from typing import Optional
from aes_crypto import AESEncryption

class CryptoToolkit:
    """
    Complete toolkit for:
    1. Encrypting files (Fernet format)
    2. Decrypting files (with password)
    3. Brute forcing encrypted files
    4. Batch processing
    
    NOW COMPATIBLE WITH AESEncryption class
    """
    
    def __init__(self):
        self.brute_force = UltimateBruteForce()
    
    def encrypt_file(self, input_file: str, output_file: str, password: str) -> bool:
        """
        Encrypt any file using Fernet - SAME as AESEncryption.encrypt_file()
        """
        try:
            # Read file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Encrypt (SAME as AESEncryption)
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            cipher = Fernet(key)
            encrypted = cipher.encrypt(data)
            
            # Save
            with open(output_file, 'wb') as f:
                f.write(encrypted)
            
            print(f"✅ ENCRYPTED: {input_file} → {output_file}")
            print(f"   Password: '{password}'")
            print(f"   Size: {len(data):,} → {len(encrypted):,} bytes")
            
            return True
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return False
    
    def decrypt_file(self, encrypted_file: str, output_file: str, 
                    password: str) -> bool:
        """
        Decrypt file with known password - SAME as AESEncryption.decrypt_file()
        """
        try:
            # Read encrypted file
            with open(encrypted_file, 'rb') as f:
                encrypted = f.read()
            
            # Decrypt (SAME as AESEncryption)
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted)
            
            # Save
            with open(output_file, 'wb') as f:
                f.write(decrypted)
            
            print(f"✅ DECRYPTED: {encrypted_file} → {output_file}")
            print(f"   Password: '{password}'")
            print(f"   Size: {len(decrypted):,} bytes")
            
            return True
            
        except Exception as e:
            print(f"❌ Decryption failed (wrong password?): {e}")
            return False
    
    def brute_force_file(self, encrypted_file: str, max_workers: int = 8) -> dict:
        """
        Brute force an encrypted file - SAME as AESEncryption.brute_force_file_decrypt_fast()
        """
        print(f"🔓 BRUTE FORCING: {encrypted_file}")
        print(f"⚡ Threads: {max_workers}")
        print("="*60)
        
        # Read file
        with open(encrypted_file, 'rb') as f:
            data = f.read()
        
        # Convert to string for brute_force_aes
        try:
            data_str = data.decode('latin1')
        except:
            data_str = data.decode('latin1', errors='ignore')
        
        # Run brute force (SAME as AESEncryption)
        start_time = time.time()
        result = self.brute_force.brute_force_aes(data_str, max_workers)
        elapsed = time.time() - start_time
        
        if result.get('success'):
            print(f"✅ Password found: {result['password']}")
            
            # Decrypt and save
            try:
                key = base64.urlsafe_b64encode(hashlib.sha256(result['password'].encode()).digest())
                cipher = Fernet(key)
                decrypted = cipher.decrypt(data)
                
                # Create output filename
                base_name = os.path.basename(encrypted_file)
                if base_name.endswith('.bin'):
                    output_file = base_name[:-4] + '_decrypted'
                elif '.' in base_name:
                    parts = base_name.split('.')
                    output_file = parts[0] + '_decrypted.' + '.'.join(parts[1:])
                else:
                    output_file = base_name + '_decrypted'
                
                # Ensure unique name
                counter = 1
                original_name = output_file
                while os.path.exists(output_file):
                    output_file = f"{original_name}_{counter}"
                    counter += 1
                
                with open(output_file, 'wb') as f:
                    f.write(decrypted)
                
                result['file_path'] = os.path.abspath(output_file)
                result['file_size'] = len(decrypted)
                
                # Add preview
                try:
                    preview = decrypted[:500].decode('utf-8', errors='ignore')
                    result['content'] = preview
                except:
                    result['content'] = "[Binary data]"
                
                print(f"💾 Decrypted file saved: {output_file} ({len(decrypted):,} bytes)")
                
            except Exception as e:
                result['decryption_error'] = str(e)
                print(f"⚠️ Decryption failed: {e}")
        
        result['total_time'] = f"{elapsed:.2f}s"
        result['time_elapsed'] = f"{elapsed:.2f}s"
        return result
    
    # NEW: Added for direct compatibility
    def brute_force_file_compatible(self, encrypted_file: str, max_workers: int = 8) -> dict:
        """Alias for brute_force_file for interface compatibility"""
        return self.brute_force_file(encrypted_file, max_workers)
    
    def batch_encrypt(self, files: list, password: str, 
                     output_dir: str = "encrypted") -> dict:
        """
        Encrypt multiple files
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        results = {
            'success': [],
            'failed': [],
            'total': len(files)
        }
        
        print(f"🔐 BATCH ENCRYPTING {len(files)} FILES")
        print(f"📁 Output directory: {output_dir}")
        print(f"🔑 Password: '{password}'")
        print("="*60)
        
        for i, file_path in enumerate(files):
            if not os.path.exists(file_path):
                print(f"❌ File not found: {file_path}")
                results['failed'].append((file_path, "File not found"))
                continue
            
            # Create output filename
            base_name = os.path.basename(file_path)
            output_file = os.path.join(output_dir, f"{base_name}.encrypted")
            
            print(f"\n[{i+1}/{len(files)}] Encrypting: {file_path}")
            
            if self.encrypt_file(file_path, output_file, password):
                results['success'].append((file_path, output_file))
            else:
                results['failed'].append((file_path, "Encryption failed"))
        
        print(f"\n✅ BATCH COMPLETE")
        print(f"   Success: {len(results['success'])} files")
        print(f"   Failed: {len(results['failed'])} files")
        
        return results
    
    def benchmark_brute_force(self, test_password: str = "test123", 
                             file_size_kb: int = 100) -> dict:
        """
        Benchmark brute force speed
        """
        print("⚡ BRUTE FORCE BENCHMARK")
        print("="*60)
        
        # Create test file
        test_data = os.urandom(file_size_kb * 1024)
        test_file = "benchmark_test.bin"
        
        # Encrypt it
        key = base64.urlsafe_b64encode(hashlib.sha256(test_password.encode()).digest())
        cipher = Fernet(key)
        encrypted = cipher.encrypt(test_data)
        
        with open(test_file, 'wb') as f:
            f.write(encrypted)
        
        print(f"📊 Created test file: {len(encrypted):,} bytes")
        print(f"🔑 Test password: '{test_password}'")
        
        # Test different thread counts
        thread_counts = [1, 2, 4, 8, 12, 16]
        results = {}
        
        for threads in thread_counts:
            print(f"\n🧪 Testing with {threads} threads...")
            
            with open(test_file, 'rb') as f:
                data = f.read()
            
            # Convert to string
            data_str = data.decode('latin1')
            
            # Warm up
            print(f"   Warming up...")
            for _ in range(3):
                self.brute_force.brute_force_aes("dummy", 1)
            
            # Actual test
            print(f"   Starting benchmark...")
            start_time = time.time()
            result = self.brute_force.brute_force_aes(data_str, threads)
            elapsed = time.time() - start_time
            
            if result['success']:
                speed = result['tested_count'] / elapsed if elapsed > 0 else 0
                results[threads] = {
                    'speed': f"{speed:,.0f} passwords/sec",
                    'time': f"{elapsed:.2f}s",
                    'tested': result['tested_count'],
                    'found_password': True
                }
                print(f"   ✅ Found password in {elapsed:.2f}s")
                print(f"   ⚡ Speed: {speed:,.0f} passwords/sec")
            else:
                speed = result['tested_count'] / elapsed if elapsed > 0 else 0
                results[threads] = {
                    'speed': f"{speed:,.0f} passwords/sec",
                    'time': f"{elapsed:.2f}s",
                    'tested': result['tested_count'],
                    'found_password': False
                }
                print(f"   ⏱️  Time: {elapsed:.2f}s")
                print(f"   ⚡ Speed: {speed:,.0f} passwords/sec")
        
        # Clean up
        os.remove(test_file)
        
        print(f"\n📈 BENCHMARK RESULTS:")
        print("Threads | Speed (passwords/sec) | Time")
        print("-" * 40)
        for threads, data in results.items():
            print(f"{threads:7d} | {data['speed']:>20} | {data['time']}")
        
        return results
    
    def create_password_strength_tester(self):
        """
        Test how strong passwords are against your brute force
        """
        print("🛡️  PASSWORD STRENGTH TESTER")
        print("="*60)
        
        test_passwords = [
            "123",           # Very weak
            "123456",        # Weak
            "password",      # Weak
            "P@ssw0rd",     # Medium
            "Str0ngP@ss!23" # Strong
        ]
        
        print("Testing password strength against your brute force:")
        print("="*60)
        
        for password in test_passwords:
            print(f"\n🔐 Password: '{password}'")
            print(f"   Length: {len(password)}")
            
            # Analyze complexity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(not c.isalnum() for c in password)
            
            complexity_score = sum([has_upper, has_lower, has_digit, has_special])
            
            print(f"   Complexity: {complexity_score}/4")
            if has_upper: print("     ✓ Uppercase")
            if has_lower: print("     ✓ Lowercase")
            if has_digit: print("     ✓ Digits")
            if has_special: print("     ✓ Special chars")
            
            # Estimate brute force time
            if len(password) <= 3:
                print(f"   ⏱️  Estimated crack time: < 1 second")
                print(f"   ⚠️  VERY WEAK")
            elif len(password) <= 5 and password.isdigit():
                print(f"   ⏱️  Estimated crack time: < 10 seconds")
                print(f"   ⚠️  WEAK")
            elif len(password) <= 6:
                print(f"   ⏱️  Estimated crack time: < 1 minute")
                print(f"   ⚠️  WEAK")
            elif len(password) <= 8 and complexity_score >= 3:
                print(f"   ⏱️  Estimated crack time: < 1 hour")
                print(f"   ⚠️  MEDIUM")
            elif len(password) >= 12 and complexity_score >= 3:
                print(f"   ⏱️  Estimated crack time: Years")
                print(f"   ✅ STRONG")
            else:
                print(f"   ⏱️  Estimated crack time: Hours to days")
                print(f"   ⚠️  MEDIUM")
                
    def encrypt_file_fast_check(self, input_file: str, output_file: str, password: str) -> bool:
        """
        Encrypt file with fast check header
        """
        try:
            # Use AESEncryption's fast method
            aes = AESEncryption()
            return aes.encrypt_file_fast(input_file, output_file, password)
            
        except Exception as e:
            print(f"❌ Fast encryption failed: {e}")
            return False
    
    def brute_force_file_phase1_fast(self, encrypted_file: str, max_workers: int = 8) -> dict:
        """
        Ultra-fast brute force using Phase 1 strategies only
        """
        print(f"🚀 **PHASE 1 FAST BRUTE FORCE**")
        print(f"📁 File: {encrypted_file}")
        
        try:
            aes = AESEncryption()
            result = aes.brute_force_file_fast(encrypted_file, max_workers)
            return result
            
        except Exception as e:
            print(f"❌ Fast brute force failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }
    
    def brute_force_file_smart(self, encrypted_file: str, max_workers: int = 8) -> dict:
        """
        Smart brute force - tries fast first, then full if needed
        """
        print(f"🎯 **SMART BRUTE FORCE**")
        
        # First try fast method
        fast_result = self.brute_force_file_phase1_fast(encrypted_file, max_workers)
        
        if fast_result.get('success'):
            return fast_result
        
        # If not found, try full brute force
        print(f"\n🔄 Fast method failed, trying FULL brute force...")
        return self.brute_force_file(encrypted_file, max_workers)