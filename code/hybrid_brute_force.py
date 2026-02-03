import itertools
import string
from concurrent.futures import ProcessPoolExecutor, as_completed
from cryptography.fernet import Fernet
import hashlib
import base64
import time
import os
from typing import Optional, Tuple, Generator

class HybridBruteForce:
    """ULTRA-FAST brute force with intelligent ordering"""
    
    def __init__(self):
        self.common_passwords = [
            '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
            '000000', '111111', '222222', '333333', '444444', '555555', '666666', '777777', '888888', '999999',
            'password', 'Password', 'PASSWORD', 'admin', 'Admin', 'ADMIN', 'test', 'Test', 'TEST',
            'hello', 'Hello', 'HELLO', 'welcome', 'Welcome', 'WELCOME', 'abc', 'xyz', 'letmein',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
        ]
        
        self.max_workers = min(8, os.cpu_count() * 2)
        self.found_password = None
        self.tested_count = 0
        self.start_time = None
        self.current_strategy = "Initializing..."
        self.encrypted_data = None
        self.key_cache = {}  # Cache derived keys
        
    def _derive_key(self, password):
        """Cached key derivation"""
        if password not in self.key_cache:
            digest = hashlib.sha256(password.encode()).digest()
            self.key_cache[password] = base64.urlsafe_b64encode(digest)
        return self.key_cache[password]
    
    def _validate_fast(self, encrypted_data: bytes, password: str) -> Tuple[bool, Optional[bytes]]:
        """Ultra-fast validation"""
        try:
            key = self._derive_key(password)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_data)
            return True, decrypted
        except:
            return False, None
    
    # 🚀 INTELLIGENT ORDERING - SHORTEST PASSWORDS FIRST!
    def generate_strategy_1_common(self) -> Generator[Tuple[str, str], None, None]:
        """Strategy 1: Common passwords"""
        self.current_strategy = "🎯 Common passwords"
        for pwd in self.common_passwords:
            yield pwd, f"Common: {pwd}"
    
    def generate_strategy_2_single_chars(self) -> Generator[Tuple[str, str], None, None]:
        """Strategy 2: Single character (a-z) - FASTEST"""
        self.current_strategy = "🔤 Single character (a-z)"
        for char in string.ascii_lowercase:
            yield char, f"Single char: {char}"
    
    def generate_strategy_3_double_chars(self) -> Generator[Tuple[str, str], None, None]:
        """Strategy 3: Two characters (aa-zz)"""
        self.current_strategy = "🔤🔤 Two characters"
        chars = string.ascii_lowercase
        count = 0
        for c1 in chars:
            for c2 in chars:
                yield c1 + c2, f"Double: {c1+c2}"
                count += 1
                if count % 1000 == 0:
                    self.current_strategy = f"🔤🔤 Two chars: {count:,}/676"
    
    def generate_strategy_4_triple_chars(self) -> Generator[Tuple[str, str], None, None]:
        """Strategy 4: Three characters (aaa-zzz)"""
        self.current_strategy = "🔤🔤🔤 Three characters"
        chars = string.ascii_lowercase
        count = 0
        total = 26 ** 3
        
        for combo in itertools.product(chars, repeat=3):
            password = ''.join(combo)
            yield password, f"Triple: {password}"
            count += 1
            if count % 50000 == 0:
                self.current_strategy = f"🔤🔤🔤 Three chars: {count:,}/{total:,}"
    
    def generate_strategy_5_numbers_short(self) -> Generator[Tuple[str, str], None, None]:
        """Strategy 5: Numbers 0-9999"""
        self.current_strategy = "🔢 Numbers 0-9,999"
        for i in range(10000):
            yield str(i), f"Number: {i}"
            if i % 1000 == 0:
                self.current_strategy = f"🔢 Numbers: {i:,}-{i+999:,}"
    
    def generate_strategy_6_four_chars(self) -> Generator[Tuple[str, str], None, None]:
        """Strategy 6: Four characters"""
        self.current_strategy = "🔤🔤🔤🔤 Four characters"
        chars = string.ascii_lowercase
        count = 0
        total = 26 ** 4
        
        for combo in itertools.product(chars, repeat=4):
            password = ''.join(combo)
            yield password, f"Four: {password}"
            count += 1
            if count % 100000 == 0:
                self.current_strategy = f"🔤🔤🔤🔤 Four chars: {count:,}/{total:,}"
    
    def get_strategy_progress(self) -> str:
        """Get current progress status"""
        elapsed = time.time() - self.start_time
        rate = self.tested_count / elapsed if elapsed > 0 else 0
        
        return (f"📊 {self.current_strategy}\n"
                f"⏳ Tested: {self.tested_count:,}\n"
                f"⚡ {rate:,.0f}/sec | Time: {elapsed:.1f}s")
    
    def _worker_task_batch(self, encrypted_data: bytes, password_batch: list) -> Optional[Tuple[str, str]]:
        """Batch validation - SUPER FAST"""
        for password, description in password_batch:
            try:
                # Fast inline validation
                key = self._derive_key(password)
                cipher = Fernet(key)
                cipher.decrypt(encrypted_data)
                return password, description
            except:
                continue
        return None
    
    def brute_force_file_phase1(self, file_path: str, max_workers: int = None, 
                              callback=None, auto_decrypt: bool = True) -> dict:
        """
        ULTRA-FAST brute force with auto-decryption
        """
        if max_workers is None:
            max_workers = self.max_workers
        
        # Setup
        self.start_time = time.time()
        self.tested_count = 0
        self.found_password = None
        self.current_strategy = "Initializing..."
        self.key_cache = {}
        
        # Read file
        try:
            with open(file_path, 'rb') as f:
                self.encrypted_data = f.read()
            file_size = len(self.encrypted_data)
        except Exception as e:
            return {'success': False, 'error': f"Cannot read file: {e}"}
        
        # 🚀 INTELLIGENT ORDER - SHORTEST FIRST!
        strategies = [
            ("🎯 COMMON PASSWORDS", self.generate_strategy_1_common),
            ("🔤 SINGLE CHARACTER", self.generate_strategy_2_single_chars),
            ("🔤🔤 TWO CHARACTERS", self.generate_strategy_3_double_chars),
            ("🔤🔤🔤 THREE CHARACTERS", self.generate_strategy_4_triple_chars),
            ("🔢 NUMBERS 0-9,999", self.generate_strategy_5_numbers_short),
            ("🔤🔤🔤🔤 FOUR CHARACTERS", self.generate_strategy_6_four_chars),
        ]
        
        print("🚀 ULTRA-FAST BRUTE FORCE")
        print(f"📁 File: {os.path.basename(file_path)} ({file_size:,} bytes)")
        print(f"⚡ Workers: {max_workers}")
        print(f"🎯 Order: Shortest passwords first!")
        print("=" * 60)
        
        if callback:
            callback("🚀 Starting ultra-fast brute force...\n")
        
        # Execute strategies
        for strategy_name, generator_func in strategies:
            if self.found_password:
                break
            
            print(f"\n{strategy_name}")
            if callback:
                callback(f"\n{strategy_name}\n")
            
            password_gen = generator_func()
            
            # Progress tracking
            last_update = time.time()
            batch_size = 1000  # Larger batches for speed
            
            try:
                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    futures = {}
                    batch = []
                    
                    while True:
                        # Fill batch
                        try:
                            for _ in range(batch_size):
                                password, description = next(password_gen)
                                batch.append((password, description))
                        except StopIteration:
                            if batch:
                                future = executor.submit(self._worker_task_batch, 
                                                       self.encrypted_data, batch.copy())
                                futures[future] = len(batch)
                                batch = []
                            break
                        
                        # Submit batch
                        if batch:
                            future = executor.submit(self._worker_task_batch, 
                                                   self.encrypted_data, batch.copy())
                            futures[future] = len(batch)
                            batch = []
                        
                        # Check completed futures
                        completed = []
                        for future in list(futures.keys()):
                            if future.done():
                                result = future.result()
                                count = futures[future]
                                
                                if result:
                                    self.found_password = result[0]
                                    description = result[1]
                                    executor.shutdown(wait=False, cancel_futures=True)
                                    print(f"\n✅ FOUND: {description}")
                                    if callback:
                                        callback(f"✅ FOUND: {description}\n")
                                    break
                                else:
                                    self.tested_count += count
                                    completed.append(future)
                        
                        # Remove completed
                        for future in completed:
                            del futures[future]
                        
                        # Check if found
                        if self.found_password:
                            break
                        
                        # Update progress
                        current_time = time.time()
                        if current_time - last_update >= 0.5:  # Faster updates
                            progress = self.get_strategy_progress()
                            print(f"\r{progress}", end="", flush=True)
                            
                            if callback:
                                callback(f"{progress}\n")
                            
                            last_update = current_time
                    
                    # Check remaining if not found
                    if not self.found_password and futures:
                        for future in as_completed(futures.keys()):
                            result = future.result()
                            count = futures[future]
                            
                            if result:
                                self.found_password = result[0]
                                description = result[1]
                                print(f"\n✅ FOUND: {description}")
                                if callback:
                                    callback(f"✅ FOUND: {description}\n")
                                break
                            else:
                                self.tested_count += count
            
            except KeyboardInterrupt:
                print(f"\n⚠️ Interrupted")
                if callback:
                    callback(f"⚠️ Interrupted\n")
                break
            
            except Exception as e:
                print(f"\n❌ Error: {e}")
                if callback:
                    callback(f"❌ Error: {e}\n")
                continue
            
            # Strategy complete
            elapsed = time.time() - self.start_time
            print(f"\n✅ {strategy_name}: {self.tested_count:,} in {elapsed:.1f}s")
        
        # Final result
        elapsed = time.time() - self.start_time
        rate = self.tested_count / elapsed if elapsed > 0 else 0
        
        if self.found_password:
            # 🔓 AUTO-DECRYPTION
            decrypted_data = None
            decrypted_file = None
            
            if auto_decrypt:
                try:
                    from aes_crypto import AESEncryption
                    aes = AESEncryption()
                    
                    # Create output filename
                    base_name = os.path.basename(file_path)
                    if base_name.endswith('.bin'):
                        output_file = base_name.replace('.bin', '_decrypted')
                    else:
                        output_file = f"decrypted_{base_name}"
                    
                    # Ensure unique
                    counter = 1
                    while os.path.exists(output_file):
                        name_parts = output_file.split('.')
                        if len(name_parts) > 1:
                            output_file = f"{name_parts[0]}_{counter}.{'.'.join(name_parts[1:])}"
                        else:
                            output_file = f"{output_file}_{counter}"
                        counter += 1
                    
                    # Decrypt file
                    decrypted_data = aes.decrypt_file(file_path, self.found_password, output_file)
                    
                    if decrypted_data is not None:
                        decrypted_file = output_file
                        print(f"\n🔓 File decrypted: {decrypted_file}")
                        if callback:
                            callback(f"\n🔓 File decrypted: {decrypted_file}\n")
                except Exception as e:
                    print(f"⚠️ Auto-decrypt failed: {e}")
            
            result_str = (
                f"🎉 PASSWORD FOUND!\n"
                f"🔑 Password: '{self.found_password}'\n"
                f"⏱️  Time: {elapsed:.3f}s\n"
                f"📊 Tested: {self.tested_count:,}\n"
                f"⚡ Speed: {rate:,.0f}/sec\n"
                f"🎯 Found in: {self.current_strategy}"
            )
            
            if decrypted_file:
                result_str += f"\n📁 Decrypted: {decrypted_file}"
            
            print("=" * 60)
            print(result_str)
            print("=" * 60)
            
            if callback:
                callback(f"\n{result_str}\n")
            
            return {
                'success': True,
                'password': self.found_password,
                'time_elapsed': elapsed,
                'tested_count': self.tested_count,
                'rate_per_sec': rate,
                'method': self.current_strategy,
                'decrypted_file': decrypted_file,
                'decrypted_data': decrypted_data
            }
        else:
            result_str = (
                f"❌ Password not found\n"
                f"⏱️  Time: {elapsed:.2f}s\n"
                f"📊 Tested: {self.tested_count:,}\n"
                f"⚡ Speed: {rate:,.0f}/sec"
            )
            
            print("=" * 60)
            print(result_str)
            print("=" * 60)
            
            if callback:
                callback(f"\n{result_str}\n")
            
            return {
                'success': False,
                'error': 'Password not found',
                'time_elapsed': elapsed,
                'tested_count': self.tested_count,
                'rate_per_sec': rate
            }
            
    def brute_force_and_decrypt(self, file_path, max_workers=None, callback=None):
        """
        Combined brute force + auto-decrypt in one method
        Returns: {'success': bool, 'password': str, 'decrypted_file': str, 'message': str}
        """
        from aes_crypto import AESEncryption
        
        aes = AESEncryption()
        
        # Step 1: Brute force
        brute_result = self.brute_force_file_phase1(
            file_path, 
            max_workers=max_workers,
            callback=callback,
            auto_decrypt=False  # We'll handle decryption ourselves
        )
        
        if not brute_result['success']:
            return brute_result
        
        # Step 2: Auto-decrypt with found password
        password = brute_result['password']
        
        if callback:
            callback(f"\n🔓 Auto-decrypting file with password '{password}'...\n")
        
        decrypt_result = aes.auto_decrypt_with_password(file_path, password)
        
        if decrypt_result['success']:
            final_result = {
                'success': True,
                'password': password,
                'decrypted_file': decrypt_result['decrypted_file'],
                'size': decrypt_result['size'],
                'brute_time': brute_result['time_elapsed'],
                'tested_count': brute_result['tested_count'],
                'message': (
                    f"✅ PASSWORD FOUND & FILE DECRYPTED!\n"
                    f"🔑 Password: '{password}'\n"
                    f"📁 Decrypted: {decrypt_result['decrypted_file']}\n"
                    f"💾 Size: {decrypt_result['size']:,} bytes\n"
                    f"⏱️  Brute force time: {brute_result['time_elapsed']:.2f}s\n"
                    f"📊 Tested: {brute_result['tested_count']:,} passwords"
                )
            }
        else:
            final_result = {
                'success': True,
                'password': password,
                'brute_time': brute_result['time_elapsed'],
                'tested_count': brute_result['tested_count'],
                'message': (
                    f"✅ PASSWORD FOUND: '{password}'\n"
                    f"⚠️  But auto-decryption failed: {decrypt_result.get('error', 'Unknown')}\n"
                    f"⏱️  Brute force time: {brute_result['time_elapsed']:.2f}s"
                )
            }
        
        return final_result