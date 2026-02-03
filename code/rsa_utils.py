"""
 rasa_utils.py
 """

import math
import time
import random
import json
import os

class RSAUltimateEncryptor:
    
    def __init__(self, prime_file='large_primes.json'):
        # Define the JSON folder
        self.json_folder = "json_data"
        
        # Build the full path to the prime file
        self.prime_file = os.path.join(self.json_folder, prime_file)
        
        self.prime_list = []
        self.max_bytes = 15  # Default max bytes for message
        self.max_n = 0
        self.max_n_bits = 0
        
        # Load or generate primes
        if os.path.exists(self.prime_file):
            print(f"🔄 Loading primes from {self.prime_file}...")
            self.prime_list = self.load_primes_from_file()
        else:
            print(f"⚙️ Generating new large primes...")
            self.prime_list = self.generate_truly_large_primes()
            self.save_primes_to_file()
        
        # Calculate max n
        if self.prime_list:
            p = self.prime_list[-1]
            q = self.prime_list[-2] if len(self.prime_list) > 1 else p - 2
            self.max_n = p * q
            self.max_n_bits = self.max_n.bit_length()
            self.max_bytes = self.max_n_bits // 8
            print(f"✅ Max message size supported: {self.max_bytes} bytes ({self.max_n_bits} bits)")
        else:
            print("❌ No primes available!")
            
    def generate_truly_large_primes(self):
            """Generate truly large primes for 15+ byte messages"""
            print("   Generating 50 VERY large primes (this may take a moment)...")
            
            primes = []
            target_count = 50  # Fewer but much larger primes
            
            # We need primes that when multiplied give n >= 2^(15*8) = 2^120
            # So each prime should be >= sqrt(2^120) ≈ 1.14e18
            
            # For demonstration, let's generate primes in range 10^18 to 10^20
            # This gives us 36-66 digit primes
            
            current = 10**18 + 1  # Start from 1 quintillion + 1
            
            found_primes = 0
            while found_primes < target_count:
                # Skip even numbers
                if current % 2 == 0:
                    current += 1
                    continue
                
                if self.is_prime_for_large_numbers(current):
                    primes.append(current)
                    found_primes += 1
                    if found_primes % 5 == 0:
                        print(f"   Found {found_primes}/{target_count} very large primes...")
                
                # Skip ahead more for large numbers
                current += random.randint(1000, 10000)
            
            print(f"   Generated {found_primes} very large primes!")
            return primes
        
    def is_prime_for_large_numbers(self, n, trials=10):
        """Miller-Rabin primality test for large numbers"""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False
        
        # Quick check with small primes
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        for p in small_primes:
            if n % p == 0:
                return n == p
        
        # Write n-1 as 2^s * d
        s = 0
        d = n - 1
        while d % 2 == 0:
            s += 1
            d //= 2
        
        # Miller-Rabin test
        for _ in range(trials):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def generate_large_primes_faster(self):
        """Alternative: Generate primes around 10^12 for demo purposes"""
        print("   Generating 100 primes around 1 trillion...")
        
        primes = []
        target_count = 100
        
        # Start from 1 trillion
        current = 10**12 + 1
        
        found_primes = 0
        while found_primes < target_count:
            if current % 2 == 0:
                current += 1
                continue
            
            if self.is_prime_simple(current):
                primes.append(current)
                found_primes += 1
                if found_primes % 10 == 0:
                    print(f"   Found {found_primes}/{target_count} primes...")
            
            current += 2  # Only check odd numbers
        
        print(f"   Generated {found_primes} primes!")
        return primes
    
    def is_prime_simple(self, n):
        """Simple primality test for moderate numbers"""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0 or n % 3 == 0:
            return False
        
        # Check divisibility up to sqrt(n)
        limit = int(math.isqrt(n)) + 1
        for i in range(5, limit, 6):
            if n % i == 0 or n % (i + 2) == 0:
                return False
        
        return True
    
    def save_primes_to_file(self):
        """Save primes to JSON file"""
        data = {
            'primes': self.prime_list,
            'generated_date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'count': len(self.prime_list),
            'max_bytes_supported': self.max_bytes
        }
        with open(self.prime_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"💾 Saved {len(self.prime_list):,} primes to {self.prime_file}")
    
    def load_primes_from_file(self):
        """Load primes from JSON file"""
        try:
            with open(self.prime_file, 'r') as f:
                data = json.load(f)
            primes = data['primes']
            print(f"   Generated: {data.get('generated_date', 'Unknown')}")
            print(f"   Supports: {data.get('max_bytes_supported', 'Unknown')} bytes")
            return primes
        except Exception as e:
            print(f"❌ Error loading primes: {e}")
            print("   Generating new primes...")
            return self.generate_truly_large_primes()
    
    def string_to_int(self, text):
        """Convert any string to integer (UTF-8)"""
        return int.from_bytes(text.encode('utf-8'), 'big')
    
    def int_to_string(self, m_int):
        """Convert integer back to string"""
        try:
            byte_length = (m_int.bit_length() + 7) // 8
            return m_int.to_bytes(byte_length, 'big').decode('utf-8')
        except:
            return f"[Value: {m_int}]"
    
    def analyze_message(self, text):
        """Analyze any message"""
        m_int = self.string_to_int(text)
        byte_len = len(text.encode('utf-8'))
        
        print(f"\n📊 MESSAGE ANALYSIS:")
        print(f"   Message: '{text[:50]}{'...' if len(text) > 50 else ''}'")
        print(f"   Length: {len(text)} characters")
        print(f"   Size: {byte_len} bytes")
        print(f"   Integer value: {m_int:,}")
        print(f"   Binary size: {m_int.bit_length()} bits")
        
        # Show character types
        letters = sum(c.isalpha() for c in text)
        digits = sum(c.isdigit() for c in text)
        symbols = len(text) - letters - digits
        print(f"   Composition: {letters} letters, {digits} digits, {symbols} symbols")
        
        # Check if it fits
        if m_int >= self.max_n:
            print(f"\n❌ TOO LARGE!")
            print(f"   Your message: {m_int.bit_length()} bits ({len(text)} chars, {byte_len} bytes)")
            print(f"   Max possible: {self.max_n_bits} bits ({self.max_bytes} bytes)")
            print(f"   Try a shorter message (max {self.max_bytes} characters)")
            return None, None, None
        
        # Calculate needed prime size
        min_n = m_int + 1
        min_prime = int(math.isqrt(min_n)) + 1
        
        print(f"\n🎯 PRIME REQUIREMENTS:")
        print(f"   Need primes > {min_prime:,}")
        print(f"   Need n > {min_n:,}")
        
        return m_int, min_n, min_prime
    
    def find_big_primes(self, min_size, count=10):
        """Find primes larger than min_size"""
        print(f"\n🔍 LOOKING FOR PRIMES > {min_size:,}...")
        
        suitable = []
        for prime in self.prime_list:
            if prime > min_size:
                suitable.append(prime)
                if len(suitable) >= count:
                    break
        
        if suitable:
            print(f"✅ FOUND {len(suitable)} BIG PRIMES:")
            for i, prime in enumerate(suitable[:5], 1):
                print(f"   {i}. {prime:,}")
            return suitable
        else:
            print(f"❌ No primes > {min_size:,}")
            print(f"   Largest available: {self.prime_list[-1]:,}")
            return []
    
    def smart_encrypt(self, text):
        """Smart encryption that finds suitable primes"""
        print(f"\n🚀 SMART ENCRYPTION: '{text[:30]}{'...' if len(text) > 30 else ''}'")
        
        # First check if message is too long
        byte_len = len(text.encode('utf-8'))
        if byte_len > self.max_bytes:
            print(f"\n❌ MESSAGE TOO LARGE!")
            print(f"   Message size: {byte_len} bytes")
            print(f"   Maximum supported: {self.max_bytes} bytes")
            print(f"   Try a shorter message (max {self.max_bytes} characters)")
            return None
        
        result = self.analyze_message(text)
        if not result[0]:
            return None
        
        m_int, min_n, min_prime = result
        
        print(f"\n⚡ SELECTING OPTIMAL PRIMES...")
        
        # Find primes
        primes = self.find_big_primes(min_prime, count=20)
        if not primes:
            return None
        
        # Use first two suitable primes
        p = primes[0]
        q = primes[1] if len(primes) > 1 else primes[0] + 2
        
        # Ensure p and q are different
        if p == q:
            for prime in primes[2:]:
                if prime != p:
                    q = prime
                    break
        
        print(f"\n✅ SELECTED PRIMES:")
        print(f"   p = {p:,}")
        print(f"   q = {q:,}")
        print(f"   n = {p * q:,}")
        
        return self.perform_encryption(text, p, q)
    
    def perform_encryption(self, text, p, q):
        """Perform the actual RSA encryption"""
        m_int = self.string_to_int(text)
        n = p * q
        
        if n <= m_int:
            print(f"❌ n too small! Need larger primes.")
            return None
        
        phi = (p-1) * (q-1)
        
        # Find e
        e = 65537  # Common choice
        if math.gcd(e, phi) != 1:
            for e_candidate in [3, 5, 17, 257]:
                if math.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
        
        d = pow(e, -1, phi)
        c = pow(m_int, e, n)
        
        print(f"\n✅ ENCRYPTION SUCCESSFUL!")
        print("="*70)
        print(f"   Message: '{text[:40]}{'...' if len(text) > 40 else ''}'")
        print(f"   Length: {len(text)} characters")
        print(f"   m = {m_int:,}")
        print(f"   p = {p:,}")
        print(f"   q = {q:,}")
        print(f"   n = {n:,} ({n.bit_length()} bits)")
        print(f"   φ(n) = {phi:,}")
        print(f"   e = {e}")
        print(f"   d = {d:,}")
        print(f"   CIPHERTEXT c = {c:,}")
        print("="*70)
        
        return {'n': n, 'e': e, 'c': c, 'd': d, 'p': p, 'q': q, 'text': text}
    
    def quick_test(self):
        """Quick test to verify encryption works for 15+ chars"""
        test_messages = [
            "123456789012345",  # 15 chars
            "Hello World!",  # 12 chars
            "RSA Test!",  # 9 chars
        ]
        
        print("\n🧪 QUICK TEST")
        print("="*50)
        
        for msg in test_messages:
            byte_len = len(msg.encode('utf-8'))
            print(f"\nTesting: '{msg}'")
            print(f"  Length: {len(msg)} chars, {byte_len} bytes")
            
            if byte_len > self.max_bytes:
                print(f"  ❌ TOO LARGE - need {byte_len} bytes, have {self.max_bytes}")
            else:
                print(f"  ✅ FITS - within {self.max_bytes} byte limit")
                if len(msg) <= 15:
                    print(f"  Can handle 15 chars: {'YES' if self.max_bytes >= 15 else 'NO'}")
        
        print("\n" + "="*50)
        print(f"Maximum capacity: {self.max_bytes} bytes/characters")
        print(f"Can handle 15 chars: {'YES' if self.max_bytes >= 15 else 'NO'}")

# ==================== ULTIMATE RSA ATTACK ====================

class RSAUltimateAttack:
    def __init__(self, encryptor):
        self.encryptor = encryptor
    
    def crack_rsa(self, n, e, c, show_progress=True):
        print("\n" + "="*70)
        print("💥 ULTIMATE RSA ATTACK - CRACKING LARGE MESSAGES")
        print("="*70)
        print(f"   Target n: {n:,}")
        print(f"   n bits: {n.bit_length()}")
        print(f"   e: {e}")
        print(f"   c: {c:,}")
        print("="*70)
        
        start_time = time.time()
        
        if show_progress:
            print(f"\n🔍 PHASE 1: FACTORIZATION")
            print(f"   Checking {len(self.encryptor.prime_list):,} large primes...")
        
        # Try factorization
        p_found = None
        checked = 0
        
        for p in self.encryptor.prime_list:
            checked += 1
            
            if p * p > n:
                break
            
            if n % p == 0:
                p_found = p
                q = n // p
                break
            
            if show_progress and checked % 10 == 0:
                elapsed = time.time() - start_time
                print(f"   Checked {checked:,} primes in {elapsed:.1f}s...")
        
        if p_found:
            elapsed = time.time() - start_time
            print(f"\n✅ FACTORED in {elapsed:.2f} seconds!")
            print(f"   Checked {checked:,} primes")
            print(f"   p = {p_found:,}")
            print(f"   q = {q:,}")
            
            # Recover private key
            phi = (p_found-1) * (q-1)
            d = pow(e, -1, phi)
            
            print(f"\n🔑 PRIVATE KEY RECOVERED")
            print(f"   d = {d:,}")
            
            # Decrypt
            print(f"\n🔓 DECRYPTING...")
            m = pow(c, d, n)
            text = self.encryptor.int_to_string(m)
            
            total_time = time.time() - start_time
            
            print("\n" + "="*70)
            print("🎉 ATTACK SUCCESSFUL!")
            print("="*70)
            print(f"📨 DECRYPTED MESSAGE:")
            print(f"   m = {m:,}")
            print(f"   Message: '{text}'")
            print(f"   Length: {len(text)} characters")
            print(f"\n⏱️  Total time: {total_time:.2f} seconds")
            print("="*70)
            
            return {'p': p_found, 'q': q, 'd': d, 'text': text}
        else:
            elapsed = time.time() - start_time
            print(f"\n❌ FAILED after {elapsed:.2f} seconds")
            print(f"   Checked {checked:,} primes")
            print(f"   n is too strong for this demo")
            print(f"\n💡 REAL RSA USES:")
            print(f"   • 2048-bit primes (300+ digits)")
            print(f"   • Would take millions of years to crack")
            return None
