'''
auto_crack_modern
'''
import base64
import re
from brute_force import AdvancedBruteForce

class ModernCryptoCracker:
    def __init__(self):
        self.brute_force = AdvancedBruteForce()
    
    def _is_likely_base64(self, text):
        """Check if text is likely Base64 encoded"""
        if not text:
            return False
        
        # Base64 characteristics
        clean_text = text.replace(" ", "").replace("\n", "").replace("\t", "")
        
        # Check length (Base64 is usually multiple of 4)
        if len(clean_text) % 4 not in [0, 2, 3]:
            return False
        
        # Check character set (Base64 uses A-Za-z0-9+/=)
        base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        if not all(c in base64_chars for c in clean_text):
            return False
        
        # Check if it decodes to something reasonable
        try:
            for padding in ['', '=', '==', '===']:
                try:
                    test_text = clean_text + padding
                    decoded_bytes = base64.b64decode(test_text, validate=True)
                    decoded_text = decoded_bytes.decode('utf-8', errors='strict')
                    if self._is_readable_text(decoded_text):
                        return True
                except:
                    continue
        except:
            pass
        
        return False
    
    def _is_likely_aes(self, text):
        """Check if text is likely AES encrypted"""
        if not text:
            return False
        
        # AES/Fernet encrypted data characteristics
        # Fernet tokens are URL-safe base64, 32+ bytes when decoded
        try:
            # Check if it's URL-safe base64 (Fernet uses this)
            clean_text = text.replace(" ", "").replace("\n", "")
            if len(clean_text) < 44:  # Minimum Fernet token size
                return False
            
            # Try to decode as base64
            decoded = base64.urlsafe_b64decode(clean_text + '=' * (4 - len(clean_text) % 4))
            
            # Fernet tokens are exactly 32 bytes when decoded from base64
            if len(decoded) == 32:
                return True
                
            # Or check for general binary data characteristics
            if len(decoded) > 16:  # Reasonable encrypted data size
                return True
                
        except:
            pass
        
        return False
    
    def crack_base64(self, text):
        """ONLY Base64 decoding - no garbage results"""
        try:
            print(f"🔍 Attempting Base64 decode...")
            
            clean_text = text.replace(" ", "").replace("\n", "").replace("\t", "")
            
            for padding in ['', '=', '==', '===']:
                try:
                    test_text = clean_text + padding
                    decoded_bytes = base64.b64decode(test_text, validate=True)
                    decoded_text = decoded_bytes.decode('utf-8', errors='strict')
                    
                    # STRICT validation - must be readable
                    if self._is_readable_text(decoded_text):
                        print(f"✅ VALID Base64: '{decoded_text}'")
                        return {
                            'success': True,
                            'cipher': 'Base64',
                            'text': decoded_text,
                            'score': 95,  # High score for valid Base64
                            'confidence': 'Very High'
                        }
                except:
                    continue
            
            return {'success': False, 'error': 'Not valid Base64'}
            
        except Exception as e:
            print(f"🔍 Base64 failed: {e}")
            return {'success': False, 'error': 'Base64 decoding failed'}
    
    def crack_aes(self, encrypted_text):
        """ONLY attempt AES if it looks like encrypted data"""
        print(f"🔐 Starting AES crack...")
        result = self.brute_force.brute_force_aes(encrypted_text, max_workers=6)
        
        if result['success']:
            decrypted_text = result.get('text', '')
            
            # Only consider it successful if we get readable text
            if self._is_readable_text(decrypted_text):
                score = self._calculate_text_score(decrypted_text)
                
                return {
                    'success': True,
                    'cipher': 'AES',
                    'text': decrypted_text,
                    'password': result['password'],
                    'score': score,
                    'confidence': 'Very High' if score > 90 else 'High',
                    'tested_passwords': result.get('tested_count', 0),
                    'time': result.get('time_elapsed', 'N/A'),
                    'method': result.get('method', 'Brute Force')
                }
            else:
                return {'success': False, 'error': 'AES decryption produced unreadable text'}
        else:
            return {'success': False, 'error': result.get('error', 'AES decryption failed')}
    
    def _is_readable_text(self, text):
        """Check if text is readable (not garbage)"""
        if not text or len(text) < 2:
            return False
        
        # Check for control characters (except common ones like \n, \t)
        if re.search(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', text):
            return False
        
        # Check if it's mostly printable characters
        printable = sum(1 for c in text if c.isprintable() or c in ' \t\n\r')
        if printable / len(text) < 0.9:  # 90% must be printable
            return False
        
        # Check for reasonable word lengths
        words = text.split()
        if words:
            avg_word_length = sum(len(word) for word in words) / len(words)
            if avg_word_length > 20:  # Unusually long "words"
                return False
        
        return True
    
    def _calculate_text_score(self, text):
        """Calculate quality score for decrypted text"""
        if not text:
            return 0
        
        score = 60  # Base score for successful decryption
        
        # Bonus for common words
        common_words = ['hello', 'the', 'and', 'password', 'test', 'admin', 'welcome', 'secret', 'message']
        found_common = sum(1 for word in common_words if word in text.lower())
        score += min(20, found_common * 5)
        
        # Bonus for proper structure
        if ' ' in text and len(text) > 5:
            score += 10
        if any(punc in text for punc in '.!?,;:'):
            score += 10
        
        return min(100, score)
    
    def auto_crack(self, text):
        """SMART auto-crack that detects cipher type first"""
        if not text or len(text.strip()) < 5:
            return {'success': False, 'error': 'Text too short'}
        
        print(f"\n" + "="*60)
        print(f"🎯 STARTING SMART AUTO-CRACK")
        print(f"🎯 Input: {text[:50]}...")
        print(f"🎯 Length: {len(text)} characters")
        print("="*60)
        
        results = []
        
        # DETECTION PHASE: Figure out what type of data we have
        print("\n🔍 ANALYZING INPUT DATA...")
        
        is_base64 = self._is_likely_base64(text)
        is_aes = self._is_likely_aes(text)
        
        print(f"📊 Base64 likely: {is_base64}")
        print(f"📊 AES likely: {is_aes}")
        
        # EXECUTION PHASE: Try appropriate methods based on detection
        if is_base64:
            print("\n1. 🔍 DECODING BASE64 (Detected as likely Base64)...")
            base64_result = self.crack_base64(text)
            if base64_result['success']:
                results.append(base64_result)
                print("✅ BASE64 SUCCESS!")
            else:
                print("❌ Base64 failed")
        
        if is_aes or not is_base64:  # Try AES if it looks encrypted OR if Base64 failed
            print("\n2. 🔐 CRACKING AES (Detected as likely encrypted)...")
            aes_result = self.crack_aes(text)
            if aes_result['success']:
                results.append(aes_result)
                print("✅ AES SUCCESS!")
            else:
                print(f"❌ AES failed: {aes_result.get('error', 'Unknown error')}")
        
        # If nothing detected but we have data, try both
        if not results and not is_base64 and not is_aes:
            print("\n🔄 TRYING ALL METHODS (No clear detection)...")
            
            base64_result = self.crack_base64(text)
            if base64_result['success']:
                results.append(base64_result)
                print("✅ BASE64 SUCCESS!")
            
            aes_result = self.crack_aes(text)
            if aes_result['success']:
                results.append(aes_result)
                print("✅ AES SUCCESS!")
        
        # SORT RESULTS by score (highest first)
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        # Final results
        print(f"\n" + "="*60)
        print(f"📊 AUTO-CRACK COMPLETE")
        print(f"📊 Results found: {len(results)}")
        
        for i, result in enumerate(results):
            cipher = result['cipher']
            score = result.get('score', 0)
            confidence = result.get('confidence', 'Unknown')
            preview = result.get('text', '')[:50]
            print(f"📊 Result {i+1}: {cipher} - Score: {score} - {confidence}")
            print(f"   Preview: {preview}")
        
        print("="*60)
        
        return {
            'success': len(results) > 0,
            'results': results,
            'summary': {
                'total_methods_tried': 2,
                'methods_found': len(results),
                'input_length': len(text),
                'best_method': results[0]['cipher'] if results else 'None',
                'detection': {
                    'base64_likely': is_base64,
                    'aes_likely': is_aes
                }
            }
        }

# Global instance
modern_cracker = ModernCryptoCracker()