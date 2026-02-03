'''cipher_crack.py'''

import re
import math
from collections import Counter
import string
from cipher_utils import decrypt, add_spaces_after_words, score_text

def crack_cipher(text):
    """
    Automatically try to crack encrypted text by testing all available ciphers.
    Returns a ranked list of the most likely decryptions based on scoring.
    """
    results = []
    
    # Common English words dictionary for validation
    common_words = set([
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 'with', 
        'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 
        'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so', 'up', 'out', 'if', 
        'about', 'who', 'get', 'which', 'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 
        'him', 'know', 'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them', 'see', 
        'other', 'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back', 
        'after', 'use', 'two', 'how', 'our', 'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because', 
        'any', 'these', 'give', 'day', 'most', 'us', 'hello', 'how', 'are', 'you', 'what', 'where', 'when', 
        'why', 'who', 'love', 'today', 'tomorrow', 'yesterday', 'please', 'thank', 'yes', 'no', 'ok', 'good'
    ])
    
    def count_valid_words(text):
        """Count how many words in the text match our dictionary"""
        words = text.lower().split()
        valid_count = 0
        total_words = len(words)
        
        if total_words == 0:
            return 0
        
        for word in words:
            # Clean the word from punctuation
            clean_word = ''.join(c for c in word if c.isalpha())
            if clean_word in common_words:
                valid_count += 1
        
        # Return percentage of valid words (0-100)
        return (valid_count / total_words) * 100
    
    def score_decryption(text):
        """
        Score the decrypted text based on word matching and text quality.
        Higher score = more likely to be correct.
        """
        if not text or len(text) < 2:
            return 0
        
        # Primary scoring: word match percentage (0-100)
        word_score = count_valid_words(text) * 10
        
        # Secondary scoring: text quality
        quality_score = 0
        
        # Bonus for reasonable letter frequency
        letters = sum(c.isalpha() for c in text)
        total_chars = len(text)
        if total_chars > 0:
            letter_ratio = letters / total_chars
            if 0.6 <= letter_ratio <= 1.0:
                quality_score += 20
        
        # Bonus for spaces (real text has spaces)
        if ' ' in text and text.count(' ') / len(text) > 0.05:
            quality_score += 15
        
        # Bonus for proper capitalization in multi-word texts
        words = text.split()
        if len(words) > 1:
            capitalized_words = sum(1 for word in words if word and word[0].isupper())
            if capitalized_words > 0:
                quality_score += 10
        
        # Penalty for too many non-printable characters
        printable = sum(c.isprintable() for c in text)
        if printable < total_chars * 0.8:
            quality_score -= 30
        
        return word_score + quality_score
    
    # Clean the input text
    clean_text = text.strip()
    
    # ===== PATTERN DETECTION =====
    # Check for special patterns first
    
    # Binary detection
    binary_chars = set('01 ')
    if all(c in binary_chars for c in clean_text.replace(' ', '')):
        try:
            decrypted = decrypt(clean_text, 'binary', "")
            score = score_decryption(decrypted)
            if score > 15:
                results.append({
                    'cipher': 'Binary',
                    'key': 'N/A',
                    'text': decrypted,
                    'score': score + 40
                })
        except:
            pass
    
    # Hexadecimal detection
    hex_chars = set('0123456789abcdefABCDEF ')
    if all(c in hex_chars for c in clean_text.replace(' ', '')):
        try:
            decrypted = decrypt(clean_text, 'hex', "")
            score = score_decryption(decrypted)
            if score > 15:
                results.append({
                    'cipher': 'Hex',
                    'key': 'N/A',
                    'text': decrypted,
                    'score': score + 40
                })
        except:
            pass
    
    # Morse code detection
    if '.-' in clean_text or clean_text.count('.') + clean_text.count('-') > len(clean_text) * 0.3:
        try:
            decrypted = decrypt(clean_text, 'morse', "")
            score = score_decryption(decrypted)
            if score > 15:
                results.append({
                    'cipher': 'Morse',
                    'key': 'N/A',
                    'text': decrypted,
                    'score': score + 40
                })
        except:
            pass
    
    # Polybius detection (pairs of numbers)
    polybius_pattern = re.match(r'^(\d{2}\s*)+\d{0,2}$', clean_text.replace(' ', ''))
    if polybius_pattern and len(clean_text.replace(' ', '')) >= 4:
        try:
            decrypted = decrypt(clean_text, 'polybius', "")
            score = score_decryption(decrypted)
            if score > 10:
                # Apply space addition for Polybius
                decrypted_with_spaces = add_spaces_after_words(decrypted, 'polybius')
                results.append({
                    'cipher': 'Polybius',
                    'key': 'N/A',
                    'text': decrypted_with_spaces,
                    'score': score + 30
                })
        except:
            pass
    
    # ===== SUBSTITUTION CIPHERS =====
    
    # Caesar cipher - try all 26 shifts
    for shift in range(1, 26):
        try:
            decrypted = decrypt(clean_text, 'caesar', shift)
            score = score_decryption(decrypted)
            if score > 20:
                results.append({
                    'cipher': 'Caesar',
                    'key': str(shift),
                    'text': decrypted,
                    'score': score
                })
        except:
            pass
    
    # Simple substitution ciphers (no key needed)
    simple_ciphers = ['reverse', 'atbash', 'rot13']
    for cipher in simple_ciphers:
        try:
            decrypted = decrypt(clean_text, cipher, "")
            score = score_decryption(decrypted)
            if score > 20:
                results.append({
                    'cipher': cipher.capitalize(),
                    'key': 'N/A',
                    'text': decrypted,
                    'score': score
                })
        except:
            pass
    
    # ===== POLYALPHABETIC CIPHERS =====
    
    # Vigenere - try common keys
    common_keys = ['KEY', 'SECRET', 'PASSWORD', 'CRYPTO', 'CODE', 'CIPHER', 
                   'HELLO', 'WORLD', 'TEST', 'DATA', 'LOVE', 'PYTHON', 'THE', 'AND']
    
    for key in common_keys:
        try:
            decrypted = decrypt(clean_text, 'vigenere', key)
            score = score_decryption(decrypted)
            if score > 25:
                results.append({
                    'cipher': 'Vigenere',
                    'key': key,
                    'text': decrypted,
                    'score': score
                })
        except:
            pass
    
    # Try Vigenere with short key lengths
    for key_len in range(2, 6):
        try:
            from cipher_utils import guess_vigenere_key
            key = guess_vigenere_key(clean_text, key_len)
            if key:
                decrypted = decrypt(clean_text, 'vigenere', key)
                score = score_decryption(decrypted)
                if score > 20:
                    results.append({
                        'cipher': 'Vigenere',
                        'key': key,
                        'text': decrypted,
                        'score': score
                    })
        except:
            pass
    
    # Beaufort cipher
    for key in common_keys[:8]:  # Try fewer keys for Beaufort
        try:
            decrypted = decrypt(clean_text, 'beaufort', key)
            score = score_decryption(decrypted)
            if score > 25:
                results.append({
                    'cipher': 'Beaufort',
                    'key': key,
                    'text': decrypted,
                    'score': score
                })
        except:
            pass
    
    # Autokey cipher
    for key in common_keys[:6]:  # Try fewer keys for Autokey
        try:
            decrypted = decrypt(clean_text, 'autokey', key)
            score = score_decryption(decrypted)
            if score > 25:
                results.append({
                    'cipher': 'Autokey',
                    'key': key,
                    'text': decrypted,
                    'score': score
                })
        except:
            pass
    
    # ===== COMPLEX CIPHERS =====
    
    # Affine cipher - try common a values
    coprime_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in coprime_values[:6]:  # Try fewer values
        for b in range(0, 26, 2):  # Try even fewer b values
            try:
                decrypted = decrypt(clean_text, 'affine', f"{a},{b}")
                score = score_decryption(decrypted)
                if score > 25:
                    results.append({
                        'cipher': 'Affine',
                        'key': f"{a},{b}",
                        'text': decrypted,
                        'score': score
                    })
            except:
                pass
    
    # ASCII shift
    for shift in range(1, 128, 3):  # Try fewer shifts
        try:
            decrypted = decrypt(clean_text, 'ascii', shift)
            score = score_decryption(decrypted)
            if score > 20:
                results.append({
                    'cipher': 'ASCII Shift',
                    'key': str(shift),
                    'text': decrypted,
                    'score': score
                })
        except:
            pass
    
    # ===== FINAL PROCESSING =====
    
    # Remove duplicates based on decrypted text
    seen_texts = set()
    unique_results = []
    
    for result in results:
        text_key = result['text'].lower().strip()
        if text_key not in seen_texts and len(result['text']) > 1:
            seen_texts.add(text_key)
            unique_results.append(result)
    
    # Sort by score (highest first)
    unique_results.sort(key=lambda x: x['score'], reverse=True)
    
    return unique_results[:10]  # Return top 10 results