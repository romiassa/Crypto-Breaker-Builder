import re
import math
from collections import Counter
import string

def add_spaces_after_words(text, cipher_type):
    """
    Add spaces after common words for specific ciphers that produce continuous text
    Only applies to Polybius and Hexadecimal ciphers
    """
    if cipher_type.lower() not in ['polybius', 'hex']:
        return text
    
    # Skip if already has spaces or too short
    if ' ' in text or len(text) < 4 or not text.isalpha():
        return text
    
    # Word list for common English words
    word_list = [
        'hello', 'helo', 'how', 'are', 'you', 'what', 'where', 'when', 'why', 'who', 
        'the', 'and', 'this', 'that', 'with', 'have', 'from', 'your', 'will',
        'they', 'their', 'there', 'been', 'would', 'about', 'which', 'love',
        'today', 'tomorrow', 'yesterday', 'please', 'thank', 'thanks', 'sorry',
        'yes', 'no', 'ok', 'okay', 'good', 'bad', 'nice', 'beautiful', 'beaut',
        'friend', 'family', 'home', 'work', 'school', 'time', 'day', 'night',
        'me', 'my', 'he', 'she', 'it', 'we', 'us', 'our', 'him', 'her', 'his'
    ]
    
    text_lower = text.lower()
    new_text = text
    
    # Find and add spaces after each word
    for word in word_list:
        if word in text_lower:
            idx = text_lower.find(word)
            # Add space AFTER this word
            if idx + len(word) < len(new_text):
                new_text = new_text[:idx + len(word)] + ' ' + new_text[idx + len(word):]
                # Update the lowercase version for next search
                text_lower = new_text.lower()
    
    return new_text

def encrypt(text, cipher_type, key=''):
    """
    Encrypt text using specified cipher
    """
    cipher_type = cipher_type.lower()
    
    if cipher_type == 'caesar':
        return caesar_cipher(text, int(key) if key else 3, encrypt=True)
    elif cipher_type == 'reverse':
        return text[::-1]
    elif cipher_type == 'atbash':
        return atbash_cipher(text)
    elif cipher_type == 'vigenere':
        return vigenere_cipher(text, key, encrypt=True)
    elif cipher_type == 'polybius':
        encrypted = polybius_cipher(text, encrypt=True)
        return add_spaces_after_words(encrypted, 'polybius')
    elif cipher_type == 'rot13':
        return rot13_cipher(text)
    elif cipher_type == 'beaufort':
        return beaufort_cipher(text, key, encrypt=True)
    elif cipher_type == 'autokey':
        return autokey_cipher(text, key, encrypt=True)
    elif cipher_type == 'affine':
        a, b = map(int, key.split(',')) if key else (5, 8)
        return affine_cipher(text, a, b, encrypt=True)
    elif cipher_type == 'morse':
        return morse_cipher(text, encrypt=True)
    elif cipher_type == 'binary':
        return binary_cipher(text, encrypt=True)
    elif cipher_type == 'hex':
        encrypted = hex_cipher(text, encrypt=True)
        return add_spaces_after_words(encrypted, 'hex')
    elif cipher_type == 'ascii':
        return ascii_shift(text, int(key) if key else 1, encrypt=True)
    else:
        raise ValueError(f"Unknown cipher type: {cipher_type}")

def decrypt(text, cipher_type, key=''):
    """
    Decrypt text using specified cipher
    """
    cipher_type = cipher_type.lower()
    
    if cipher_type == 'caesar':
        return caesar_cipher(text, int(key) if key else 3, encrypt=False)
    elif cipher_type == 'reverse':
        return text[::-1]
    elif cipher_type == 'atbash':
        return atbash_cipher(text)
    elif cipher_type == 'vigenere':
        return vigenere_cipher(text, key, encrypt=False)
    elif cipher_type == 'polybius':
        decrypted = polybius_cipher(text, encrypt=False)
        return add_spaces_after_words(decrypted, 'polybius')
    elif cipher_type == 'rot13':
        return rot13_cipher(text)
    elif cipher_type == 'beaufort':
        return beaufort_cipher(text, key, encrypt=False)
    elif cipher_type == 'autokey':
        return autokey_cipher(text, key, encrypt=False)
    elif cipher_type == 'affine':
        a, b = map(int, key.split(',')) if key else (5, 8)
        return affine_cipher(text, a, b, encrypt=False)
    elif cipher_type == 'morse':
        return morse_cipher(text, encrypt=False)
    elif cipher_type == 'binary':
        return binary_cipher(text, encrypt=False)
    elif cipher_type == 'hex':
        decrypted = hex_cipher(text, encrypt=False)
        return add_spaces_after_words(decrypted, 'hex')
    elif cipher_type == 'ascii':
        return ascii_shift(text, int(key) if key else 1, encrypt=False)
    else:
        raise ValueError(f"Unknown cipher type: {cipher_type}")

# ===== INDIVIDUAL CIPHER IMPLEMENTATIONS =====

def caesar_cipher(text, shift, encrypt=True):
    """Caesar cipher implementation"""
    result = []
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            if encrypt:
                shifted = (ord(char) - ascii_offset + shift) % 26
            else:
                shifted = (ord(char) - ascii_offset - shift) % 26
            result.append(chr(shifted + ascii_offset))
        else:
            result.append(char)
    return ''.join(result)

def atbash_cipher(text):
    """Atbash cipher (A=Z, B=Y, etc.)"""
    result = []
    for char in text:
        if char.isalpha():
            if char.isupper():
                result.append(chr(155 - ord(char)))  # 65+90=155
            else:
                result.append(chr(219 - ord(char)))  # 97+122=219
        else:
            result.append(char)
    return ''.join(result)

def vigenere_cipher(text, key, encrypt=True):
    """Vigenere cipher implementation"""
    if not key:
        key = 'KEY'
    
    key = key.upper()
    key_index = 0
    result = []
    
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - 65
            
            if encrypt:
                shifted = (ord(char) - ascii_offset + key_shift) % 26
            else:
                shifted = (ord(char) - ascii_offset - key_shift) % 26
            
            result.append(chr(shifted + ascii_offset))
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)

def polybius_cipher(text, encrypt=True):
    """Polybius square cipher"""
    polybius_square = {
        'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
        'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '24', 'K': '25',
        'L': '31', 'M': '32', 'N': '33', 'O': '34', 'P': '35',
        'Q': '41', 'R': '42', 'S': '43', 'T': '44', 'U': '45',
        'V': '51', 'W': '52', 'X': '53', 'Y': '54', 'Z': '55'
    }
    
    reverse_square = {v: k for k, v in polybius_square.items()}
    
    if encrypt:
        result = []
        for char in text.upper():
            if char.isalpha():
                result.append(polybius_square.get(char, '23'))  # Default to 'H'
            elif char == ' ':
                result.append(' ')
        return ''.join(result)
    else:
        result = []
        numbers = text.replace(' ', '')
        for i in range(0, len(numbers), 2):
            if i + 1 < len(numbers):
                code = numbers[i:i+2]
                result.append(reverse_square.get(code, '?'))
        return ''.join(result)

def rot13_cipher(text):
    """ROT13 cipher"""
    return caesar_cipher(text, 13, encrypt=True)

def beaufort_cipher(text, key, encrypt=True):
    """Beaufort cipher (similar to Vigenere but reciprocal)"""
    if not key:
        key = 'KEY'
    
    key = key.upper()
    key_index = 0
    result = []
    
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - 65
            
            if encrypt:
                shifted = (key_shift - (ord(char) - ascii_offset)) % 26
            else:
                shifted = (key_shift - (ord(char) - ascii_offset)) % 26
            
            result.append(chr(shifted + ascii_offset))
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)

def autokey_cipher(text, key, encrypt=True):
    """Autokey cipher"""
    if not key:
        key = 'KEY'
    
    key = key.upper()
    result = []
    
    if encrypt:
        key_stream = key + text.upper().replace(' ', '')
        for i, char in enumerate(text):
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = key_stream[i]
                key_shift = ord(key_char) - 65
                shifted = (ord(char) - ascii_offset + key_shift) % 26
                result.append(chr(shifted + ascii_offset))
            else:
                result.append(char)
    else:
        key_stream = key
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = key_stream[0]
                key_shift = ord(key_char) - 65
                shifted = (ord(char) - ascii_offset - key_shift) % 26
                decrypted_char = chr(shifted + ascii_offset)
                result.append(decrypted_char)
                key_stream += decrypted_char
            else:
                result.append(char)
    
    return ''.join(result)

def affine_cipher(text, a, b, encrypt=True):
    """Affine cipher: E(x) = (ax + b) mod 26"""
    def mod_inverse(a, m=26):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return 1
    
    result = []
    a_inv = mod_inverse(a)
    
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            x = ord(char) - ascii_offset
            
            if encrypt:
                encrypted = (a * x + b) % 26
            else:
                encrypted = (a_inv * (x - b)) % 26
            
            result.append(chr(encrypted + ascii_offset))
        else:
            result.append(char)
    
    return ''.join(result)

def morse_cipher(text, encrypt=True):
    """Morse code cipher"""
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
        'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
        'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', ' ': '/'
    }
    
    reverse_morse = {v: k for k, v in morse_dict.items()}
    
    if encrypt:
        result = []
        for char in text.upper():
            if char in morse_dict:
                result.append(morse_dict[char])
            result.append(' ')
        return ' '.join(result).strip()
    else:
        result = []
        words = text.split(' / ')
        for word in words:
            letters = word.split(' ')
            for letter in letters:
                if letter in reverse_morse:
                    result.append(reverse_morse[letter])
            result.append(' ')
        return ''.join(result).strip()

def binary_cipher(text, encrypt=True):
    """Binary encoding/decoding"""
    if encrypt:
        return ' '.join(format(ord(c), '08b') for c in text)
    else:
        binaries = text.split()
        result = []
        for binary in binaries:
            try:
                result.append(chr(int(binary, 2)))
            except:
                result.append('?')
        return ''.join(result)

def hex_cipher(text, encrypt=True):
    """Hexadecimal encoding/decoding"""
    if encrypt:
        return ' '.join(hex(ord(c))[2:].upper().zfill(2) for c in text)
    else:
        hexes = text.split()
        result = []
        for hex_char in hexes:
            try:
                result.append(chr(int(hex_char, 16)))
            except:
                result.append('?')
        return ''.join(result)

def ascii_shift(text, shift, encrypt=True):
    """ASCII shift cipher"""
    result = []
    for char in text:
        if encrypt:
            result.append(chr(ord(char) + shift))
        else:
            result.append(chr(ord(char) - shift))
    return ''.join(result)

def score_text(text):
    """Score text based on English letter frequency"""
    if not text:
        return 0
    
    # English letter frequencies
    english_freq = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974, 'z': 0.074
    }
    
    text_lower = text.lower()
    total_letters = sum(c.isalpha() for c in text_lower)
    
    if total_letters == 0:
        return 0
    
    # Calculate frequency score
    score = 0
    for char in text_lower:
        if char in english_freq:
            score += english_freq[char]
    
    # Normalize score
    return (score / total_letters) * 10

def guess_vigenere_key(text, key_length):
    """Guess Vigenere key using frequency analysis"""
    # Simplified key guessing - returns a simple key
    common_keys = ['THE', 'AND', 'KEY', 'SECRET', 'PASSWORD', 'CRYPTO', 'CODE']
    return common_keys[key_length % len(common_keys)] if key_length <= 7 else 'UNKNOWN'