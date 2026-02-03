# 🔐 Python Crypto Project - Comprehensive Report

## 📋 Project Overview

**Project Name:** CryptoTool - Complete Security Toolkit  
**Language:** Python 3.12+  
**GUI Framework:** Tkinter with TkinterDnD2  
**Database:** SQLite with SQLAlchemy ORM  
**Main File:** `cryptotool_tkinter.py` (6,684 lines)

---

## 🏗️ Architecture

```
pythone_crytpo/
├── 📁 Core Modules
│   ├── cryptotool_tkinter.py      # Main GUI application (6,684 lines)
│   ├── database_orm.py            # SQLite database with user management
│   ├── aes_crypto.py              # AES-128 encryption/decryption
│   ├── rsa_utils.py               # RSA cryptography (15+ char messages)
│   ├── hash_cracker.py            # Advanced hash cracking with rainbow table
│   ├── cipher_utils.py            # Classic cipher implementations
│   └── cipher_crack.py            # Auto-detection and cracking
│
├── 📁 Steganography
│   ├── steganography_utils.py     # Image & Audio LSB steganography
│
├── 📁 Brute Force Tools
│   ├── brute_force.py             # AES brute force attacks
│   ├── hybrid_brute_force.py      # Ultra-fast multi-strategy brute force
│   ├── auto_crack_modern.py       # Modern crypto auto-cracking
│   │
├── 📁 Security Scanning
│   ├── nmap_scanner.py            # Network port scanning
│   ├── bulk_ssl_scanner.py        # SSL/TLS certificate analysis
│   └── quantum_checker.py         # Quantum resistance analysis
│
├── 📁 Data & Resources
│   ├── data/crypto_history.db     # SQLite database
│   ├── json_data/
│   │   ├── learned_passwords.json # Auto-learned passwords
│   │   ├── rainbow_table.json     # Hash rainbow table
│   │   └── rsa_primes.json        # RSA prime database
│   └── Backup/                    # Backup files
│
└── 📁 Setup
    ├── requirements.txt           # Python dependencies
    └── SETUP.txt                  # Installation instructions
```

---

## 🔑 Key Features

### 1. **Text Encryption/Decryption**
- **Classic Ciphers:**
  - Caesar Cipher (with variable shift)
  - ROT13
  - Atbash (A↔Z, B↔Y)
  - Vigenère Cipher (with key)
  - Beaufort Cipher
  - Autokey Cipher
  - Affine Cipher
  - Polybius Square
  - Reverse Text

- **Encoding Methods:**
  - Morse Code
  - Binary Encoding
  - Hexadecimal Encoding
  - ASCII Shift

### 2. **File Encryption**
- AES-128-CBC encryption (Fernet)
- Password-protected
- Drag & drop support
- Auto-open decrypted files
- **Brute Force Protection:**
  - Multi-strategy attack
  - Parallel processing (8 workers)
  - Intelligent ordering (shortest first)

### 3. **Steganography**
- **Image Steganography (LSB):**
  - Hide messages in PNG images
  - Extract hidden messages
  - Lossless encoding
  
- **Audio Steganography (LSB):**
  - Hide messages in WAV files
  - Extract hidden messages

### 4. **RSA Cryptography**
- Large prime generation (10^18 range)
- Smart encryption (auto-select primes)
- Manual encryption (custom primes)
- **RSA Attack:**
  - Factorization attack
  - Private key recovery
  - Message decryption
- Support for 15+ character messages

### 5. **Hash Cracking**
- **Supported Hash Types:**
  - MD5
  - SHA1
  - SHA256
  - SHA512

- **Attack Methods:**
  - Rainbow Table Lookup (instant)
  - Dictionary Attack
  - Brute Force (multi-char-set)
  - Smart Pattern Recognition

- **Auto-Learning:**
  - Learns every generated hash
  - Builds rainbow table automatically
  - Persists learned passwords to JSON

### 6. **Auto-Crack Tools**
- **Classic Cipher Auto-Detection:**
  - Tests 26 Caesar shifts
  - Tries common Vigenère keys
  - Pattern detection for binary/hex/morse
  - Scores results by English frequency
  
- **Modern Crypto Auto-Crack:**
  - Base64 detection & decoding
  - AES encrypted data detection
  - Brute force fallback

### 7. **User Management**
- **Authentication System:**
  - Username/password login
  - Email verification (Gmail SMTP)
  - Admin vs. Standard modes
  - Session management
  
- **Database Tracking:**
  - All operations logged
  - User-specific history
  - Admin can view all users
  - Operation statistics

### 8. **Network Security Scanner**
- **Nmap Integration:**
  - Port scanning
  - Service detection
  - OS fingerprinting
  
- **SSL/TLS Analysis:**
  - Certificate validation
  - Expiration checking
  - Algorithm analysis
  
- **Quantum Resistance:**
  - Key strength analysis
  - Vulnerability assessment

---

## 📊 Database Schema

### Tables:
1. **users** - User accounts
   - id, username, email, password_hash, salt
   - is_admin, is_verified
   - created_at, last_login

2. **operations** - All crypto operations
   - id, user_id (NULL = standard mode)
   - operation_type, cipher_type
   - input_text, output_text, key_used
   - timestamp, score
   - Flags: is_file_operation, is_image_operation, is_audio_operation, is_rsa_operation, is_security_operation, is_auto_crack

3. **hash_operations** - Hash generation/cracking
   - id, user_id
   - hash_type, original_text, hash_value
   - cracked, cracked_text, crack_time, attempts_made

4. **suggestions** - Popular ciphers
   - id, user_id, cipher_type, frequency, last_used

5. **hash_crack_attempts** - Crack attempt history
   - id, user_id, hash_operation_id
   - attempt_type, attempts_made, success

---

## 🎨 GUI Features

### Main Interface:
- **15 Tabbed Sections:**
  1. Text Encrypt
  2. Text Decrypt
  3. Crack Classic
  4. Image Steg
  5. Audio Steg
  6. File Encrypt
  7. Modern Crypto
  8. Auto Crack Modern
  9. RSA Complete
  10. History
  11. Hash Cracking
  12. Network Scanner
  13. SSL Scanner
  14. Quantum Checker
  15. Admin

### Design:
- Dark theme (#0a0e27 background)
- Cyan accent color (#00d9ff)
- Real-time progress updates
- Threaded operations (UI doesn't freeze)
- Drag & drop file support
- Copy to clipboard

---

## 📦 Dependencies

```txt
# GUI & Core
tk==0.1.0
Pillow==10.1.0
tkinterdnd2==0.3.0

# Cryptography
cryptography==41.0.7
pycryptodome==3.19.1
fernet==1.0.1

# Database
sqlite3==2.6.0
SQLAlchemy

# Network
python-nmap==0.7.1
pyOpenSSL==23.2.0
requests==2.31.0

# Processing
numpy==1.24.3
opencv-python==4.8.1.78
pydub==0.25.1
```

---

## 🔒 Security Features

1. **Password Hashing:** SHA-256 with salt
2. **Email Verification:** 6-digit code (24hr expiry)
3. **Operation Logging:** All actions tracked
4. **User Isolation:** Standard vs. Custom mode
5. **Admin Privileges:** Separate admin login

---

## ⚡ Performance Optimizations

1. **Multi-threading:** Operations run in background
2. **Process Pooling:** Brute force uses multiple CPUs
3. **Key Caching:** Derived keys cached for speed
4. **Batch Processing:** 1000 passwords per batch
5. **Intelligent Ordering:** Shortest passwords first
6. **Rainbow Table:** Instant hash lookup

---

## 📈 Statistics

| Metric | Value |
|--------|-------|
| Total Python Files | 15+ |
| Main Application | 6,684 lines |
| Database ORM | 1,500+ lines |
| Supported Ciphers | 12+ |
| Hash Types | 4 |
| Lines of Code | ~10,000+ |

---

## 🚀 Usage Modes

### Standard Mode (No Login)
- Shared history
- All features available
- Quick start

### Custom Mode (Login Required)
- Private history
- Email verification
- Admin features available

### Admin Mode
- View all users' operations
- User management
- Delete operations
- Promote/demote users

---

## 📝 Auto-Learning System

The hash cracker **automatically learns** every hash it generates:

1. When you hash any text, it's saved
2. Rainbow table updated in real-time
3. JSON files persist between sessions
4. Next crack attempt uses learned data
5. Grows smarter over time

---

## 🎯 Example Workflows

### 1. Encrypt a Message
```
1. Go to "Text Encrypt" tab
2. Enter text: "Secret Message"
3. Select cipher: "Caesar"
4. Enter key: "3"
5. Click "Encrypt"
6. Result: "Vhfuhw Phvvdjh"
```

### 2. Crack an Unknown Cipher
```
1. Go to "Crack Classic" tab
2. Enter encrypted text
3. Click "Auto-Crack"
4. System tests 26+ methods
5. Shows ranked results
6. Best match highlighted
```

### 3. Protect a File
```
1. Go to "File Encrypt" tab
2. Drag & drop file
3. Enter password
4. Click "Encrypt"
5. Download encrypted .bin file
```

### 4. Recover Password
```
1. Go to "Modern Crypto" tab
2. Enter encrypted file
3. Click "Brute Force"
4. System tries common passwords
5. Auto-decrypts when found
```

---

## 📊 Project Health

✅ **Active Development**  
✅ **Comprehensive Testing**  
✅ **User Authentication**  
✅ **Database Persistence**  
✅ **Modern GUI**  
✅ **Multi-threading**  
✅ **Security Scanning**  
✅ **Documentation**  

---

## 🎓 Educational Value

This project demonstrates:
- Symmetric encryption (AES)
- Asymmetric encryption (RSA)
- Hash functions & cracking
- Classic cryptography
- Steganography
- Network security
- Database design
- GUI programming
- Multi-threading
- User authentication

---

**Report Generated:** Auto-generated from codebase analysis  
**Total Modules:** 15+ Python files  
**Lines of Code:** ~10,000+

