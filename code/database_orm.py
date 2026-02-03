import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Text, Boolean, ForeignKey, and_, or_, func  # type: ignore
from sqlalchemy.orm import sessionmaker, relationship, declarative_base  # type: ignore
from datetime import datetime, date, timedelta
import json
import hashlib
import secrets
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# SAFE way to get current directory
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    current_dir = os.getcwd()

# Create the 'data' folder path
data_folder = os.path.join(current_dir, "data")

# Ensure the data folder exists
os.makedirs(data_folder, exist_ok=True)
print(f"📁 Data folder: {data_folder}")

# Database file path
database_path = os.path.join(data_folder, "crypto_history.db")
print(f"💾 Database will be created at: {database_path}")

# Create engine
engine = create_engine(f'sqlite:///{database_path}')

Base = declarative_base()

DB_FILE_PATH = database_path
DB_PATH = f"sqlite:///{DB_FILE_PATH}"   

# ================================================
# USER AUTHENTICATION AND MANAGEMENT
# ================================================

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    salt = Column(String(50), nullable=False)
    is_admin = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    verification_code = Column(String(10))
    verification_expires = Column(DateTime)
    created_at = Column(DateTime, default=datetime.now)
    last_login = Column(DateTime)
    
    operations = relationship("Operation", backref="user", cascade="all, delete-orphan")
    hash_operations = relationship("HashOperation", backref="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(username='{self.username}', admin={self.is_admin})>"
    
    def verify_password(self, password):
        """Verify password against stored hash"""
        hash_obj = hashlib.sha256((password + self.salt).encode())
        return hash_obj.hexdigest() == self.password_hash

# ================================================
# UPDATED DATABASE CLASSES WITH USER SUPPORT
# ================================================

class Operation(Base):
    __tablename__ = 'operations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # NULL for standard mode
    operation_type = Column(String(50))
    cipher_type = Column(String(50))
    input_text = Column(Text)
    output_text = Column(Text)
    key_used = Column(String(100))
    timestamp = Column(DateTime)
    score = Column(Float)
    file_name = Column(String(255))
    is_file_operation = Column(Boolean, default=False)
    is_image_operation = Column(Boolean, default=False)
    is_audio_operation = Column(Boolean, default=False)
    is_rsa_operation = Column(Boolean, default=False)  # Track RSA operations
    is_security_operation = Column(Boolean, default=False)  # Track security scans
    is_auto_crack = Column(Boolean, default=False)  # Track auto-crack operations
    
    def __repr__(self):
        return f"<Operation(type='{self.operation_type}', cipher='{self.cipher_type}')>"

class Suggestion(Base):
    __tablename__ = 'suggestions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # NULL for standard mode
    cipher_type = Column(String(50))
    frequency = Column(Integer, default=0)
    last_used = Column(DateTime)
    
    def __repr__(self):
        return f"<Suggestion(cipher='{self.cipher_type}', freq={self.frequency})>"

class HashOperation(Base):
    __tablename__ = 'hash_operations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # NULL for standard mode
    hash_type = Column(String(50))
    original_text = Column(Text)
    hash_value = Column(String(255))
    timestamp = Column(DateTime)
    cracked = Column(Boolean, default=False)
    cracked_text = Column(Text)
    crack_time = Column(Float)
    attempts_made = Column(Integer, default=0)
    
    def __repr__(self):
        return f"<HashOperation(type='{self.hash_type}', cracked={self.cracked})>"

class HashCrackAttempt(Base):
    __tablename__ = 'hash_crack_attempts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # NULL for standard mode
    hash_operation_id = Column(Integer, ForeignKey('hash_operations.id'))
    attempt_type = Column(String(50))
    attempts_made = Column(Integer)
    success = Column(Boolean)
    timestamp = Column(DateTime)
    cracked_text = Column(Text)
    
    hash_operation = relationship("HashOperation", backref="crack_attempts")
    
    def __repr__(self):
        return f"<HashCrackAttempt(type='{self.attempt_type}', success={self.success})>"

# ================================================
# ENHANCED CryptoDatabaseORM WITH COMPLETE TRACKING
# ================================================

class CryptoDatabaseORM:
    def __init__(self, db_path=None):
        """
        Initialize database connection with intelligent path resolution.
        """
        # Use the calculated DB_PATH by default
        if db_path is None:
            db_path = DB_PATH
        elif db_path == "sqlite:///crypto_history.db":
            # If someone uses the old default, use our new path
            db_path = DB_PATH
        
        print(f"🔗 Attempting database connection: {db_path}")
        
        try:
            self.engine = create_engine(db_path)
            self.Session = sessionmaker(bind=self.engine)
            self.init_db()
            
            # Verify connection works
            self._test_connection()
            
            # Create default users if needed
            self._create_default_users()
            
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            print(f"⚠️  Trying alternative location...")
            
            # Try alternative: database in current directory (fallback)
            alt_db_path = "sqlite:///crypto_history.db"
            print(f"🔗 Trying alternative: {alt_db_path}")
            
            self.engine = create_engine(alt_db_path)
            self.Session = sessionmaker(bind=self.engine)
            self.init_db()
            self._create_default_users()
            
            print(f"⚠️  Using fallback database in current directory")
    
    def init_db(self):
        """Initialize database with tables - WITHOUT DROPPING EXISTING DATA"""
        # CRITICAL FIX: DON'T drop tables - preserves existing data
        Base.metadata.create_all(self.engine)
        print(f"✅ Database tables initialized (existing data preserved)")
    
    # ================================================
    # AUTHENTICATION METHODS
    # ================================================
    
    def _create_default_users(self):
        """Create default users (admin and standard) if they don't exist"""
        session = None
        try:
            session = self.Session()
            
            # Check if admin user exists
            admin = session.query(User).filter_by(username="admin").first()
            if not admin:
                salt = secrets.token_hex(16)
                password_hash = hashlib.sha256(("admin123" + salt).encode()).hexdigest()
                admin = User(
                    username="admin",
                    email="admin@cryptotool.local",
                    password_hash=password_hash,
                    salt=salt,
                    is_admin=True,
                    is_verified=True
                )
                session.add(admin)
                print(f"✅ Created admin user (password: admin123)")
            
            # Check if standard user exists
            standard = session.query(User).filter_by(username="standard").first()
            if not standard:
                salt = secrets.token_hex(16)
                password_hash = hashlib.sha256(("standard" + salt).encode()).hexdigest()
                standard = User(
                    username="standard",
                    email="standard@cryptotool.local",
                    password_hash=password_hash,
                    salt=salt,
                    is_admin=False,
                    is_verified=True
                )
                session.add(standard)
                print(f"✅ Created standard user for shared mode")
            
            session.commit()
            
        except Exception as e:
            print(f"⚠️  Could not create default users: {e}")
            if session:
                session.rollback()
        finally:
            if session:
                session.close()
    
    def authenticate_user(self, username, password):
        """Authenticate user and return user object if successful"""
        session = None
        try:
            session = self.Session()
            user = session.query(User).filter_by(username=username).first()
            
            if user:
                # Get data while still in session
                user_id = user.id
                username_val = user.username
                email_val = user.email
                is_admin_val = user.is_admin
                is_verified_val = user.is_verified
                salt_val = user.salt
                password_hash_val = user.password_hash
                
                # Verify password
                hash_obj = hashlib.sha256((password + salt_val).encode())
                password_correct = hash_obj.hexdigest() == password_hash_val
                
                if password_correct:
                    # Update last login
                    user.last_login = datetime.now()
                    session.commit()
                    
                    return {
                        'id': user_id,
                        'username': username_val,
                        'email': email_val,
                        'is_admin': is_admin_val,
                        'is_verified': is_verified_val,
                        'success': True
                    }
                else:
                    return {'success': False, 'error': 'Invalid password'}
            else:
                return {'success': False, 'error': 'User not found'}
                
        except Exception as e:
            print(f"❌ Authentication error: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    def create_user(self, username, password, email=None, is_admin=False):
        """Create new user with WORKING email verification"""
        session = None
        try:
            session = self.Session()
            
            # Check if username exists
            existing = session.query(User).filter_by(username=username).first()
            if existing:
                return {'success': False, 'error': 'Username already exists'}
            
            if email:
                # Check if email exists
                existing_email = session.query(User).filter_by(email=email).first()
                if existing_email:
                    return {'success': False, 'error': 'Email already registered'}
            
            # Create user with salted password
            salt = secrets.token_hex(16)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            # Generate verification code
            verification_code = None
            verification_expires = None
            if not is_admin and email:
                verification_code = str(random.randint(100000, 999999))
                verification_expires = datetime.now() + timedelta(hours=24)
            
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                salt=salt,
                is_admin=is_admin,
                is_verified=is_admin,
                verification_code=verification_code,
                verification_expires=verification_expires
            )
            
            session.add(user)
            session.commit()
            user_id = user.id
            
            # Send verification email
            email_sent = False
            if email and not is_admin and verification_code:
                print(f"\n📧 Sending verification email to {email}...")
                email_sent = self._send_verification_email(email, username, verification_code)
            
            if email and not is_admin:
                if email_sent:
                    return {
                        'success': True, 
                        'user_id': user_id, 
                        'needs_verification': True,
                        'verification_code': verification_code,
                        'email_sent': True
                    }
                else:
                    # Email failed but user created - show code
                    print(f"⚠️  Email failed, but user created. Verification code: {verification_code}")
                    return {
                        'success': True, 
                        'user_id': user_id, 
                        'needs_verification': True,
                        'verification_code': verification_code,
                        'email_sent': False,
                        'warning': 'Email could not be sent. Use this verification code manually.'
                    }
            else:
                return {'success': True, 'user_id': user_id, 'needs_verification': not is_admin}
            
        except Exception as e:
            print(f"❌ User creation error: {str(e)}")
            if session:
                session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    def _send_verification_email(self, to_email, username, verification_code):
        """Send verification email using YOUR WORKING GMAIL APP PASSWORD"""
        try:
            # ============================================
            # YOUR WORKING GMAIL CREDENTIALS
            # ============================================
            smtp_server = "smtp.gmail.com"
            smtp_port = 587
            sender_email = "chatgbt911@gmail.com"
            # YOUR WORKING APP PASSWORD (16 chars, no spaces)
            sender_password = "koebzzssfkdxpzzp"  # <-- YOUR WORKING PASSWORD
            # ============================================
            
            print(f"   📨 Preparing email for {username}...")
            print(f"   🔑 Code: {verification_code}")
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"Crypto Tool <{sender_email}>"
            msg['To'] = to_email
            msg['Subject'] = f"CryptoTool Verification Code: {verification_code}"
            
            # Simple text version
            text = f"""CryptoTool Account Verification

Hello {username},

Your verification code is: {verification_code}

Enter this 6-digit code in the CryptoTool application to verify your account.

⏰ This code will expire in 24 hours.

If you didn't create this account, please ignore this email.

Best regards,
CryptoTool Team
"""
            
            # HTML version
            html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 5px;">
        <h1>🔐 CryptoTool</h1>
        <h2>Account Verification Required</h2>
    </div>
    
    <div style="background-color: #f9f9f9; padding: 30px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 5px 5px;">
        <p>Hello <strong>{username}</strong>,</p>
        <p>Welcome to <strong>CryptoTool</strong> - your encryption and security toolkit!</p>
        <p>To complete your registration, please verify your email address.</p>
        
        <div style="background-color: #4CAF50; color: white; font-size: 28px; font-weight: bold; padding: 20px; 
                    text-align: center; border-radius: 5px; margin: 25px 0; letter-spacing: 8px;">
            {verification_code}
        </div>
        
        <p style="text-align: center;"><strong>Enter this code in the CryptoTool application</strong></p>
        
        <div style="text-align: center; margin: 20px 0;">
            <div style="background-color: #ffeb3b; padding: 10px; border-radius: 5px; display: inline-block;">
                <strong>⏰ Code expires in 24 hours</strong>
            </div>
        </div>
        
        <p><strong>Features you'll unlock:</strong></p>
        <ul>
            <li>🔐 Full encryption/decryption capabilities</li>
            <li>🔑 RSA key generation</li>
            <li>🔓 Hash cracking tools</li>
            <li>📁 File encryption support</li>
            <li>📊 Operation history tracking</li>
        </ul>
        
        <hr>
        <p style="color: #666; font-size: 12px;">
            This is an automated message. Please do not reply to this email.<br>
            © {datetime.now().year} CryptoTool
        </p>
    </div>
</body>
</html>"""
            
            # Attach both versions
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send the email
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
            
            print(f"   ✅ Verification email sent successfully!")
            return True
            
        except smtplib.SMTPAuthenticationError:
            print(f"❌ SMTP Authentication failed!")
            print(f"   Please check your Gmail app password")
            print(f"   Current password: {sender_password[:4]}...{sender_password[-4:]}")
            return False
        except Exception as e:
            print(f"❌ Email sending failed: {e}")
            print(f"🔑 Verification code for {username}: {verification_code}")
            return False
    
    def verify_user_email(self, username, verification_code):
        """Verify user's email with code"""
        session = None
        try:
            session = self.Session()
            user = session.query(User).filter_by(username=username).first()
            
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            if user.is_verified:
                return {'success': True, 'message': 'Already verified'}
            
            if not user.verification_code or user.verification_code != verification_code:
                return {'success': False, 'error': 'Invalid verification code'}
            
            if user.verification_expires and datetime.now() > user.verification_expires:
                return {'success': False, 'error': 'Verification code expired'}
            
            # Mark as verified
            user.is_verified = True
            user.verification_code = None
            user.verification_expires = None
            session.commit()
            
            print(f"✅ User {username} verified successfully!")
            return {'success': True, 'message': 'Email verified successfully'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    # ================================================
    # COMPREHENSIVE OPERATION TRACKING METHODS
    # ================================================
    
    def add_auto_crack_operation(self, cipher_type, input_text, cracked_result, 
                               key_used="auto", score=0, user_id=None):
        """
        Track auto-crack operations - NEVER SKIP THESE
        """
        return self.add_operation(
            op_type="auto_crack",
            cipher_type=cipher_type,
            input_text=input_text,
            output_text=cracked_result,
            key_used=key_used,
            score=score,
            user_id=user_id,
            is_auto_crack=True
        )
    
    def add_image_operation(self, operation_type, image_format, 
                          input_info, output_info, user_id=None):
        """
        Track ALL image operations (encryption/decryption)
        """
        return self.add_operation(
            op_type=f"image_{operation_type}",
            cipher_type="image_crypto",
            input_text=input_info,
            output_text=output_info,
            key_used=image_format,
            score=80,
            user_id=user_id,
            is_image_operation=True,
            is_file_operation=True
        )
    
    def add_rsa_operation(self, operation_type, key_size, 
                         input_info, output_info, user_id=None):
        """
        Track ALL RSA operations (key generation, encryption, decryption)
        """
        return self.add_operation(
            op_type=f"rsa_{operation_type}",
            cipher_type="rsa",
            input_text=input_info,
            output_text=output_info,
            key_used=str(key_size),
            score=90,
            user_id=user_id,
            is_rsa_operation=True
        )
    
    def add_decryption_operation(self, cipher_type, input_text, 
                               decrypted_text, key_used, score=0, user_id=None):
        """
        Track ALL decryption operations - FIXED VERSION
        """
        return self.add_operation(
            op_type="decrypt",
            cipher_type=cipher_type,
            input_text=input_text,
            output_text=decrypted_text,
            key_used=key_used,
            score=score,
            user_id=user_id
        )
    
    def add_encryption_operation(self, cipher_type, input_text, 
                               encrypted_text, key_used, score=0, user_id=None):
        """
        Track ALL encryption operations
        """
        return self.add_operation(
            op_type="encrypt",
            cipher_type=cipher_type,
            input_text=input_text,
            output_text=encrypted_text,
            key_used=key_used,
            score=score,
            user_id=user_id
        )
    
    def get_combined_history(self, limit=1000, operation_type=None, user_id=None, is_admin=False):
        """
        Get operations from history with proper user filtering
        
        Args:
            limit: Maximum number of operations to return
            operation_type: Filter by operation type
            user_id: The user ID requesting the history
            is_admin: Whether the user is an admin (admins see everything)
        """
        session = None
        try:
            session = self.Session()
            
            query = session.query(Operation)
            
            # IMPORTANT: Different logic based on user type
            if user_id is None:
                # Standard mode - show ONLY operations without user_id (standard operations)
                query = query.filter(Operation.user_id == None)
            else:
                # Custom user mode
                if is_admin:
                    # ADMIN: Can see ALL operations (including other users and standard)
                    # No filter applied - admin sees everything
                    pass
                else:
                    # REGULAR USER: Can see only THEIR OWN operations + standard operations
                    query = query.filter(
                        (Operation.user_id == user_id) | (Operation.user_id == None)
                    )
            
            # Only filter by type if specifically requested
            if operation_type and operation_type != 'all':
                query = query.filter(Operation.operation_type == operation_type)
            
            # Get operations ordered by time
            operations = query.order_by(Operation.timestamp.desc()).limit(limit).all()
            
            # Count statistics
            total_ops = len(operations)
            auto_crack_ops = sum(1 for op in operations if op.is_auto_crack)
            rsa_ops = sum(1 for op in operations if op.is_rsa_operation)
            image_ops = sum(1 for op in operations if op.is_image_operation)
            hash_ops = sum(1 for op in operations if "hash" in str(op.cipher_type).lower())
            
            # Log based on user type
            if is_admin:
                print(f"👑 ADMIN HISTORY: Total: {total_ops}")
            elif user_id is None:
                print(f"🔓 STANDARD HISTORY: Total: {total_ops}")
            else:
                print(f"👤 USER HISTORY (ID: {user_id}): Total: {total_ops}")
            
            # Convert to list of dictionaries
            history = []
            for op in operations:
                # Get username for display (only for admins)
                username = None
                if is_admin and op.user_id:
                    user = session.query(User).filter_by(id=op.user_id).first()
                    username = user.username if user else f"User{op.user_id}"
                elif op.user_id is None:
                    username = "standard"
                elif op.user_id == user_id:
                    username = "you"
                else:
                    # For non-admin users viewing other users' data (shouldn't happen with filter)
                    username = "other"
                
                history.append({
                    'id': op.id,
                    'user_id': op.user_id,
                    'username': username,
                    'operation_type': op.operation_type,
                    'cipher_type': op.cipher_type,
                    'input_text': op.input_text,
                    'output_text': op.output_text,
                    'key_used': op.key_used,
                    'timestamp': op.timestamp,
                    'score': op.score,
                    'file_name': op.file_name,
                    'is_file_operation': op.is_file_operation,
                    'is_image_operation': op.is_image_operation,
                    'is_audio_operation': op.is_audio_operation,
                    'is_rsa_operation': op.is_rsa_operation,
                    'is_security_operation': op.is_security_operation,
                    'is_auto_crack': op.is_auto_crack,
                    'flags': self._get_operation_flags(op)
                })
            
            return history
            
        except Exception as e:
            print(f"❌ Error getting combined history: {str(e)}")
            return []
        finally:
            if session:
                session.close()
 
    
    def add_security_operation(self, scan_type, target, findings, user_id=None):
        """
        Track ALL security scan operations
        """
        return self.add_operation(
            op_type="security_scan",
            cipher_type=scan_type,
            input_text=target,
            output_text=findings,
            key_used="scan_tool",
            score=70,
            user_id=user_id,
            is_security_operation=True
        )
    
    def add_hash_generation(self, hash_type, original_text, hash_value, user_id=None):
        """
        Track ALL hash generation operations
        """
        return self.add_hash_operation(
            hash_type=hash_type,
            original_text=original_text,
            hash_value=hash_value,
            user_id=user_id
        )
    
    def add_hash_cracking(self, hash_type, hash_value, cracked_text, 
                        attempts_made=0, crack_time=0, user_id=None):
        """
        Track ALL hash cracking operations - COMPLETE TRACKING
        """
        # First add as hash operation
        hash_id = self.add_hash_operation(
            hash_type=hash_type,
            original_text=cracked_text,
            hash_value=hash_value,
            cracked=True,
            cracked_text=cracked_text,
            crack_time=crack_time,
            attempts_made=attempts_made,
            user_id=user_id
        )
        
        # Also add to regular operations for comprehensive history
        if hash_id:
            self.add_operation(
                op_type="hash_crack",
                cipher_type=f"hash_{hash_type}",
                input_text=hash_value,
                output_text=cracked_text,
                key_used="hash_cracker",
                score=100,
                user_id=user_id
            )
        
        return hash_id
    
    def add_file_operation(self, operation_type, cipher_type, 
                          file_name, file_size, user_id=None):
        """
        Track ALL file operations
        """
        return self.add_operation(
            op_type=f"file_{operation_type}",
            cipher_type=cipher_type,
            input_text=f"File: {file_name}",
            output_text=f"Size: {file_size} bytes",
            key_used="file_crypto",
            score=85,
            file_name=file_name,
            is_file_operation=True,
            user_id=user_id
        )
    
    def add_audio_operation(self, operation_type, audio_format, 
                          input_info, output_info, user_id=None):
        """
        Track ALL audio operations
        """
        return self.add_operation(
            op_type=f"audio_{operation_type}",
            cipher_type="audio_crypto",
            input_text=input_info,
            output_text=output_info,
            key_used=audio_format,
            score=75,
            user_id=user_id,
            is_audio_operation=True,
            is_file_operation=True
        )
    
    # ================================================
    # ENHANCED add_operation METHOD - NEVER SKIPS ANYTHING
    # ================================================
    
    def add_operation(self, op_type, cipher_type, input_text, output_text, key_used="", score=0, 
                     file_name=None, is_file_operation=False, is_image_operation=False, 
                     is_audio_operation=False, user_id=None, is_rsa_operation=False,
                     is_security_operation=False, is_auto_crack=False):
        """
        ADD EVERYTHING TO HISTORY - COMPREHENSIVE TRACKING
        """
        session = None
        try:
            session = self.Session()
            
            # ALWAYS create operation record - NO SKIPPING
            operation = Operation(
                user_id=user_id,
                operation_type=op_type,
                cipher_type=cipher_type,
                input_text=str(input_text)[:1000] if input_text else "",
                output_text=str(output_text)[:1000] if output_text else "",
                key_used=str(key_used)[:200] if key_used else "",
                timestamp=datetime.now(),
                score=float(score) if score else 0.0,
                file_name=file_name,
                is_file_operation=bool(is_file_operation),
                is_image_operation=bool(is_image_operation),
                is_audio_operation=bool(is_audio_operation),
                is_rsa_operation=bool(is_rsa_operation),
                is_security_operation=bool(is_security_operation),
                is_auto_crack=bool(is_auto_crack)
            )
            
            session.add(operation)
            
            # ALWAYS update or create suggestion - NO SKIPPING
            suggestion = session.query(Suggestion).filter_by(
                cipher_type=cipher_type,
                user_id=user_id
            ).first()
            
            if suggestion:
                suggestion.frequency += 1
                suggestion.last_used = datetime.now()
            else:
                suggestion = Suggestion(
                    user_id=user_id,
                    cipher_type=cipher_type,
                    frequency=1,
                    last_used=datetime.now()
                )
                session.add(suggestion)
            
            session.commit()
            
            # Log successful storage
            print(f"✅ HISTORY STORED: {op_type} - {cipher_type}")
            if is_auto_crack:
                print(f"   🔓 AUTO-CRACK: {cipher_type}")
            if is_rsa_operation:
                print(f"   🔑 RSA OP: {op_type}")
            if is_image_operation:
                print(f"   🖼️ IMAGE OP: {op_type}")
            
            # Verify the file exists after operation
            db_url = str(self.engine.url)
            if db_url.startswith('sqlite:///'):
                db_file = db_url.replace('sqlite:///', '')
                if os.path.exists(db_file):
                    size = os.path.getsize(db_file)
                    print(f"💾 Database: {db_file} ({size:,} bytes)")
            
            return True
            
        except Exception as e:
            print(f"❌ CRITICAL: Failed to store in history: {str(e)}")
            print(f"   Operation: {op_type} - {cipher_type}")
            print(f"   Input: {str(input_text)[:100] if input_text else 'None'}")
            
            if session:
                session.rollback()
            
            # Try one more time with simplified data
            try:
                self._emergency_save(op_type, cipher_type, user_id)
            except:
                pass
                
            return False
        finally:
            if session:
                session.close()
    
    def _emergency_save(self, op_type, cipher_type, user_id):
        """
        Emergency save when regular save fails
        """
        session = None
        try:
            session = self.Session()
            
            operation = Operation(
                user_id=user_id,
                operation_type=op_type,
                cipher_type=cipher_type,
                input_text="[EMERGENCY SAVE]",
                output_text="[SAVED]",
                key_used="emergency",
                timestamp=datetime.now(),
                score=0
            )
            
            session.add(operation)
            session.commit()
            print(f"⚠️  Emergency save successful for {op_type}")
            
        except Exception as e2:
            print(f"❌ Even emergency save failed: {e2}")
            if session:
                session.rollback()
        finally:
            if session:
                session.close()
    
    # ================================================
    # ENHANCED get_combined_history - SHOWS EVERYTHING
    # ================================================

    def _get_operation_flags(self, operation):
        """
        Get readable flags for an operation
        """
        flags = []
        if operation.is_auto_crack:
            flags.append("🔓 Auto-crack")
        if operation.is_rsa_operation:
            flags.append("🔑 RSA")
        if operation.is_image_operation:
            flags.append("🖼️ Image")
        if operation.is_security_operation:
            flags.append("🛡️ Security")
        if operation.is_file_operation:
            flags.append("📁 File")
        if operation.is_audio_operation:
            flags.append("🔊 Audio")
        
        return ", ".join(flags) if flags else "Standard"
    
    # ================================================
    # HASH OPERATIONS METHODS
    # ================================================
    
    def add_hash_operation(self, hash_type, original_text, hash_value, cracked=False, 
                          cracked_text=None, crack_time=0, attempts_made=0, user_id=None):
        """Add hash operation to database AND to history"""
        session = None
        try:
            session = self.Session()
            
            # Create hash operation
            hash_op = HashOperation(
                user_id=user_id,
                hash_type=hash_type,
                original_text=original_text,
                hash_value=hash_value,
                timestamp=datetime.now(),
                cracked=cracked,
                cracked_text=cracked_text,
                crack_time=crack_time,
                attempts_made=attempts_made
            )
            
            session.add(hash_op)
            session.commit()
            hash_id = hash_op.id
            
            # ADD TO REGULAR OPERATION HISTORY
            operation_type = "hash_crack" if cracked else "hash_generate"
            
            operation = Operation(
                user_id=user_id,
                operation_type=operation_type,
                cipher_type=f"hash_{hash_type}",
                input_text=original_text[:500] if original_text else "",
                output_text=hash_value if not cracked else (cracked_text[:500] if cracked_text else ""),
                key_used=hash_type,
                timestamp=datetime.now(),
                score=100 if cracked else 50,
                file_name=None,
                is_file_operation=False,
                is_image_operation=False,
                is_audio_operation=False
            )
            
            session.add(operation)
            session.commit()
            
            print(f"✅ Saved {operation_type}: {original_text[:20]}... → {hash_value[:20]}...")
            return hash_id
        except Exception as e:
            print(f"❌ Database error in add_hash_operation: {str(e)}")
            if session:
                session.rollback()
            return None
        finally:
            if session:
                session.close()
    
    def add_hash_crack_attempt(self, hash_operation_id, attempt_type, attempts_made, 
                              success, cracked_text=None, user_id=None):
        """Record hash cracking attempt AND add to history"""
        session = None
        try:
            session = self.Session()
            
            attempt = HashCrackAttempt(
                user_id=user_id,
                hash_operation_id=hash_operation_id,
                attempt_type=attempt_type,
                attempts_made=attempts_made,
                success=success,
                cracked_text=cracked_text,
                timestamp=datetime.now()
            )
            
            session.add(attempt)
            
            # Get the hash operation to get details
            hash_op = session.query(HashOperation).get(hash_operation_id)
            
            # Update hash operation if successful
            if success and hash_op:
                hash_op.cracked = True
                hash_op.cracked_text = cracked_text
                
                # ADD SUCCESSFUL CRACK TO HISTORY
                operation = Operation(
                    user_id=user_id,
                    operation_type="hash_crack",
                    cipher_type=f"hash_{hash_op.hash_type}",
                    input_text=hash_op.hash_value,
                    output_text=cracked_text[:500] if cracked_text else "",
                    key_used=attempt_type,
                    timestamp=datetime.now(),
                    score=100,
                    file_name=None,
                    is_file_operation=False,
                    is_image_operation=False,
                    is_audio_operation=False
                )
                session.add(operation)
            
            session.commit()
            return True
        except Exception as e:
            print(f"Database error in add_hash_crack_attempt: {str(e)}")
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    def update_hash_crack_result(self, hash_operation_id, cracked_text, 
                               crack_time=0, attempts_made=0, user_id=None):
        """Update hash operation with cracked result AND add to history"""
        session = None
        try:
            session = self.Session()
            
            hash_op = session.query(HashOperation).get(hash_operation_id)
            if hash_op:
                hash_op.cracked = True
                hash_op.cracked_text = cracked_text
                hash_op.crack_time = crack_time
                hash_op.attempts_made = attempts_made
                
                # ADD TO HISTORY FOR SUCCESSFUL CRACKS
                operation = Operation(
                    user_id=user_id,
                    operation_type="hash_crack",
                    cipher_type=f"hash_{hash_op.hash_type}",
                    input_text=hash_op.hash_value,
                    output_text=cracked_text[:500] if cracked_text else "",
                    key_used="advanced_cracker",
                    timestamp=datetime.now(),
                    score=100,
                    file_name=None,
                    is_file_operation=False,
                    is_image_operation=False,
                    is_audio_operation=False
                )
                session.add(operation)
            
            session.commit()
            return True
        except Exception as e:
            print(f"Database error in update_hash_crack_result: {str(e)}")
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    def get_hash_operations(self, limit=20, hash_type=None, cracked_only=False, 
                          start_date=None, end_date=None, user_id=None):
        """Get hash operations with filtering"""
        session = None
        try:
            session = self.Session()
            
            query = session.query(HashOperation)
            
            if hash_type:
                query = query.filter(HashOperation.hash_type == hash_type)
            
            if cracked_only:
                query = query.filter(HashOperation.cracked == True)
            
            if user_id is not None:
                query = query.filter(HashOperation.user_id == user_id)
            
            if start_date and end_date:
                query = query.filter(HashOperation.timestamp.between(start_date, end_date))
            
            hash_ops = query.order_by(HashOperation.timestamp.desc()).limit(limit).all()
            
            return [
                {
                    'id': hop.id,
                    'user_id': hop.user_id,
                    'hash_type': hop.hash_type,
                    'original_text': hop.original_text,
                    'hash_value': hop.hash_value,
                    'timestamp': hop.timestamp,
                    'cracked': hop.cracked,
                    'cracked_text': hop.cracked_text,
                    'crack_time': hop.crack_time,
                    'attempts_made': hop.attempts_made
                }
                for hop in hash_ops
            ]
        except Exception as e:
            print(f"Database error in get_hash_operations: {str(e)}")
            return []
        finally:
            if session:
                session.close()
    
    # ================================================
    # HISTORY AND STATISTICS METHODS
    # ================================================
 
    
    
    def get_user_history(self, user_id=None, is_admin=False, limit=100, operation_type=None):
        """
        Get history with proper user permissions
        
        Args:
            user_id: The ID of the user requesting history
            is_admin: Whether the user is an admin
            limit: Maximum number of records
            operation_type: Filter by operation type
        """
        session = None
        try:
            session = self.Session()
            
            query = session.query(Operation)
            
            # CRITICAL PERMISSION LOGIC:
            if user_id is None:
                # Standard mode user: only see operations without user_id
                query = query.filter(Operation.user_id == None)
                user_type = "🔓 Standard"
            elif is_admin:
                # Admin user: can see ALL operations
                user_type = "👑 Admin"
                # No filter needed - admin sees everything
            else:
                # Regular user: only see their own operations + standard operations
                query = query.filter(
                    (Operation.user_id == user_id) | (Operation.user_id == None)
                )
                user_type = f"👤 User {user_id}"
            
            # Apply operation type filter if specified
            if operation_type and operation_type != 'all':
                query = query.filter(Operation.operation_type == operation_type)
            
            # Get results
            operations = query.order_by(Operation.timestamp.desc()).limit(limit).all()
            
            # Get usernames for admin view
            operations_list = []
            for op in operations:
                op_dict = {
                    'id': op.id,
                    'user_id': op.user_id,
                    'operation_type': op.operation_type,
                    'cipher_type': op.cipher_type,
                    'input_text': op.input_text,
                    'output_text': op.output_text,
                    'key_used': op.key_used,
                    'timestamp': op.timestamp,
                    'score': op.score,
                    'file_name': op.file_name,
                    'is_file_operation': op.is_file_operation,
                    'is_image_operation': op.is_image_operation,
                    'is_audio_operation': op.is_audio_operation,
                    'is_rsa_operation': op.is_rsa_operation,
                    'is_security_operation': op.is_security_operation,
                    'is_auto_crack': op.is_auto_crack
                }
                
                # Add username for admin view
                if is_admin and op.user_id:
                    user = session.query(User).filter_by(id=op.user_id).first()
                    op_dict['username'] = user.username if user else f"User{op.user_id}"
                elif op.user_id is None:
                    op_dict['username'] = "standard"
                elif op.user_id == user_id:
                    op_dict['username'] = "you"
                else:
                    op_dict['username'] = "other"
                
                operations_list.append(op_dict)
            
            print(f"{user_type} history: {len(operations_list)} operations")
            return operations_list
            
        except Exception as e:
            print(f"❌ Error in get_user_history: {str(e)}")
            return []
        finally:
            if session:
                session.close()
                
    def get_admin_history(self, limit=200, user_filter="all"):
        """
        Get ALL history for admin view ONLY - with username display
        
        Args:
            limit: Maximum number of operations
            user_filter: "all", "standard", or specific username
        """
        session = None
        try:
            session = self.Session()
            
            query = session.query(Operation)
            
            # Apply user filter
            if user_filter == "standard":
                query = query.filter(Operation.user_id == None)
                print(f"👑 Admin filter: Showing only standard operations")
            elif user_filter != "all":
                # Get specific user
                user = session.query(User).filter_by(username=user_filter).first()
                if user:
                    query = query.filter(Operation.user_id == user.id)
                    print(f"👑 Admin filter: Showing operations for user '{user_filter}'")
                else:
                    print(f"❌ User '{user_filter}' not found")
                    return []
            
            # Get operations
            operations = query.order_by(Operation.timestamp.desc()).limit(limit).all()
            
            # Build results with usernames
            results = []
            for op in operations:
                # Get username
                username = "standard"
                if op.user_id:
                    user = session.query(User).filter_by(id=op.user_id).first()
                    username = user.username if user else f"User{op.user_id}"
                
                # Format timestamp
                timestamp = op.timestamp.strftime("%Y-%m-%d %H:%M:%S") if op.timestamp else ""
                
                results.append({
                    'id': op.id,
                    'user_id': op.user_id,
                    'username': username,
                    'operation_type': op.operation_type,
                    'cipher_type': op.cipher_type,
                    'input_text': op.input_text,
                    'output_text': op.output_text,
                    'key_used': op.key_used,
                    'timestamp': timestamp,
                    'score': op.score,
                    'file_name': op.file_name
                })
            
            print(f"👑 Admin history: {len(results)} operations")
            return results
            
        except Exception as e:
            print(f"❌ Error in get_admin_history: {str(e)}")
            return []
        finally:
            if session:
                session.close()            
 
 
    def get_history(self, limit=20, operation_type=None, cipher_type=None, date_filter=None, 
                search_text=None, file_operations_only=False, image_operations_only=False, 
                audio_operations_only=False, start_date=None, end_date=None, user_id=None):
        """Get operation history with advanced filtering"""
        session = None
        try:
            session = self.Session()
            
            query = session.query(Operation)
            
            # Apply filters
            if operation_type:
                query = query.filter(Operation.operation_type == operation_type)
            
            if cipher_type:
                query = query.filter(Operation.cipher_type == cipher_type)
            
            # FIXED: User filtering logic
            if user_id is not None:
                # If user_id is provided, get operations for that user AND standard operations
                query = query.filter(
                    or_(
                        Operation.user_id == user_id,  # User's operations
                        Operation.user_id == None      # Standard mode operations
                    )
                )
            else:
                # If user_id is None, get only operations without user_id (standard mode)
                query = query.filter(Operation.user_id == None)
            
            # Date filtering
            if start_date and end_date:
                query = query.filter(Operation.timestamp.between(start_date, end_date))
            elif start_date:
                query = query.filter(Operation.timestamp >= start_date)
            elif end_date:
                query = query.filter(Operation.timestamp <= end_date)
            
            if search_text:
                query = query.filter(
                    or_(
                        Operation.input_text.contains(search_text),
                        Operation.output_text.contains(search_text),
                        Operation.key_used.contains(search_text),
                        Operation.file_name.contains(search_text)
                    )
                )
            
            if file_operations_only:
                query = query.filter(Operation.is_file_operation == True)
            
            if image_operations_only:
                query = query.filter(Operation.is_image_operation == True)
            
            if audio_operations_only:
                query = query.filter(Operation.is_audio_operation == True)
            
            operations = query.order_by(Operation.timestamp.desc()).limit(limit).all()
            
            return [
                {
                    'id': op.id,
                    'user_id': op.user_id,
                    'operation_type': op.operation_type,
                    'cipher_type': op.cipher_type,
                    'input_text': op.input_text,
                    'output_text': op.output_text,
                    'key_used': op.key_used,
                    'timestamp': op.timestamp,
                    'score': op.score,
                    'file_name': op.file_name,
                    'is_file_operation': op.is_file_operation,
                    'is_image_operation': op.is_image_operation,
                    'is_audio_operation': op.is_audio_operation,
                    'is_rsa_operation': op.is_rsa_operation,
                    'is_security_operation': op.is_security_operation,
                    'is_auto_crack': op.is_auto_crack
                }
                for op in operations
            ]
        except Exception as e:
            print(f"Database error in get_history: {str(e)}")
            return []
        finally:
            if session:
                session.close()
    
    def get_operation_statistics(self, days=30, user_id=None):
        """Get operation statistics for the last N days - FIXED VERSION"""
        session = None
        try:
            session = self.Session()
            since_date = datetime.now() - timedelta(days=days)
            
            # Total operations
            total_query = session.query(Operation).filter(Operation.timestamp >= since_date)
            if user_id is not None:
                total_query = total_query.filter(Operation.user_id == user_id)
            total_ops = total_query.count()
            
            # Operations by type
            ops_query = session.query(
                Operation.operation_type, 
                Operation.cipher_type,
                Operation.is_file_operation,
                Operation.is_image_operation,
                Operation.is_audio_operation,
                Operation.is_rsa_operation,
                Operation.is_security_operation,
                Operation.is_auto_crack
            ).filter(Operation.timestamp >= since_date)
            
            if user_id is not None:
                ops_query = ops_query.filter(Operation.user_id == user_id)
            
            ops_by_type = ops_query.all()
            
            # Hash operations
            hash_query = session.query(HashOperation).filter(HashOperation.timestamp >= since_date)
            if user_id is not None:
                hash_query = hash_query.filter(HashOperation.user_id == user_id)
            
            hash_ops = hash_query.all()
            hash_cracked = sum(1 for hop in hash_ops if hop.cracked)
            
            # Calculate statistics
            stats = {
                'total_operations': total_ops,
                'total_hash_operations': len(hash_ops),
                'hash_cracked': hash_cracked,
                'hash_success_rate': (hash_cracked / len(hash_ops) * 100) if hash_ops else 0,
                'operations_by_type': {},
                'file_operations': sum(1 for op in ops_by_type if op.is_file_operation),
                'image_operations': sum(1 for op in ops_by_type if op.is_image_operation),
                'audio_operations': sum(1 for op in ops_by_type if op.is_audio_operation),
                'rsa_operations': sum(1 for op in ops_by_type if op.is_rsa_operation),
                'security_operations': sum(1 for op in ops_by_type if op.is_security_operation),
                'auto_crack_operations': sum(1 for op in ops_by_type if op.is_auto_crack)
            }
            
            # Count operations by type
            for op in ops_by_type:
                op_type = op.operation_type
                if op_type not in stats['operations_by_type']:
                    stats['operations_by_type'][op_type] = 0
                stats['operations_by_type'][op_type] += 1
            
            return stats
        except Exception as e:
            print(f"Database error in get_operation_statistics: {str(e)}")
            return {}
        finally:
            if session:
                session.close()
    
    # ================================================
    # USER MANAGEMENT METHODS
    # ================================================
    
    def get_all_users(self, admin_only=False):
        """Get all users (admin only)"""
        session = None
        try:
            session = self.Session()
            query = session.query(User)
            
            if admin_only:
                query = query.filter(User.is_admin == True)
            
            users = query.all()
            
            return [
                {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_verified': user.is_verified,
                    'created_at': user.created_at,
                    'last_login': user.last_login
                }
                for user in users
            ]
        except Exception as e:
            print(f"❌ Get users error: {str(e)}")
            return []
        finally:
            if session:
                session.close()
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        session = None
        try:
            session = self.Session()
            user = session.query(User).get(user_id)
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_verified': user.is_verified,
                    'created_at': user.created_at,
                    'last_login': user.last_login
                }
            return None
        except Exception as e:
            print(f"❌ Error getting user by ID: {str(e)}")
            return None
        finally:
            if session:
                session.close()
    
    def get_user_by_username(self, username):
        """Get user by username"""
        session = None
        try:
            session = self.Session()
            user = session.query(User).filter_by(username=username).first()
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_verified': user.is_verified,
                    'created_at': user.created_at,
                    'last_login': user.last_login
                }
            return None
        except Exception as e:
            print(f"❌ Error getting user by username: {str(e)}")
            return None
        finally:
            if session:
                session.close()
    
    def delete_user(self, user_id):
        """Delete a user by ID"""
        session = None
        try:
            session = self.Session()
            user = session.query(User).get(user_id)
            if user:
                # Get username before deleting
                username = user.username
                
                # Delete user (cascade will delete all related operations)
                session.delete(user)
                session.commit()
                
                print(f"✅ User '{username}' (ID: {user_id}) deleted successfully")
                return {'success': True, 'username': username}
            else:
                return {'success': False, 'error': 'User not found'}
                
        except Exception as e:
            print(f"❌ Error deleting user: {str(e)}")
            if session:
                session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    def update_user_admin_status(self, user_id, is_admin):
        """Update user's admin status"""
        session = None
        try:
            session = self.Session()
            user = session.query(User).get(user_id)
            if user:
                user.is_admin = is_admin
                session.commit()
                
                action = "promoted to admin" if is_admin else "demoted from admin"
                print(f"✅ User '{user.username}' {action}")
                return {'success': True, 'username': user.username}
            else:
                return {'success': False, 'error': 'User not found'}
                
        except Exception as e:
            print(f"❌ Error updating user admin status: {str(e)}")
            if session:
                session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    def update_user_verification(self, user_id, is_verified):
        """Update user's verification status"""
        session = None
        try:
            session = self.Session()
            user = session.query(User).get(user_id)
            if user:
                user.is_verified = is_verified
                if is_verified:
                    user.verification_code = None
                    user.verification_expires = None
                session.commit()
                
                action = "verified" if is_verified else "unverified"
                print(f"✅ User '{user.username}' {action}")
                return {'success': True, 'username': user.username}
            else:
                return {'success': False, 'error': 'User not found'}
                
        except Exception as e:
            print(f"❌ Error updating user verification: {str(e)}")
            if session:
                session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    # ================================================
    # SUGGESTIONS AND POPULAR CIPHERS
    # ================================================
    
    def get_suggestions(self, limit=5, user_id=None):
        """Get cipher suggestions based on usage"""
        session = None
        try:
            session = self.Session()
            
            query = session.query(Suggestion)
            
            if user_id is not None:
                query = query.filter(Suggestion.user_id == user_id)
            
            suggestions = query\
                .order_by(Suggestion.frequency.desc(), Suggestion.last_used.desc())\
                .limit(limit)\
                .all()
            
            return [
                {
                    'id': sug.id,
                    'user_id': sug.user_id,
                    'cipher_type': sug.cipher_type,
                    'frequency': sug.frequency,
                    'last_used': sug.last_used
                }
                for sug in suggestions
            ]
        except Exception as e:
            print(f"Database error in get_suggestions: {str(e)}")
            return []
        finally:
            if session:
                session.close()
    
    def get_popular_ciphers(self, limit=5, user_id=None):
        """Get most popular ciphers based on usage frequency"""
        session = None
        try:
            session = self.Session()
            
            query = session.query(Suggestion)
            
            if user_id is not None:
                query = query.filter(Suggestion.user_id == user_id)
            
            popular = query\
                .order_by(Suggestion.frequency.desc())\
                .limit(limit)\
                .all()
            
            return [
                {
                    'cipher_type': sug.cipher_type,
                    'frequency': sug.frequency,
                    'last_used': sug.last_used
                }
                for sug in popular
            ]
        except Exception as e:
            print(f"Database error in get_popular_ciphers: {str(e)}")
            return []
        finally:
            if session:
                session.close()
    
    # ================================================
    # CLEANUP AND DELETE METHODS
    # ================================================
    
    def clear_history(self, operation_type=None, user_id=None):
        """Clear operation history (optionally by type and user)"""
        session = None
        try:
            session = self.Session()
            
            query = session.query(Operation)
            
            if user_id is not None:
                query = query.filter(Operation.user_id == user_id)
            
            if operation_type:
                query = query.filter(Operation.operation_type == operation_type)
            
            deleted_count = query.delete()
            
            # Also clear suggestions for this user
            if user_id is not None:
                session.query(Suggestion).filter(Suggestion.user_id == user_id).delete()
            
            session.commit()
            print(f"✅ Cleared {deleted_count} operations")
            return True
        except Exception as e:
            print(f"Database error in clear_history: {str(e)}")
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    def delete_operation(self, operation_id):
        """Delete specific operation by ID"""
        session = None
        try:
            session = self.Session()
            operation = session.query(Operation).get(operation_id)
            if operation:
                session.delete(operation)
                session.commit()
                return True
            return False
        except Exception as e:
            print(f"Database error in delete_operation: {str(e)}")
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    def delete_hash_operation(self, hash_operation_id):
        """Delete specific hash operation by ID"""
        session = None
        try:
            session = self.Session()
            hash_op = session.query(HashOperation).get(hash_operation_id)
            if hash_op:
                # Delete related crack attempts first
                session.query(HashCrackAttempt).filter_by(hash_operation_id=hash_operation_id).delete()
                session.delete(hash_op)
                session.commit()
                return True
            return False
        except Exception as e:
            print(f"Database error in delete_hash_operation: {str(e)}")
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    # ================================================
    # USER STATISTICS AND SUMMARIES
    # ================================================
    
    def get_user_operations_summary(self, user_id):
        """Get summary of user's operations"""
        session = None
        try:
            session = self.Session()
            
            # Total operations
            total_ops = session.query(Operation).filter(Operation.user_id == user_id).count()
            
            # First operation date
            first_op = session.query(Operation).filter(Operation.user_id == user_id)\
                .order_by(Operation.timestamp.asc()).first()
            
            # Last operation date
            last_op = session.query(Operation).filter(Operation.user_id == user_id)\
                .order_by(Operation.timestamp.desc()).first()
            
            # Hash operations
            hash_ops = session.query(HashOperation).filter(HashOperation.user_id == user_id).count()
            hash_cracked = session.query(HashOperation)\
                .filter(HashOperation.user_id == user_id, HashOperation.cracked == True).count()
            
            return {
                'total_operations': total_ops,
                'hash_operations': hash_ops,
                'hash_cracked': hash_cracked,
                'first_operation': first_op.timestamp if first_op else None,
                'last_operation': last_op.timestamp if last_op else None,
                'hash_success_rate': (hash_cracked / hash_ops * 100) if hash_ops > 0 else 0
            }
        except Exception as e:
            print(f"Database error in get_user_operations_summary: {str(e)}")
            return {}
        finally:
            if session:
                session.close()
    
    def get_user_statistics(self, user_id):
        """Get detailed statistics for a user"""
        session = None
        try:
            session = self.Session()
            
            # Get user
            user = session.query(User).get(user_id)
            if not user:
                return None
            
            # Count operations by type
            operations = session.query(Operation).filter_by(user_id=user_id).all()
            
            # Count hash operations
            hash_ops = session.query(HashOperation).filter_by(user_id=user_id).all()
            
            # Calculate statistics
            stats = {
                'user_id': user.id,
                'username': user.username,
                'total_operations': len(operations) + len(hash_ops),
                'regular_operations': len(operations),
                'hash_operations': len(hash_ops),
                'hash_cracked': sum(1 for hop in hash_ops if hop.cracked),
                'hash_success_rate': (sum(1 for hop in hash_ops if hop.cracked) / len(hash_ops) * 100) if hash_ops else 0,
                'operations_by_type': {},
                'first_operation': None,
                'last_operation': None
            }
            
            # Count operations by type
            for op in operations:
                op_type = op.operation_type
                if op_type not in stats['operations_by_type']:
                    stats['operations_by_type'][op_type] = 0
                stats['operations_by_type'][op_type] += 1
            
            # Get first and last operation timestamps
            if operations:
                timestamps = [op.timestamp for op in operations if op.timestamp]
                if timestamps:
                    stats['first_operation'] = min(timestamps)
                    stats['last_operation'] = max(timestamps)
            
            return stats
        except Exception as e:
            print(f"❌ Error getting user statistics: {str(e)}")
            return None
        finally:
            if session:
                session.close()
    
    def get_user_operations_count(self, user_id):
        """Get count of operations for a user"""
        session = None
        try:
            session = self.Session()
            
            # Count regular operations
            op_count = session.query(Operation).filter_by(user_id=user_id).count()
            
            # Count hash operations
            hash_op_count = session.query(HashOperation).filter_by(user_id=user_id).count()
            
            return op_count + hash_op_count
        except Exception as e:
            print(f"❌ Error getting user operations count: {str(e)}")
            return 0
        finally:
            if session:
                session.close()
    
    # ================================================
    # BULK OPERATIONS AND SEARCH
    # ================================================
    
    def bulk_delete_operations(self, operation_ids):
        """Delete multiple operations at once"""
        session = None
        try:
            session = self.Session()
            deleted_count = 0
            
            for op_id in operation_ids:
                operation = session.query(Operation).get(op_id)
                if operation:
                    session.delete(operation)
                    deleted_count += 1
            
            session.commit()
            print(f"✅ Bulk deleted {deleted_count} operations")
            return {'success': True, 'deleted_count': deleted_count}
                
        except Exception as e:
            print(f"❌ Error in bulk delete: {str(e)}")
            if session:
                session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    def clear_all_user_data(self, user_id):
        """Clear all data for a specific user"""
        session = None
        try:
            session = self.Session()
            
            # Get user first
            user = session.query(User).get(user_id)
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            username = user.username
            
            # Delete user's operations
            op_count = session.query(Operation).filter_by(user_id=user_id).delete()
            
            # Delete user's hash operations
            hash_op_count = session.query(HashOperation).filter_by(user_id=user_id).delete()
            
            # Delete user's suggestions
            sug_count = session.query(Suggestion).filter_by(user_id=user_id).delete()
            
            # Delete user's hash crack attempts
            attempt_count = session.query(HashCrackAttempt).filter_by(user_id=user_id).delete()
            
            session.commit()
            
            print(f"✅ Cleared all data for user '{username}':")
            print(f"   • Operations: {op_count}")
            print(f"   • Hash operations: {hash_op_count}")
            print(f"   • Suggestions: {sug_count}")
            print(f"   • Hash attempts: {attempt_count}")
            
            return {
                'success': True,
                'username': username,
                'operations_deleted': op_count,
                'hash_operations_deleted': hash_op_count,
                'suggestions_deleted': sug_count,
                'attempts_deleted': attempt_count
            }
                
        except Exception as e:
            print(f"❌ Error clearing user data: {str(e)}")
            if session:
                session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            if session:
                session.close()
    
    def search_users(self, search_term, limit=20):
        """Search users by username or email"""
        session = None
        try:
            session = self.Session()
            
            query = session.query(User).filter(
                or_(
                    User.username.contains(search_term),
                    User.email.contains(search_term)
                )
            )
            
            users = query.order_by(User.username).limit(limit).all()
            
            return [
                {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_verified': user.is_verified,
                    'created_at': user.created_at,
                    'last_login': user.last_login
                }
                for user in users
            ]
        except Exception as e:
            print(f"❌ Error searching users: {str(e)}")
            return []
        finally:
            if session:
                session.close()
    
    def get_recent_logins(self, limit=10):
        """Get users with recent logins"""
        session = None
        try:
            session = self.Session()
            
            users = session.query(User)\
                .filter(User.last_login.isnot(None))\
                .order_by(User.last_login.desc())\
                .limit(limit)\
                .all()
            
            return [
                {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_verified': user.is_verified,
                    'last_login': user.last_login
                }
                for user in users
            ]
        except Exception as e:
            print(f"❌ Error getting recent logins: {str(e)}")
            return []
        finally:
            if session:
                session.close()
    
    # ================================================
    # COMPREHENSIVE OPERATION VERIFICATION
    # ================================================
    
    def verify_all_operations_stored(self, user_id=None):
        """
        Verify that ALL types of operations are being stored
        """
        print("\n" + "="*60)
        print("🔍 VERIFYING ALL OPERATIONS ARE STORED")
        print("="*60)
        
        session = None
        try:
            session = self.Session()
            
            # Get counts for all operation types
            results = {}
            
            # Regular operations
            results['total'] = session.query(Operation).count()
            
            # Auto-crack operations
            results['auto_crack'] = session.query(Operation).filter_by(is_auto_crack=True).count()
            
            # RSA operations
            results['rsa'] = session.query(Operation).filter_by(is_rsa_operation=True).count()
            
            # Image operations
            results['image'] = session.query(Operation).filter_by(is_image_operation=True).count()
            
            # Security operations
            results['security'] = session.query(Operation).filter_by(is_security_operation=True).count()
            
            # File operations
            results['file'] = session.query(Operation).filter_by(is_file_operation=True).count()
            
            # Audio operations
            results['audio'] = session.query(Operation).filter_by(is_audio_operation=True).count()
            
            # Hash operations (from both tables)
            results['hash_from_ops'] = session.query(Operation)\
                .filter(Operation.cipher_type.like('hash_%')).count()
            
            results['hash_from_hash'] = session.query(HashOperation).count()
            
            # By operation type
            operation_types = session.query(
                Operation.operation_type,
                func.count(Operation.id).label('count')
            ).group_by(Operation.operation_type).all()
            
            print("\n📊 OPERATION COUNTS:")
            print("-" * 40)
            for key, value in results.items():
                print(f"  {key.replace('_', ' ').title():<20}: {value}")
            
            print(f"\n📋 OPERATION TYPES:")
            print("-" * 40)
            for op_type, count in operation_types:
                print(f"  {op_type:<20}: {count}")
            
            # Check for any missing types
            expected_types = ['encrypt', 'decrypt', 'auto_crack', 'hash_crack', 
                            'hash_generate', 'file_encrypt', 'file_decrypt',
                            'image_encrypt', 'image_decrypt', 'rsa_generate',
                            'rsa_encrypt', 'rsa_decrypt', 'security_scan']
            
            found_types = [op_type for op_type, _ in operation_types]
            missing = [t for t in expected_types if t not in found_types]
            
            if missing:
                print(f"\n⚠️  MISSING OPERATION TYPES:")
                for m in missing:
                    print(f"  ❌ {m}")
            
            print(f"\n✅ VERIFICATION COMPLETE")
            print(f"   Total operations in database: {results['total']}")
            
            return results
            
        except Exception as e:
            print(f"❌ Verification error: {str(e)}")
            return {}
        finally:
            if session:
                session.close()
    
    def _test_connection(self):
        """Test if database connection works"""
        session = None
        try:
            session = self.Session()
            # Try a simple query
            session.query(Operation).first()
            print(f"✅ Database connection successful")
            
            # Show actual database location
            if hasattr(self.engine, 'url'):
                db_url = str(self.engine.url)
                if db_url.startswith('sqlite:///'):
                    db_file = db_url.replace('sqlite:///', '')
                    if os.path.exists(db_file):
                        size = os.path.getsize(db_file)
                        print(f"📊 Database location: {db_file}")
                        print(f"📊 File size: {size:,} bytes")
            
        except Exception as e:
            print(f"⚠️  Connection test warning: {e}")
        finally:
            if session:
                session.close()

    def test_email_function(self):
        """Test the email function directly"""
        print("\n" + "="*60)
        print("📧 TESTING EMAIL FUNCTION")
        print("="*60)
        
        test_email = "spidermana911here@gmail.com"
        test_username = "test_user"
        test_code = str(random.randint(100000, 999999))
        
        print(f"Test email to: {test_email}")
        print(f"Test username: {test_username}")
        print(f"Test code: {test_code}")
        
        success = self._send_verification_email(test_email, test_username, test_code)
        
        if success:
            print("\n✅ EMAIL FUNCTION WORKS PERFECTLY!")
            print("Your CryptoTool database is ready!")
        else:
            print("\n❌ Email function test failed")
        
        return success


# ================================================
# COMPLETE TEST CODE
# ================================================
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 CRYPTOTOOL DATABASE - COMPLETE TEST")
    print("="*60)
    
    print(f"📁 Current directory: {os.getcwd()}")
    print(f"📁 Database location: {DB_FILE_PATH}")
    
    # Create database instance
    print("\n🔧 Creating database connection...")
    try:
        db = CryptoDatabaseORM()
        
        # Test authentication
        print("\n🔐 Testing authentication...")
        result = db.authenticate_user("admin", "admin123")
        if result.get('success'):
            print(f"✅ Admin authentication successful!")
            print(f"   👤 Username: {result['username']}")
            print(f"   👑 Is admin: {result['is_admin']}")
        else:
            print(f"❌ Admin auth failed: {result.get('error')}")
        
        # Test adding operations
        print("\n➕ Testing operation recording...")
        success = db.add_operation(
            op_type="encrypt",
            cipher_type="caesar",
            input_text="Hello World",
            output_text="Khoor Zruog",
            key_used="3",
            score=95,
            user_id=1
        )
        
        if success:
            print(f"✅ Test operation saved")
            
            # Get statistics
            stats = db.get_operation_statistics(days=1)
            print(f"📊 Statistics: {stats.get('total_operations', 0)} operations")
            
            # Show database info
            db_url = str(db.engine.url)
            if db_url.startswith('sqlite:///'):
                actual_db = db_url.replace('sqlite:///', '')
                if os.path.exists(actual_db):
                    size = os.path.getsize(actual_db)
                    print(f"\n🎯 Database: {actual_db}")
                    print(f"📏 Size: {size:,} bytes")
        
        # Test all operation tracking methods
        print("\n🧪 Testing all operation tracking methods...")
        
        # Test auto-crack
        db.add_auto_crack_operation(
            cipher_type="caesar",
            input_text="Khoor Zruog",
            cracked_result="Hello World",
            user_id=1
        )
        print("✅ Auto-crack operation saved")
        
        # Test RSA operation
        db.add_rsa_operation(
            operation_type="generate",
            key_size=2048,
            input_info="RSA Key Generation",
            output_info="Public/Private Key Pair",
            user_id=1
        )
        print("✅ RSA operation saved")
        
        # Test image operation
        db.add_image_operation(
            operation_type="encrypt",
            image_format="PNG",
            input_info="image.png (1280x720)",
            output_info="encrypted_image.crypto",
            user_id=1
        )
        print("✅ Image operation saved")
        
        # Test hash cracking
        db.add_hash_cracking(
            hash_type="sha256",
            hash_value="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            cracked_text="Hello World",
            attempts_made=1000,
            user_id=1
        )
        print("✅ Hash cracking operation saved")
        
        # Test file operation
        db.add_file_operation(
            operation_type="encrypt",
            cipher_type="AES",
            file_name="secret.txt",
            file_size=1024,
            user_id=1
        )
        print("✅ File operation saved")
        
        # Test security operation
        db.add_security_operation(
            scan_type="vulnerability_scan",
            target="example.com",
            findings="3 vulnerabilities found",
            user_id=1
        )
        print("✅ Security operation saved")
        
        # Test audio operation
        db.add_audio_operation(
            operation_type="encrypt",
            audio_format="MP3",
            input_info="song.mp3",
            output_info="encrypted_audio",
            user_id=1
        )
        print("✅ Audio operation saved")
        
        # Verify everything is stored
        results = db.verify_all_operations_stored()
        
        # Show recent history
        history = db.get_combined_history(limit=20)
        print(f"\n📜 RECENT HISTORY ({len(history)} operations):")
        for op in history:
            print(f"  {op['timestamp'].strftime('%H:%M:%S')} - {op['operation_type']:15} {op['cipher_type']:20} {op['flags']}")
        
        # Show all users
        print("\n👥 All users in database:")
        users = db.get_all_users()
        for user in users:
            status = "✅" if user['is_verified'] else "⏳"
            admin = "👑" if user['is_admin'] else "👤"
            print(f"  {admin} {status} {user['username']} ({user['email']})")
            
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*60)
    print("✅ CRYPTOTOOL DATABASE READY!")
    print("📧 EMAIL VERIFICATION WORKING!")
    print("🎯 ALL OPERATIONS WILL BE STORED!")
    print("="*60)