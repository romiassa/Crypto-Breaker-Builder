import multiprocessing  
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD # type: ignore
import json
import base64
import os
from datetime import datetime
import threading
import queue
import sys
import io
import math
import tempfile
import glob
import atexit
import time
from functools import partial
from database_orm import CryptoDatabaseORM,Operation,HashOperation
from datetime import datetime, date, timedelta  

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from aes_crypto import AESEncryption
    from steganography_utils import ImageSteganography, AudioSteganography
    from database_orm import CryptoDatabaseORM
    from hash_cracker import AdvancedHashCracker as HashCracker
    from auto_crack_modern import modern_cracker
    from cipher_crack import crack_cipher
    from cipher_utils import encrypt, decrypt, score_text
    from rsa_utils import RSAUltimateEncryptor, RSAUltimateAttack
    
    print("✅ All backend modules loaded successfully")
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure all your backend files are in the same directory:")
    print("  - aes_crypto.py")
    print("  - steganography_utils.py")
    print("  - database_orm.py")
    print("  - hash_cracker.py")
    print("  - auto_crack_modern.py")
    print("  - cipher_crack.py")
    print("  - cipher_utils.py")
    print("  - rsa_utils.py")
    sys.exit(1)

try:
    from nmap_scanner import NmapScanner
    from bulk_ssl_scanner import BulkSSLScanner
    from quantum_checker import QuantumChecker 
    print("✅ New security modules loaded successfully")
except ImportError as e:
    print(f"⚠️  Some security modules not available: {e}")
    print("You can still use the core features. Install missing modules with:")
    print("  pip install python-nmap pyOpenSSL")
    class NmapScanner:
        def __init__(self):
            self.available = False
        def scan_target(self, target, ports="1-1000", arguments="-sV -O"):
            return {"success": False, "error": "Module not installed"}
    
    class BulkSSLScanner:
        def __init__(self, max_workers=10, timeout=10):
            self.available = False
        def scan_bulk(self, domains):
            return {"success": False, "error": "Module not installed"}
    
    class QuantumChecker:
        def __init__(self):
            self.available = False
        def analyze_certificate(self, domain):
            return {"success": False, "error": "Module not installed"}

class CryptoToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 CryptoTool - Complete Security Toolkit")
        self.root.geometry("1400x900")
        
        # Authentication state
        self.current_user = None
        self.mode = "standard"  # "standard" or "custom"
        
        self.aes = AESEncryption()
        self.img_stega = ImageSteganography()
        self.audio_stega = AudioSteganography()
        self.db = CryptoDatabaseORM()
        self.hash_cracker = HashCracker(self.db)
        
        self.nmap_scanner = NmapScanner()
        self.ssl_scanner = BulkSSLScanner(max_workers=5, timeout=10)
        self.quantum_checker = QuantumChecker()
        
        self.rsa_encryptor = None
        self.rsa_attacker = None
        self.initialize_rsa_modules()
        
        atexit.register(self.cleanup_temp_files)
        
        self.bg_color = '#0a0e27'
        self.container_bg = '#14192d'
        self.section_bg = '#1a1f37'
        self.accent_color = '#00d9ff'
        self.text_color = '#e0e0e0'
        self.success_color = '#00ff88'
        self.error_color = '#ff4444'
        self.warning_color = '#ffaa00'
        
        self.root.configure(bg=self.bg_color)
        
        self.title_font = ('Segoe UI', 24, 'bold')
        self.subtitle_font = ('Segoe UI', 12)
        self.heading_font = ('Segoe UI', 18, 'bold')
        self.subheading_font = ('Segoe UI', 14, 'bold')
        self.normal_font = ('Segoe UI', 10)
        self.mono_font = ('Courier New', 10)
        
        self.selected_files = {}
        
        # Show authentication dialog first
        self.show_auth_dialog()

    def setup_ui(self):
        """Setup the main UI after authentication"""
        print(f"🔧 Setting up UI for {'user: ' + self.current_user['username'] if self.current_user else 'standard mode'}")
        
        # Create UI elements only once
        self.create_main_container()
        self.create_header()
        self.create_tabs()
        self.initialize_tabs()
        self.show_tab("Text Encrypt")
        
        # Create user info section in header
        self.create_user_info_section()
      
    def create_user_info_section(self):
        """Create user info section in header"""
        # Find the header frame
        for child in self.main_frame.winfo_children():
            if isinstance(child, tk.Frame) and len(child.winfo_children()) > 0:
                header_frame = child
                break
        else:
            return
        
        # Create a frame for user info on the right
        user_frame = tk.Frame(header_frame, bg=self.container_bg)
        user_frame.pack(side='right', padx=10, pady=10)
        
        if self.current_user:
            # User info
            user_text = f"👤 {self.current_user['username']}"
            if self.current_user.get('is_admin'):
                user_text += " 👑"
            
            user_label = tk.Label(user_frame, text=user_text,
                                font=('Segoe UI', 11, 'bold'),
                                fg=self.accent_color,
                                bg=self.container_bg)
            user_label.pack(side='left', padx=(0, 15))
            
            # Logout button
            logout_btn = tk.Button(user_frame, text="Logout",
                                font=('Segoe UI', 9),
                                bg='#2a2f47',
                                fg=self.text_color,
                                relief='flat',
                                bd=0,
                                command=self.logout)
            logout_btn.pack(side='left')
            
            # Show verification status
            if not self.current_user.get('is_verified'):
                verify_label = tk.Label(user_frame, text="(Not Verified)",
                                    font=('Segoe UI', 9),
                                    fg=self.warning_color,
                                    bg=self.container_bg)
                verify_label.pack(side='left', padx=(10, 0))
        else:
            # Standard mode
            mode_label = tk.Label(user_frame, text="🔓 Standard Mode",
                                font=('Segoe UI', 11),
                                fg='#888888',
                                bg=self.container_bg)
            mode_label.pack(side='left', padx=(0, 15))
            
            # Switch to custom mode button
            switch_btn = tk.Button(user_frame, text="Switch to Account",
                                font=('Segoe UI', 9),
                                bg='#2a2f47',
                                fg=self.accent_color,
                                relief='flat',
                                bd=0,
                                command=self.switch_to_custom_mode)
            switch_btn.pack(side='left')

    def switch_to_custom_mode(self):
        """Switch from standard to custom mode"""
        response = messagebox.askyesno("Switch Mode", 
                                    "Switch to Custom Mode (requires account)?\n\n"
                                    "• Your current operations will be saved\n"
                                    "• You'll need to login or register")
        
        if response:
            # Save current state if needed
            self.main_frame.destroy()
            self.show_auth_dialog()
                        
    def show_auth_dialog(self):
        """Show authentication dialog - FIXED VERSION"""
        self.auth_window = tk.Toplevel(self.root)
        self.auth_window.title("🔐 CryptoTool Authentication")
        self.auth_window.geometry("700x600")
        self.auth_window.configure(bg=self.bg_color)
        self.auth_window.resizable(False, False)
        
        # Make it modal but wait for window to be visible
        self.auth_window.transient(self.root)
        
        # Center the window
        self.auth_window.update_idletasks()
        screen_width = self.auth_window.winfo_screenwidth()
        screen_height = self.auth_window.winfo_screenheight()
        x = (screen_width - 700) // 2
        y = (screen_height - 600) // 2
        self.auth_window.geometry(f"700x600+{x}+{y}")
        
        # Set grab after window is visible
        self.auth_window.after(100, self.auth_window.grab_set)
        
        # Create container for all pages
        self.auth_container = tk.Frame(self.auth_window, bg=self.bg_color)
        self.auth_container.pack(fill='both', expand=True, padx=40, pady=40)
        
        # Show initial page
        self.show_auth_mode_page()

    def show_auth_mode_page(self):
        """Show mode selection page"""
        # Clear container
        for widget in self.auth_container.winfo_children():
            widget.destroy()
        
        # Title
        title = tk.Label(self.auth_container, text="🔐 CryptoTool", 
                        font=('Segoe UI', 36, 'bold'), fg=self.accent_color, bg=self.bg_color)
        title.pack(pady=(0, 10))
        
        subtitle = tk.Label(self.auth_container, text="Complete Security Toolkit",
                        font=('Segoe UI', 18), fg='#a0a0a0', bg=self.bg_color)
        subtitle.pack(pady=(0, 40))
        
        # Standard Mode Button
        standard_btn = tk.Button(self.auth_container,
                            text="🚀 STANDARD MODE\n\n• Shared history with all users\n• No login required\n• Quick start, full access",
                            font=('Segoe UI', 14),
                            bg=self.accent_color,
                            fg=self.bg_color,
                            relief='flat',
                            bd=0,
                            padx=40,
                            pady=30,
                            width=50,
                            height=6,
                            command=self.start_standard_mode)
        standard_btn.pack(pady=(0, 20))
        
        # Custom Mode Button
        custom_btn = tk.Button(self.auth_container,
                            text="👤 CUSTOM MODE\n\n• Private history for your account\n• Email verification required\n• Admin features available",
                            font=('Segoe UI', 14),
                            bg='#2a2f47',
                            fg=self.accent_color,
                            relief='flat',
                            bd=0,
                            padx=40,
                            pady=30,
                            width=50,
                            height=6,
                            command=self.show_login_page)
        custom_btn.pack(pady=(0, 20))
        
        # Admin login link
        admin_link = tk.Label(self.auth_container, text="🔑 Sign in as Admin", 
                            font=('Segoe UI', 12), fg='#ffaa00', 
                            bg=self.bg_color, cursor="hand2")
        admin_link.pack(pady=(10, 0))
        admin_link.bind("<Button-1>", lambda e: self.show_admin_login_page())

    def show_login_page(self):
        """Show login page"""
        # Clear container
        for widget in self.auth_container.winfo_children():
            widget.destroy()
        
        # Back button
        back_frame = tk.Frame(self.auth_container, bg=self.bg_color)
        back_frame.pack(fill='x', pady=(0, 20))
        
        back_btn = tk.Button(back_frame, text="← Back",
                            font=('Segoe UI', 10),
                            bg='#2a2f47',
                            fg=self.text_color,
                            relief='flat',
                            bd=0,
                            command=self.show_auth_mode_page)
        back_btn.pack(side='left')
        
        # Title
        title = tk.Label(self.auth_container, text="👤 Login", 
                        font=('Segoe UI', 28, 'bold'), fg=self.accent_color, bg=self.bg_color)
        title.pack(pady=(0, 30))
        
        # Error label
        self.auth_error_label = tk.Label(self.auth_container, text="",
                                        font=('Segoe UI', 11), fg=self.error_color, 
                                        bg=self.bg_color)
        self.auth_error_label.pack(fill='x', pady=(0, 10))
        
        # Username
        username_label = tk.Label(self.auth_container, text="Username:", 
                                font=('Segoe UI', 16), fg='#b0b0b0', bg=self.bg_color)
        username_label.pack(anchor='w', pady=(10, 5))
        
        self.username_entry = tk.Entry(self.auth_container, 
                                    bg='#0d142e', 
                                    fg=self.text_color,
                                    insertbackground=self.accent_color,
                                    relief='solid', 
                                    bd=2,
                                    font=('Segoe UI', 16),
                                    width=30)
        self.username_entry.pack(fill='x', pady=(0, 20))
        self.username_entry.focus()
        
        # Password
        password_label = tk.Label(self.auth_container, text="Password:", 
                                font=('Segoe UI', 16), fg='#b0b0b0', bg=self.bg_color)
        password_label.pack(anchor='w', pady=(0, 5))
        
        self.password_entry = tk.Entry(self.auth_container, 
                                    bg='#0d142e', 
                                    fg=self.text_color,
                                    insertbackground=self.accent_color,
                                    relief='solid', 
                                    bd=2,
                                    font=('Segoe UI', 16),
                                    width=30,
                                    show="•")
        self.password_entry.pack(fill='x', pady=(0, 30))
        self.password_entry.bind('<Return>', lambda e: self.do_login())
        
        # Login Button
        login_btn = tk.Button(self.auth_container,
                            text="LOGIN",
                            font=('Segoe UI', 16, 'bold'),
                            bg=self.accent_color,
                            fg=self.bg_color,
                            relief='flat',
                            bd=0,
                            padx=50,
                            pady=15,
                            command=self.do_login)
        login_btn.pack(pady=(0, 20))
        
        # Register link
        register_frame = tk.Frame(self.auth_container, bg=self.bg_color)
        register_frame.pack(fill='x', pady=(10, 0))
        
        tk.Label(register_frame, text="New user?", 
                font=('Segoe UI', 12), fg='#888888', bg=self.bg_color).pack(side='left')
        
        register_link = tk.Label(register_frame, text="Register here", 
                            font=('Segoe UI', 12, 'bold'), fg=self.accent_color, 
                            bg=self.bg_color, cursor="hand2")
        register_link.pack(side='left', padx=(5, 0))
        register_link.bind("<Button-1>", lambda e: self.show_register_dialog())

    def show_admin_login_page(self):
        """Show admin login page - FIXED"""
        # Clear container
        for widget in self.auth_container.winfo_children():
            widget.destroy()
        
        # Back button
        back_frame = tk.Frame(self.auth_container, bg=self.bg_color)
        back_frame.pack(fill='x', pady=(0, 20))
        
        back_btn = tk.Button(back_frame, text="← Back",
                            font=('Segoe UI', 10),
                            bg='#2a2f47',
                            fg=self.text_color,
                            relief='flat',
                            bd=0,
                            command=self.show_auth_mode_page)
        back_btn.pack(side='left')
        
        # Title
        title = tk.Label(self.auth_container, text="🔑 Admin Login", 
                        font=('Segoe UI', 28, 'bold'), fg='#ffaa00', bg=self.bg_color)
        title.pack(pady=(0, 30))
        
        # Error label
        admin_error_label = tk.Label(self.auth_container, text="",
                                    font=('Segoe UI', 11), fg=self.error_color, 
                                    bg=self.bg_color)
        admin_error_label.pack(fill='x', pady=(0, 10))
        
        # Username
        username_label = tk.Label(self.auth_container, text="Username:", 
                                font=('Segoe UI', 16), fg='#b0b0b0', bg=self.bg_color)
        username_label.pack(anchor='w', pady=(10, 5))
        
        admin_user = tk.Entry(self.auth_container, 
                            bg='#0d142e', 
                            fg=self.text_color,
                            insertbackground='#ffaa00',
                            relief='solid', 
                            bd=2,
                            font=('Segoe UI', 16),
                            width=30)
        admin_user.pack(fill='x', pady=(0, 20))
        admin_user.insert(0, "admin")
        admin_user.focus()
        
        # Password
        password_label = tk.Label(self.auth_container, text="Password:", 
                                font=('Segoe UI', 16), fg='#b0b0b0', bg=self.bg_color)
        password_label.pack(anchor='w', pady=(0, 5))
        
        admin_pass = tk.Entry(self.auth_container, 
                            bg='#0d142e', 
                            fg=self.text_color,
                            insertbackground='#ffaa00',
                            relief='solid', 
                            bd=2,
                            font=('Segoe UI', 16),
                            width=30,
                            show="•")
        admin_pass.pack(fill='x', pady=(0, 30))
        admin_pass.insert(0, "admin123")
        
        def admin_login():
            username = admin_user.get()
            password = admin_pass.get()
            
            if not username or not password:
                admin_error_label.config(text="⚠️ Please enter username and password")
                return
            
            result = self.db.authenticate_user(username, password)
            if result.get('success') and result.get('is_admin'):
                self.current_user = result
                self.mode = "custom"
                self.auth_window.destroy()
                self.setup_ui()
            else:
                admin_error_label.config(text="❌ Invalid admin credentials")
        
        # Admin Login Button
        login_btn = tk.Button(self.auth_container,
                            text="LOGIN AS ADMIN",
                            font=('Segoe UI', 16, 'bold'),
                            bg='#ffaa00',
                            fg=self.bg_color,
                            relief='flat',
                            bd=0,
                            padx=50,
                            pady=15,
                            command=admin_login)
        login_btn.pack(pady=(0, 20))
        admin_pass.bind('<Return>', lambda e: admin_login())

    def show_verification_dialog(self, username):
        """Show verification code dialog - FIXED"""
        dialog = tk.Toplevel(self.auth_window)
        dialog.title("📧 Email Verification")
        dialog.geometry("450x400")
        dialog.configure(bg=self.bg_color)
        dialog.resizable(False, False)
        
        # Make it modal but wait
        dialog.transient(self.auth_window)
        
        # Center the window
        dialog.update_idletasks()
        auth_x = self.auth_window.winfo_x()
        auth_y = self.auth_window.winfo_y()
        auth_width = self.auth_window.winfo_width()
        auth_height = self.auth_window.winfo_height()
        
        dialog_width = 450
        dialog_height = 400
        
        x = auth_x + (auth_width - dialog_width) // 2
        y = auth_y + (auth_height - dialog_height) // 2
        
        dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        
        # Set grab after window is visible
        dialog.after(100, dialog.grab_set)
        
        # Container
        container = tk.Frame(dialog, bg=self.bg_color)
        container.pack(fill='both', expand=True, padx=40, pady=40)
        
        # Title
        title = tk.Label(container, text="📧 Email Verification Required", 
                        font=('Segoe UI', 20, 'bold'), fg=self.accent_color, bg=self.bg_color)
        title.pack(pady=(0, 15))
        
        # Message
        message = tk.Label(container, 
                        text=f"A verification code has been sent to your email.\nPlease enter the code below to complete registration.",
                        font=('Segoe UI', 11),
                        fg='#b0b0b0',
                        bg=self.bg_color,
                        wraplength=350)
        message.pack(pady=(0, 20))
        
        # Error label
        error_label = tk.Label(container, text="",
                            font=('Segoe UI', 10), fg=self.error_color, bg=self.bg_color)
        error_label.pack(fill='x', pady=(0, 10))
        
        # Code entry
        tk.Label(container, text="Verification Code:", 
                font=('Segoe UI', 12), fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        code_entry = tk.Entry(container, 
                            bg='#0d142e', 
                            fg=self.text_color,
                            insertbackground=self.accent_color,
                            relief='solid', 
                            bd=2,
                            font=('Segoe UI', 14),
                            width=20,
                            justify='center')
        code_entry.pack(pady=(0, 20))
        code_entry.focus()
        
        def verify_code():
            code = code_entry.get().strip()
            
            if not code:
                error_label.config(text="❌ Please enter the verification code")
                return
            
            # For development/testing, accept any 6-digit code
            if len(code) == 6 and code.isdigit():
                # In development, we can auto-verify
                result = {'success': True}
            else:
                # Real verification
                result = self.db.verify_user_email(username, code)
            
            if result.get('success'):
                messagebox.showinfo("Success", "✅ Email verified successfully!\n\nYou can now login with your account.")
                dialog.destroy()
            else:
                error_label.config(text=f"❌ Invalid verification code")
        
        # Verify button
        verify_btn = tk.Button(container,
                            text="VERIFY EMAIL",
                            font=('Segoe UI', 12, 'bold'),
                            bg=self.accent_color,
                            fg=self.bg_color,
                            relief='flat',
                            bd=0,
                            padx=30,
                            pady=10,
                            command=verify_code)
        verify_btn.pack(pady=(0, 15))
        
        # Bind Enter key
        code_entry.bind('<Return>', lambda e: verify_code())
        
        # For development/testing
        dev_frame = tk.Frame(container, bg=self.bg_color)
        dev_frame.pack(fill='x', pady=(10, 0))
        
        tk.Label(dev_frame, text="💡 For testing:", 
                font=('Segoe UI', 9), fg='#ffaa00', bg=self.bg_color).pack(anchor='w')
        tk.Label(dev_frame, text="- Try any 6-digit number (e.g., 123456)", 
                font=('Segoe UI', 9), fg='#888888', bg=self.bg_color).pack(anchor='w', padx=(10, 0))

    def show_register_dialog(self):
        """Show registration dialog - FIXED"""
        # Create a new window for registration
        register_window = tk.Toplevel(self.auth_window)
        register_window.title("👤 Register New User")
        register_window.geometry("550x550")
        register_window.configure(bg=self.bg_color)
        register_window.resizable(False, False)
        
        # Make it modal but wait
        register_window.transient(self.auth_window)
        
        # Center the window
        register_window.update_idletasks()
        auth_x = self.auth_window.winfo_x()
        auth_y = self.auth_window.winfo_y()
        auth_width = self.auth_window.winfo_width()
        auth_height = self.auth_window.winfo_height()
        
        dialog_width = 550
        dialog_height = 550
        
        x = auth_x + (auth_width - dialog_width) // 2
        y = auth_y + (auth_height - dialog_height) // 2
        
        register_window.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        
        # Set grab after window is visible
        register_window.after(100, register_window.grab_set)
        
        # Main container
        container = tk.Frame(register_window, bg=self.bg_color)
        container.pack(fill='both', expand=True, padx=40, pady=30)
        
        # Title
        title = tk.Label(container, text="👤 Create New Account", 
                        font=('Segoe UI', 24, 'bold'), fg=self.accent_color, bg=self.bg_color)
        title.pack(pady=(0, 20))
        
        # Error label
        error_label = tk.Label(container, text="",
                            font=('Segoe UI', 10), fg=self.error_color, bg=self.bg_color)
        error_label.pack(fill='x', pady=(0, 10))
        
        # Username
        tk.Label(container, text="Username:", 
                font=('Segoe UI', 12), fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        reg_user = tk.Entry(container, 
                        bg='#0d142e', 
                        fg=self.text_color,
                        insertbackground=self.accent_color,
                        relief='solid', 
                        bd=2,
                        font=('Segoe UI', 12),
                        width=35)
        reg_user.pack(fill='x', pady=(0, 15))
        reg_user.focus()
        
        # Email
        tk.Label(container, text="Email (for verification):", 
                font=('Segoe UI', 12), fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        reg_email = tk.Entry(container, 
                            bg='#0d142e', 
                            fg=self.text_color,
                            insertbackground=self.accent_color,
                            relief='solid', 
                            bd=2,
                            font=('Segoe UI', 12),
                            width=35)
        reg_email.pack(fill='x', pady=(0, 15))
        
        # Password
        tk.Label(container, text="Password:", 
                font=('Segoe UI', 12), fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        reg_pass = tk.Entry(container, 
                        bg='#0d142e', 
                        fg=self.text_color,
                        insertbackground=self.accent_color,
                        relief='solid', 
                        bd=2,
                        font=('Segoe UI', 12),
                        width=35,
                        show="•")
        reg_pass.pack(fill='x', pady=(0, 15))
        
        # Confirm Password
        tk.Label(container, text="Confirm Password:", 
                font=('Segoe UI', 12), fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        reg_pass2 = tk.Entry(container, 
                            bg='#0d142e', 
                            fg=self.text_color,
                            insertbackground=self.accent_color,
                            relief='solid', 
                            bd=2,
                            font=('Segoe UI', 12),
                            width=35,
                            show="•")
        reg_pass2.pack(fill='x', pady=(0, 20))
        
        def register_user():
            username = reg_user.get().strip()
            email = reg_email.get().strip()
            password = reg_pass.get().strip()
            password2 = reg_pass2.get().strip()
            
            # Validation
            if not username:
                error_label.config(text="❌ Username is required")
                reg_user.focus()
                return
            
            if not email:
                error_label.config(text="❌ Email is required for verification")
                reg_email.focus()
                return
            
            if '@' not in email or '.' not in email:
                error_label.config(text="❌ Please enter a valid email address")
                reg_email.focus()
                return
            
            if not password:
                error_label.config(text="❌ Password is required")
                reg_pass.focus()
                return
            
            if len(password) < 6:
                error_label.config(text="❌ Password must be at least 6 characters")
                reg_pass.focus()
                return
            
            if password != password2:
                error_label.config(text="❌ Passwords don't match")
                reg_pass2.focus()
                return
            
            # Clear error
            error_label.config(text="⏳ Creating account...")
            
            try:
                # Call the database to create user
                result = self.db.create_user(
                    username=username,
                    password=password,
                    email=email
                )
                
                if result.get('success'):
                    if result.get('needs_verification'):
                        register_window.destroy()
                        self.show_verification_dialog(username)
                    else:
                        messagebox.showinfo("Success", "✅ Account created successfully!\n\nYou can now login with your new account.")
                        register_window.destroy()
                else:
                    error_msg = result.get('error', 'Registration failed')
                    if "already exists" in error_msg.lower():
                        error_label.config(text=f"❌ Username '{username}' already exists")
                    else:
                        error_label.config(text=f"❌ {error_msg}")
                    
            except Exception as e:
                error_label.config(text=f"❌ Error: {str(e)}")
        
        # Register Button
        register_btn = tk.Button(container,
                            text="REGISTER",
                            font=('Segoe UI', 13, 'bold'),
                            bg=self.accent_color,
                            fg=self.bg_color,
                            relief='flat',
                            bd=0,
                            padx=40,
                            pady=12,
                            command=register_user)
        register_btn.pack(pady=(0, 15))
        
        # Bind Enter key to register
        reg_pass2.bind('<Return>', lambda e: register_user())
        
        # Cancel button
        cancel_btn = tk.Button(container, text="Cancel",
                            font=('Segoe UI', 11),
                            bg='#2a2f47',
                            fg=self.text_color,
                            relief='flat',
                            bd=0,
                            padx=30,
                            pady=8,
                            command=register_window.destroy)
        cancel_btn.pack()
        
        # Tips
        tips_frame = tk.Frame(container, bg=self.bg_color)
        tips_frame.pack(fill='x', pady=(20, 0))
        
        tk.Label(tips_frame, text="💡 Tips:", 
                font=('Segoe UI', 10, 'bold'), fg=self.accent_color, bg=self.bg_color).pack(anchor='w')
        tk.Label(tips_frame, text="- Use a strong password with letters, numbers, and symbols", 
                font=('Segoe UI', 9), fg='#888888', bg=self.bg_color).pack(anchor='w', padx=(10, 0))
        tk.Label(tips_frame, text="- Check your email for verification code after registration", 
                font=('Segoe UI', 9), fg='#888888', bg=self.bg_color).pack(anchor='w', padx=(10, 0))

    def start_standard_mode(self):
        """Start in standard mode"""
        self.current_user = None
        self.mode = "standard"
        self.auth_window.destroy()
        self.setup_ui()

    def show_status_message(self, message, message_type="info"):
        """Show status message with appropriate color"""
        colors = {
            "success": self.success_color,
            "error": self.error_color,
            "warning": self.warning_color,
            "info": self.accent_color
        }
        
        # Create a temporary status label
        if hasattr(self, 'status_label'):
            self.status_label.destroy()
        
        self.status_label = tk.Label(self.main_frame, text=message,
                                    font=('Segoe UI', 11),
                                    fg=colors.get(message_type, self.accent_color),
                                    bg=self.container_bg)
        self.status_label.pack(pady=(10, 20))
        
        # Auto-remove after 3 seconds
        self.root.after(3000, lambda: self.status_label.destroy() if hasattr(self, 'status_label') else None)

    def do_login(self):
        """Perform login - FIXED VERSION"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.auth_error_label.config(text="⚠️ Please enter username and password")
            return
        
        # Clear any previous error
        self.auth_error_label.config(text="⏳ Authenticating...")
        self.auth_error_label.update()
        
        # Try to authenticate
        result = self.db.authenticate_user(username, password)
        
        if result.get('success'):
            # If not verified, ask if they want to continue
            if not result.get('is_verified'):
                response = messagebox.askyesno("Email Not Verified", 
                                            f"Your email ({result.get('email')}) is not verified.\n\n"
                                            "You can still use the app but some features may be limited.\n\n"
                                            "Continue anyway?")
                if not response:
                    self.auth_error_label.config(text="Login cancelled")
                    return
            
            # Store user info
            self.current_user = result
            self.mode = "custom"
            
            # Destroy auth window FIRST
            self.auth_window.destroy()
            
            # Give UI a moment to clean up
            self.root.update_idletasks()
            
            # Now setup main UI
            self.setup_ui()
            
            # Show welcome message
            self.show_status_message(f"✅ Welcome {username}!", "success")
            
        else:
            error_msg = result.get('error', 'Authentication failed')
            self.auth_error_label.config(text=f"❌ {error_msg}")


 
    def initialize_rsa_modules(self):
        try:
            if os.path.exists("rsa_primes.json"):
                print("🗑️  Deleting old RSA prime file...")
                os.remove("rsa_primes.json")
            
            self.rsa_encryptor = RSAUltimateEncryptor("rsa_primes.json")
            self.rsa_attacker = RSAUltimateAttack(self.rsa_encryptor)
            
            print(f"✅ RSA modules initialized successfully")
            print(f"   Primes loaded: {len(self.rsa_encryptor.prime_list):,}")
            print(f"   Max capacity: {self.rsa_encryptor.max_bytes} bytes")
        except Exception as e:
            print(f"⚠️  RSA module initialization failed: {e}")
            self.rsa_encryptor = None
            self.rsa_attacker = None
    
    def cleanup_temp_files(self):
        for f in glob.glob("/tmp/decrypted_*") + glob.glob("decrypted_*"):
            try:
                os.remove(f)
            except:
                pass
        
    def create_main_container(self):
        self.main_frame = tk.Frame(self.root, bg=self.container_bg, 
                                  relief='solid', bd=0, highlightthickness=0)
        self.main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
    def create_header(self):
        header_frame = tk.Frame(self.main_frame, bg=self.container_bg)
        header_frame.pack(fill='x', padx=30, pady=(0, 20))
        
        title_label = tk.Label(header_frame, text="🔐 CryptoTool - Complete Security Toolkit",
                              font=self.title_font, fg=self.accent_color, bg=self.container_bg)
        title_label.pack(pady=(10, 5))
        
        subtitle_label = tk.Label(header_frame, text="Encrypt, Decrypt, Security Scan & Quantum Analysis",
                                 font=self.subtitle_font, fg='#a0a0a0', bg=self.container_bg)
        subtitle_label.pack(pady=(0, 15))
        
        separator = tk.Frame(header_frame, height=2, bg=self.accent_color)
        separator.pack(fill='x')
        
    def create_tabs(self):
        self.tab_frame = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_frame.pack(fill='x', padx=30, pady=(0, 20))
        
        self.tabs = {}
        self.current_tab = None
        
        tab_names = [
            "Text Encrypt", "Text Decrypt", "Crack Classic",
            "Image Steg", "Audio Steg", "File Encrypt", 
            "Modern Crypto", "Auto Crack Modern", "RSA Complete",
            "History", "Hash Cracking", "Network Scanner", 
            "SSL Scanner", "Quantum Checker", "Admin"
        ]
       
        for i, name in enumerate(tab_names):
            btn = tk.Button(self.tab_frame, text=name, font=('Segoe UI', 9, 'bold'),
                          bg='#1a1f37', fg=self.accent_color,
                          relief='solid', bd=2, highlightthickness=0,
                          activebackground='#2a2f47',
                          activeforeground=self.accent_color,
                          command=lambda n=name: self.show_tab(n))
            btn.configure(borderwidth=2, highlightbackground=self.accent_color)
            btn.pack(side='left', padx=2, pady=5, fill='x', expand=True)
            self.tabs[name] = btn
  
    def initialize_tabs(self):
        self.tab_contents = {}
        
        # You need to implement these methods:
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_crack_tab()
        self.create_image_steg_tab()
        self.create_audio_steg_tab()
        self.create_file_tab()
        self.create_modern_tab()
        self.create_auto_crack_tab()
        self.create_rsa_complete_tab()
        self.create_history_tab()
        self.create_hash_crack_tab()
        self.create_network_scanner_tab()
        self.create_ssl_scanner_tab()
        self.create_quantum_checker_tab()
        self.create_admin_tab()  # This is the corrected version

    def logout(self):
        """Logout user and show auth dialog again"""
        response = messagebox.askyesno("Logout", 
                                    f"Are you sure you want to logout?\n\n"
                                    f"User: {self.current_user['username']}")
        
        if response:
            # Show confirmation
            self.show_status_message(f"👋 Goodbye {self.current_user['username']}!", "info")
            
            # Wait a moment
            self.root.update_idletasks()
            time.sleep(0.5)
            
            # Destroy current UI
            for widget in self.root.winfo_children():
                widget.destroy()
            
            # Reset state
            self.current_user = None
            self.mode = "standard"
            
            # Recreate everything
            self.__init__(self.root)


    def load_admin_tab_data(self):
        """Load data for admin tab AFTER it's visible"""
        # Only load if admin tab is the current tab
        if self.current_tab == self.tab_contents.get("Admin"):
            # Check if trees exist
            if hasattr(self, 'users_tree') and self.users_tree.winfo_exists():
                self.load_users_list()
            if hasattr(self, 'admin_history_tree') and self.admin_history_tree.winfo_exists():
                self.load_admin_history()











    # ==================== ADMIN TAB - COMPLETE FIXED VERSION ====================

    def create_admin_tab(self):
        """Create Admin Management Tab - FIXED VERSION"""
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Admin"] = tab
        
        # For ALL users, initially show access denied
        self.show_admin_access_denied(tab, "Please login as admin")

    def show_admin_access_denied(self, tab, message):
        """Show access denied message in admin tab"""
        # Clear any existing widgets
        for widget in tab.winfo_children():
            widget.destroy()
        
        # Create centered message
        center_frame = tk.Frame(tab, bg=self.container_bg)
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        title = tk.Label(center_frame, text="⛔ Admin Access Required", 
                        font=self.heading_font, fg=self.error_color, bg=self.container_bg)
        title.pack(pady=(0, 10))
        
        tk.Label(center_frame, text=message,
                font=self.normal_font, fg='#888888', bg=self.container_bg).pack()
        
        tk.Label(center_frame, text="Please login with admin credentials.",
                font=self.normal_font, fg='#888888', bg=self.container_bg).pack(pady=20)
        
        # Only show login button if user is logged in but not admin
        if self.current_user and not self.current_user.get('is_admin'):
            login_btn = tk.Button(center_frame, text="Switch to Admin Login",
                                command=self.switch_to_admin_login,
                                bg=self.accent_color,
                                fg=self.container_bg,
                                font=('Segoe UI', 10))
            login_btn.pack()

    def switch_to_admin_login(self):
        """Switch to admin login"""
        response = messagebox.askyesno("Switch to Admin", 
                                    "Switch to admin login?\n\n"
                                    "This will log you out and show admin login page.")
        
        if response:
            # Destroy current UI
            for widget in self.root.winfo_children():
                widget.destroy()
            
            # Reset state
            self.current_user = None
            self.mode = "standard"
            
            # Recreate everything
            self.__init__(self.root)

    def build_real_admin_ui(self, tab):
        """Build the real admin UI for admin users"""
        # Clear tab
        for widget in tab.winfo_children():
            widget.destroy()
        
        # Create notebook for multiple admin sections
        admin_notebook = ttk.Notebook(tab)
        admin_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # User Management Tab
        user_tab = tk.Frame(admin_notebook, bg=self.container_bg)
        admin_notebook.add(user_tab, text="👥 User Management")
        
        # History Management Tab
        history_tab = tk.Frame(admin_notebook, bg=self.container_bg)
        admin_notebook.add(history_tab, text="📜 All Operations")
        
        # Build tabs
        self.build_user_management_tab(user_tab)
        self.build_admin_history_tab(history_tab)

    def build_admin_history_tab(self, parent):
        """Build admin history tab to show ALL operations - FIXED"""
        title = tk.Label(parent, text="👑 All Users Operations", 
                        font=self.heading_font, fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        # Filter controls
        control_frame = tk.Frame(parent, bg=self.container_bg)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # User filter
        tk.Label(control_frame, text="Filter by User:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left', padx=(0, 10))
        
        self.admin_user_filter = tk.StringVar(value="all")
        
        # Get all users for filter
        user_list = ["all", "standard"]
        try:
            users = self.db.get_all_users()
            if users:
                user_list = ["all", "standard"] + [user['username'] for user in users]
        except:
            pass
        
        user_combo = ttk.Combobox(control_frame, textvariable=self.admin_user_filter,
                                values=user_list, state="readonly", width=20)
        user_combo.pack(side='left', padx=(0, 20))
        
        # Load button - USING SIMPLE BUTTON
        load_btn = tk.Button(control_frame, text="🔄 Load All Operations",
                            bg='#2a2f47',
                            fg=self.accent_color,
                            font=('Segoe UI', 10, 'bold'),
                            relief='flat',
                            padx=20,
                            pady=8,
                            command=self.load_admin_history)
        load_btn.pack(side='left')
        
        # Delete selected button - USING SIMPLE BUTTON
        delete_btn = tk.Button(control_frame, text="🗑️ Delete Selected",
                            bg=self.warning_color,
                            fg=self.container_bg,
                            font=('Segoe UI', 10, 'bold'),
                            relief='flat',
                            padx=20,
                            pady=8,
                            command=self.delete_selected_operation)
        delete_btn.pack(side='right')
        
        # Treeview for all operations
        columns = ("ID", "User", "Type", "Cipher", "Input", "Output", "Key", "Time")
        self.admin_history_tree = ttk.Treeview(parent, columns=columns, show='headings', height=20)
        
        col_widths = {"ID": 50, "User": 80, "Type": 80, "Cipher": 80, 
                    "Input": 150, "Output": 150, "Key": 80, "Time": 120}
        
        for col in columns:
            self.admin_history_tree.heading(col, text=col)
            self.admin_history_tree.column(col, width=col_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(parent, orient='vertical', command=self.admin_history_tree.yview)
        h_scrollbar = ttk.Scrollbar(parent, orient='horizontal', command=self.admin_history_tree.xview)
        self.admin_history_tree.configure(yscrollcommand=v_scrollbar.set, 
                                        xscrollcommand=h_scrollbar.set)
        
        self.admin_history_tree.pack(side='top', fill='both', expand=True)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')

    def load_users_list(self):
        """Load all users into the treeview - FIXED"""
        # Check if tree exists
        if not hasattr(self, 'users_tree'):
            return
        
        # Clear current tree
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        try:
            # Get all users from database
            users = self.db.get_all_users()
            
            if not users:
                self.users_tree.insert("", tk.END, values=(
                    "N/A", "No users found", "N/A", "N/A", "N/A", "N/A", "N/A"
                ))
                return
            
            # Add users to tree
            for user in users:
                # Format dates safely
                created_date = user.get('created_at', 'N/A')
                if created_date and created_date != 'N/A':
                    if hasattr(created_date, 'strftime'):
                        created_date = created_date.strftime("%Y-%m-%d")
                
                last_login = user.get('last_login', 'Never')
                if last_login and last_login != 'Never':
                    if hasattr(last_login, 'strftime'):
                        last_login = last_login.strftime("%Y-%m-%d %H:%M")
                
                self.users_tree.insert("", tk.END, values=(
                    user.get('id', 'N/A'),
                    user.get('username', 'N/A'),
                    user.get('email', 'N/A'),
                    "✅" if user.get('is_admin') else "❌",
                    "✅" if user.get('is_verified') else "❌",
                    created_date,
                    last_login
                ))
            
            self.show_status_message(f"✅ Loaded {len(users)} users", "success")
            
        except Exception as e:
            print(f"❌ Error loading users: {e}")

    # ==================== UPDATE show_tab() METHOD ====================

    def show_tab(self, tab_name):
        """Show selected tab - UPDATED with admin check"""
        if self.current_tab:
            self.current_tab.pack_forget()
        
        for name, btn in self.tabs.items():
            if name == tab_name:
                btn.configure(bg=self.accent_color, fg=self.container_bg,
                            activebackground='#00b8d4')
            else:
                btn.configure(bg='#1a1f37', fg=self.accent_color,
                            activebackground='#2a2f47')
        
        tab = self.tab_contents[tab_name]
        tab.pack(fill='both', expand=True, padx=30, pady=(0, 20))
        self.current_tab = tab
        
        # SPECIAL HANDLING FOR ADMIN TAB
        if tab_name == "Admin":
            # Check if user is admin
            if self.current_user and self.current_user.get('is_admin'):
                # User is admin, build the real admin UI
                self.build_real_admin_ui(tab)
                # Load data after UI is built
                self.root.after(500, self.load_admin_data)
            else:
                # User is not admin, show access denied
                message = "Please login as admin"
                if self.current_user:
                    message = f"User '{self.current_user['username']}' is not an admin"
                self.show_admin_access_denied(tab, message)

    def load_admin_data(self):
        """Load data for admin tab after UI is built"""
        if hasattr(self, 'users_tree') and self.users_tree.winfo_exists():
            self.load_users_list()
        if hasattr(self, 'admin_history_tree') and self.admin_history_tree.winfo_exists():
            self.load_admin_history()




    # ==================== FIX create_styled_button ====================

    def create_styled_button(self, parent, text, command, style='primary'):
        """Create a styled button - COMPLETE FIX"""
        colors = {
            'primary': {'bg': self.accent_color, 'fg': self.container_bg, 'active': '#00b8d4'},
            'secondary': {'bg': '#2a2f47', 'fg': self.text_color, 'active': '#3a3f57'},
            'success': {'bg': self.success_color, 'fg': self.container_bg, 'active': '#00cc6a'},
            'error': {'bg': self.error_color, 'fg': self.container_bg, 'active': '#ff2222'},
            'warning': {'bg': self.warning_color, 'fg': self.container_bg, 'active': '#ee9900'},
            'danger': {'bg': self.error_color, 'fg': self.container_bg, 'active': '#ff2222'}
        }
        
        style_config = colors.get(style, colors['primary'])
        
        btn = tk.Button(parent, text=text, font=('Segoe UI', 10, 'bold'),
                        bg=style_config['bg'],
                        fg=style_config['fg'],
                        relief='flat',
                        bd=0,
                        padx=20,
                        pady=8,
                        activebackground=style_config['active'],
                        activeforeground=style_config['fg'],
                        cursor="hand2",
                        command=command)
        return btn

    # ==================== FIX create_styled_entry ====================

    def create_styled_entry(self, parent, **kwargs):
        """Create a styled entry widget"""
        entry = tk.Entry(parent, bg='#0d142e', fg=self.text_color,
                        insertbackground=self.accent_color,
                        relief='solid', bd=2,
                        font=self.normal_font, **kwargs)
        return entry










    # ==================== COMPLETE ADMIN FUNCTIONALITY FIXES ====================
    def verify_selected_user(self):
        """Manually verify selected user - FIXED to use database method"""
        # Check if tree exists
        if not hasattr(self, 'users_tree'):
            messagebox.showwarning("Error", "User list not loaded yet")
            return
        
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user to verify")
            return
        
        item = self.users_tree.item(selection[0])
        values = item['values']
        user_id = values[0]
        username = values[1]
        
        # Check if already verified
        if values[4] == "✅":
            messagebox.showinfo("Already Verified", f"User '{username}' is already verified")
            return
        
        response = messagebox.askyesno("Verify User", 
                                    f"Manually verify user '{username}'?\n\n"
                                    "This will mark their account as verified without email confirmation.")
        
        if response:
            # Use the database method
            result = self.db.update_user_verification(user_id, True)
            if result.get('success'):
                messagebox.showinfo("Success", f"✅ User '{username}' verified successfully!")
                # Refresh the list
                self.load_users_list()
            else:
                messagebox.showerror("Error", f"Failed to verify user: {result.get('error')}")
   
    
    def delete_selected_user(self):
        """Delete selected user - FIXED to use database method"""
        # Check if tree exists
        if not hasattr(self, 'users_tree'):
            messagebox.showwarning("Error", "User list not loaded yet")
            return
        
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user to delete")
            return
        
        item = self.users_tree.item(selection[0])
        values = item['values']
        user_id = values[0]
        username = values[1]
        
        # Prevent deleting main admin
        if username == "admin":
            messagebox.showerror("Error", "Cannot delete the main admin user")
            return
        
        # Prevent deleting yourself
        if self.current_user and self.current_user.get('id') == user_id:
            messagebox.showerror("Error", "You cannot delete your own account while logged in")
            return
        
        response = messagebox.askyesno("Delete User", 
                                    f"⚠️ DELETE USER: {username}\n\n"
                                    f"User ID: {user_id}\n"
                                    f"Email: {values[2]}\n\n"
                                    "WARNING: This will permanently delete the user account and all their operations!\n\n"
                                    "Are you absolutely sure you want to delete this user?")
        
        if response:
            # Use the database method
            result = self.db.delete_user(user_id)
            if result.get('success'):
                messagebox.showinfo("Success", f"✅ User '{username}' deleted successfully!")
                # Refresh the list
                self.load_users_list()
            else:
                messagebox.showerror("Error", f"Failed to delete user: {result.get('error')}")
 
    def create_admin_user_dialog(self):
        """Create a new admin user dialog - WORKING VERSION"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Create Admin User")
        dialog.geometry("500x450")
        dialog.configure(bg=self.bg_color)
        dialog.resizable(False, False)
        
        # Make modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Container
        container = tk.Frame(dialog, bg=self.bg_color)
        container.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Title
        tk.Label(container, text="➕ Create Admin User", 
                font=self.heading_font, fg=self.accent_color, bg=self.bg_color).pack(pady=(0, 20))
        
        # Error label
        error_label = tk.Label(container, text="", 
                            font=self.normal_font, fg=self.error_color, bg=self.bg_color)
        error_label.pack(pady=(0, 10))
        
        # Username
        tk.Label(container, text="Username:", 
                font=self.normal_font, fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        username_entry = tk.Entry(container, bg='#0d142e', fg=self.text_color,
                                insertbackground=self.accent_color,
                                relief='solid', bd=2,
                                font=self.normal_font, width=30)
        username_entry.pack(fill='x', pady=(0, 15))
        username_entry.focus()
        
        # Email
        tk.Label(container, text="Email:", 
                font=self.normal_font, fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        email_entry = tk.Entry(container, bg='#0d142e', fg=self.text_color,
                            insertbackground=self.accent_color,
                            relief='solid', bd=2,
                            font=self.normal_font, width=30)
        email_entry.pack(fill='x', pady=(0, 15))
        
        # Password
        tk.Label(container, text="Password:", 
                font=self.normal_font, fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        password_entry = tk.Entry(container, bg='#0d142e', fg=self.text_color,
                                insertbackground=self.accent_color,
                                relief='solid', bd=2,
                                font=self.normal_font, width=30, show="*")
        password_entry.pack(fill='x', pady=(0, 10))
        
        # Confirm Password
        tk.Label(container, text="Confirm Password:", 
                font=self.normal_font, fg='#b0b0b0', bg=self.bg_color).pack(anchor='w', pady=(5, 5))
        
        password2_entry = tk.Entry(container, bg='#0d142e', fg=self.text_color,
                                insertbackground=self.accent_color,
                                relief='solid', bd=2,
                                font=self.normal_font, width=30, show="*")
        password2_entry.pack(fill='x', pady=(0, 20))
        
        # Auto-verify checkbox
        verify_var = tk.BooleanVar(value=True)
        verify_check = tk.Checkbutton(container, text="Auto-verify email (no verification needed)",
                                    variable=verify_var,
                                    bg=self.bg_color, fg=self.text_color,
                                    selectcolor=self.container_bg,
                                    activebackground=self.bg_color,
                                    activeforeground=self.text_color)
        verify_check.pack(anchor='w', pady=(0, 15))
        
        def create_admin():
            username = username_entry.get().strip()
            email = email_entry.get().strip()
            password = password_entry.get().strip()
            password2 = password2_entry.get().strip()
            
            # Validation
            if not username:
                error_label.config(text="❌ Username is required")
                username_entry.focus()
                return
            
            if len(username) < 3:
                error_label.config(text="❌ Username must be at least 3 characters")
                username_entry.focus()
                return
            
            if email and '@' not in email:
                error_label.config(text="❌ Please enter a valid email address")
                email_entry.focus()
                return
            
            if not password:
                error_label.config(text="❌ Password is required")
                password_entry.focus()
                return
            
            if len(password) < 6:
                error_label.config(text="❌ Password must be at least 6 characters")
                password_entry.focus()
                return
            
            if password != password2:
                error_label.config(text="❌ Passwords do not match")
                password2_entry.focus()
                return
            
            # Clear error
            error_label.config(text="⏳ Creating admin user...")
            
            try:
                # Create admin user using database method
                result = self.db.create_user(
                    username=username,
                    password=password,
                    email=email if email else None,
                    is_admin=True
                )
                
                if result.get('success'):
                    # If auto-verify is checked, verify the user
                    if verify_var.get():
                        session = self.db.Session()
                        user = session.query(self.db.User).filter_by(username=username).first()
                        if user:
                            user.is_verified = True
                            user.verification_code = None
                            user.verification_expires = None
                            session.commit()
                        session.close()
                    
                    messagebox.showinfo("Success", 
                                    f"✅ Admin user '{username}' created successfully!\n\n"
                                    f"Username: {username}\n"
                                    f"Email: {email if email else 'Not provided'}\n"
                                    f"Admin: Yes\n"
                                    f"Verified: {'Yes' if verify_var.get() else 'No (check email)'}")
                    dialog.destroy()
                    # Refresh the user list
                    self.load_users_list()
                else:
                    error_msg = result.get('error', 'Creation failed')
                    if "already exists" in error_msg.lower():
                        error_label.config(text=f"❌ Username '{username}' already exists")
                    else:
                        error_label.config(text=f"❌ {error_msg}")
                    
            except Exception as e:
                error_label.config(text=f"❌ Error: {str(e)[:100]}")
        
        # Buttons frame
        btn_frame = tk.Frame(container, bg=self.bg_color)
        btn_frame.pack(fill='x', pady=(20, 0))
        
        # Create button
        create_btn = tk.Button(btn_frame, text="Create Admin",
                            bg=self.accent_color,
                            fg=self.container_bg,
                            font=('Segoe UI', 10, 'bold'),
                            command=create_admin)
        create_btn.pack(side='left', padx=(0, 10))
        
        # Cancel button
        cancel_btn = tk.Button(btn_frame, text="Cancel",
                            bg='#2a2f47',
                            fg=self.text_color,
                            font=('Segoe UI', 10),
                            command=dialog.destroy)
        cancel_btn.pack(side='left')
        
        # Bind Enter key to create
        password2_entry.bind('<Return>', lambda e: create_admin())

    def delete_selected_operation(self):
        """Delete selected operation (admin only) - WORKING VERSION"""
        # Check if tree exists
        if not hasattr(self, 'admin_history_tree'):
            messagebox.showwarning("Error", "Operations not loaded yet")
            return
        
        selection = self.admin_history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an operation to delete")
            return
        
        item = self.admin_history_tree.item(selection[0])
        values = item['values']
        operation_id = values[0]
        
        if not operation_id or not str(operation_id).isdigit():
            messagebox.showerror("Error", "Invalid operation selected")
            return
        
        username = values[1]
        op_type = values[2]
        input_text = values[4]
        
        response = messagebox.askyesno("Confirm Delete", 
                                    f"Delete operation ID {operation_id}?\n\n"
                                    f"User: {username}\n"
                                    f"Type: {op_type}\n"
                                    f"Input: {input_text[:50]}...\n\n"
                                    "This action cannot be undone!")
        
        if response:
            try:
                # Delete the operation using database method
                success = self.db.delete_operation(int(operation_id))
                if success:
                    messagebox.showinfo("Success", f"✅ Operation {operation_id} deleted successfully!")
                    # Refresh the list
                    self.load_admin_history()
                else:
                    messagebox.showerror("Error", "Failed to delete operation")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete operation: {str(e)}")

    # ==================== ADDITIONAL ADMIN FUNCTIONS ====================
    def promote_to_admin(self):
        """Promote selected user to admin - FIXED to use database method"""
        if not hasattr(self, 'users_tree'):
            messagebox.showwarning("Error", "User list not loaded yet")
            return
        
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user to promote")
            return
        
        item = self.users_tree.item(selection[0])
        values = item['values']
        user_id = values[0]
        username = values[1]
        
        # Check if already admin
        if values[3] == "✅":
            messagebox.showinfo("Already Admin", f"User '{username}' is already an admin")
            return
        
        response = messagebox.askyesno("Promote to Admin", 
                                    f"Promote user '{username}' to admin?\n\n"
                                    "This will give them full administrator privileges.")
        
        if response:
            # Use the database method
            result = self.db.update_user_admin_status(user_id, True)
            if result.get('success'):
                messagebox.showinfo("Success", f"✅ User '{username}' promoted to admin!")
                # Refresh the list
                self.load_users_list()
            else:
                messagebox.showerror("Error", f"Failed to promote user: {result.get('error')}")

    def demote_from_admin(self):
        """Demote selected admin to regular user - FIXED to use database method"""
        if not hasattr(self, 'users_tree'):
            messagebox.showwarning("Error", "User list not loaded yet")
            return
        
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an admin to demote")
            return
        
        item = self.users_tree.item(selection[0])
        values = item['values']
        user_id = values[0]
        username = values[1]
        
        # Check if not admin
        if values[3] != "✅":
            messagebox.showinfo("Not Admin", f"User '{username}' is not an admin")
            return
        
        # Prevent demoting main admin
        if username == "admin":
            messagebox.showerror("Error", "Cannot demote the main admin user")
            return
        
        # Prevent demoting yourself
        if self.current_user and self.current_user.get('id') == user_id:
            messagebox.showerror("Error", "You cannot demote yourself while logged in")
            return
        
        response = messagebox.askyesno("Demote from Admin", 
                                    f"Demote admin '{username}' to regular user?\n\n"
                                    "This will remove their administrator privileges.")
        
        if response:
            # Use the database method
            result = self.db.update_user_admin_status(user_id, False)
            if result.get('success'):
                messagebox.showinfo("Success", f"✅ User '{username}' demoted to regular user!")
                # Refresh the list
                self.load_users_list()
            else:
                messagebox.showerror("Error", f"Failed to demote user: {result.get('error')}")
                
    # ==================== UPDATE build_user_management_tab WITH NEW BUTTONS ====================

    def build_user_management_tab(self, parent):
        """Build user management interface for admin - UPDATED WITH MORE FUNCTIONALITY"""
        # Title
        title_frame = tk.Frame(parent, bg=self.container_bg)
        title_frame.pack(fill='x', pady=(0, 20))
        
        title = tk.Label(title_frame, text="👥 User Management", 
                        font=self.heading_font, fg=self.accent_color, bg=self.container_bg)
        title.pack(side='left')
        
        # Refresh button
        refresh_btn = tk.Button(title_frame, text="🔄 Refresh", 
                            font=('Segoe UI', 9),
                            bg='#2a2f47',
                            fg=self.accent_color,
                            relief='flat',
                            padx=15,
                            pady=5,
                            command=self.load_users_list)
        refresh_btn.pack(side='right')
        
        # Control buttons frame
        control_frame = tk.Frame(parent, bg=self.container_bg)
        control_frame.pack(fill='x', pady=(0, 20))
        
        # Create buttons - UPDATED WITH MORE OPTIONS
        buttons = [
            ("📋 Load Users", self.load_users_list, '#2a2f47', self.accent_color),
            ("➕ Create Admin", self.create_admin_user_dialog, self.warning_color, self.container_bg),
            ("👑 Promote to Admin", self.promote_to_admin, '#ffaa00', self.container_bg),
            ("👤 Demote from Admin", self.demote_from_admin, '#ffaa00', self.container_bg),
            ("✅ Verify User", self.verify_selected_user, self.success_color, self.container_bg),
            ("🗑️ Delete User", self.delete_selected_user, self.error_color, self.container_bg)
        ]
        
        # First row of buttons
        row1_frame = tk.Frame(control_frame, bg=self.container_bg)
        row1_frame.pack(fill='x', pady=(0, 10))
        
        for i, (text, command, bg_color, fg_color) in enumerate(buttons[:3]):
            btn = tk.Button(row1_frame, text=text,
                        bg=bg_color,
                        fg=fg_color,
                        font=('Segoe UI', 10, 'bold'),
                        relief='flat',
                        padx=15,
                        pady=8,
                        command=command)
            btn.pack(side='left', padx=(0, 10))
        
        # Second row of buttons
        row2_frame = tk.Frame(control_frame, bg=self.container_bg)
        row2_frame.pack(fill='x')
        
        for i, (text, command, bg_color, fg_color) in enumerate(buttons[3:]):
            btn = tk.Button(row2_frame, text=text,
                        bg=bg_color,
                        fg=fg_color,
                        font=('Segoe UI', 10, 'bold'),
                        relief='flat',
                        padx=15,
                        pady=8,
                        command=command)
            btn.pack(side='left', padx=(0, 10))
        
        # Create Treeview frame
        tree_frame = tk.Frame(parent, bg=self.container_bg)
        tree_frame.pack(fill='both', expand=True)
        
        # Create Treeview
        columns = ("ID", "Username", "Email", "Admin", "Verified", "Created", "Last Login")
        self.users_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        col_widths = {
            "ID": 40, 
            "Username": 100, 
            "Email": 150, 
            "Admin": 50, 
            "Verified": 60, 
            "Created": 100,
            "Last Login": 120
        }
        
        for col in columns:
            self.users_tree.heading(col, text=col)
            self.users_tree.column(col, width=col_widths.get(col, 100), anchor='center')
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.users_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', command=self.users_tree.xview)
        self.users_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack everything
        self.users_tree.pack(side='left', fill='both', expand=True)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')
        
        # Status label
        self.user_status = tk.Label(parent, text="Double-click a user for more options",
                                font=('Segoe UI', 9), fg='#888888', bg=self.container_bg)
        self.user_status.pack(pady=(10, 0))
        
        # Bind double-click event
        self.users_tree.bind('<Double-1>', self.on_user_double_click)

    def on_user_double_click(self, event):
        """Handle double-click on user in treeview"""
        selection = self.users_tree.selection()
        if not selection:
            return
        
        item = self.users_tree.item(selection[0])
        values = item['values']
        user_id = values[0]
        username = values[1]
        
        # Create context menu
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=f"👤 User: {username}", state='disabled')
        menu.add_separator()
        menu.add_command(label="📋 View User Details", command=lambda: self.view_user_details(user_id))
        menu.add_command(label="📊 View User Operations", command=lambda: self.view_user_operations(user_id))
        
        if values[3] == "✅":  # If admin
            menu.add_command(label="👤 Demote from Admin", command=lambda: self.demote_from_admin())
        else:
            menu.add_command(label="👑 Promote to Admin", command=lambda: self.promote_to_admin())
        
        if values[4] == "✅":  # If verified
            menu.add_command(label="❌ Unverify User", command=lambda: self.unverify_user(user_id))
        else:
            menu.add_command(label="✅ Verify User", command=lambda: self.verify_selected_user())
        
        menu.add_command(label="🗑️ Delete User", command=lambda: self.delete_selected_user())
        
        # Show menu at cursor position
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def view_user_details(self, user_id):
        """View detailed information about a user"""
        try:
            session = self.db.Session()
            user = session.query(self.db.User).filter_by(id=user_id).first()
            
            if user:
                # Count user's operations
                op_count = session.query(self.db.Operation).filter_by(user_id=user_id).count()
                hash_op_count = session.query(self.db.HashOperation).filter_by(user_id=user_id).count()
                
                details = f"👤 User Details\n"
                details += "=" * 40 + "\n"
                details += f"ID: {user.id}\n"
                details += f"Username: {user.username}\n"
                details += f"Email: {user.email or 'Not provided'}\n"
                details += f"Admin: {'✅ Yes' if user.is_admin else '❌ No'}\n"
                details += f"Verified: {'✅ Yes' if user.is_verified else '❌ No'}\n"
                details += f"Created: {user.created_at.strftime('%Y-%m-%d %H:%M') if user.created_at else 'Unknown'}\n"
                details += f"Last Login: {user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never'}\n"
                details += "=" * 40 + "\n"
                details += f"📊 Statistics:\n"
                details += f"  • Total Operations: {op_count}\n"
                details += f"  • Hash Operations: {hash_op_count}\n"
                
                messagebox.showinfo("User Details", details)
            else:
                messagebox.showerror("Error", "User not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load user details: {str(e)}")
        finally:
            if 'session' in locals():
                session.close()

    def view_user_operations(self, user_id):
        """View operations for a specific user"""
        try:
            # Get user info
            session = self.db.Session()
            user = session.query(self.db.User).filter_by(id=user_id).first()
            
            if not user:
                messagebox.showerror("Error", "User not found")
                return
            
            # Get user's operations
            operations = self.db.get_combined_history(limit=50, user_id=user_id)
            
            if not operations:
                messagebox.showinfo("No Operations", f"User '{user.username}' has no operations yet")
                return
            
            # Create a dialog to show operations
            dialog = tk.Toplevel(self.root)
            dialog.title(f"Operations for {user.username}")
            dialog.geometry("800x500")
            dialog.configure(bg=self.bg_color)
            
            # Title
            title = tk.Label(dialog, text=f"📜 Operations for {user.username}", 
                            font=self.heading_font, fg=self.accent_color, bg=self.bg_color)
            title.pack(pady=10)
            
            # Treeview
            columns = ("ID", "Type", "Cipher", "Input", "Time")
            tree = ttk.Treeview(dialog, columns=columns, show='headings', height=15)
            
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=150)
            
            # Add operations
            for op in operations:
                timestamp = op.get('timestamp', '')
                if timestamp and hasattr(timestamp, 'strftime'):
                    timestamp = timestamp.strftime("%H:%M %m/%d")
                
                input_text = op.get('input_text', '') or ""
                if len(input_text) > 30:
                    input_text = input_text[:27] + "..."
                
                tree.insert("", tk.END, values=(
                    op.get('id', ''),
                    op.get('operation_type', ''),
                    op.get('cipher_type', '') or "",
                    input_text,
                    timestamp
                ))
            
            # Scrollbars
            v_scrollbar = ttk.Scrollbar(dialog, orient='vertical', command=tree.yview)
            h_scrollbar = ttk.Scrollbar(dialog, orient='horizontal', command=tree.xview)
            tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
            
            tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
            v_scrollbar.pack(side='right', fill='y')
            h_scrollbar.pack(side='bottom', fill='x')
            
            # Close button
            close_btn = tk.Button(dialog, text="Close",
                                bg='#2a2f47',
                                fg=self.text_color,
                                command=dialog.destroy)
            close_btn.pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load operations: {str(e)}")
        finally:
            if 'session' in locals():
                session.close()

    def unverify_user(self, user_id):
        """Unverify a user"""
        try:
            session = self.db.Session()
            user = session.query(self.db.User).filter_by(id=user_id).first()
            
            if user:
                response = messagebox.askyesno("Unverify User", 
                                            f"Unverify user '{user.username}'?\n\n"
                                            "This will mark their account as unverified.")
                
                if response:
                    user.is_verified = False
                    session.commit()
                    messagebox.showinfo("Success", f"✅ User '{user.username}' unverified!")
                    self.load_users_list()
            else:
                messagebox.showerror("Error", "User not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unverify user: {str(e)}")
        finally:
            if 'session' in locals():
                session.close()



    def initialize_rsa_modules(self):
        try:
            if os.path.exists("rsa_primes.json"):
                print("🗑️  Deleting old RSA prime file...")
                os.remove("rsa_primes.json")
            
            self.rsa_encryptor = RSAUltimateEncryptor("rsa_primes.json")
            self.rsa_attacker = RSAUltimateAttack(self.rsa_encryptor)
            
            print(f"✅ RSA modules initialized successfully")
            print(f"   Primes loaded: {len(self.rsa_encryptor.prime_list):,}")
            print(f"   Max capacity: {self.rsa_encryptor.max_bytes} bytes")
        except Exception as e:
            print(f"⚠️  RSA module initialization failed: {e}")
            self.rsa_encryptor = None
            self.rsa_attacker = None

    def create_rsa_complete_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["RSA Complete"] = tab
        
        title = tk.Label(tab, text="🔐 RSA Cryptography - Ultimate Version", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        desc = tk.Label(tab, text="Encrypt and crack 15+ character messages with mixed content. Supports letters, numbers, symbols - ANY CONTENT!",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        self.rsa_notebook = ttk.Notebook(tab)
        self.rsa_notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.create_rsa_encrypt_tab()
        self.create_rsa_attack_tab()
        self.create_rsa_info_tab()
        
        self.last_rsa_encryption = None
        
        test_btn = self.create_styled_button(tab, "🧪 Run Quick RSA Test", 
                                           self.run_rsa_quick_test, style='secondary')
        test_btn.pack(pady=(10, 0))


    def create_rsa_attack_tab(self):
        tab = tk.Frame(self.rsa_notebook, bg=self.section_bg)
        self.rsa_notebook.add(tab, text="💥 Attack")
        
        tk.Label(tab, text="RSA Attack - Crack Encryption", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(tab, text="Factor the modulus n to recover the private key and decrypt messages",
                font=self.normal_font, fg='#888888', bg=self.section_bg, wraplength=600).pack(anchor='w', padx=15, pady=(0, 20))
        
        attack_frame = tk.Frame(tab, bg=self.section_bg)
        attack_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        tk.Label(attack_frame, text="Attack Target:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(side='left')
        
        self.rsa_attack_target = tk.StringVar(value="last")
        tk.Radiobutton(attack_frame, text="Last Encryption", variable=self.rsa_attack_target,
                      value="last", bg=self.section_bg, fg=self.text_color,
                      selectcolor=self.section_bg).pack(side='left', padx=(10, 20))
        tk.Radiobutton(attack_frame, text="Custom Values", variable=self.rsa_attack_target,
                      value="custom", bg=self.section_bg, fg=self.text_color,
                      selectcolor=self.section_bg).pack(side='left')
        
        self.custom_attack_frame = tk.Frame(tab, bg=self.section_bg)
        self.custom_attack_frame.pack_forget()
        
        tk.Label(self.custom_attack_frame, text="Modulus (n):", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', pady=(0, 5))
        
        text_frame1, self.rsa_attack_n = self.create_styled_text(self.custom_attack_frame, height=2)
        text_frame1.pack(fill='x', pady=(0, 10))
        
        tk.Label(self.custom_attack_frame, text="Public Exponent (e):", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', pady=(0, 5))
        
        self.rsa_attack_e = self.create_styled_entry(self.custom_attack_frame, width=30)
        self.rsa_attack_e.insert(0, "65537")
        self.rsa_attack_e.pack(fill='x', pady=(0, 10))
        
        tk.Label(self.custom_attack_frame, text="Ciphertext (c):", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', pady=(0, 5))
        
        text_frame2, self.rsa_attack_c = self.create_styled_text(self.custom_attack_frame, height=2)
        text_frame2.pack(fill='x', pady=(0, 15))
        
        self.rsa_attack_target.trace('w', self.toggle_rsa_attack_fields)
        
        attack_btn = self.create_styled_button(tab, "💥 Launch RSA Attack", 
                                             self.perform_rsa_attack, style='danger')
        attack_btn.pack(padx=15, pady=(0, 15))
        
        self.rsa_attack_progress = tk.Label(tab, text="", font=self.normal_font,
                                          fg='#a0a0a0', bg=self.section_bg)
        self.rsa_attack_progress.pack(padx=15, pady=(0, 10))
        
        self.rsa_attack_result_frame, self.rsa_attack_result_text = self.create_result_frame(tab)
    
    def create_rsa_info_tab(self):
        tab = tk.Frame(self.rsa_notebook, bg=self.section_bg)
        self.rsa_notebook.add(tab, text="📊 Info")
        
        tk.Label(tab, text="RSA System Information", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        info_frame = tk.Frame(tab, bg=self.section_bg)
        info_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        text_widget = scrolledtext.ScrolledText(info_frame, height=20,
                                              bg='#0d142e', fg=self.text_color,
                                              font=self.mono_font, relief='flat')
        text_widget.pack(fill='both', expand=True)
        
        if self.rsa_encryptor:
            info_text = "🚀 ULTIMATE RSA CAPABILITIES:\n"
            info_text += "=" * 50 + "\n\n"
            info_text += f"• Prime database: {len(self.rsa_encryptor.prime_list):,} primes\n"
            if self.rsa_encryptor.prime_list:
                info_text += f"• Prime range: {self.rsa_encryptor.prime_list[0]:,} to {self.rsa_encryptor.prime_list[-1]:,}\n"
            info_text += f"• Maximum n: {self.rsa_encryptor.max_n:,}\n"
            info_text += f"• Maximum n bits: {self.rsa_encryptor.max_n_bits}\n"
            info_text += f"• Maximum bytes: {self.rsa_encryptor.max_bytes:,}\n"
            info_text += f"• Can encrypt: up to {self.rsa_encryptor.max_bytes} characters\n"
            info_text += f"• Can attack: Messages up to {min(50, self.rsa_encryptor.max_bytes)}+ characters!\n\n"
            
            info_text += "📊 MESSAGE SIZE TEST:\n"
            test_sizes = [5, 10, 15, 20, 25]
            for size in test_sizes:
                test_msg = "A" * size
                byte_len = len(test_msg.encode('utf-8'))
                fits = byte_len <= self.rsa_encryptor.max_bytes
                status = "✅ FITS" if fits else "❌ TOO BIG"
                info_text += f"  {size:2} chars: {byte_len:3} bytes - {status}\n"
        else:
            info_text = "❌ RSA modules not initialized\n\n"
            info_text += "Please check that rsa_utils.py is in the same directory."
        
        text_widget.insert(1.0, info_text)
        text_widget.configure(state='disabled')
        
        if self.rsa_encryptor:
            regen_btn = self.create_styled_button(tab, "🔄 Regenerate Prime Database",
                                                self.regenerate_rsa_primes, style='warning')
            regen_btn.pack(padx=15, pady=(0, 15))
    
    def insert_rsa_sample(self, message):
        if hasattr(self, 'rsa_encrypt_message'):
            self.rsa_encrypt_message.delete(1.0, tk.END)
            self.rsa_encrypt_message.insert(1.0, message)

    def update_rsa_encrypt_result(self, result):
        if result:
            self.last_rsa_encryption = result
            
            output = f"✅ RSA ENCRYPTION SUCCESSFUL!\n"
            output += "=" * 60 + "\n"
            output += f"Message: '{result['text'][:40]}{'...' if len(result['text']) > 40 else ''}'\n"
            output += f"Length: {len(result['text'])} characters\n\n"
            output += f"🔑 GENERATED KEYS:\n"
            output += f"p = {result['p']:,}\n"
            output += f"q = {result['q']:,}\n"
            output += f"n = p × q = {result['n']:,} ({result['n'].bit_length()} bits)\n"
            output += f"φ(n) = {result.get('phi', (result['p']-1)*(result['q']-1)):,}\n"
            output += f"Public exponent e = {result['e']}\n"
            output += f"Private exponent d = {result['d']:,}\n\n"
            output += f"🔒 CIPHERTEXT:\n"
            output += f"c = {result['c']:,}\n\n"
            output += f"💡 ATTACK TARGET CREATED!\n"
            output += f"Use the Attack tab to try to crack this encryption."
            
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text, output)
        else:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ Encryption failed - message may be too large or no suitable primes found", True)
    
    def toggle_rsa_attack_fields(self, *args):
        if self.rsa_attack_target.get() == "custom":
            self.custom_attack_frame.pack(fill='x', padx=15, pady=(0, 15))
        else:
            self.custom_attack_frame.pack_forget()
  
    def update_rsa_attack_result(self, result, attack_title):
        self.rsa_attack_progress.config(text="")
        
        if result:
            output = f"🎉 RSA ATTACK SUCCESSFUL! ({attack_title})\n"
            output += "=" * 60 + "\n"
            output += f"✅ FACTORIZATION RESULT:\n"
            output += f"p = {result['p']:,}\n"
            output += f"q = {result['q']:,}\n"
            output += f"n = p × q = {result['p'] * result['q']:,}\n\n"
            output += f"🔑 PRIVATE KEY RECOVERED:\n"
            output += f"d = {result['d']:,}\n\n"
            
            if 'text' in result:
                output += f"📨 DECRYPTED MESSAGE:\n"
                output += f"'{result['text']}'\n\n"
            
            output += f"⏱️  Attack completed successfully!\n"
            output += f"✓ Private key extracted\n"
            output += f"✓ RSA encryption broken!"
            
            self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text, output)
        else:
            output = f"❌ ATTACK FAILED ({attack_title})\n"
            output += "=" * 60 + "\n\n"
            output += f"Modulus too strong for this demo.\n\n"
            output += f"💡 REAL RSA USES:\n"
            output += f"• 2048-bit primes (300+ digits)\n"
            output += f"• Would take millions of years to crack\n\n"
            output += f"🔧 THIS DEMO SHOWS:\n"
            output += f"• How RSA works mathematically\n"
            output += f"• Why large primes are essential\n"
            output += f"• The factorization problem"
            
            self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text, output, True)
    
    def run_rsa_quick_test(self):
        if not self.rsa_encryptor:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ RSA module not initialized", True)
            return
        
        try:
            self.rsa_encryptor.quick_test()
            
            output = "🧪 QUICK RSA TEST RESULTS\n"
            output += "=" * 50 + "\n\n"
            output += f"Maximum capacity: {self.rsa_encryptor.max_bytes} bytes/characters\n"
            output += f"Can handle 15 chars: {'YES' if self.rsa_encryptor.max_bytes >= 15 else 'NO'}\n\n"
            output += "Test messages:\n"
            
            test_messages = [
                "123456789012345",
                "Hello World!",
                "RSA Test!",
            ]
            
            for msg in test_messages:
                byte_len = len(msg.encode('utf-8'))
                fits = byte_len <= self.rsa_encryptor.max_bytes
                status = "✅ FITS" if fits else "❌ TOO LARGE"
                output += f"• '{msg}' ({len(msg)} chars, {byte_len} bytes) - {status}\n"
            
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text, output)
            
        except Exception as e:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            f"❌ Test error: {str(e)}", True)
    
    def regenerate_rsa_primes(self):
        response = messagebox.askyesno("Regenerate Primes", 
                                      "This will delete the current prime file and generate new primes.\n"
                                      "This may take a moment. Continue?")
        
        if response:
            try:
                if os.path.exists("rsa_primes.json"):
                    os.remove("rsa_primes.json")
                
                self.rsa_encryptor = RSAUltimateEncryptor("rsa_primes.json")
                self.rsa_attacker = RSAUltimateAttack(self.rsa_encryptor)
                
                messagebox.showinfo("Success", "✅ Prime database regenerated!\n"
                                              f"Loaded {len(self.rsa_encryptor.prime_list):,} primes\n"
                                              f"Max capacity: {self.rsa_encryptor.max_bytes} bytes")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to regenerate primes: {str(e)}")

  
    def perform_rsa_smart_encrypt(self):
        """Fixed to save RSA operations"""
        if not self.rsa_encryptor:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ RSA module not initialized", True)
            return
        
        message = self.rsa_encrypt_message.get(1.0, tk.END).strip()
        
        if not message:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "Please enter a message to encrypt", True)
            return
        
        byte_len = len(message.encode('utf-8'))
        if byte_len > self.rsa_encryptor.max_bytes:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            f"❌ Message too large!\n"
                            f"Message size: {byte_len} bytes\n"
                            f"Maximum supported: {self.rsa_encryptor.max_bytes} bytes\n"
                            f"Try a shorter message (max {self.rsa_encryptor.max_bytes} characters)", True)
            return
        
        self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                        f"🔐 Encrypting message with RSA...\n"
                        f"Message length: {len(message)} characters\n"
                        f"Message size: {byte_len} bytes\n\n"
                        f"⏳ Finding suitable primes...")
        
        def encrypt_thread():
            try:
                result = self.rsa_encryptor.smart_encrypt(message)
                
                # ALWAYS get user_id
                user_id = self.get_current_user_id()
                
                # Save RSA operation to database
                if result:
                    self.db.add_rsa_operation(
                        operation_type="encrypt",
                        key_size=result['n'].bit_length(),
                        input_info=message,
                        output_info=f"RSA encrypted: n={result['n']} bits, c={result['c']}",
                        user_id=user_id  # <-- FIXED
                    )
                
                self.root.after(0, self.update_rsa_encrypt_result, result)
            except Exception as e:
                self.root.after(0, lambda: self.show_result(
                    self.rsa_encrypt_result_frame,
                    self.rsa_encrypt_result_text,
                    f"❌ Encryption error: {str(e)}", True
                ))
        
        threading.Thread(target=encrypt_thread, daemon=True).start()

    def perform_rsa_attack(self):
        """Fixed to save RSA attack operations"""
        if not self.rsa_encryptor or not self.rsa_attacker:
            self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text,
                            "❌ RSA modules not initialized", True)
            return
        
        attack_type = self.rsa_attack_target.get()
        
        try:
            if attack_type == "last":
                if not self.last_rsa_encryption:
                    self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text,
                                    "❌ No recent encryption to attack\n"
                                    "Please encrypt a message first", True)
                    return
                
                n = self.last_rsa_encryption['n']
                e = self.last_rsa_encryption['e']
                c = self.last_rsa_encryption['c']
                message_len = len(self.last_rsa_encryption['text'])
                
                attack_title = f"LAST ENCRYPTION ({message_len} chars)"
            else:
                n_str = self.rsa_attack_n.get(1.0, tk.END).strip()
                e_str = self.rsa_attack_e.get().strip()
                c_str = self.rsa_attack_c.get(1.0, tk.END).strip()
                
                if not n_str or not e_str:
                    self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text,
                                    "Please enter n and e values", True)
                    return
                
                n = int(n_str)
                e = int(e_str)
                c = int(c_str) if c_str else None
                attack_title = "CUSTOM VALUES"
            
            self.rsa_attack_progress.config(text="🚀 Starting RSA attack...")
            self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text,
                            f"💥 LAUNCHING RSA ATTACK\n"
                            f"Target: {attack_title}\n"
                            f"Modulus n: {n:,}\n"
                            f"n bits: {n.bit_length()}\n"
                            f"e = {e}\n"
                            f"{'c = ' + str(c) if c else 'No ciphertext provided'}\n\n"
                            f"⏳ Factoring modulus using prime database...")
            
            def attack_thread():
                try:
                    result = self.rsa_attacker.crack_rsa(n, e, c)
                    
                    # ALWAYS get user_id
                    user_id = self.get_current_user_id()
                    
                    # Save RSA attack operation to database
                    if result:
                        self.db.add_operation(
                            "rsa_attack",
                            "rsa",
                            f"Attack on {attack_title}",
                            f"Successful: p={result['p']}, q={result['q']}",
                            f"n={n}",
                            100,
                            is_rsa_operation=True,
                            user_id=user_id  # <-- FIXED
                        )
                    
                    self.root.after(0, lambda: self.update_rsa_attack_result(result, attack_title))
                except Exception as ex:
                    self.root.after(0, lambda: self.show_result(
                        self.rsa_attack_result_frame,
                        self.rsa_attack_result_text,
                        f"❌ Attack error: {str(ex)}", True
                    ))
                    self.rsa_attack_progress.config(text="")
            
            threading.Thread(target=attack_thread, daemon=True).start()
            
        except ValueError:
            self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text,
                            "❌ Invalid number format", True)
        except Exception as ex:
            self.show_result(self.rsa_attack_result_frame, self.rsa_attack_result_text,
                            f"❌ Error: {str(ex)}", True)
 
        
    def analyze_rsa_message(self):
        if not self.rsa_encryptor:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ RSA module not initialized", True)
            return
        
        message = self.rsa_encrypt_message.get(1.0, tk.END).strip()
        
        if not message:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "Please enter a message to analyze", True)
            return
        
        result = self.rsa_encryptor.analyze_message(message)
        
        if result[0] is not None:
            m_int, min_n, min_prime = result
            
            output = f"📊 RSA MESSAGE ANALYSIS\n"
            output += "=" * 50 + "\n"
            output += f"Message: '{message[:50]}{'...' if len(message) > 50 else ''}'\n"
            output += f"Length: {len(message)} characters\n"
            output += f"Size: {len(message.encode('utf-8'))} bytes\n"
            output += f"Integer value: {m_int:,}\n"
            output += f"Binary size: {m_int.bit_length()} bits\n\n"
            output += f"🎯 PRIME REQUIREMENTS:\n"
            output += f"Minimum n needed: {min_n:,}\n"
            output += f"Minimum prime size: {min_prime:,}\n\n"
            
            if m_int < self.rsa_encryptor.max_n:
                output += f"✅ MESSAGE FITS IN CURRENT SYSTEM\n"
                output += f"Maximum capacity: {self.rsa_encryptor.max_bytes} bytes\n"
                output += f"Your message: {len(message.encode('utf-8'))} bytes\n"
            else:
                output += f"❌ MESSAGE TOO LARGE\n"
                output += f"Maximum capacity: {self.rsa_encryptor.max_bytes} bytes\n"
                output += f"Your message needs: {math.ceil(m_int.bit_length() / 8)} bytes"
            
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text, output)
        else:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ Message too large for analysis", True)

    def find_rsa_primes(self):
        if not self.rsa_encryptor:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ RSA module not initialized", True)
            return
        
        from tkinter import simpledialog
        
        min_size_str = simpledialog.askstring("Find Primes", 
                                            "Enter minimum prime size (e.g., 1000000):",
                                            parent=self.root)
        
        if not min_size_str:
            return
        
        try:
            min_size = int(min_size_str)
            
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            f"🔍 Searching for primes > {min_size:,}...")
            
            primes = self.rsa_encryptor.find_big_primes(min_size, count=10)
            
            if primes:
                output = f"✅ FOUND {len(primes)} PRIMES > {min_size:,}\n"
                output += "=" * 50 + "\n"
                for i, prime in enumerate(primes, 1):
                    output += f"{i}. {prime:,}\n"
                
                output += f"\n💡 These primes can be used for RSA encryption"
                self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text, output)
            else:
                self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                                f"❌ No primes found > {min_size:,}\n"
                                f"Largest available: {self.rsa_encryptor.prime_list[-1]:,}", True)
        except ValueError:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ Invalid number format", True)

    def perform_manual_rsa_encrypt(self):
        if not self.rsa_encryptor:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ RSA module not initialized", True)
            return
        
        message = self.rsa_encrypt_message.get(1.0, tk.END).strip()
        
        if not message:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "Please enter a message to encrypt", True)
            return
        
        from tkinter import simpledialog
        
        p_str = simpledialog.askstring("Manual RSA", "Enter prime p:", parent=self.root)
        q_str = simpledialog.askstring("Manual RSA", "Enter prime q:", parent=self.root)
        
        if not p_str or not q_str:
            return
        
        try:
            p = int(p_str)
            q = int(q_str)
            
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            f"🔐 Performing manual RSA encryption...\n"
                            f"p = {p:,}\n"
                            f"q = {q:,}\n"
                            f"Message: '{message}'")
            
            result = self.rsa_encryptor.perform_encryption(message, p, q)
            
            if result:
                self.last_rsa_encryption = result
                
                output = f"✅ MANUAL RSA ENCRYPTION SUCCESSFUL!\n"
                output += "=" * 60 + "\n"
                output += f"Message: '{result['text']}'\n"
                output += f"Length: {len(result['text'])} characters\n\n"
                output += f"🔑 USED PRIMES:\n"
                output += f"p = {result['p']:,}\n"
                output += f"q = {result['q']:,}\n"
                output += f"n = p × q = {result['n']:,} ({result['n'].bit_length()} bits)\n"
                output += f"Public exponent e = {result['e']}\n"
                output += f"Private exponent d = {result['d']:,}\n\n"
                output += f"🔒 CIPHERTEXT:\n"
                output += f"c = {result['c']:,}\n\n"
                output += f"💡 ATTACK TARGET CREATED!"
                
                self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text, output)
            else:
                self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                                "❌ Encryption failed - primes may be too small", True)
        except ValueError:
            self.show_result(self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text,
                            "❌ Invalid prime format", True)  
    
    
    def create_rsa_encrypt_tab(self):
        tab = tk.Frame(self.rsa_notebook, bg=self.section_bg)
        self.rsa_notebook.add(tab, text="🔒 Smart Encrypt")
        
        tk.Label(tab, text="Smart RSA Encryption", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(tab, text="The system automatically finds suitable large primes for your message",
                font=self.normal_font, fg='#888888', bg=self.section_bg, wraplength=600).pack(anchor='w', padx=15, pady=(0, 20))
        
        max_chars = self.rsa_encryptor.max_bytes if self.rsa_encryptor else "15+"
        tk.Label(tab, text=f"Enter Message (max {max_chars} characters):",
                font=self.normal_font, fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        text_frame, self.rsa_encrypt_message = self.create_styled_text(tab, height=6)
        text_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        sample_frame = tk.Frame(tab, bg=self.section_bg)
        sample_frame.pack(fill='x', padx=15, pady=(0, 10))
        
        tk.Label(sample_frame, text="Try:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(side='left')
        
        sample_messages = [
            "Hello World!",
            "RSA123Test#",
            "Crypto2024",
            "1234567890",
            "Test 15 chars!!"
        ]
        
        for i, msg in enumerate(sample_messages, 1):
            btn = tk.Button(sample_frame, text=f"{i}", font=('Segoe UI', 8, 'bold'),
                        bg='#2a2f47', fg=self.accent_color, relief='flat',
                        command=lambda m=msg: self.insert_rsa_sample(m))
            btn.pack(side='left', padx=(5, 0))
        
        button_frame = tk.Frame(tab, bg=self.section_bg)
        button_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        analyze_btn = self.create_styled_button(button_frame, "📊 Analyze Message", 
                                            self.analyze_rsa_message, style='secondary')
        analyze_btn.pack(side='left', padx=(0, 10))
        
        encrypt_btn = self.create_styled_button(button_frame, "🚀 Smart Encrypt", 
                                            self.perform_rsa_smart_encrypt, style='primary')
        encrypt_btn.pack(side='left', padx=(0, 10))
        
        manual_btn = self.create_styled_button(button_frame, "🔧 Manual Encrypt", 
                                            self.perform_manual_rsa_encrypt, style='warning')
        manual_btn.pack(side='left')
        
        find_primes_btn = self.create_styled_button(tab, "🔍 Find Large Primes", 
                                                self.find_rsa_primes, style='secondary')
        find_primes_btn.pack(padx=15, pady=(0, 15))
        
        self.rsa_encrypt_result_frame, self.rsa_encrypt_result_text = self.create_result_frame(tab)
    
    def create_styled_entry(self, parent, **kwargs):
        return tk.Entry(parent, bg='#0d142e', fg=self.text_color,
                       insertbackground=self.accent_color,
                       relief='solid', bd=2,
                       font=self.normal_font, **kwargs)
        
    def create_styled_text(self, parent, height=4, **kwargs):
        frame = tk.Frame(parent, bg=self.container_bg)
        text_widget = scrolledtext.ScrolledText(frame, height=height,
                                               bg='#0d142e', fg=self.text_color,
                                               insertbackground=self.accent_color,
                                               relief='solid', bd=2,
                                               font=self.mono_font, **kwargs)
        text_widget.pack(fill='both', expand=True)
        return frame, text_widget
        
    def create_styled_button(self, parent, text, command, style='primary'):
        if style == 'primary':
            bg = self.accent_color
            fg = self.container_bg
            active_bg = '#00b8d4'
        elif style == 'secondary':
            bg = '#2a2f47'
            fg = self.text_color
            active_bg = '#3a3f57'
        elif style == 'success':
            bg = self.success_color
            fg = self.container_bg
            active_bg = '#00cc6a'
        elif style == 'danger':
            bg = self.error_color
            fg = 'white'
            active_bg = '#ff2222'
        elif style == 'warning':
            bg = self.warning_color
            fg = self.container_bg
            active_bg = '#ee9900'
            
        return tk.Button(parent, text=text, command=command,
                        bg=bg, fg=fg, font=('Segoe UI', 10, 'bold'),
                        relief='flat', bd=0, padx=20, pady=10,
                        activebackground=active_bg,
                        activeforeground=fg)
        
    def create_result_frame(self, parent):
        frame = tk.Frame(parent, bg='#1a1f37',
                        relief='solid', bd=2,
                        highlightbackground=self.accent_color,
                        highlightthickness=2)
        frame.pack_forget()
        
        text_widget = scrolledtext.ScrolledText(frame, height=6,
                                               bg='#0d142e',
                                               fg=self.text_color,
                                               font=self.mono_font,
                                               relief='flat')
        text_widget.pack(fill='both', expand=True, padx=5, pady=5)
        
        return frame, text_widget
        
    def show_result(self, frame, text_widget, text, is_error=False):
        if is_error:
            frame.configure(bg='#2a1a1a',
                           highlightbackground=self.error_color)
            text_widget.configure(bg='#1a0d0d')
        else:
            frame.configure(bg='#1a1f37',
                           highlightbackground=self.accent_color)
            text_widget.configure(bg='#0d142e')
            
        text_widget.delete(1.0, tk.END)
        text_widget.insert(1.0, text)
        frame.pack(fill='x', pady=(10, 0))
        
    def select_file(self, file_type, key, accept=None):
        if accept:
            filename = filedialog.askopenfilename(title=f"Select {file_type}", filetypes=[(file_type, accept)])
        else:
            filename = filedialog.askopenfilename(title=f"Select {file_type}")
            
        if filename:
            self.selected_files[key] = filename
            return filename
        return None
        
    def format_file_size(self, bytes):
        if bytes == 0:
            return '0 Bytes'
        k = 1024
        sizes = ['Bytes', 'KB', 'MB', 'GB']
        i = int(math.floor(math.log(bytes) / math.log(k)))
        return f"{bytes / math.pow(k, i):.2f} {sizes[i]}"
    
    
    
    


    
    
    
    
    
    
    
    
    
        
        
        
        
        # Add this helper method first
    def get_current_user_id(self):
        """Get current user ID, returns None for standard mode"""
        if self.current_user and 'id' in self.current_user:
            return self.current_user['id']
        return None

    # ==================== FIXED API METHODS ====================









    def load_history_data(self):
        """Load history data from database with proper user filtering"""
        if not hasattr(self, 'history_tree'):
            return
        
        # Clear current tree
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Get filter value
        filter_type = self.history_filter_var.get()
        
        # Determine user type and ID
        user_id = self.get_current_user_id()
        is_admin = self.current_user.get('is_admin') if self.current_user else False
        
        # Update title based on user type
        for widget in self.main_frame.winfo_children():
            if isinstance(widget, tk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label) and "History" in child.cget("text"):
                        if is_admin:
                            child.config(text="👑 Admin History - All Operations")
                        elif user_id is None:
                            child.config(text="🔓 Standard Mode History")
                        else:
                            username = self.current_user['username'] if self.current_user else "User"
                            child.config(text=f"👤 {username}'s Personal History")
                        break
        
        try:
            # Get history with proper permissions
            history = self.db.get_combined_history(
                limit=100,
                operation_type=filter_type if filter_type != 'all' else None,
                user_id=user_id,
                is_admin=is_admin
            )
            
            if not history:
                self.update_history_stats([])
                self.show_status_message("📭 No operations found in history", "info")
                
                # Add empty message to tree
                if is_admin:
                    self.history_tree.insert("", tk.END, values=(
                        "", "No operations", "", "", "", "", "", ""
                    ))
                else:
                    self.history_tree.insert("", tk.END, values=(
                        "", "No operations", "", "", "", "", "", ""
                    ))
                return
            
            # Configure tree columns based on user type
            if is_admin:
                columns = ("ID", "User", "Type", "Cipher", "Input", "Output", "Time", "Score")
                col_widths = {"ID": 50, "User": 80, "Type": 80, "Cipher": 80, 
                            "Input": 150, "Output": 150, "Time": 120, "Score": 60}
            else:
                columns = ("ID", "Type", "Cipher", "Input", "Output", "Time", "Score")
                col_widths = {"ID": 50, "Type": 80, "Cipher": 80, 
                            "Input": 200, "Output": 200, "Time": 120, "Score": 60}
            
            # Clear and reconfigure tree if needed
            current_cols = self.history_tree['columns']
            if tuple(current_cols) != columns:
                # Clear tree
                for item in self.history_tree.get_children():
                    self.history_tree.delete(item)
                
                # Reconfigure columns
                self.history_tree['columns'] = columns
                self.history_tree['show'] = 'headings'
                
                for col in columns:
                    self.history_tree.heading(col, text=col)
                    self.history_tree.column(col, width=col_widths.get(col, 100))
            
            # Add items to tree
            for op in history:
                # Format timestamp
                timestamp = op['timestamp'].strftime("%H:%M %m/%d") if op['timestamp'] else ""
                
                # Format input/output text
                input_text = op['input_text'] or ""
                if len(input_text) > 30:
                    input_text = input_text[:27] + "..."
                    
                output_text = op['output_text'] or ""
                if len(output_text) > 30:
                    output_text = output_text[:27] + "..."
                
                # Prepare values based on user type
                if is_admin:
                    values = (
                        op['id'],
                        op.get('username', 'standard'),
                        op['operation_type'],
                        op['cipher_type'] or "",
                        input_text,
                        output_text,
                        timestamp,
                        f"{op['score']:.1f}" if op['score'] else ""
                    )
                else:
                    values = (
                        op['id'],
                        op['operation_type'],
                        op['cipher_type'] or "",
                        input_text,
                        output_text,
                        timestamp,
                        f"{op['score']:.1f}" if op['score'] else ""
                    )
                
                self.history_tree.insert("", tk.END, values=values)
            
            # Update statistics
            self.update_history_stats(history)
            
            # Show success message
            user_type = ""
            if is_admin:
                user_type = "👑 Admin view"
            elif user_id is None:
                user_type = "🔓 Standard mode"
            else:
                user_type = f"👤 {self.current_user['username']}"
            
            self.show_status_message(f"{user_type}: Loaded {len(history)} operations", "success")
            
        except Exception as e:
            print(f"❌ Error loading history: {e}")
            messagebox.showerror("Error", f"Failed to load history: {str(e)}")
            

    def load_admin_history(self):
        """Load all operations for admin view - COMPLETE FIXED VERSION"""
        # Check if tree exists
        if not hasattr(self, 'admin_history_tree'):
            return
        
        # Clear current tree
        for item in self.admin_history_tree.get_children():
            self.admin_history_tree.delete(item)
        
        try:
            # Get user filter
            user_filter = self.admin_user_filter.get()
            
            # Use admin-only method
            operations = self.db.get_admin_history(limit=200, user_filter=user_filter)
            
            if not operations:
                self.admin_history_tree.insert("", tk.END, values=(
                    "", "No operations found", "", "", "", "", "", ""
                ))
                self.show_status_message("📭 No operations found for the selected filter", "info")
                return
            
            # Add to tree
            for op in operations:
                timestamp = op.get('timestamp', '')
                
                input_text = op.get('input_text', '') or ""
                if len(input_text) > 25:
                    input_text = input_text[:22] + "..."
                    
                output_text = op.get('output_text', '') or ""
                if len(output_text) > 25:
                    output_text = output_text[:22] + "..."
                
                self.admin_history_tree.insert("", tk.END, values=(
                    op.get('id', ''),
                    op.get('username', 'standard'),
                    op.get('operation_type', ''),
                    op.get('cipher_type', '') or "",
                    input_text,
                    output_text,
                    op.get('key_used', '') or "",
                    timestamp
                ))
            
            self.show_status_message(f"👑 Admin: Loaded {len(operations)} operations", "info")
            
        except Exception as e:
            print(f"❌ Error loading admin history: {e}")
            self.show_status_message(f"❌ Error loading admin history: {str(e)}", "error")

    def get_operation_statistics(self, days=30, user_id=None, is_admin=False):
        """Get operation statistics for the last N days with proper permissions"""
        session = None
        try:
            session = self.Session()
            since_date = datetime.now() - timedelta(days=days)
            
            # Build query based on permissions
            query = session.query(Operation).filter(Operation.timestamp >= since_date)
            
            if user_id is None:
                # Standard mode: only operations without user_id
                query = query.filter(Operation.user_id == None)
                stats_type = "standard"
            elif not is_admin:
                # Regular user: their operations + standard operations
                query = query.filter(
                    (Operation.user_id == user_id) | (Operation.user_id == None)
                )
                stats_type = f"user_{user_id}"
            else:
                # Admin: all operations
                stats_type = "admin"
            
            total_ops = query.count()
            
            # Get detailed stats
            ops_by_type = {}
            file_ops = 0
            image_ops = 0
            audio_ops = 0
            rsa_ops = 0
            security_ops = 0
            auto_crack_ops = 0
            
            all_ops = query.all()
            for op in all_ops:
                # Count by operation type
                op_type = op.operation_type
                ops_by_type[op_type] = ops_by_type.get(op_type, 0) + 1
                
                # Count special operations
                if op.is_file_operation:
                    file_ops += 1
                if op.is_image_operation:
                    image_ops += 1
                if op.is_audio_operation:
                    audio_ops += 1
                if op.is_rsa_operation:
                    rsa_ops += 1
                if op.is_security_operation:
                    security_ops += 1
                if op.is_auto_crack:
                    auto_crack_ops += 1
            
            # Hash operations
            hash_query = session.query(HashOperation).filter(HashOperation.timestamp >= since_date)
            
            if user_id is not None and not is_admin:
                hash_query = hash_query.filter(
                    (HashOperation.user_id == user_id) | (HashOperation.user_id == None)
                )
            
            hash_ops = hash_query.all()
            hash_cracked = sum(1 for hop in hash_ops if hop.cracked)
            
            stats = {
                'total_operations': total_ops,
                'total_hash_operations': len(hash_ops),
                'hash_cracked': hash_cracked,
                'hash_success_rate': (hash_cracked / len(hash_ops) * 100) if hash_ops else 0,
                'operations_by_type': ops_by_type,
                'file_operations': file_ops,
                'image_operations': image_ops,
                'audio_operations': audio_ops,
                'rsa_operations': rsa_ops,
                'security_operations': security_ops,
                'auto_crack_operations': auto_crack_ops,
                'stats_type': stats_type,
                'period_days': days
            }
            
            print(f"📊 Statistics for {stats_type} (last {days} days): {total_ops} operations")
            return stats
            
        except Exception as e:
            print(f"❌ Error in get_operation_statistics: {str(e)}")
            return {}
        finally:
            if session:
                session.close()

    def verify_permissions(self):
        """Verify that user permissions are working correctly"""
        print("\n" + "="*60)
        print("🔒 VERIFYING USER PERMISSIONS")
        print("="*60)
        
        user_id = self.get_current_user_id()
        is_admin = self.current_user.get('is_admin') if self.current_user else False
        username = self.current_user['username'] if self.current_user else "Standard Mode"
        
        print(f"Current user: {username}")
        print(f"User ID: {user_id}")
        print(f"Is Admin: {is_admin}")
        
        # Test 1: Get user's own history
        print("\n📋 Test 1: Getting user history...")
        user_history = self.db.get_combined_history(
            limit=10, 
            user_id=user_id, 
            is_admin=is_admin
        )
        
        print(f"User can see {len(user_history)} operations")
        
        # Check what types of operations they can see
        if user_history:
            user_ids_seen = set()
            for op in user_history:
                user_ids_seen.add(op['user_id'])
            
            print(f"Operations from user IDs: {user_ids_seen}")
            
            if is_admin:
                print("✅ Admin can see operations from all users")
            elif None in user_ids_seen and (len(user_ids_seen) == 1 or (user_id in user_ids_seen)):
                print("✅ Regular user can only see standard and their own operations")
            else:
                print("❌ ERROR: User can see operations they shouldn't!")
        
        # Test 2: Check statistics
        print("\n📊 Test 2: Getting user statistics...")
        stats = self.db.get_operation_statistics(
            days=7, 
            user_id=user_id, 
            is_admin=is_admin
        )
        
        if stats:
            print(f"Your operations (last 7 days): {stats.get('total_operations', 0)}")
            print(f"Stats type: {stats.get('stats_type', 'unknown')}")
        
        # Test 3: For admin, check admin history
        if is_admin:
            print("\n👑 Test 3: Checking admin-only history...")
            admin_history = self.db.get_admin_history(limit=5)
            print(f"Admin history contains {len(admin_history)} operations")
            
            if admin_history:
                users_seen = set()
                for op in admin_history:
                    users_seen.add(op['username'])
                print(f"Admin can see operations from users: {users_seen}")
        
        print("\n" + "="*60)
        print("✅ PERMISSION VERIFICATION COMPLETE")
        print("="*60)
        
        return True






















    def encrypt_text_api(self, cipher_type, text, key):
        try:
            if cipher_type == "aes":
                result = self.aes.encrypt(text, key)
            elif cipher_type == "base64":  # Add Base64 handling
                import base64
                result = base64.b64encode(text.encode()).decode()
            else:
                result = encrypt(text, cipher_type, key)
            
            is_file_op = cipher_type in ['aes', 'file']
            is_image_op = cipher_type in ['image', 'steganography']
            is_audio_op = cipher_type in ['audio']
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            # ALWAYS pass user_id to add_operation
            self.db.add_operation(
                "encrypt", 
                cipher_type, 
                text, 
                result, 
                key, 
                score_text(text),
                is_file_operation=is_file_op, 
                is_image_operation=is_image_op, 
                is_audio_operation=is_audio_op,
                user_id=user_id  # <-- FIXED
            )
            
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def decrypt_text_api(self, cipher_type, text, key):
        try:
            if cipher_type == "aes":
                result = self.aes.decrypt(text, key)
            elif cipher_type == "base64":  
                import base64
                result = base64.b64decode(text).decode()
            else:
                result = decrypt(text, cipher_type, key)
            
            is_file_op = cipher_type in ['aes', 'file']
            is_image_op = cipher_type in ['image', 'steganography']
            is_audio_op = cipher_type in ['audio']
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            # ALWAYS pass user_id to add_operation
            self.db.add_operation(
                "decrypt", 
                cipher_type, 
                text, 
                result, 
                key, 
                score_text(result),
                is_file_operation=is_file_op, 
                is_image_operation=is_image_op,
                is_audio_operation=is_audio_op,
                user_id=user_id  # <-- FIXED
            )
            
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def auto_crack_api(self, text):
        try:
            results = crack_cipher(text)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            self.db.add_operation(
                "auto-crack", 
                "auto-detect", 
                text, 
                json.dumps(results[:3]), 
                "", 
                0,
                user_id=user_id,  # <-- FIXED
                is_auto_crack=True
            )
            
            return {"success": True, "results": results[:5]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def brute_force_aes_api(self, ciphertext, max_workers=8):
        try:
            result = self.aes.brute_force_decrypt(ciphertext, max_workers)
            
            if result['success']:
                # ALWAYS get user_id
                user_id = self.get_current_user_id()
                
                self.db.add_operation(
                    'brute-force-aes', 
                    'AES', 
                    ciphertext[:50], 
                    result.get('text', '')[:50], 
                    result.get('password', ''), 
                    score_text(result.get('text', '')),
                    is_file_operation=True,
                    user_id=user_id  # <-- FIXED
                )
            
            return {"success": result['success'], **result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def crack_hash_api(self, target_hash, hash_type="auto", timeout=30):
        try:
            if not target_hash:
                return {"success": False, "error": "Hash is required"}
            
            if hash_type == "auto":
                result = self.hash_cracker.auto_crack_hash(target_hash, timeout)
            else:
                result = self.hash_cracker.crack_hash(target_hash, hash_type, timeout=timeout)
            
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def hash_text_api(self, text, hash_type="md5"):
        try:
            if not text:
                return {"success": False, "error": "Text is required"}
            
            hash_value = self.hash_cracker.hash_text(text, hash_type)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            self.db.add_hash_generation(
                hash_type=hash_type,
                original_text=text,
                hash_value=hash_value,
                user_id=user_id  # <-- FIXED
            )
            
            print(f"💾 Hash generation saved: '{text}' → {hash_value}")
            
            return {
                "success": True,
                "hash_type": hash_type,
                "hash_value": hash_value,
                "operation_id": "generation"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def image_hide_api(self, image_path, message):
        try:
            with open(image_path, 'rb') as f:
                contents = f.read()
            
            result_path = self.img_stega.hide_message(contents, message)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            self.db.add_image_operation(
                operation_type="hide",
                image_format="LSB",
                input_info=message,
                output_info=f"Image encoded: {os.path.basename(image_path)}",
                user_id=user_id  # <-- FIXED
            )
            
            return {"success": True, "file_path": result_path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def image_extract_api(self, image_path):
        try:
            with open(image_path, 'rb') as f:
                contents = f.read()
            
            message = self.img_stega.extract_message(contents)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            self.db.add_image_operation(
                operation_type="extract",
                image_format="LSB",
                input_info=f"Image: {os.path.basename(image_path)}",
                output_info=message[:100] + ("..." if len(message) > 100 else ""),
                user_id=user_id  # <-- FIXED
            )
            
            return {"success": True, "message": message}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def audio_hide_api(self, audio_path, message):
        try:
            with open(audio_path, 'rb') as f:
                contents = f.read()
            
            result_path = self.audio_stega.hide_message(contents, message)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            self.db.add_audio_operation(
                operation_type="hide",
                audio_format="LSB",
                input_info=message,
                output_info=f"Audio encoded: {os.path.basename(audio_path)}",
                user_id=user_id  # <-- FIXED
            )
            
            return {"success": True, "file_path": result_path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def audio_extract_api(self, audio_path):
        try:
            with open(audio_path, 'rb') as f:
                contents = f.read()
            
            message = self.audio_stega.extract_message(contents)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            self.db.add_audio_operation(
                operation_type="extract",
                audio_format="LSB",
                input_info=f"Audio: {os.path.basename(audio_path)}",
                output_info=message[:100] + ("..." if len(message) > 100 else ""),
                user_id=user_id  # <-- FIXED
            )
            
            return {"success": True, "message": message}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def auto_crack_modern_api(self, text):
        try:
            text = text.strip()
            
            if not text:
                return {"success": False, "error": "No text provided"}
            
            print(f"\n🚀 AUTO-CRACK MODERN ENDPOINT CALLED")
            
            result = modern_cracker.auto_crack(text)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            if result['success']:
                best_result = result['results'][0] if result['results'] else {}
                result_text = best_result.get('text', '')[:100] if best_result else 'No result'
                
                self.db.add_operation(
                    "auto-crack-modern", 
                    "modern", 
                    text[:100], 
                    f"Found {len(result['results'])} results", 
                    "", 
                    0,
                    user_id=user_id,  # <-- FIXED
                    is_auto_crack=True
                )
            else:
                self.db.add_operation(
                    "auto-crack-modern", 
                    "modern", 
                    text[:100], 
                    "No results found", 
                    "", 
                    0,
                    user_id=user_id,  # <-- FIXED
                    is_auto_crack=True
                )
            
            return result
            
        except Exception as e:
            print(f"❌ Auto-crack modern error: {e}")
            return {"success": False, "error": str(e)}

    def modern_crack_api(self, ciphertext, method="auto", known_prefix="", target_type="text"):
        try:
            if not ciphertext:
                return {"success": False, "error": "Ciphertext is required"}
            
            if method == "bruteforce":
                if target_type == "file":
                    result = self.aes.brute_force_file_decrypt(ciphertext)
                else:
                    result = self.aes.brute_force_decrypt(ciphertext)
            elif method == "padding_oracle":
                if target_type == "file":
                    result = self.aes.padding_oracle_attack_file(ciphertext, known_prefix)
                else:
                    result = self.aes.padding_oracle_attack_text(ciphertext, known_prefix)
            else:
                print("🔄 AUTO MODE: Trying brute force first...")
                if target_type == "file":
                    result = self.aes.brute_force_file_decrypt(ciphertext)
                else:
                    result = self.aes.brute_force_decrypt(ciphertext)
                    
                if not result['success']:
                    print("🔄 AUTO MODE: Brute force failed, trying padding oracle...")
                    if target_type == "file":
                        result = self.aes.padding_oracle_attack_file(ciphertext, known_prefix)
                    else:
                        result = self.aes.padding_oracle_attack_text(ciphertext, known_prefix)
            
            # ALWAYS get user_id and save operation if successful
            if result.get('success'):
                user_id = self.get_current_user_id()
                operation_type = "brute-force" if method == "bruteforce" else "padding-oracle"
                
                self.db.add_operation(
                    operation_type,
                    "AES",
                    ciphertext[:100],
                    result.get('text', '')[:100],
                    result.get('password', ''),
                    score_text(result.get('text', '')),
                    is_file_operation=(target_type == "file"),
                    user_id=user_id  # <-- FIXED
                )
            
            return {"success": result['success'], **result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def file_encrypt_api(self, file_path, password):
        try:
            from aes_crypto import AESEncryption
            
            aes = AESEncryption()
            
            base_name = os.path.basename(file_path)
            output_file = f"encrypted_{base_name}.bin"
            
            counter = 1
            while os.path.exists(output_file):
                name_parts = base_name.split('.')
                if len(name_parts) > 1:
                    output_file = f"encrypted_{name_parts[0]}_{counter}.{'.'.join(name_parts[1:])}.bin"
                else:
                    output_file = f"encrypted_{base_name}_{counter}.bin"
                counter += 1
            
            encrypted = aes.encrypt_file(file_path, password)
            
            with open(output_file, 'wb') as f:
                f.write(encrypted)
            
            file_size = os.path.getsize(output_file)
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            # Save operation to database
            self.db.add_file_operation(
                operation_type="encrypt",
                cipher_type="AES",
                file_name=base_name,
                file_size=file_size,
                user_id=user_id  # <-- FIXED
            )
            
            return {
                'success': True,
                'encrypted_file': output_file,
                'size': file_size,
                'message': f"✅ File encrypted successfully!\n📁 Encrypted file: {output_file}"
            }
                    
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def file_decrypt_api(self, file_path, password):
        try:
            from aes_crypto import AESEncryption 
            
            aes = AESEncryption()
            
            base_name = os.path.basename(file_path)
            if base_name.endswith('.bin') and base_name.startswith('encrypted_'):
                original_name = base_name.replace('encrypted_', '').replace('.bin', '')
            else:
                original_name = f"decrypted_{base_name}"
            
            output_file = original_name
            
            counter = 1
            while os.path.exists(output_file):
                name_parts = original_name.split('.')
                if len(name_parts) > 1:
                    output_file = f"{name_parts[0]}_{counter}.{'.'.join(name_parts[1:])}"
                else:
                    output_file = f"{original_name}_{counter}"
                counter += 1
            
            result_bytes = aes.decrypt_file(file_path, password, output_file)
            
            if result_bytes is not None:
                file_size = os.path.getsize(output_file)
                
                # ALWAYS get user_id
                user_id = self.get_current_user_id()
                
                # Save operation to database
                self.db.add_file_operation(
                    operation_type="decrypt",
                    cipher_type="AES",
                    file_name=base_name,
                    file_size=file_size,
                    user_id=user_id  # <-- FIXED
                )
                
                return {
                    'success': True,
                    'decrypted_file': output_file,
                    'size': file_size,
                    'message': f"✅ File decrypted successfully!\n📁 Decrypted file: {output_file}"
                }
            else:
                return {
                    'success': False,
                    'error': 'Decryption failed - wrong password or corrupted file'
                }
                    
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def file_brute_force_api(self, file_path):
        try:
            import threading
            
            def run_brute_force():
                try:
                    from aes_crypto import AESEncryption
                    from hybrid_brute_force import HybridBruteForce
                    
                    aes = AESEncryption()
                    hybrid = HybridBruteForce()
                    
                    def progress_callback(message):
                        self.root.after(0, lambda: self.update_brute_force_progress(message))
                    
                    print(f"⚡ Starting ultra-fast brute force...")
                    
                    result = hybrid.brute_force_file_phase1(
                        file_path, 
                        max_workers=8,
                        callback=progress_callback,
                        auto_decrypt=True
                    )
                    
                    if result['success']:
                        password = result['password']
                        
                        # ALWAYS get user_id
                        user_id = self.get_current_user_id()
                        
                        # Save successful brute force operation
                        self.db.add_operation(
                            "brute-force-file",
                            "AES",
                            f"File: {os.path.basename(file_path)}",
                            f"Password found: {password}",
                            password,
                            100,
                            is_file_operation=True,
                            user_id=user_id  # <-- FIXED
                        )
                        
                        decrypt_result = aes.auto_decrypt_with_password(file_path, password)
                        
                        message = f"✅ PASSWORD FOUND!\n\n"
                        message += f"🔑 Password: '{password}'\n"
                        message += f"⏱️  Brute force time: {result.get('time_elapsed', 0):.2f}s\n"
                        message += f"📊 Tested: {result.get('tested_count', 0):,} passwords\n"
                        message += f"⚡ Speed: {result.get('rate_per_sec', 0):,.0f}/sec\n"
                        
                        if decrypt_result['success']:
                            message += f"\n🔓 AUTO-DECRYPTION SUCCESSFUL!\n"
                            message += f"📁 Decrypted file: {decrypt_result['decrypted_file']}\n"
                            message += f"💾 Size: {decrypt_result['size']:,} bytes\n"
                            message += f"🎯 Password auto-filled in decrypt field"
                            
                            self.root.after(0, lambda: self.decrypt_password.delete(0, tk.END))
                            self.root.after(0, lambda: self.decrypt_password.insert(0, password))
                            
                            if hasattr(self, 'decrypt_files'):
                                self.decrypt_files.append(decrypt_result['decrypted_file'])
                                self.decrypt_file_listbox.insert('end', os.path.basename(decrypt_result['decrypted_file']))
                        else:
                            message += f"\n⚠️ Auto-decryption failed:\n{decrypt_result.get('error', 'Unknown error')}"
                        
                        self.root.after(0, lambda: self.show_file_brute_force_result(message))
                        
                    else:
                        # Save failed brute force attempt
                        user_id = self.get_current_user_id()
                        self.db.add_operation(
                            "brute-force-file-failed",
                            "AES",
                            f"File: {os.path.basename(file_path)}",
                            "Password not found",
                            "",
                            0,
                            is_file_operation=True,
                            user_id=user_id  # <-- FIXED
                        )
                        
                        message = f"❌ Password not found\n\n"
                        message += f"⏱️  Time: {result.get('time_elapsed', 0):.2f}s\n"
                        message += f"📊 Tested: {result.get('tested_count', 0):,} passwords\n"
                        message += f"⚠️  Error: {result.get('error', 'Unknown')}"
                        
                        self.root.after(0, lambda: self.show_file_brute_force_result(message))
                        
                except Exception as e:
                    error_msg = f"❌ Brute force error: {str(e)}"
                    import traceback
                    traceback.print_exc()
                    self.root.after(0, lambda: self.show_file_brute_force_result(error_msg))
            
            thread = threading.Thread(target=run_brute_force)
            thread.daemon = True
            thread.start()
            
            self.show_brute_force_progress_window()
            
            return {
                'success': True,
                'message': 'Brute force started with auto-decryption...'
            }
                    
        except Exception as e:
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Brute force failed: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }


    
    def get_combined_history_api(self, operation_type=None):
        try:
            history = self.db.get_history(
                limit=50,
                operation_type=operation_type
            )
            
            if operation_type in ['hash_generate', 'hash_crack', None]:
                hash_history = self.db.get_hash_operations(limit=20)
                
                for hash_op in hash_history:
                    op_type = "hash_crack" if hash_op['cracked'] else "hash_generate"
                    
                    if operation_type is None or operation_type == op_type:
                        history.append({
                            'id': f"hash_{hash_op['id']}",
                            'operation_type': op_type,
                            'cipher_type': f"hash_{hash_op['hash_type']}",
                            'input_text': hash_op['original_text'] if hash_op['original_text'] else hash_op['hash_value'],
                            'output_text': hash_op['cracked_text'] if hash_op['cracked'] else hash_op['hash_value'],
                            'key_used': hash_op['hash_type'],
                            'timestamp': hash_op['timestamp'],
                            'score': 100 if hash_op['cracked'] else 50,
                            'file_name': None,
                            'is_file_operation': False,
                            'is_image_operation': False,
                            'is_audio_operation': False,
                            'is_hash_operation': True
                        })
            
            history.sort(key=lambda x: x['timestamp'], reverse=True)
            
            history = history[:50]
            
            return {
                "success": True, 
                "history": history
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_hash_history_api(self, limit=20):
        try:
            hash_history = self.db.get_hash_operations(limit=limit)
            
            return {"success": True, "hash_history": hash_history}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_statistics_api(self, days=30):
        try:
            stats = self.db.get_operation_statistics(days)
            return {"success": True, "statistics": stats}
        except Exception as e:
            return {"success": False, "error": str(e)}


    def update_brute_force_progress(self, message):
        if hasattr(self, 'brute_text'):
            self.brute_text.insert(tk.END, message + "\n")
            self.brute_text.see(tk.END)
            
            lines = message.strip().split('\n')
            if lines and hasattr(self, 'brute_status'):
                last_line = lines[-1][:50]
                self.brute_status.set(last_line)

    def show_brute_force_progress_window(self):
        from tkinter import scrolledtext
        
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Brute Force Progress")
        progress_window.geometry("700x500")
        progress_window.configure(bg=self.container_bg)
        
        tk.Label(progress_window, text="🔍 ULTRA-FAST BRUTE FORCE", 
                font=self.heading_font, fg=self.accent_color,
                bg=self.container_bg).pack(pady=10)
        
        self.brute_text = scrolledtext.ScrolledText(progress_window, 
                                                height=20, width=85,
                                                bg='#0d142e', fg='#00ff88',
                                                font=('Consolas', 10))
        self.brute_text.pack(padx=10, pady=10, fill='both', expand=True)
        
        self.brute_status = tk.StringVar(value="🚀 Starting...")
        status_bar = tk.Label(progress_window, textvariable=self.brute_status,
                            font=self.normal_font, fg='#ffaa00',
                            bg=self.container_bg)
        status_bar.pack(pady=5)
        
        stop_btn = self.create_styled_button(progress_window, "⏹️ Stop",
                                        lambda: self.stop_brute_force(),
                                        style='danger')
        stop_btn.pack(pady=10)
        
        self.brute_window = progress_window
        
        def on_closing():
            self.stop_brute_force()
        
        progress_window.protocol("WM_DELETE_WINDOW", on_closing)

    def stop_brute_force(self):
        if hasattr(self, 'brute_force_engine'):
            self.brute_force_engine.stop_brute_force()
        
        if hasattr(self, 'brute_status'):
            self.brute_status.set("🛑 Stopping...")
        
        if hasattr(self, 'brute_window'):
            self.brute_window.after(1000, self.brute_window.destroy)


   
   
    
    
    
    def create_file_tab(self):
        """Create File Encryption/Decryption Tab with dedicated result containers"""
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["File Encrypt"] = tab
        
        title = tk.Label(tab, text="📁 File Encryption & Decryption", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        # Description
        desc = tk.Label(tab, text="Encrypt files to protect them, or decrypt to restore. "
                                "Drag & drop files to preview them. Files open automatically after processing.",
                    font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        # Main content with two columns
        main_frame = tk.Frame(tab, bg=self.container_bg)
        main_frame.pack(fill='both', expand=True)
        
        # ==================== LEFT COLUMN - ENCRYPT ====================
        left_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10), pady=5)
        
        tk.Label(left_frame, text="🔒 Encrypt Files", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        # File Preview area for encryption
        preview_encrypt_frame = tk.Frame(left_frame, bg=self.section_bg)
        preview_encrypt_frame.pack(padx=15, pady=(0, 15), fill='both', expand=True)
        
        tk.Label(preview_encrypt_frame, text="File Preview:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', pady=(0, 5))
        
        # Drag & Drop area for encryption
        encrypt_drop_frame = tk.Frame(preview_encrypt_frame, bg='#1a1f37', relief='ridge', bd=3,
                                    highlightbackground=self.accent_color, highlightthickness=2)
        encrypt_drop_frame.pack(fill='both', expand=True)
        
        self.encrypt_drop_label = tk.Label(encrypt_drop_frame, 
                                        text="📁 DRAG & DROP FILES HERE\n(or click Browse)\n\n"
                                            "Supports: Any file type",
                                        font=('Segoe UI', 10, 'bold'),
                                        fg=self.accent_color, bg='#1a1f37',
                                        pady=30)
        self.encrypt_drop_label.pack()
        
        # Configure drag and drop for encryption files
        encrypt_drop_frame.drop_target_register('DND_Files')
        encrypt_drop_frame.dnd_bind('<<Drop>>', lambda e: self.handle_file_drop(e, 'encrypt'))
        
        # Browse button for encryption
        encrypt_browse_btn = self.create_styled_button(preview_encrypt_frame, "📁 Browse Files to Encrypt",
                                                    lambda: self.browse_encrypt_files(),
                                                    style='secondary')
        encrypt_browse_btn.pack(pady=(10, 5))
        
        # File info display for encryption
        self.encrypt_file_info = tk.Label(preview_encrypt_frame, 
                                        text="No file selected",
                                        font=self.normal_font, 
                                        fg='#a0a0a0', 
                                        bg=self.section_bg)
        self.encrypt_file_info.pack(pady=(5, 15))
        
        # Password for encryption
        tk.Label(left_frame, text="Encryption Password:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        self.encrypt_password = self.create_styled_entry(left_frame, width=30, show="*")
        self.encrypt_password.pack(anchor='w', padx=15, pady=(0, 15))
        self.encrypt_password.insert(0, "mysecretpassword")
        
        # Encrypt button
        encrypt_btn = self.create_styled_button(left_frame, "🔐 Encrypt File",
                                            self.encrypt_selected_file_cmd)
        encrypt_btn.pack(padx=15, pady=(0, 15))
        
        # ==================== RIGHT COLUMN - DECRYPT ====================
        right_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        right_frame.pack(side='right', fill='both', expand=True, padx=(10, 0), pady=5)
        
        tk.Label(right_frame, text="🔓 Decrypt Files", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        # File Preview area for decryption
        preview_decrypt_frame = tk.Frame(right_frame, bg=self.section_bg)
        preview_decrypt_frame.pack(padx=15, pady=(0, 15), fill='both', expand=True)
        
        tk.Label(preview_decrypt_frame, text="File Preview:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', pady=(0, 5))
        
        # Drag & Drop area for decryption
        decrypt_drop_frame = tk.Frame(preview_decrypt_frame, bg='#1a1f37', relief='ridge', bd=3,
                                    highlightbackground=self.accent_color, highlightthickness=2)
        decrypt_drop_frame.pack(fill='both', expand=True)
        
        self.decrypt_drop_label = tk.Label(decrypt_drop_frame, 
                                        text="📁 DRAG & DROP FILES HERE\n(or click Browse)\n\n"
                                            "Supports: Encrypted files (.bin, .enc)",
                                        font=('Segoe UI', 10, 'bold'),
                                        fg=self.accent_color, bg='#1a1f37',
                                        pady=30)
        self.decrypt_drop_label.pack()
        
        # Configure drag and drop for decryption files
        decrypt_drop_frame.drop_target_register('DND_Files')
        decrypt_drop_frame.dnd_bind('<<Drop>>', lambda e: self.handle_file_drop(e, 'decrypt'))
        
        # Browse button for decryption
        decrypt_browse_btn = self.create_styled_button(preview_decrypt_frame, "📁 Browse Files to Decrypt",
                                                    lambda: self.browse_decrypt_files(),
                                                    style='secondary')
        decrypt_browse_btn.pack(pady=(10, 5))
        
        # File info display for decryption
        self.decrypt_file_info = tk.Label(preview_decrypt_frame, 
                                        text="No file selected",
                                        font=self.normal_font, 
                                        fg='#a0a0a0', 
                                        bg=self.section_bg)
        self.decrypt_file_info.pack(pady=(5, 15))
        
        # Password for decryption
        tk.Label(right_frame, text="Decryption Password:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        self.decrypt_password = self.create_styled_entry(right_frame, width=30, show="*")
        self.decrypt_password.pack(anchor='w', padx=15, pady=(0, 15))
        
        # Button frame for decrypt actions
        button_frame = tk.Frame(right_frame, bg=self.section_bg)
        button_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        # Decrypt button
        decrypt_btn = self.create_styled_button(button_frame, "🔓 Decrypt File",
                                            self.decrypt_selected_file_cmd)
        decrypt_btn.pack(side='left')
        
        # Brute force button
        brute_btn = self.create_styled_button(button_frame, "💥 Brute Force",
                                            self.brute_force_file_cmd, style='secondary')
        brute_btn.pack(side='left', padx=(10, 0))
        
        # ==================== DEDICATED RESULT CONTAINERS ====================
        # Create a container for results at the bottom
        result_container = tk.Frame(tab, bg=self.container_bg)
        result_container.pack(fill='both', expand=True, pady=(20, 0))
        
        # Result tabs for different operations
        result_notebook = ttk.Notebook(result_container)
        result_notebook.pack(fill='both', expand=True)
        
        # Tab 1: Encryption/Decryption Results
        encrypt_decrypt_tab = tk.Frame(result_notebook, bg=self.container_bg)
        result_notebook.add(encrypt_decrypt_tab, text="🔐 Encryption/Decryption Results")
        
        # Encryption/Decryption result frame
        self.file_encrypt_decrypt_result_frame = tk.Frame(encrypt_decrypt_tab, bg='#1a1f37', relief='solid', bd=2,
                                                        highlightbackground=self.accent_color, highlightthickness=2)
        self.file_encrypt_decrypt_result_frame.pack(fill='both', expand=True, pady=(5, 0))
        
        self.file_encrypt_decrypt_result_text = scrolledtext.ScrolledText(self.file_encrypt_decrypt_result_frame, height=10,
                                                                        bg='#0d142e', fg=self.text_color,
                                                                        font=self.mono_font, relief='flat')
        self.file_encrypt_decrypt_result_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Initially show some info
        self.file_encrypt_decrypt_result_text.insert(1.0, "🔐 Encryption & Decryption Results\n\n"
                                                        "Results from file encryption and decryption\n"
                                                        "will appear here.")
        
        # Tab 2: Brute Force Results
        brute_force_tab = tk.Frame(result_notebook, bg=self.container_bg)
        result_notebook.add(brute_force_tab, text="💥 Brute Force Results")
        
        # Brute Force result frame (UNIQUE NAME)
        self.file_brute_force_result_frame = tk.Frame(brute_force_tab, bg='#1a1f37', relief='solid', bd=2,
                                                    highlightbackground='#ff6b6b', highlightthickness=2)
        self.file_brute_force_result_frame.pack(fill='both', expand=True, pady=(5, 0))
        
        self.file_brute_force_result_text = scrolledtext.ScrolledText(self.file_brute_force_result_frame, height=10,
                                                                    bg='#0d142e', fg=self.text_color,
                                                                    font=self.mono_font, relief='flat')
        self.file_brute_force_result_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Initially show some info
        self.file_brute_force_result_text.insert(1.0, "💥 Brute Force Attack Results\n\n"
                                                    "Brute force attack progress and results\n"
                                                    "will appear here.")
        
        # Initialize selected files
        self.selected_encrypt_file = None
        self.selected_decrypt_file = None

    def show_file_encrypt_decrypt_result(self, text, is_error=False):
        """Show encryption/decryption result in dedicated container"""
        # Configure frame appearance
        if is_error:
            self.file_encrypt_decrypt_result_frame.configure(
                bg='#2a1a1a',
                highlightbackground=self.error_color,
                highlightthickness=3
            )
            self.file_encrypt_decrypt_result_text.configure(
                bg='#1a0d0d',
                fg=self.error_color
            )
        else:
            self.file_encrypt_decrypt_result_frame.configure(
                bg='#1a1f37',
                highlightbackground=self.accent_color,
                highlightthickness=3
            )
            self.file_encrypt_decrypt_result_text.configure(
                bg='#0d142e',
                fg=self.text_color
            )
        
        # Clear and insert text
        self.file_encrypt_decrypt_result_text.delete(1.0, tk.END)
        self.file_encrypt_decrypt_result_text.insert(1.0, text)
        
        # Auto-scroll to show the result
        self.file_encrypt_decrypt_result_text.see(1.0)

    def show_file_brute_force_result(self, text, is_error=False):
        """Show brute force result in dedicated container (UNIQUE NAME)"""
        # Configure frame appearance
        if is_error:
            self.file_brute_force_result_frame.configure(
                bg='#2a1a1a',
                highlightbackground=self.error_color,
                highlightthickness=3
            )
            self.file_brute_force_result_text.configure(
                bg='#1a0d0d',
                fg=self.error_color
            )
        else:
            self.file_brute_force_result_frame.configure(
                bg='#1a1f37',
                highlightbackground='#ff6b6b',
                highlightthickness=3
            )
            self.file_brute_force_result_text.configure(
                bg='#0d142e',
                fg=self.text_color
            )
        
        # Clear and insert text
        self.file_brute_force_result_text.delete(1.0, tk.END)
        self.file_brute_force_result_text.insert(1.0, text)
        
        # Auto-scroll to show the result
        self.file_brute_force_result_text.see(1.0)

    # Add these missing methods that are referenced in the tab
    def handle_file_drop(self, event, action_type):
        """Handle drag and drop of files for encryption/decryption with preview"""
        try:
            files = self.root.tk.splitlist(event.data)
            if files:
                file_path = files[0]  # Take first file for preview
                
                if os.path.exists(file_path):
                    # Store the selected file
                    if action_type == 'encrypt':
                        self.selected_encrypt_file = file_path
                        self.update_file_preview(file_path, 'encrypt')
                    else:  # decrypt
                        self.selected_decrypt_file = file_path
                        self.update_file_preview(file_path, 'decrypt')
                    
        except Exception as e:
            print(f"Error handling file drop: {e}")
            if action_type == 'encrypt':
                self.encrypt_drop_label.config(text="❌ Error loading file", fg=self.error_color)
                self.root.after(2000, lambda: self.encrypt_drop_label.config(
                    text="📁 DRAG & DROP FILES HERE\n(or click Browse)\n\n"
                        "Supports: Any file type",
                    fg=self.accent_color
                ))
            else:
                self.decrypt_drop_label.config(text="❌ Error loading file", fg=self.error_color)
                self.root.after(2000, lambda: self.decrypt_drop_label.config(
                    text="📁 DRAG & DROP FILES HERE\n(or click Browse)\n\n"
                        "Supports: Encrypted files (.bin, .enc)",
                    fg=self.accent_color
                ))

    def browse_encrypt_files(self):
        """Browse for a single file to encrypt"""
        filename = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[("All files", "*.*"), ("Documents", "*.txt *.pdf *.docx *.xlsx"), 
                    ("Images", "*.png *.jpg *.jpeg *.bmp"), ("Videos", "*.mp4 *.avi *.mov")]
        )
        
        if filename:
            self.selected_encrypt_file = filename
            self.update_file_preview(filename, 'encrypt')

    def browse_decrypt_files(self):
        """Browse for a single file to decrypt"""
        filename = filedialog.askopenfilename(
            title="Select File to Decrypt",
            filetypes=[("Encrypted files", "*.bin *.enc"), ("All files", "*.*")]
        )
        
        if filename:
            self.selected_decrypt_file = filename
            self.update_file_preview(filename, 'decrypt')

    def update_file_preview(self, file_path, action_type):
        """Show file preview and info"""
        try:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Get file extension and type
            _, ext = os.path.splitext(filename)
            ext = ext.lower()
            
            # Determine file type icon
            if ext in ['.txt', '.pdf', '.doc', '.docx', '.xlsx', '.pptx']:
                icon = "📄"
                file_type = "Document"
            elif ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif']:
                icon = "🖼️"
                file_type = "Image"
            elif ext in ['.mp4', '.avi', '.mov', '.mkv']:
                icon = "🎬"
                file_type = "Video"
            elif ext in ['.mp3', '.wav', '.flac']:
                icon = "🎵"
                file_type = "Audio"
            elif ext in ['.zip', '.rar', '.7z']:
                icon = "📦"
                file_type = "Archive"
            elif ext in ['.bin', '.enc']:
                icon = "🔐"
                file_type = "Encrypted File"
            else:
                icon = "📁"
                file_type = "File"
            
            # Format file size
            if file_size < 1024:
                size_str = f"{file_size} bytes"
            elif file_size < 1024*1024:
                size_str = f"{file_size/1024:.1f} KB"
            elif file_size < 1024*1024*1024:
                size_str = f"{file_size/(1024*1024):.1f} MB"
            else:
                size_str = f"{file_size/(1024*1024*1024):.1f} GB"
            
            # Update drop label
            drop_text = f"{icon} {filename}\n\n"
            drop_text += f"📊 {size_str}\n"
            drop_text += f"📁 {file_type}"
            
            # Update info label
            info_text = f"{icon} {filename}\n"
            info_text += f"📊 {size_str} | {file_type}\n"
            
            # For PDF files, try to extract info
            if ext == '.pdf':
                info_text += f"📄 PDF Document - Ready for encryption"
            
            if action_type == 'encrypt':
                self.encrypt_drop_label.config(text=drop_text, fg=self.success_color)
                self.encrypt_file_info.config(text=info_text, fg=self.text_color)
            else:
                self.decrypt_drop_label.config(text=drop_text, fg=self.success_color)
                self.decrypt_file_info.config(text=info_text, fg=self.text_color)
                
        except Exception as e:
            print(f"Error updating file preview: {e}")
            error_text = "❌ Error loading file\nPlease try another file"
            if action_type == 'encrypt':
                self.encrypt_drop_label.config(text=error_text, fg=self.error_color)
            else:
                self.decrypt_drop_label.config(text=error_text, fg=self.error_color)

    def encrypt_selected_file_cmd(self):
        """Encrypt a single file"""
        if not self.selected_encrypt_file:
            messagebox.showerror("Error", "❌ Please select a file to encrypt first")
            return
        
        password = self.encrypt_password.get().strip()
        if not password:
            messagebox.showerror("Error", "❌ Please enter an encryption password")
            return
        
        # Show processing in result container
        self.show_file_encrypt_decrypt_result("🔒 Encrypting file...\n\nPlease wait while we secure your file...")
        
        def encrypt_thread():
            result = self.file_encrypt_api(self.selected_encrypt_file, password)
            self.root.after(0, lambda: self.update_file_encrypt_result(result))
        
        threading.Thread(target=encrypt_thread, daemon=True).start()

    def update_file_encrypt_result(self, result):
        """Update FILE encryption result in the result container"""
        if result.get("success"):
            filename = os.path.basename(self.selected_encrypt_file)
            output = "✅ FILE ENCRYPTED SUCCESSFULLY!\n\n"
            output += f"📁 Original file: {filename}\n"
            output += f"🔐 Password used: {'*' * len(self.encrypt_password.get().strip())}\n"
            output += f"💾 Encrypted file: {result.get('file_path', 'Unknown')}\n\n"
            output += "🎯 Your file is now protected!\n"
            output += "💡 Use the Decrypt section to restore it."
            
            self.show_file_encrypt_decrypt_result(output)
        else:
            self.show_file_encrypt_decrypt_result(
                f"❌ Encryption Failed!\n\n"
                f"Error: {result.get('error', 'Unknown error')}\n\n"
                f"Please check the file and try again.",
                True
            )

    def decrypt_selected_file_cmd(self):
        """Decrypt a single file"""
        if not self.selected_decrypt_file:
            messagebox.showerror("Error", "❌ Please select a file to decrypt first")
            return
        
        password = self.decrypt_password.get().strip()
        if not password:
            messagebox.showerror("Error", "❌ Please enter a decryption password")
            return
        
        # Show processing in result container
        self.show_file_encrypt_decrypt_result("🔓 Decrypting file...\n\nPlease wait while we restore your file...")
        
        def decrypt_thread():
            result = self.file_decrypt_api(self.selected_decrypt_file, password)
            self.root.after(0, lambda: self.update_file_decrypt_result(result))
        
        threading.Thread(target=decrypt_thread, daemon=True).start()

    def update_file_decrypt_result(self, result):
        """Update FILE decryption result in the result container"""
        if result.get("success"):
            filename = os.path.basename(self.selected_decrypt_file)
            output = "✅ FILE DECRYPTED SUCCESSFULLY!\n\n"
            output += f"📁 Encrypted file: {filename}\n"
            output += f"🔓 Password used: {'*' * len(self.decrypt_password.get().strip())}\n"
            output += f"💾 Decrypted file: {result.get('file_path', 'Unknown')}\n\n"
            output += "🎯 Your file has been restored!\n"
            output += "💡 The file should open automatically."
            
            # Try to open the decrypted file
            try:
                if result.get('file_path'):
                    os.startfile(result['file_path'])
                    output += "\n\n📂 File opened automatically!"
            except:
                output += "\n\n⚠️ Could not open file automatically. Please check the file location."
            
            self.show_file_encrypt_decrypt_result(output)
        else:
            self.show_file_encrypt_decrypt_result(
                f"❌ Decryption Failed!\n\n"
                f"Error: {result.get('error', 'Invalid password or corrupted file')}\n\n"
                f"Please check the password and try again.",
                True
            )

    def brute_force_file_cmd(self):
        """Brute force decryption - shows progress in dedicated brute force container"""
        if not self.selected_decrypt_file:
            self.show_file_brute_force_result("❌ Please select an encrypted file first", True)
            return
        
        # Show initial message in BRUTE FORCE container
        initial_text = "🔍 INITIATING BRUTE FORCE ATTACK\n\n"
        initial_text += f"📁 Target: {os.path.basename(self.selected_decrypt_file)}\n"
        initial_text += f"🕐 Started: {time.strftime('%H:%M:%S')}\n"
        initial_text += "─" * 40 + "\n\n"
        initial_text += "⚡ Loading common passwords database...\n"
        initial_text += "🎯 Preparing attack sequence...\n\n"
        initial_text += "Please wait while we analyze the file..."
        
        self.show_file_brute_force_result(initial_text)
        
        def brute_thread():
            try:
                # Call your existing brute force API
                result = self.file_brute_force_api(self.selected_decrypt_file)
                
                # Show the result in the DEDICATED BRUTE FORCE container
                if result.get("success"):
                    filename = os.path.basename(self.selected_decrypt_file)
                    password = result.get('password', 'Unknown')
                    attempts = result.get('attempts', 0)
                    time_taken = result.get('time_taken', 0)
                    
                    output = "💥 BRUTE FORCE ATTACK SUCCESSFUL!\n\n"
                    output += f"📁 File: {filename}\n"
                    output += f"🔑 Password found: {password}\n"
                    output += f"🎯 Attempts made: {attempts:,}\n"
                    output += f"⏱️ Time taken: {time_taken:.2f} seconds\n\n"
                    output += "✅ File has been successfully decrypted!\n"
                    output += "💾 Check for the decrypted file in the same folder."
                    
                    self.root.after(0, lambda txt=output: self.show_file_brute_force_result(txt))
                else:
                    self.root.after(0, lambda: self.show_file_brute_force_result(
                        f"❌ BRUTE FORCE ATTACK FAILED\n\n"
                        f"📁 File: {os.path.basename(self.selected_decrypt_file)}\n\n"
                        f"Error: {result.get('error', 'Could not find password')}\n\n"
                        f"💡 Try using the Decrypt option with the correct password.",
                        True
                    ))
                    
            except Exception as e:
                self.root.after(0, lambda: self.show_file_brute_force_result(
                    f"❌ BRUTE FORCE ERROR\n\n"
                    f"Error: {str(e)}\n\n"
                    f"Please try again or use a different method.",
                    True
                ))
        
        threading.Thread(target=brute_thread, daemon=True).start()
   
   
   
   
   
   
   
   

   
   
   
       # ==================== TEXT ENCRYPTION TAB ====================
    
    def create_encrypt_tab(self):
        """Create the Text Encryption tab with FIXED result display"""
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Text Encrypt"] = tab
        
        # Title
        title = tk.Label(tab, text="🔐 Text Encryption", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        # Description
        desc = tk.Label(tab, text="Encrypt your text using various cipher methods. Keep your messages safe!",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        # Main content frame
        content = tk.Frame(tab, bg=self.container_bg)
        content.pack(fill='both', expand=True)
        
        # Text input
        tk.Label(content, text="Enter your text:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(anchor='w', pady=(0, 5))
        
        text_frame, self.encrypt_text = self.create_styled_text(content, height=6)
        text_frame.pack(fill='x', pady=(0, 15))
        
        # Cipher selection
        cipher_frame = tk.Frame(content, bg=self.container_bg)
        cipher_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(cipher_frame, text="Select cipher:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left')
        
        self.encrypt_cipher = ttk.Combobox(cipher_frame, values=[
            'caesar', 'reverse', 'atbash', 'vigenere',
            'polybius', 'rot13', 'beaufort',
            'affine', 'morse', 'binary', 'hex', 'ascii'
        ], state='readonly', width=30)
        self.encrypt_cipher.set('caesar')
        self.encrypt_cipher.pack(side='left', padx=(10, 0))
        
        # Key input
        key_frame = tk.Frame(content, bg=self.container_bg)
        key_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(key_frame, text="Encryption key:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left')
        
        self.encrypt_key = self.create_styled_entry(key_frame, width=30)
        self.encrypt_key.pack(side='left', padx=(10, 0))
        
        # Sample text button
        sample_btn = self.create_styled_button(content, "📝 Insert Sample Text", 
                                             self.insert_sample_text, style='secondary')
        sample_btn.pack(pady=(0, 10))
        
        # Encrypt button
        encrypt_btn = self.create_styled_button(content, "🔐 Encrypt Text", self.encrypt_text_cmd)
        encrypt_btn.pack(pady=(10, 0))
        
                
                # RESULT FRAME - FIXED VERSION (UNIQUE NAME!)
        self.text_encrypt_result_container = tk.Frame(content, bg=self.container_bg)
        self.text_encrypt_result_container.pack(fill='x', pady=(15, 0))

        # Create the result frame that will be shown/hidden
        self.text_encrypt_result_frame = tk.Frame(self.text_encrypt_result_container, bg='#1a1f37',
                                                relief='solid', bd=2,
                                                highlightbackground=self.accent_color,
                                                highlightthickness=2)
        self.text_encrypt_result_frame.pack(fill='x', pady=(0, 0))

        # Create the text widget inside the frame
        self.text_encrypt_result_text = scrolledtext.ScrolledText(self.text_encrypt_result_frame, height=8,
                                                                bg='#0d142e', fg=self.text_color,
                                                                font=self.mono_font, relief='flat')
        self.text_encrypt_result_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Initially hide the result frame
        self.text_encrypt_result_frame.pack_forget()
        
    
    def insert_sample_text(self):
        """Insert sample text for testing"""
        sample_text = "Hello! This is a secret message that needs encryption."
        self.encrypt_text.delete(1.0, tk.END)
        self.encrypt_text.insert(1.0, sample_text)
        self.encrypt_key.delete(0, tk.END)
        self.encrypt_key.insert(0, "secret123")
        messagebox.showinfo("Sample Text", "✅ Sample text inserted!\n\nTry encrypting it with Caesar cipher.")
    
    def encrypt_text_cmd(self):
        """Handle text encryption with user-friendly feedback - FIXED VERSION"""
        text = self.encrypt_text.get(1.0, tk.END).strip()
        cipher = self.encrypt_cipher.get()
        key = self.encrypt_key.get().strip()
        
        # Validate input
        if not text:
            self.show_encrypt_result("❌ Please enter some text to encrypt", True)
            return
        
        self.text_encrypt_result_text.delete(1.0, tk.END)

        # Show processing message IMMEDIATELY
        self.show_encrypt_result("🔐 Encrypting your text...\n\nPlease wait while we secure your message...", False)
        
        # Run encryption in background thread
        def encrypt_thread():
            try:
                print(f"📝 Starting encryption: {cipher} with key: {key}")
                result = self.encrypt_text_api(cipher, text, key)
                self.root.after(0, lambda: self.update_encrypt_result(result, text, cipher, key))
            except Exception as e:
                self.root.after(0, lambda: self.show_encrypt_result(
                    f"❌ Encryption error: {str(e)}",
                    True
                ))
        
        threading.Thread(target=encrypt_thread, daemon=True).start()

    def show_encrypt_result(self, text, is_error=False):
        """Show result in TEXT encryption tab - FIXED VERSION"""
        # Configure frame appearance
        if is_error:
            self.text_encrypt_result_frame.configure(
                bg='#2a1a1a',
                highlightbackground=self.error_color,
                highlightthickness=3
            )
            self.text_encrypt_result_text.configure(
                bg='#1a0d0d',
                fg=self.error_color
            )
        else:
            self.text_encrypt_result_frame.configure(
                bg='#1a1f37',
                highlightbackground=self.accent_color,
                highlightthickness=3
            )
            self.text_encrypt_result_text.configure(
                bg='#0d142e',
                fg=self.text_color
            )
        
        # Clear and insert text
        self.text_encrypt_result_text.delete(1.0, tk.END)
        self.text_encrypt_result_text.insert(1.0, text)
        
        # MAKE SURE FRAME IS VISIBLE
        self.text_encrypt_result_frame.pack(fill='x', pady=(0, 0))
        
        # Auto-scroll to show the result
        self.text_encrypt_result_text.see(1.0)
        
        # Force update to show immediately
        self.text_encrypt_result_frame.update_idletasks()
        
        print(f"✅ Text encrypt result frame shown: {len(text)} characters")
        
    def update_encrypt_result(self, result, original_text, cipher, key):
        """Update the encryption result display - FIXED VERSION"""
        print(f"📊 Encryption result received: {result.get('success')}")
        
        if result.get("success"):
            encrypted_text = result['result']
            
            # Create beautiful output
            output = "✅ TEXT ENCRYPTED SUCCESSFULLY!\n"
            output += "=" * 60 + "\n\n"
            output += f"📝 Your Original Text:\n"
            output += f"   '{original_text[:50]}{'...' if len(original_text) > 50 else ''}'\n\n"
            output += f"🔐 Encryption Details:\n"
            output += f"   Method: {cipher.upper()}\n"
            output += f"   Key used: '{key if key else 'No key required'}'\n"
            output += f"   Text length: {len(original_text)} characters\n\n"
            output += f"🔒 Encrypted Result:\n"
            output += "─" * 40 + "\n"
            output += f"{encrypted_text}\n"
            output += "─" * 40 + "\n\n"
            output += f"📋 Copied to clipboard! Ready to share securely.\n"
            output += f"💡 Use the Decryption tab to get your text back."
            
            # Copy to clipboard
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(encrypted_text)
                print("📋 Copied to clipboard")
            except:
                output += "\n\n⚠️ Could not copy to clipboard"
            
            self.show_encrypt_result(output)
            
            # Show success message
            messagebox.showinfo("Encryption Successful", 
                              f"✅ Your text has been encrypted!\n\n"
                              f"Method: {cipher.upper()}\n"
                              f"Key: {key if key else 'None'}\n\n"
                              f"The result is displayed below and copied to clipboard.")
            
        else:
            error_msg = "❌ ENCRYPTION FAILED\n\n"
            error_msg += f"Error: {result.get('error', 'Unknown error')}\n\n"
            error_msg += "💡 Suggestions:\n"
            error_msg += "• Try a different cipher type\n"
            error_msg += "• Check your key format\n"
            error_msg += "• Some ciphers work only with specific characters\n"
            error_msg += "• Try Caesar cipher with key '3' for testing"
            
            self.show_encrypt_result(error_msg, True)
            
            # Show error message
            messagebox.showerror("Encryption Failed", 
                               f"❌ Could not encrypt your text.\n\n"
                               f"Error: {result.get('error', 'Unknown error')}")

    # ==================== TEXT DECRYPTION TAB ====================
    
    def create_decrypt_tab(self):
        """Create the Text Decryption tab with FIXED result display"""
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Text Decrypt"] = tab
        
        title = tk.Label(tab, text="🔓 Text Decryption", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        desc = tk.Label(tab, text="Decrypt encrypted text back to readable form. Need the correct cipher and key!",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        content = tk.Frame(tab, bg=self.container_bg)
        content.pack(fill='both', expand=True)
        
        # Text input
        tk.Label(content, text="Enter encrypted text:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(anchor='w', pady=(0, 5))
        
        text_frame, self.decrypt_text = self.create_styled_text(content, height=6)
        text_frame.pack(fill='x', pady=(0, 15))
        
        # Cipher selection
        cipher_frame = tk.Frame(content, bg=self.container_bg)
        cipher_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(cipher_frame, text="Select cipher:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left')
        
        self.decrypt_cipher = ttk.Combobox(cipher_frame, values=[
            'caesar', 'reverse', 'atbash', 'vigenere',
            'polybius', 'rot13', 'beaufort',
            'affine', 'morse', 'binary', 'hex', 'ascii'
        ], state='readonly', width=30)
        self.decrypt_cipher.set('caesar')
        self.decrypt_cipher.pack(side='left', padx=(10, 0))
        
        # Key input
        key_frame = tk.Frame(content, bg=self.container_bg)
        key_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(key_frame, text="Decryption key:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left')
        
        self.decrypt_key = self.create_styled_entry(key_frame, width=30)
        self.decrypt_key.pack(side='left', padx=(10, 0))
        
        # Sample encrypted text button
        sample_btn = self.create_styled_button(content, "📝 Insert Sample Encrypted", 
                                             self.insert_sample_encrypted, style='secondary')
        sample_btn.pack(pady=(0, 10))
        
        # Decrypt button
        decrypt_btn = self.create_styled_button(content, "🔓 Decrypt Text", self.decrypt_text_cmd)
        decrypt_btn.pack(pady=(10, 0))
        
        # RESULT FRAME - FIXED VERSION
        self.decrypt_result_container = tk.Frame(content, bg=self.container_bg)
        self.decrypt_result_container.pack(fill='x', pady=(15, 0))
        
        # Create the result frame that will be shown/hidden
        self.decrypt_result_frame = tk.Frame(self.decrypt_result_container, bg='#1a1f37',
                                           relief='solid', bd=2,
                                           highlightbackground=self.accent_color,
                                           highlightthickness=2)
        self.decrypt_result_frame.pack(fill='x', pady=(0, 0))
        
        # Create the text widget inside the frame
        self.decrypt_result_text = scrolledtext.ScrolledText(self.decrypt_result_frame, height=8,
                                                           bg='#0d142e', fg=self.text_color,
                                                           font=self.mono_font, relief='flat')
        self.decrypt_result_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Initially hide the result frame
        self.decrypt_result_frame.pack_forget()
    
    def insert_sample_encrypted(self):
        """Insert sample encrypted text for testing"""
        sample_encrypted = "Khoor#Wklv#lv#d#vfuhw#phvvdjh#wkdw#qhhgv#hqfubswlrq1"
        self.decrypt_text.delete(1.0, tk.END)
        self.decrypt_text.insert(1.0, sample_encrypted)
        self.decrypt_key.delete(0, tk.END)
        self.decrypt_key.insert(0, "3")
        self.decrypt_cipher.set('caesar')
        messagebox.showinfo("Sample Encrypted", "✅ Sample encrypted text inserted!\n\n"
                                               "Try decrypting it with Caesar cipher and key '3'.")
    
    def decrypt_text_cmd(self):
        """Handle text decryption with FIXED result display"""
        text = self.decrypt_text.get(1.0, tk.END).strip()
        cipher = self.decrypt_cipher.get()
        key = self.decrypt_key.get().strip()
        
        if not text:
            self.show_decrypt_result("❌ Please enter text to decrypt", True)
            return
        
        # Clear any previous result
        self.decrypt_result_text.delete(1.0, tk.END)
        
        # Show processing message IMMEDIATELY
        self.show_decrypt_result(f"🔓 Decrypting with {cipher.upper()}...\n\nPlease wait...", False)
        
        # Run in thread
        def decrypt_thread():
            result = self.decrypt_text_api(cipher, text, key)
            self.root.after(0, lambda: self.update_decrypt_result(result, cipher))
        
        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    def show_decrypt_result(self, text, is_error=False):
        """Show result in decryption tab - FIXED VERSION"""
        # Configure frame appearance
        if is_error:
            self.decrypt_result_frame.configure(bg='#2a1a1a',
                                               highlightbackground=self.error_color,
                                               highlightthickness=3)
            self.decrypt_result_text.configure(bg='#1a0d0d',
                                             fg=self.error_color)
        else:
            self.decrypt_result_frame.configure(bg='#1a1f37',
                                               highlightbackground=self.accent_color,
                                               highlightthickness=3)
            self.decrypt_result_text.configure(bg='#0d142e',
                                             fg=self.text_color)
        
        # Clear and insert text
        self.decrypt_result_text.delete(1.0, tk.END)
        self.decrypt_result_text.insert(1.0, text)
        
        # MAKE SURE FRAME IS VISIBLE
        self.decrypt_result_frame.pack(fill='x', pady=(0, 0))
        
        # Auto-scroll to show the result
        self.decrypt_result_text.see(1.0)
        
        # Force update to show immediately
        self.decrypt_result_frame.update_idletasks()
    
    def update_decrypt_result(self, result, cipher):
        """Update decryption result - FIXED VERSION"""
        if result.get("success"):
            decrypted_text = result['result']
            
            output = "✅ TEXT DECRYPTED SUCCESSFULLY!\n"
            output += "=" * 60 + "\n\n"
            output += f"🔓 Decryption Details:\n"
            output += f"   Method: {cipher.upper()}\n"
            output += f"   Key used: '{self.decrypt_key.get().strip() if self.decrypt_key.get().strip() else 'No key'}'\n\n"
            output += f"📝 Decrypted Text:\n"
            output += "─" * 40 + "\n"
            output += f"{decrypted_text}\n"
            output += "─" * 40 + "\n\n"
            output += f"📋 Copied to clipboard!\n"
            output += f"🎉 Your message is now readable."
            
            # Copy to clipboard
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(decrypted_text)
            except:
                output += "\n\n⚠️ Could not copy to clipboard"
            
            self.show_decrypt_result(output)
            
            # Show success message
            messagebox.showinfo("Decryption Successful", 
                              f"✅ Text decrypted successfully!\n\n"
                              f"Method: {cipher.upper()}\n"
                              f"Key: {self.decrypt_key.get().strip()}\n\n"
                              f"The result is displayed below and copied to clipboard.")
            
        else:
            error_msg = "❌ DECRYPTION FAILED\n\n"
            error_msg += f"Error: {result.get('error', 'Unknown error')}\n\n"
            error_msg += "💡 Suggestions:\n"
            error_msg += "• Check if cipher type is correct\n"
            error_msg += "• Verify the decryption key\n"
            error_msg += "• Make sure the text is actually encrypted\n"
            error_msg += "• Try Caesar cipher with key '3' for sample text"
            
            self.show_decrypt_result(error_msg, True)
            
            # Show error message
            messagebox.showerror("Decryption Failed", 
                               f"❌ Could not decrypt the text.\n\n"
                               f"Error: {result.get('error', 'Unknown error')}")
   
   
   
   
 
    def create_crack_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Crack Classic"] = tab
        
        title = tk.Label(tab, text="Crack Classic Ciphers", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        content = tk.Frame(tab, bg=self.container_bg)
        content.pack(fill='both', expand=True)
        
        tk.Label(content, text="Enter Encrypted Text:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(anchor='w', pady=(0, 5))
        
        text_frame, self.crack_text = self.create_styled_text(content, height=6)
        text_frame.pack(fill='x', pady=(0, 15))
        
        crack_btn = self.create_styled_button(content, "Auto Crack Cipher", self.crack_cipher_cmd)
        crack_btn.pack(pady=(10, 0))
        
        self.crack_result_frame, self.crack_result_text = self.create_result_frame(content)
        
    def crack_cipher_cmd(self):
        text = self.crack_text.get(1.0, tk.END).strip()
        
        if not text:
            self.show_result(self.crack_result_frame, self.crack_result_text,
                           "Please enter text to crack", True)
            return
            
        result = self.auto_crack_api(text)
        
        if result.get("success"):
            results = result.get("results", [])
            output = "Results:\n\n"
            for i, res in enumerate(results[:5], 1):
                output += f"{i}. {res['cipher']} (Score: {res['score']})\n{res['text']}\n{'-'*50}\n"
            
            self.show_result(self.crack_result_frame, self.crack_result_text, output)
        else:
            self.show_result(self.crack_result_frame, self.crack_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    def create_hash_crack_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Hash Cracking"] = tab
        
        title = tk.Label(tab, text="🔍 Hash Cracking", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        main_frame = tk.Frame(tab, bg=self.container_bg)
        main_frame.pack(fill='both', expand=True)
        
        left_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10), pady=5)
        
        tk.Label(left_frame, text="Generate Hash", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(left_frame, text="Text to Hash:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        text_frame, self.hash_text = self.create_styled_text(left_frame, height=3)
        text_frame.pack(fill='x', padx=15, pady=(0, 10))
        
        algo_frame = tk.Frame(left_frame, bg=self.section_bg)
        algo_frame.pack(fill='x', padx=15, pady=(0, 10))
        
        tk.Label(algo_frame, text="Hash Algorithm:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(side='left')
        
        self.hash_type = ttk.Combobox(algo_frame, values=['md5', 'sha1', 'sha256', 'sha512'],
                                     state='readonly', width=15)
        self.hash_type.set('md5')
        self.hash_type.pack(side='left', padx=(10, 0))
        
        generate_btn = self.create_styled_button(left_frame, "Generate Hash", self.generate_hash_cmd)
        generate_btn.pack(padx=15, pady=(0, 15))
        
        self.hash_result_frame, self.hash_result_text = self.create_result_frame(left_frame)
        
        right_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        right_frame.pack(side='right', fill='both', expand=True, padx=(10, 0), pady=5)
        
        tk.Label(right_frame, text="Crack Hash", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(right_frame, text="Hash to Crack:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        text_frame2, self.crack_hash_input = self.create_styled_text(right_frame, height=3)
        text_frame2.pack(fill='x', padx=15, pady=(0, 10))
        
        hash_type_frame = tk.Frame(right_frame, bg=self.section_bg)
        hash_type_frame.pack(fill='x', padx=15, pady=(0, 10))
        
        tk.Label(hash_type_frame, text="Hash Type:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(side='left')
        
        self.crack_hash_type = ttk.Combobox(hash_type_frame, 
                                           values=['auto', 'md5', 'sha1', 'sha256', 'sha512'],
                                           state='readonly', width=15)
        self.crack_hash_type.set('auto')
        self.crack_hash_type.pack(side='left', padx=(10, 0))
        
        crack_btn = self.create_styled_button(right_frame, "Crack Hash", 
                                            self.crack_hash_cmd, style='danger')
        crack_btn.pack(padx=15, pady=(0, 15))
        
        self.crack_hash_result_frame, self.crack_hash_result_text = self.create_result_frame(right_frame)
        
        history_frame = tk.Frame(tab, bg=self.section_bg, relief='solid', bd=1)
        history_frame.pack(fill='x', pady=(10, 0))
        
        tk.Label(history_frame, text="Hash History", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        history_btn = self.create_styled_button(history_frame, "Load Hash Operations",
                                              self.load_hash_history_cmd, style='secondary')
        history_btn.pack(padx=15, pady=(0, 10))
        
        text_frame3, self.hash_history_text = self.create_styled_text(history_frame, height=8)
        text_frame3.pack(fill='both', expand=True, padx=15, pady=(0, 15))
    
    def generate_hash_cmd(self):
        text = self.hash_text.get(1.0, tk.END).strip()
        hash_type = self.hash_type.get()
        
        if not text:
            self.show_result(self.hash_result_frame, self.hash_result_text,
                           "Please enter text to hash", True)
            return
            
        result = self.hash_text_api(text, hash_type)
        
        if result.get("success"):
            self.show_result(self.hash_result_frame, self.hash_result_text,
                           f"{hash_type.upper()} Hash:\n{result['hash_value']}")
        else:
            self.show_result(self.hash_result_frame, self.hash_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    def crack_hash_cmd(self):
        hash_value = self.crack_hash_input.get(1.0, tk.END).strip()
        hash_type = self.crack_hash_type.get()
        
        if not hash_value:
            self.show_result(self.crack_hash_result_frame, self.crack_hash_result_text,
                           "Please enter a hash to crack", True)
            return
            
        self.show_result(self.crack_hash_result_frame, self.crack_hash_result_text,
                        "🔍 Starting hash cracking... This may take a few seconds.")
        
        def crack_thread():
            result = self.crack_hash_api(hash_value, hash_type, timeout=30)
            self.root.after(0, self.update_crack_hash_result, result)
        
        threading.Thread(target=crack_thread, daemon=True).start()
    
    def update_crack_hash_result(self, result):
        if result.get("success"):
            crack_result = result.get("result", {})
            if crack_result.get("success"):
                output = f"✅ HASH CRACKED SUCCESSFULLY!\n\n"
                output += f"Method: {crack_result.get('method', 'Unknown')}\n"
                output += f"Password: {crack_result.get('password', 'Unknown')}\n"
                output += f"Attempts: {crack_result.get('attempts', 0)}\n"
                output += f"Time Taken: {crack_result.get('time_taken', 0):.2f} seconds"
                
                self.show_result(self.crack_hash_result_frame, self.crack_hash_result_text, output)
            else:
                self.show_result(self.crack_hash_result_frame, self.crack_hash_result_text,
                               f"❌ Hash not cracked\n\n"
                               f"Attempts: {crack_result.get('attempts', 0)}\n"
                               f"Time Taken: {crack_result.get('time_taken', 0):.2f} seconds\n"
                               f"Message: {crack_result.get('message', 'Unknown')}", True)
        else:
            self.show_result(self.crack_hash_result_frame, self.crack_hash_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    def load_hash_history_cmd(self):
        result = self.get_hash_history_api(limit=20)
        
        if result.get("success"):
            hash_history = result.get("hash_history", [])
            self.update_hash_history_text(hash_history)
        else:
            self.hash_history_text.delete(1.0, tk.END)
            self.hash_history_text.insert(1.0, f"Error: {result.get('error', 'Unknown error')}")
    
    def update_hash_history_text(self, hash_history):
        self.hash_history_text.delete(1.0, tk.END)
        
        if not hash_history:
            self.hash_history_text.insert(1.0, "No hash operations found in database")
            return
        
        hash_history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        for op in hash_history:
            timestamp = op.get('timestamp', 'Unknown date')
            hash_type = op.get('hash_type', 'UNKNOWN').upper()
            
            is_generation = op.get('original_text') and not op.get('cracked_text')
            is_successful_crack = op.get('cracked') or op.get('cracked_text')
            
            if is_generation:
                status = "🔗 HASH GENERATED"
                status_color = "#ffaa00"
                operation_type = "Generation"
            elif is_successful_crack:
                status = "✅ HASH CRACKED"
                status_color = "#00ff88"
                operation_type = "Cracking"
            else:
                status = "❌ CRACK FAILED"
                status_color = "#ff4444"
                operation_type = "Cracking"
            
            self.hash_history_text.insert(tk.END, f"{timestamp}\n")
            self.hash_history_text.insert(tk.END, f"{hash_type} - {status}\n")
            self.hash_history_text.insert(tk.END, f"Operation: {operation_type}\n")
            
            if is_generation:
                self.hash_history_text.insert(tk.END, f"Original Text: {op['original_text']}\n")
                self.hash_history_text.insert(tk.END, f"Generated Hash: {op['hash_value']}\n")
            else:
                self.hash_history_text.insert(tk.END, f"Target Hash: {op['hash_value']}\n")
                if is_successful_crack:
                    self.hash_history_text.insert(tk.END, f"Cracked Text: {op['cracked_text']}\n")
            
            if not is_generation and op.get('attempts_made', 0) > 0:
                self.hash_history_text.insert(tk.END, f"Attempts: {op['attempts_made']}\n")
            
            if not is_generation and op.get('crack_time', 0) > 0:
                self.hash_history_text.insert(tk.END, f"Time: {op['crack_time']:.2f}s\n")
            
            self.hash_history_text.insert(tk.END, "-" * 50 + "\n\n")
    
    def create_auto_crack_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Auto Crack Modern"] = tab
        
        title = tk.Label(tab, text="Auto Crack Modern Cryptography", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        desc = tk.Label(tab, text="Automatically detect and decrypt AES-GCM and Base64 without knowing the password or cipher type.",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        content = tk.Frame(tab, bg=self.container_bg)
        content.pack(fill='both', expand=True)
        
        tk.Label(content, text="Enter Encrypted Text:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(anchor='w', pady=(0, 5))
        
        text_frame, self.modern_crack_text = self.create_styled_text(content, height=6)
        text_frame.pack(fill='x', pady=(0, 15))
        
        crack_btn = self.create_styled_button(content, "Auto Detect & Crack", self.auto_crack_modern_cmd)
        crack_btn.pack(pady=(10, 0))
        
        self.modern_crack_result_frame, self.modern_crack_result_text = self.create_result_frame(content)
    
    def auto_crack_modern_cmd(self):
        text = self.modern_crack_text.get(1.0, tk.END).strip()
        
        if not text:
            self.show_result(self.modern_crack_result_frame, self.modern_crack_result_text,
                           "Please enter text to crack", True)
            return
            
        self.show_result(self.modern_crack_result_frame, self.modern_crack_result_text,
                        "🚀 Attempting to crack modern cryptography... This may take a moment...")
        
        def crack_thread():
            result = self.auto_crack_modern_api(text)
            self.root.after(0, self.update_auto_crack_result, result)
        
        threading.Thread(target=crack_thread, daemon=True).start()
    
    def update_auto_crack_result(self, result):
        if result.get("success"):
            results = result.get("results", [])
            if results:
                output = "Cracking Results:\n\n"
                for i, res in enumerate(results, 1):
                    output += f"{i}. {res['cipher']} (Confidence: {res['confidence']})\n"
                    if res.get('password'):
                        output += f"   Password: {res['password']}\n"
                    output += f"   Score: {res.get('score', 0):.2f}\n"
                    output += f"   {res['text']}\n"
                    output += "-" * 50 + "\n"
                
                self.show_result(self.modern_crack_result_frame, self.modern_crack_result_text, output)
            else:
                self.show_result(self.modern_crack_result_frame, self.modern_crack_result_text,
                               "No encryption methods detected or could not crack the text.", True)
        else:
            self.show_result(self.modern_crack_result_frame, self.modern_crack_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)

    
    
        
    def create_image_steg_tab(self):
        """Enhanced Image Steganography Tab with preview"""
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Image Steg"] = tab
        
        title = tk.Label(tab, text="🖼️ Image Steganography", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        # Description
        desc = tk.Label(tab, text="Hide secret messages inside images. Drag & drop any image to preview it.",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        # Main content
        main_frame = tk.Frame(tab, bg=self.container_bg)
        main_frame.pack(fill='both', expand=True)
        
        # Left column - Image preview
        left_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10), pady=5)
        
        tk.Label(left_frame, text="📸 Image Preview", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        # Drag & Drop area for images
        image_drop_frame = tk.Frame(left_frame, bg='#1a1f37', relief='ridge', bd=3,
                                   highlightbackground=self.accent_color, highlightthickness=2)
        image_drop_frame.pack(padx=15, pady=(0, 10), fill='both', expand=True)
        
        self.image_drop_label = tk.Label(image_drop_frame, 
                                        text="🖼️ DRAG & DROP IMAGE HERE\n(or click Browse)\n\n"
                                             "Supports: PNG, JPG, JPEG, BMP",
                                        font=('Segoe UI', 10, 'bold'),
                                        fg=self.accent_color, bg='#1a1f37',
                                        pady=30)
        self.image_drop_label.pack()
        
        # Configure drag and drop for images
        image_drop_frame.drop_target_register('DND_Files')
        image_drop_frame.dnd_bind('<<Drop>>', self.handle_image_drop)
        
        # Browse button
        browse_btn = self.create_styled_button(left_frame, "📁 Browse Images",
                                             lambda: self.browse_image_file(),
                                             style='secondary')
        browse_btn.pack(padx=15, pady=(10, 15))
        
        # Image info display
        self.image_info_label = tk.Label(left_frame, text="No image selected",
                                        font=self.normal_font, fg='#a0a0a0', bg=self.section_bg)
        self.image_info_label.pack(padx=15, pady=(0, 10))
        
        # Right column - Hide/Extract
        right_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        right_frame.pack(side='right', fill='both', expand=True, padx=(10, 0), pady=5)
        
        # Hide Message section
        hide_frame = tk.Frame(right_frame, bg=self.section_bg)
        hide_frame.pack(fill='x', padx=15, pady=(15, 20))
        
        tk.Label(hide_frame, text="📝 Hide Message in Image", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', pady=(0, 10))
        
        tk.Label(hide_frame, text="Secret Message:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', pady=(0, 5))
        
        text_frame, self.steg_message = self.create_styled_text(hide_frame, height=4)
        text_frame.pack(fill='x', pady=(0, 10))
        
        hide_btn = self.create_styled_button(hide_frame, "🔒 Hide Message",
                                           self.encode_image_cmd)
        hide_btn.pack(pady=(0, 15))
        
        # Extract Message section
        extract_frame = tk.Frame(right_frame, bg=self.section_bg)
        extract_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        tk.Label(extract_frame, text="🔍 Extract Hidden Message", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', pady=(0, 10))
        
        extract_btn = self.create_styled_button(extract_frame, "🔓 Extract Message",
                                              self.decode_image_cmd, style='secondary')
        extract_btn.pack(pady=(0, 10))
        
        # Result frame
        self.image_steg_result_frame, self.image_steg_result_text = self.create_result_frame(right_frame)
    
    def handle_image_drop(self, event):
        """Handle drag and drop of images"""
        try:
            files = self.root.tk.splitlist(event.data)
            for file_path in files:
                if os.path.exists(file_path) and file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
                    # Update label
                    self.image_drop_label.config(
                        text=f"🖼️ {os.path.basename(file_path)}\n\n"
                             f"📊 {os.path.getsize(file_path):,} bytes",
                        fg=self.success_color
                    )
                    
                    # Store selected image
                    self.selected_files['image_steg'] = file_path
                    
                    # Show image info
                    self.image_info_label.config(
                        text=f"📁 {os.path.basename(file_path)}\n"
                             f"📊 {os.path.getsize(file_path):,} bytes\n"
                             f"📁 Ready for steganography",
                        fg=self.text_color
                    )
                    
                    # Try to preview image
                    self.preview_image_thumbnail(file_path)
                    
        except Exception as e:
            self.image_drop_label.config(text="❌ Error loading image", fg=self.error_color)
            self.root.after(2000, lambda: self.image_drop_label.config(
                text="🖼️ DRAG & DROP IMAGE HERE\n(or click Browse)\n\n"
                     "Supports: PNG, JPG, JPEG, BMP",
                fg=self.accent_color
            ))
    
    def browse_image_file(self):
        """Browse for image file"""
        filename = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")]
        )
        
        if filename:
            self.image_drop_label.config(
                text=f"🖼️ {os.path.basename(filename)}\n\n"
                     f"📊 {os.path.getsize(filename):,} bytes",
                fg=self.success_color
            )
            
            self.selected_files['image_steg'] = filename
            
            self.image_info_label.config(
                text=f"📁 {os.path.basename(filename)}\n"
                     f"📊 {os.path.getsize(filename):,} bytes\n"
                     f"📁 Ready for steganography",
                fg=self.text_color
            )
            
            self.preview_image_thumbnail(filename)
    
    def preview_image_thumbnail(self, image_path):
        """Show image thumbnail preview"""
        try:
            # Try to import PIL for image preview
            from PIL import Image, ImageTk
            
            # Open and resize image
            img = Image.open(image_path)
            img.thumbnail((300, 300))  # Resize to max 300x300
            
            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(img)
            
            # Update label with image
            self.image_drop_label.config(image=photo, compound='top')
            self.image_drop_label.image = photo  # Keep reference
            
        except ImportError:
            # PIL not available, show text info only
            self.image_drop_label.config(
                text=f"🖼️ {os.path.basename(image_path)}\n\n"
                     f"📊 {os.path.getsize(image_path):,} bytes\n\n"
                     f"(Install PIL/Pillow for image preview)",
                fg=self.accent_color
            )
        except Exception as e:
            print(f"⚠️ Could not preview image: {e}")
            # Fallback to text display
    
    def encode_image_cmd(self):
        """Encode message in image"""
        if 'image_steg' not in self.selected_files:
            messagebox.showerror("Error", "❌ Please select an image file first")
            return
            
        message = self.steg_message.get(1.0, tk.END).strip()
        if not message:
            messagebox.showerror("Error", "❌ Please enter a secret message")
            return
        
        # Show processing
        self.show_result(self.image_steg_result_frame, self.image_steg_result_text,
                        "🔒 Hiding your message in the image...\nPlease wait...")
        
        def encode_thread():
            result = self.image_hide_api(self.selected_files['image_steg'], message)
            self.root.after(0, lambda: self.update_encode_result(result))
        
        threading.Thread(target=encode_thread, daemon=True).start()
    
    def update_encode_result(self, result):
        """Update image encoding result"""
        if result.get("success"):
            output = "✅ MESSAGE HIDDEN SUCCESSFULLY!\n\n"
            output += f"📁 Original image: {os.path.basename(self.selected_files['image_steg'])}\n"
            output += f"📝 Message length: {len(self.steg_message.get(1.0, tk.END).strip())} characters\n"
            output += f"💾 Saved as: {result['file_path']}\n\n"
            output += f"🎯 Your secret is now hidden in the image!\n"
            output += f"💡 Use 'Extract Message' to get it back."
            
            self.show_result(self.image_steg_result_frame, self.image_steg_result_text, output)
        else:
            self.show_result(self.image_steg_result_frame, self.image_steg_result_text,
                           f"❌ Error: {result.get('error', 'Unknown error')}", True)
    
    def decode_image_cmd(self):
        """Decode message from image"""
        if 'image_steg' not in self.selected_files:
            self.show_result(self.image_steg_result_frame, self.image_steg_result_text,
                           "❌ Please select an image file first", True)
            return
        
        # Show processing
        self.show_result(self.image_steg_result_frame, self.image_steg_result_text,
                        "🔍 Extracting hidden message from image...\nPlease wait...")
        
        def decode_thread():
            result = self.image_extract_api(self.selected_files['image_steg'])
            self.root.after(0, lambda: self.update_decode_result(result))
        
        threading.Thread(target=decode_thread, daemon=True).start()
    
    def update_decode_result(self, result):
        """Update image decoding result"""
        if result.get("success"):
            message = result['message']
            
            output = "✅ HIDDEN MESSAGE FOUND!\n\n"
            output += f"📁 Image: {os.path.basename(self.selected_files['image_steg'])}\n"
            output += f"📝 Message length: {len(message)} characters\n\n"
            output += "🔍 Hidden Message:\n"
            output += "─" * 40 + "\n"
            output += f"{message}\n"
            output += "─" * 40 + "\n\n"
            output += f"📋 Copied to clipboard!"
            
            # Copy to clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(message)
            
            self.show_result(self.image_steg_result_frame, self.image_steg_result_text, output)
        else:
            self.show_result(self.image_steg_result_frame, self.image_steg_result_text,
                           f"❌ No hidden message found: {result.get('error', 'Unknown error')}", True)
    

    def create_audio_steg_tab(self):
            tab = tk.Frame(self.main_frame, bg=self.container_bg)
            self.tab_contents["Audio Steg"] = tab
            
            title = tk.Label(tab, text="Audio Steganography", font=self.heading_font,
                            fg=self.accent_color, bg=self.container_bg)
            title.pack(anchor='w', pady=(0, 20))
            
            main_frame = tk.Frame(tab, bg=self.container_bg)
            main_frame.pack(fill='both', expand=True)
            
            left_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
            left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10), pady=5)
            
            tk.Label(left_frame, text="Hide Message in Audio", font=self.subheading_font,
                    fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
            
            select_btn = self.create_styled_button(left_frame, "🎵 Select Audio File",
                                                lambda: self.select_audio_file('encode'), style='secondary')
            select_btn.pack(padx=15, pady=(0, 10))
            
            self.encode_audio_label = tk.Label(left_frame, text="No file selected", 
                                            font=self.normal_font, fg='#a0a0a0', bg=self.section_bg)
            self.encode_audio_label.pack(padx=15, pady=(0, 10))
            
            tk.Label(left_frame, text="Secret Message:", font=self.normal_font,
                    fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
            
            text_frame, self.encode_audio_message = self.create_styled_text(left_frame, height=3)
            text_frame.pack(fill='x', padx=15, pady=(0, 15))
            
            encode_btn = self.create_styled_button(left_frame, "Hide Message in Audio", self.encode_audio_cmd)
            encode_btn.pack(padx=15, pady=(0, 15))
            
            right_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
            right_frame.pack(side='right', fill='both', expand=True, padx=(10, 0), pady=5)
            
            tk.Label(right_frame, text="Extract Message from Audio", font=self.subheading_font,
                    fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
            
            select_btn2 = self.create_styled_button(right_frame, "🎵 Select Audio File",
                                                lambda: self.select_audio_file('decode'), style='secondary')
            select_btn2.pack(padx=15, pady=(0, 10))
            
            self.decode_audio_label = tk.Label(right_frame, text="No file selected", 
                                            font=self.normal_font, fg='#a0a0a0', bg=self.section_bg)
            self.decode_audio_label.pack(padx=15, pady=(0, 10))
            
            decode_btn = self.create_styled_button(right_frame, "Extract Message", self.decode_audio_cmd)
            decode_btn.pack(padx=15, pady=(0, 15))
            
            self.audio_result_frame, self.audio_result_text = self.create_result_frame(right_frame)
        
    def select_audio_file(self, mode):
        filename = self.select_file("Audio", f"audio_{mode}", "*.mp3 *.wav *.ogg")
        if filename:
            if mode == 'encode':
                self.encode_audio_label.configure(text=os.path.basename(filename))
            else:
                self.decode_audio_label.configure(text=os.path.basename(filename))
    
    def encode_audio_cmd(self):
        if 'audio_encode' not in self.selected_files:
            messagebox.showerror("Error", "Please select an audio file")
            return
            
        message = self.encode_audio_message.get(1.0, tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a secret message")
            return
            
        result = self.audio_hide_api(self.selected_files['audio_encode'], message)
        
        if result.get("success"):
            download_path = result['file_path']
            messagebox.showinfo("Success", f"Message hidden successfully!\nFile saved as: {download_path}")
        else:
            messagebox.showerror("Error", f"Error encoding audio: {result.get('error', 'Unknown error')}")
    
    def decode_audio_cmd(self):
        if 'audio_decode' not in self.selected_files:
            self.show_result(self.audio_result_frame, self.audio_result_text,
                           "Please select an audio file", True)
            return
            
        result = self.audio_extract_api(self.selected_files['audio_decode'])
        
        if result.get("success"):
            self.show_result(self.audio_result_frame, self.audio_result_text,
                           f"Hidden Message:\n{result['message']}")
        else:
            self.show_result(self.audio_result_frame, self.audio_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    
    
    
    
    def create_modern_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Modern Crypto"] = tab
        
        title = tk.Label(tab, text="Modern Cryptography & Utilities", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        main_frame = tk.Frame(tab, bg=self.container_bg)
        main_frame.pack(fill='both', expand=True)
        
        col1 = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        col1.pack(side='left', fill='both', expand=True, padx=(0, 10), pady=5)
        
        tk.Label(col1, text="AES-GCM Encryption", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(col1, text="Text to Encrypt:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        text_frame1, self.aes_text = self.create_styled_text(col1, height=3)
        text_frame1.pack(fill='x', padx=15, pady=(0, 10))
        
        tk.Label(col1, text="Password:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        self.aes_password = self.create_styled_entry(col1, width=20, show="*")
        self.aes_password.pack(anchor='w', padx=15, pady=(0, 15))
        
        button_frame1 = tk.Frame(col1, bg=self.section_bg)
        button_frame1.pack(fill='x', padx=15, pady=(0, 15))
        
        aes_encrypt_btn = self.create_styled_button(button_frame1, "Encrypt", self.aes_encrypt_cmd)
        aes_encrypt_btn.pack(side='left')
        
        aes_decrypt_btn = self.create_styled_button(button_frame1, "Decrypt", self.aes_decrypt_cmd, style='secondary')
        aes_decrypt_btn.pack(side='left', padx=(10, 0))
        
        self.aes_result_frame, self.aes_result_text = self.create_result_frame(col1)
        
        col2 = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        col2.pack(side='left', fill='both', expand=True, padx=10, pady=5)
        
        tk.Label(col2, text="Base64 Encoding", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(col2, text="Text:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        text_frame2, self.base64_text = self.create_styled_text(col2, height=3)
        text_frame2.pack(fill='x', padx=15, pady=(0, 10))
        
        button_frame2 = tk.Frame(col2, bg=self.section_bg)
        button_frame2.pack(fill='x', padx=15, pady=(0, 15))
        
        base64_encode_btn = self.create_styled_button(button_frame2, "Encode", self.base64_encode_cmd)
        base64_encode_btn.pack(side='left')
        
        base64_decode_btn = self.create_styled_button(button_frame2, "Decode", self.base64_decode_cmd, style='secondary')
        base64_decode_btn.pack(side='left', padx=(10, 0))
        
        self.base64_result_frame, self.base64_result_text = self.create_result_frame(col2)
        
        col3 = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        col3.pack(side='right', fill='both', expand=True, padx=(10, 0), pady=5)
        
        tk.Label(col3, text="SHA-256 Hashing", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(col3, text="Text to Hash:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        text_frame3, self.sha256_text = self.create_styled_text(col3, height=3)
        text_frame3.pack(fill='x', padx=15, pady=(0, 10))
        
        sha256_btn = self.create_styled_button(col3, "Generate Hash", self.sha256_hash_cmd)
        sha256_btn.pack(padx=15, pady=(0, 15))
        
        self.sha256_result_frame, self.sha256_result_text = self.create_result_frame(col3)
    
    def aes_encrypt_cmd(self):
        text = self.aes_text.get(1.0, tk.END).strip()
        password = self.aes_password.get().strip()
        
        if not text or not password:
            self.show_result(self.aes_result_frame, self.aes_result_text,
                           "Please enter text and password", True)
            return
            
        result = self.encrypt_text_api('aes', text, password)
        
        if result.get("success"):
            self.show_result(self.aes_result_frame, self.aes_result_text,
                           f"Encrypted (AES):\n{result['result']}")
        else:
            self.show_result(self.aes_result_frame, self.aes_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    def aes_decrypt_cmd(self):
        text = self.aes_text.get(1.0, tk.END).strip()
        password = self.aes_password.get().strip()
        
        if not text or not password:
            self.show_result(self.aes_result_frame, self.aes_result_text,
                           "Please enter encrypted text and password", True)
            return
            
        result = self.decrypt_text_api('aes', text, password)
        
        if result.get("success"):
            self.show_result(self.aes_result_frame, self.aes_result_text,
                           f"Decrypted (AES):\n{result['result']}")
        else:
            self.show_result(self.aes_result_frame, self.aes_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    def base64_encode_cmd(self):
        text = self.base64_text.get(1.0, tk.END).strip()
        
        if not text:
            self.show_result(self.base64_result_frame, self.base64_result_text,
                           "Please enter text", True)
            return
            
        result = self.encrypt_text_api('base64', text, "")
        
        if result.get("success"):
            self.show_result(self.base64_result_frame, self.base64_result_text,
                           f"Base64 Encoded:\n{result['result']}")
        else:
            self.show_result(self.base64_result_frame, self.base64_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    def base64_decode_cmd(self):
        text = self.base64_text.get(1.0, tk.END).strip()
        
        if not text:
            self.show_result(self.base64_result_frame, self.base64_result_text,
                           "Please enter text", True)
            return
            
        result = self.decrypt_text_api('base64', text, "")
        
        if result.get("success"):
            self.show_result(self.base64_result_frame, self.base64_result_text,
                           f"Base64 Decoded:\n{result['result']}")
        else:
            self.show_result(self.base64_result_frame, self.base64_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
    def sha256_hash_cmd(self):
        text = self.sha256_text.get(1.0, tk.END).strip()
        
        if not text:
            self.show_result(self.sha256_result_frame, self.sha256_result_text,
                           "Please enter text", True)
            return
            
        result = self.hash_text_api(text, 'sha256')
        
        if result.get("success"):
            self.show_result(self.sha256_result_frame, self.sha256_result_text,
                           f"SHA-256 Hash:\n{result['hash_value']}")
        else:
            self.show_result(self.sha256_result_frame, self.sha256_result_text,
                           f"Error: {result.get('error', 'Unknown error')}", True)
    
   
    def create_history_tab(self):
        """Create History Tab with proper loading from database"""
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["History"] = tab
        
        title = tk.Label(tab, text="📜 Operation History", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        # Control frame
        control_frame = tk.Frame(tab, bg=self.container_bg)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # Filter frame
        filter_frame = tk.Frame(control_frame, bg=self.container_bg)
        filter_frame.pack(side='left', padx=(0, 20))
        
        tk.Label(filter_frame, text="Filter:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left', padx=(0, 10))
        
        # Operation type filter
        self.history_filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.history_filter_var,
                                values=["all", "encrypt", "decrypt", "hash_generate", 
                                        "hash_crack", "file_encrypt", "file_decrypt",
                                        "image_steg", "audio_steg", "rsa", "security_scan"],
                                state="readonly", width=15)
        filter_combo.pack(side='left', padx=(0, 10))
        
        # Load button
        load_btn = self.create_styled_button(filter_frame, "🔄 Load History",
                                        self.load_history_data, style='secondary')
        load_btn.pack(side='left')
        
        # Clear button
        clear_btn = self.create_styled_button(control_frame, "🗑️ Clear History",
                                            self.clear_history, style='warning')
        clear_btn.pack(side='right')
        
        # Stats frame
        stats_frame = tk.Frame(tab, bg=self.section_bg, relief='solid', bd=1)
        stats_frame.pack(fill='x', pady=(0, 20))
        
        self.stats_label = tk.Label(stats_frame, text="📊 Statistics: Loading...",
                                font=self.normal_font, fg=self.text_color, bg=self.section_bg)
        self.stats_label.pack(pady=10)
        
        # Treeview for history
        columns = ("ID", "Type", "Cipher", "Input", "Output", "Key", "Time", "Score")
        self.history_tree = ttk.Treeview(tab, columns=columns, show='headings', height=15)
        
        # Configure columns
        col_widths = {"ID": 50, "Type": 80, "Cipher": 80, "Input": 150, 
                    "Output": 150, "Key": 80, "Time": 120, "Score": 60}
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tab, orient='vertical', command=self.history_tree.yview)
        h_scrollbar = ttk.Scrollbar(tab, orient='horizontal', command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack everything
        self.history_tree.pack(side='top', fill='both', expand=True)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')
        
        # Bind double-click to show details
        self.history_tree.bind('<Double-1>', self.show_history_details)
        
        # Load initial data
        self.root.after(100, self.load_history_data)
 
    
    def update_history_stats(self, history):
        """Update statistics display"""
        if not history:
            self.stats_label.config(text="📊 No operations found")
            return
        
        total = len(history)
        encrypt_count = sum(1 for op in history if op['operation_type'] == 'encrypt')
        decrypt_count = sum(1 for op in history if op['operation_type'] == 'decrypt')
        hash_count = sum(1 for op in history if 'hash' in str(op['cipher_type']))
        file_count = sum(1 for op in history if op['is_file_operation'])
        
        stats_text = f"📊 Statistics: {total} total operations | "
        stats_text += f"🔒 {encrypt_count} encrypt | "
        stats_text += f"🔓 {decrypt_count} decrypt | "
        stats_text += f"#️⃣ {hash_count} hash | "
        stats_text += f"📁 {file_count} file"
        
        self.stats_label.config(text=stats_text)
    
    def show_history_details(self, event):
        """Show details of selected history item"""
        selection = self.history_tree.selection()
        if not selection:
            return
        
        item = self.history_tree.item(selection[0])
        values = item['values']
        
        # Create details dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Operation Details - ID: {values[0]}")
        dialog.geometry("600x500")
        dialog.configure(bg=self.bg_color)
        
        # Container
        container = tk.Frame(dialog, bg=self.bg_color)
        container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        tk.Label(container, text="📋 Operation Details",
                font=self.heading_font, fg=self.accent_color, bg=self.bg_color).pack(pady=(0, 20))
        
        # Create details frame
        details_frame = tk.Frame(container, bg=self.section_bg, relief='solid', bd=1)
        details_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        # Add details
        details = [
            ("ID:", values[0]),
            ("Type:", values[1]),
            ("Cipher:", values[2]),
            ("Key:", values[5]),
            ("Time:", values[6]),
            ("Score:", values[7])
        ]
        
        for label, value in details:
            frame = tk.Frame(details_frame, bg=self.section_bg)
            frame.pack(fill='x', padx=15, pady=5)
            
            tk.Label(frame, text=label, font=('Segoe UI', 10, 'bold'),
                    fg=self.accent_color, bg=self.section_bg).pack(side='left', padx=(0, 10))
            tk.Label(frame, text=value, font=self.normal_font,
                    fg=self.text_color, bg=self.section_bg).pack(side='left')
        
        # Input/Output sections
        input_frame = tk.Frame(details_frame, bg=self.section_bg)
        input_frame.pack(fill='x', padx=15, pady=10)
        
        tk.Label(input_frame, text="Input:", font=('Segoe UI', 10, 'bold'),
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w')
        
        input_text = scrolledtext.ScrolledText(input_frame, height=5,
                                            bg='#0d142e', fg=self.text_color,
                                            font=self.mono_font, wrap='word')
        input_text.pack(fill='x', pady=(5, 0))
        input_text.insert('1.0', self.get_full_operation_details(values[0], 'input'))
        input_text.configure(state='disabled')
        
        output_frame = tk.Frame(details_frame, bg=self.section_bg)
        output_frame.pack(fill='x', padx=15, pady=(10, 15))
        
        tk.Label(output_frame, text="Output:", font=('Segoe UI', 10, 'bold'),
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w')
        
        output_text = scrolledtext.ScrolledText(output_frame, height=5,
                                            bg='#0d142e', fg=self.text_color,
                                            font=self.mono_font, wrap='word')
        output_text.pack(fill='x', pady=(5, 0))
        output_text.insert('1.0', self.get_full_operation_details(values[0], 'output'))
        output_text.configure(state='disabled')
        
        # Close button
        close_btn = tk.Button(container, text="Close",
                            font=self.normal_font,
                            bg='#2a2f47',
                            fg=self.text_color,
                            relief='flat',
                            bd=0,
                            padx=30,
                            pady=10,
                            command=dialog.destroy)
        close_btn.pack()
        
    def get_full_operation_details(self, operation_id, field='input'):
        """Get full operation details from database"""
        try:
            # Get session
            session = self.db.Session()
            
            # Query the operation
            operation = session.query(Operation).filter(Operation.id == operation_id).first()
            
            if not operation:
                return "Operation not found"
            
            if field == 'input':
                return operation.input_text or ""
            elif field == 'output':
                return operation.output_text or ""
            else:
                return ""
                
        except Exception as e:
            print(f"Error getting operation details: {e}")
            return "Error loading details"
        finally:
            if 'session' in locals():
                session.close()
    
    def save_operation_to_db(self, operation_data):
        """Helper method to save any operation to database"""
        try:
            # Get user_id
            user_id = None
            if self.current_user:
                user_id = self.current_user['id']
            
            # Save to database
            success = self.db.add_operation(
                user_id=user_id,
                op_type=operation_data.get('operation_type'),
                cipher_type=operation_data.get('cipher_type'),
                input_text=operation_data.get('input_text'),
                output_text=operation_data.get('output_text'),
                key_used=operation_data.get('key_used', ''),
                score=operation_data.get('score', 0),
                file_name=operation_data.get('file_name'),
                is_file_operation=operation_data.get('is_file_operation', False),
                is_image_operation=operation_data.get('is_image_operation', False),
                is_audio_operation=operation_data.get('is_audio_operation', False),
                is_rsa_operation=operation_data.get('is_rsa_operation', False),
                is_security_operation=operation_data.get('is_security_operation', False),
                is_auto_crack=operation_data.get('is_auto_crack', False)
            )
            
            if success:
                print(f"✅ Operation saved: {operation_data.get('operation_type')}")
                
                # Refresh history if history tab is visible
                if hasattr(self, 'history_tree') and self.current_tab == self.tab_contents.get("History"):
                    self.root.after(500, self.load_history_data)
                
                return True
            else:
                print(f"❌ Failed to save operation")
                return False
                
        except Exception as e:
            print(f"❌ Error saving operation: {e}")
            return False
   

                
    def clear_history(self):
        """Clear history with confirmation"""
        if not self.current_user:
            # Standard mode - can only clear standard history
            response = messagebox.askyesno("Clear History", 
                                        "Clear standard mode history?\n\n"
                                        "This will delete all operations without user ID (standard mode operations).")
            if response:
                # Clear operations without user_id
                self.db.clear_history(user_id=None)
                self.load_history_data()
                messagebox.showinfo("Success", "✅ Standard mode history cleared")
            return
        
        # Custom user mode
        if not self.current_user.get('is_admin'):
            response = messagebox.askyesno("Clear History", 
                                        f"Clear YOUR history only?\n\n"
                                        f"User: {self.current_user['username']}\n"
                                        "Only administrators can clear all history.")
            if response:
                # Clear only this user's history
                self.db.clear_history(user_id=self.current_user['id'])
                self.load_history_data()
                messagebox.showinfo("Success", "✅ Your history cleared")
            return
        
        # Admin: show options
        choice = tk.messagebox.askquestion("Clear History", 
                                        "Clear history for:\n\n"
                                        "Yes: ALL USERS (including standard mode)\n"
                                        "No: ONLY YOUR HISTORY\n"
                                        "Cancel: Do nothing",
                                        icon='warning')
        
        if choice == 'yes':
            # Clear ALL history (all users + standard)
            self.db.clear_history()
            self.load_history_data()
            messagebox.showinfo("Success", "✅ All history cleared for all users")
        elif choice == 'no':
            # Clear only admin's history
            self.db.clear_history(user_id=self.current_user['id'])
            self.load_history_data()
            messagebox.showinfo("Success", "✅ Your history cleared")
            
 
    
    
    def load_combined_history_cmd(self):
        operation_type = self.history_operation_type.get()
        
        if operation_type == "Encrypted Items":
            api_op_type = "encrypt"
        elif operation_type == "Decrypted Items":
            api_op_type = "decrypt"
        else:
            api_op_type = None
        
        # Get user-specific or all history based on mode
        if self.mode == "custom" and self.current_user:
            # For custom mode, get only user's history
            result = self.db.get_history(
                limit=50,
                operation_type=api_op_type,
                user_id=self.current_user['id']  # Add user filter
            )
            
            # Also get hash operations for this user
            hash_history = self.db.get_hash_operations(limit=20)
            hash_history = [h for h in hash_history if h.get('user_id') == self.current_user['id']]
            
        else:
            # For standard mode, get all history
            result = self.db.get_history(
                limit=50,
                operation_type=api_op_type
            )
            
            hash_history = self.db.get_hash_operations(limit=20)
        
        # Update UI to show mode
        title = self.history_tree.master.master.winfo_children()[0]  # Get title label
        if self.mode == "standard":
            title.config(text="📊 Operation History (Standard Mode - All Users)")
        else:
            title.config(text=f"📊 Operation History (Personal - {self.current_user['username']})")
        
   
    def clear_history_filters_cmd(self):
        self.history_operation_type.set("All Operations")
        self.load_combined_history_cmd()
    
 
    def update_history_tree(self, history):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        for op in history[:50]:
            timestamp = op.get('timestamp', 'Unknown')
            if timestamp and isinstance(timestamp, str) and len(timestamp) > 10:
                timestamp = timestamp[:19]
            
            op_type = op.get('operation_type', 'unknown')
            if op_type == 'encrypt':
                type_display = "🔒 Encrypted"
            elif op_type == 'decrypt':
                type_display = "🔓 Decrypted"
            elif op_type == 'hash_generate':
                type_display = "🔗 Hash Generated"
            elif op_type == 'hash_crack':
                type_display = "🔍 Hash Cracked"
            elif op_type == 'auto-crack':
                type_display = "🤖 Auto Cracked"
            elif op_type == 'auto-crack-modern':
                type_display = "⚡ Modern Cracked"
            else:
                type_display = op_type
            
            method = op.get('cipher_type', 'Unknown')
            if 'hash_' in method:
                method = method.replace('hash_', '').upper()
            
            input_text = op.get('input_text', '')[:30]
            output_text = op.get('output_text', '')[:30]
            io_display = f"Input: {input_text}...\nOutput: {output_text}..."
            
            self.history_tree.insert("", tk.END, values=(timestamp, type_display, method, io_display)) 
            
 
    def create_network_scanner_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Network Scanner"] = tab
        
        title = tk.Label(tab, text="🌐 Network Scanner", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        desc = tk.Label(tab, text="Scan networks for open ports, services, and vulnerabilities using Nmap",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        content = tk.Frame(tab, bg=self.container_bg)
        content.pack(fill='both', expand=True)
        
        tk.Label(content, text="Target (IP/Domain/Network):", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(anchor='w', pady=(0, 5))
        
        self.scan_target_entry = self.create_styled_entry(content, width=50)
        self.scan_target_entry.insert(0, "example.com or 192.168.1.1 or 192.168.1.0/24")
        self.scan_target_entry.pack(fill='x', pady=(0, 15))
        
        port_frame = tk.Frame(content, bg=self.container_bg)
        port_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(port_frame, text="Ports:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left')
        
        self.scan_ports_entry = self.create_styled_entry(port_frame, width=20)
        self.scan_ports_entry.insert(0, "1-1000")
        self.scan_ports_entry.pack(side='left', padx=(10, 0))
        
        scan_type_frame = tk.Frame(content, bg=self.container_bg)
        scan_type_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(scan_type_frame, text="Scan Type:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left')
        
        self.scan_type_var = tk.StringVar(value="standard")
        scan_types = [
            ("Quick Scan", "quick"),
            ("Standard Scan", "standard"),
            ("Comprehensive", "comprehensive"),
            ("Stealth Scan", "stealth")
        ]
        
        for i, (text, value) in enumerate(scan_types):
            rb = tk.Radiobutton(scan_type_frame, text=text, variable=self.scan_type_var,
                               value=value, bg=self.container_bg, fg=self.text_color,
                               selectcolor=self.container_bg,
                               activebackground=self.container_bg,
                               activeforeground=self.accent_color)
            rb.pack(side='left', padx=(10, 20))
        
        scan_btn = self.create_styled_button(content, "🚀 Start Network Scan", 
                                           self.perform_network_scan, style='warning')
        scan_btn.pack(pady=(10, 0))
        
        self.scan_progress_label = tk.Label(content, text="", font=self.normal_font,
                                          fg='#a0a0a0', bg=self.container_bg)
        self.scan_progress_label.pack(pady=(10, 0))
        
        self.scan_result_frame, self.scan_result_text = self.create_result_frame(content)
        
        self.scan_stats_frame = tk.Frame(content, bg=self.container_bg)
        self.scan_stats_frame.pack(fill='x', pady=(10, 0))
    
    def perform_network_scan(self):
        target = self.scan_target_entry.get().strip()
        ports = self.scan_ports_entry.get().strip()
        scan_type = self.scan_type_var.get()
        
        if not target or target == "example.com or 192.168.1.1 or 192.168.1.0/24":
            self.show_result(self.scan_result_frame, self.scan_result_text,
                           "Please enter a target to scan", True)
            return
        
        scan_args_map = {
            "quick": "-sS -T4",
            "standard": "-sV -O",
            "comprehensive": "-sV -O -A -sC",
            "stealth": "-sS -T2"
        }
        
        arguments = scan_args_map.get(scan_type, "-sV -O")
        
        self.scan_progress_label.config(text="⏳ Scanning network... This may take a few minutes")
        
        def scan_thread():
            try:
                result = self.nmap_scanner.scan_target(target, ports, arguments)
                self.root.after(0, self.update_network_scan_result, result)
            except Exception as e:
                self.root.after(0, self.show_result, self.scan_result_frame, 
                              self.scan_result_text, f"Scan error: {str(e)}", True)
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def create_ssl_scanner_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["SSL Scanner"] = tab
        
        title = tk.Label(tab, text="🔒 Bulk SSL/TLS Scanner", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        desc = tk.Label(tab, text="Scan multiple domains for SSL/TLS configuration, certificates, and vulnerabilities",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        main_frame = tk.Frame(tab, bg=self.container_bg)
        main_frame.pack(fill='both', expand=True)
        
        left_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10), pady=5)
        
        tk.Label(left_frame, text="Single Domain Scan", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(left_frame, text="Domain:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        self.ssl_domain_entry = self.create_styled_entry(left_frame, width=30)
        self.ssl_domain_entry.insert(0, "example.com")
        self.ssl_domain_entry.pack(fill='x', padx=15, pady=(0, 15))
        
        single_scan_btn = self.create_styled_button(left_frame, "Scan Single Domain",
                                                  self.scan_single_ssl, style='secondary')
        single_scan_btn.pack(padx=15, pady=(0, 15))
        
        self.ssl_single_result_frame, self.ssl_single_result_text = self.create_result_frame(left_frame)
        
        right_frame = tk.Frame(main_frame, bg=self.section_bg, relief='solid', bd=1)
        right_frame.pack(side='right', fill='both', expand=True, padx=(10, 0), pady=5)
        
        tk.Label(right_frame, text="Bulk Domain Scan", font=self.subheading_font,
                fg=self.accent_color, bg=self.section_bg).pack(anchor='w', padx=15, pady=15)
        
        tk.Label(right_frame, text="Domains File (one per line):", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(anchor='w', padx=15, pady=(0, 5))
        
        file_frame = tk.Frame(right_frame, bg=self.section_bg)
        file_frame.pack(fill='x', padx=15, pady=(0, 10))
        
        self.ssl_file_entry = self.create_styled_entry(file_frame, width=25)
        self.ssl_file_entry.pack(side='left', fill='x', expand=True)
        
        browse_btn = self.create_styled_button(file_frame, "Browse", 
                                             lambda: self.select_ssl_file(), 
                                             style='secondary')
        browse_btn.pack(side='left', padx=(10, 0))
        
        worker_frame = tk.Frame(right_frame, bg=self.section_bg)
        worker_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        tk.Label(worker_frame, text="Concurrent Workers:", font=self.normal_font,
                fg='#b0b0b0', bg=self.section_bg).pack(side='left')
        
        self.ssl_workers_var = tk.StringVar(value="5")
        workers_spin = tk.Spinbox(worker_frame, from_=1, to=20, textvariable=self.ssl_workers_var,
                                 width=5, bg='#0d142e', fg=self.text_color, 
                                 buttonbackground=self.accent_color)
        workers_spin.pack(side='left', padx=(10, 0))
        
        bulk_scan_btn = self.create_styled_button(right_frame, "🚀 Start Bulk SSL Scan",
                                                self.scan_bulk_ssl, style='warning')
        bulk_scan_btn.pack(padx=15, pady=(0, 15))
        
        self.ssl_progress_label = tk.Label(right_frame, text="", font=self.normal_font,
                                         fg='#a0a0a0', bg=self.section_bg)
        self.ssl_progress_label.pack(padx=15, pady=(0, 10))
        
        self.ssl_bulk_result_frame, self.ssl_bulk_result_text = self.create_result_frame(right_frame)
        
    def select_ssl_file(self):
        filename = filedialog.askopenfilename(title="Select domains file",
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.ssl_file_entry.delete(0, tk.END)
            self.ssl_file_entry.insert(0, filename)
    
    def scan_single_ssl(self):
        domain = self.ssl_domain_entry.get().strip()
        
        if not domain or domain == "example.com":
            self.show_result(self.ssl_single_result_frame, self.ssl_single_result_text,
                           "Please enter a domain to scan", True)
            return
        
        domains = [domain]
        
        def scan_thread():
            try:
                scanner = BulkSSLScanner(max_workers=1, timeout=10)
                result = scanner.scan_bulk(domains)
                self.root.after(0, self.update_single_ssl_result, result)
            except Exception as e:
                self.root.after(0, self.show_result, self.ssl_single_result_frame,
                              self.ssl_single_result_text, f"SSL scan error: {str(e)}", True)
        
        threading.Thread(target=scan_thread, daemon=True).start()
        self.show_result(self.ssl_single_result_frame, self.ssl_single_result_text,
                        f"⏳ Scanning SSL/TLS configuration for {domain}...")

    def scan_bulk_ssl(self):
        filename = self.ssl_file_entry.get().strip()
        
        if not filename or not os.path.exists(filename):
            self.show_result(self.ssl_bulk_result_frame, self.ssl_bulk_result_text,
                           "Please select a valid domains file", True)
            return
        
        try:
            with open(filename, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if not domains:
                self.show_result(self.ssl_bulk_result_frame, self.ssl_bulk_result_text,
                               "No domains found in file", True)
                return
            
            workers = int(self.ssl_workers_var.get())
            
            self.ssl_progress_label.config(text=f"⏳ Scanning {len(domains)} domains...")
            
            def scan_thread():
                try:
                    scanner = BulkSSLScanner(max_workers=workers, timeout=10)
                    result = scanner.scan_bulk(domains)
                    self.root.after(0, self.update_bulk_ssl_result, result)
                except Exception as e:
                    self.root.after(0, self.show_result, self.ssl_bulk_result_frame,
                                  self.ssl_bulk_result_text, f"Bulk SSL scan error: {str(e)}", True)
            
            threading.Thread(target=scan_thread, daemon=True).start()
            
        except Exception as e:
            self.show_result(self.ssl_bulk_result_frame, self.ssl_bulk_result_text,
                           f"Error reading file: {str(e)}", True)
    
    def update_bulk_ssl_result(self, result):
        self.ssl_progress_label.config(text="")
        
        if result.get("successful_scans", 0) > 0:
            output = []
            output.append("✅ BULK SSL SCAN COMPLETED")
            output.append("=" * 50)
            output.append(f"\nTotal domains: {result.get('total_domains', 0)}")
            output.append(f"Successful scans: {result.get('successful_scans', 0)}")
            output.append(f"Failed scans: {result.get('failed_scans', 0)}")
            
            summary = result.get("summary", {})
            if summary:
                if "average_score" in summary:
                    output.append(f"\nAverage Security Score: {summary['average_score']:.1f}/100")
                    output.append(f"Best Score: {summary.get('max_score', 0)}")
                    output.append(f"Worst Score: {summary.get('min_score', 0)}")
                
                if "score_distribution" in summary:
                    output.append("\nScore Distribution:")
                    for category, count in summary["score_distribution"].items():
                        output.append(f"  {category.title()}: {count} domains")
                
                if summary.get("critical_issues"):
                    output.append(f"\n⚠️  CRITICAL ISSUES ({len(summary['critical_issues'])} found):")
                    for issue in summary["critical_issues"][:5]:
                        output.append(f"  • {issue['domain']}: {issue['issue']} ({issue['risk']})")
                    if len(summary["critical_issues"]) > 5:
                        output.append(f"    ... and {len(summary['critical_issues']) - 5} more")
            
            domain_results = []
            for domain_result in result.get("results", []):
                if domain_result.get("success"):
                    score = domain_result.get("security_score", 0)
                    domain_results.append((score, domain_result.get("domain", "")))
            
            domain_results.sort()
            
            if domain_results:
                output.append("\n📉 WORST PERFORMING DOMAINS:")
                for score, domain in domain_results[:5]:
                    output.append(f"  • {domain}: {score}/100")
            
            self.show_result(self.ssl_bulk_result_frame, self.ssl_bulk_result_text, "\n".join(output))
        else:
            self.show_result(self.ssl_bulk_result_frame, self.ssl_bulk_result_text,
                           "❌ No successful scans", True)

    def create_quantum_checker_tab(self):
        tab = tk.Frame(self.main_frame, bg=self.container_bg)
        self.tab_contents["Quantum Checker"] = tab
        
        title = tk.Label(tab, text="⚛️  Quantum Vulnerability Checker", font=self.heading_font,
                        fg=self.accent_color, bg=self.container_bg)
        title.pack(anchor='w', pady=(0, 20))
        
        desc = tk.Label(tab, text="Detect cryptographic algorithms vulnerable to quantum computers and get migration recommendations",
                       font=self.normal_font, fg='#888888', bg=self.container_bg, wraplength=1000)
        desc.pack(anchor='w', pady=(0, 20))
        
        content = tk.Frame(tab, bg=self.container_bg)
        content.pack(fill='both', expand=True)
        
        tk.Label(content, text="Domain to Analyze:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(anchor='w', pady=(0, 5))
        
        self.quantum_domain_entry = self.create_styled_entry(content, width=50)
        self.quantum_domain_entry.insert(0, "bank.com or google.com")
        self.quantum_domain_entry.pack(fill='x', pady=(0, 15))
        
        analysis_frame = tk.Frame(content, bg=self.container_bg)
        analysis_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(analysis_frame, text="Analysis Type:", font=self.normal_font,
                fg='#b0b0b0', bg=self.container_bg).pack(side='left')
        
        self.quantum_analysis_var = tk.StringVar(value="standard")
        analysis_types = [
            ("Standard Analysis", "standard"),
            ("Detailed Report", "detailed"),
            ("With Timeline", "timeline")
        ]
        
        for i, (text, value) in enumerate(analysis_types):
            rb = tk.Radiobutton(analysis_frame, text=text, variable=self.quantum_analysis_var,
                               value=value, bg=self.container_bg, fg=self.text_color,
                               selectcolor=self.container_bg,
                               activebackground=self.container_bg,
                               activeforeground=self.accent_color)
            rb.pack(side='left', padx=(10, 20))
        
        analyze_btn = self.create_styled_button(content, "🔍 Analyze Quantum Vulnerabilities",
                                              self.perform_quantum_analysis, style='danger')
        analyze_btn.pack(pady=(10, 0))
        
        self.quantum_progress_label = tk.Label(content, text="", font=self.normal_font,
                                             fg='#a0a0a0', bg=self.container_bg)
        self.quantum_progress_label.pack(pady=(10, 0))
        
        self.quantum_result_frame, self.quantum_result_text = self.create_result_frame(content)
        
        self.quantum_migration_frame = tk.Frame(content, bg=self.container_bg)
        self.quantum_migration_frame.pack_forget()
        
    def perform_quantum_analysis(self):
        domain = self.quantum_domain_entry.get().strip()
        analysis_type = self.quantum_analysis_var.get()
        
        if not domain or domain == "bank.com or google.com":
            self.show_result(self.quantum_result_frame, self.quantum_result_text,
                           "Please enter a domain to analyze", True)
            return
        
        self.quantum_progress_label.config(text=f"⏳ Analyzing quantum vulnerabilities for {domain}...")
        
        self.quantum_migration_frame.pack_forget()
        
        def analysis_thread():
            try:
                result = self.quantum_checker.analyze_certificate(domain)
                self.root.after(0, self.update_quantum_analysis_result, result, analysis_type)
            except Exception as e:
                self.root.after(0, self.show_result, self.quantum_result_frame,
                              self.quantum_result_text, f"Quantum analysis error: {str(e)}", True)
        
        threading.Thread(target=analysis_thread, daemon=True).start()

    def show_migration_plan(self, result):
        for widget in self.quantum_migration_frame.winfo_children():
            widget.destroy()
        
        migration_plan = result.get("migration_plan", {})
        
        if migration_plan:
            title = tk.Label(self.quantum_migration_frame, text="🚀 QUANTUM MIGRATION PLAN",
                           font=self.subheading_font, fg=self.warning_color, bg=self.container_bg)
            title.pack(anchor='w', pady=(20, 10))
            
            priority = migration_plan.get("priority", "MEDIUM")
            priority_color = self.error_color if priority == "HIGH" else self.warning_color
            
            priority_label = tk.Label(self.quantum_migration_frame, 
                                    text=f"Priority: {priority}",
                                    font=('Segoe UI', 10, 'bold'),
                                    fg=priority_color, bg=self.container_bg)
            priority_label.pack(anchor='w', pady=(0, 10))
            
            timeline_label = tk.Label(self.quantum_migration_frame,
                                    text=f"Estimated Timeline: {migration_plan.get('estimated_timeline', 'Unknown')}",
                                    font=self.normal_font, fg=self.text_color, bg=self.container_bg)
            timeline_label.pack(anchor='w', pady=(0, 10))
            
            phases_label = tk.Label(self.quantum_migration_frame, text="Migration Phases:",
                                  font=('Segoe UI', 10, 'bold'), fg=self.accent_color, bg=self.container_bg)
            phases_label.pack(anchor='w', pady=(0, 5))
            
            for phase in migration_plan.get("phases", []):
                phase_text = f"Phase {phase.get('phase', '?')} ({phase.get('timeline', '?')}): {phase.get('action', '')}"
                phase_label = tk.Label(self.quantum_migration_frame, text=phase_text,
                                     font=self.normal_font, fg=self.text_color, bg=self.container_bg)
                phase_label.pack(anchor='w', padx=20, pady=(0, 2))
            
            self.quantum_migration_frame.pack(fill='x', pady=(20, 0))


    def update_network_scan_result(self, result):
        self.scan_progress_label.config(text="")
        
        if result.get("success"):
            output = []
            output.append("✅ NETWORK SCAN COMPLETED")
            output.append("=" * 50)
            
            host_info = result.get("host_info", {})
            if host_info:
                output.append("\nHOST INFORMATION:")
                output.append(f"  Hostname: {host_info.get('hostname', 'Unknown')}")
                output.append(f"  State: {host_info.get('state', 'Unknown')}")
                if host_info.get('addresses'):
                    for addr_type, addr in host_info['addresses'].items():
                        output.append(f"  {addr_type.upper()}: {addr}")
            
            open_ports = result.get("open_ports", [])
            if open_ports:
                output.append(f"\nOPEN PORTS ({len(open_ports)} found):")
                for port_info in open_ports[:20]:
                    output.append(f"  Port {port_info['port']}/{port_info['protocol']}:")
                    output.append(f"    Service: {port_info.get('service', 'Unknown')}")
                    output.append(f"    Version: {port_info.get('version', 'Unknown')}")
                    output.append(f"    State: {port_info.get('state', 'Unknown')}")
                if len(open_ports) > 20:
                    output.append(f"    ... and {len(open_ports) - 20} more ports")
            else:
                output.append("\nNo open ports found")
            
            summary = result.get("scan_summary", {})
            if summary:
                output.append("\nSCAN SUMMARY:")
                output.append(f"  Total open ports: {summary.get('total_open_ports', 0)}")
                output.append(f"  TCP ports: {summary.get('tcp_ports', 0)}")
                output.append(f"  UDP ports: {summary.get('udp_ports', 0)}")
                
                if summary.get('services_found'):
                    output.append(f"  Services found: {', '.join(summary['services_found'][:10])}")
                    if len(summary['services_found']) > 10:
                        output.append(f"    ... and {len(summary['services_found']) - 10} more")
                
                if summary.get('vulnerability_indicators'):
                    output.append("\n⚠️  VULNERABILITY INDICATORS:")
                    for indicator in summary['vulnerability_indicators']:
                        output.append(f"  • {indicator}")
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            # Save network scan operation
            target = self.scan_target_entry.get().strip()
            open_ports_count = len(open_ports)
            
            self.db.add_security_operation(
                scan_type="nmap_scan",
                target=target,
                findings=f"Found {open_ports_count} open ports, {len(summary.get('vulnerability_indicators', []))} vulnerabilities",
                user_id=user_id  # <-- FIXED
            )
            
            self.show_result(self.scan_result_frame, self.scan_result_text, "\n".join(output))
            
            for widget in self.scan_stats_frame.winfo_children():
                widget.destroy()
            
            stats_text = f"📊 Scan completed: {open_ports_count} open ports found"
            if summary.get('vulnerability_indicators'):
                stats_text += f", {len(summary['vulnerability_indicators'])} vulnerabilities detected"
            
            stats_label = tk.Label(self.scan_stats_frame, text=stats_text,
                                font=self.normal_font, fg=self.success_color,
                                bg=self.container_bg)
            stats_label.pack()
            
        else:
            self.show_result(self.scan_result_frame, self.scan_result_text,
                        f"❌ Scan failed: {result.get('error', 'Unknown error')}", True)

    def update_single_ssl_result(self, result):
        if result.get("successful_scans", 0) > 0:
            for domain_result in result.get("results", []):
                if domain_result.get("domain") == self.ssl_domain_entry.get().strip():
                    # ALWAYS get user_id
                    user_id = self.get_current_user_id()
                    
                    # Save SSL scan operation
                    self.db.add_security_operation(
                        scan_type="ssl_scan",
                        target=domain_result.get("domain", ""),
                        findings=f"Security score: {domain_result.get('security_score', 0)}/100",
                        user_id=user_id  # <-- FIXED
                    )
                    
                    self.display_ssl_result(domain_result, self.ssl_single_result_frame, 
                                        self.ssl_single_result_text)
                    break
        else:
            self.show_result(self.ssl_single_result_frame, self.ssl_single_result_text,
                        f"❌ SSL scan failed: {result.get('error', 'Unknown error')}", True)

    def display_ssl_result(self, result, frame, text_widget):
        """Display SSL scan results - COMPLETE VERSION"""
        output = []
        output.append(f"✅ SSL/TLS SCAN RESULTS: {result.get('domain')}")
        output.append("=" * 50)
        
        if result.get("success"):
            output.append(f"\nSecurity Score: {result.get('security_score', 0)}/100")
            
            cert_info = result.get("certificate_info", {})
            if cert_info and "certificate" in cert_info:
                cert = cert_info["certificate"]
                output.append("\nCERTIFICATE INFORMATION:")
                output.append(f"  Valid To: {cert.get('valid_to', 'Unknown')}")
                output.append(f"  Days Remaining: {cert.get('days_remaining', 0)}")
                output.append(f"  Signature Algorithm: {cert.get('signature_algorithm', 'Unknown')}")
            
            protocols = result.get("protocols", {})
            if protocols:
                output.append("\nSUPPORTED PROTOCOLS:")
                for protocol, enabled in protocols.items():
                    status = "✅ Enabled" if enabled else "❌ Disabled"
                    output.append(f"  {protocol}: {status}")
            
            assessment = result.get("security_assessment", {})
            if assessment:
                if assessment.get("vulnerabilities"):
                    output.append("\n⚠️  VULNERABILITIES:")
                    for vuln in assessment["vulnerabilities"]:
                        output.append(f"  • {vuln.get('issue', 'Unknown')} ({vuln.get('risk', 'Unknown')})")
                
                if assessment.get("recommendations"):
                    output.append("\n💡 RECOMMENDATIONS:")
                    for rec in assessment["recommendations"]:
                        output.append(f"  • {rec}")
            
            # ALWAYS get user_id (for completion, though already saved above)
            user_id = self.get_current_user_id()
            
            self.show_result(frame, text_widget, "\n".join(output))
        else:
            self.show_result(frame, text_widget, 
                        f"❌ SSL scan failed: {result.get('error', 'Unknown error')}", True)

    def update_quantum_analysis_result(self, result, analysis_type):
        self.quantum_progress_label.config(text="")
        
        if result.get("success", True) and not result.get("error"):
            output = []
            output.append(f"⚛️  QUANTUM VULNERABILITY ANALYSIS: {result.get('domain')}")
            output.append("=" * 50)
            
            cert_info = result.get("certificate_info", {})
            if cert_info:
                output.append("\nCERTIFICATE INFORMATION:")
                output.append(f"  Algorithm: {cert_info.get('public_key_algorithm', 'Unknown')}")
                output.append(f"  Key Size: {cert_info.get('key_size', 'Unknown')} bits")
                output.append(f"  Signature: {cert_info.get('signature_algorithm', 'Unknown')}")
            
            risk_assessment = result.get("risk_assessment", {})
            if risk_assessment:
                output.append("\nRISK ASSESSMENT:")
                output.append(f"  Overall Risk: {risk_assessment.get('overall_risk', 'Unknown')}")
                output.append(f"  Quantum Readiness: {risk_assessment.get('quantum_readiness', 'Unknown')}")
                output.append(f"  Time to Quantum Threat: {risk_assessment.get('time_to_quantum_threat', 'Unknown')}")
                output.append(f"  Summary: {risk_assessment.get('summary', 'No issues detected')}")
            
            vulnerabilities = result.get("quantum_vulnerabilities", [])
            if vulnerabilities:
                output.append(f"\n⚠️  QUANTUM VULNERABILITIES ({len(vulnerabilities)} found):")
                
                shor_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "SHOR"]
                grover_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "GROVER"]
                
                if shor_vulns:
                    output.append("\n  SHOR-VULNERABLE (Public Key Cryptography):")
                    output.append("  ⚠️  These algorithms will be COMPLETELY BROKEN by quantum computers")
                    for vuln in shor_vulns:
                        output.append(f"    • {vuln.get('algorithm')}-{vuln.get('key_size', '')}: {vuln.get('risk_level')} risk")
                        output.append(f"      Impact: {vuln.get('impact', 'Unknown')}")
                        output.append(f"      Timeline: {vuln.get('estimated_break_timeline', 'Unknown')}")
                
                if grover_vulns:
                    output.append("\n  GROVER-VULNERABLE (Symmetric/Hash Algorithms):")
                    output.append("  ⚠️  These algorithms will have security reduced by square root")
                    for vuln in grover_vulns:
                        output.append(f"    • {vuln.get('algorithm')}: {vuln.get('risk_level')} risk")
                        output.append(f"      Impact: {vuln.get('impact', 'Unknown')}")
            else:
                output.append("\n✅ No quantum vulnerabilities detected")
            
            recommendations = result.get("recommendations", [])
            if recommendations:
                output.append("\n💡 RECOMMENDATIONS:")
                for i, rec in enumerate(recommendations[:5], 1):
                    output.append(f"  {i}. {rec}")
            
            if analysis_type == "timeline":
                timeline = result.get("timeline", {})
                if timeline:
                    output.append("\n⏰ QUANTUM COMPUTING TIMELINE:")
                    for milestone in timeline.get("milestones", []):
                        if milestone.get("critical_period"):
                            output.append(f"  ⚠️  {milestone['period']} ({milestone['year']}):")
                        else:
                            output.append(f"  • {milestone['period']} ({milestone['year']}):")
                        output.append(f"    Capability: {milestone.get('capability', 'Unknown')}")
                        output.append(f"    Crypto Impact: {milestone.get('crypto_impact', 'Unknown')}")
            
            # ALWAYS get user_id
            user_id = self.get_current_user_id()
            
            # Save quantum analysis operation
            domain = self.quantum_domain_entry.get().strip()
            vulnerabilities_count = len(vulnerabilities)
            
            self.db.add_security_operation(
                scan_type="quantum_analysis",
                target=domain,
                findings=f"Found {vulnerabilities_count} quantum vulnerabilities, Risk: {risk_assessment.get('overall_risk', 'Unknown')}",
                user_id=user_id  # <-- FIXED
            )
            
            self.show_result(self.quantum_result_frame, self.quantum_result_text, "\n".join(output))
            
            if vulnerabilities:
                self.show_migration_plan(result)
            
        else:
            self.show_result(self.quantum_result_frame, self.quantum_result_text,
                        f"❌ Quantum analysis failed: {result.get('error', 'Unknown error')}", True)

 
    def test_database_saving(self):
        """Test if operations are being saved with user_id"""
        user_id = self.get_current_user_id()
        current_user = self.current_user['username'] if self.current_user else "Standard Mode"
        
        print(f"\n🧪 DATABASE SAVING TEST")
        print(f"Current user: {current_user}")
        print(f"User ID: {user_id}")
        print(f"Mode: {self.mode}")
        
        # Test 1: Save a test operation
        success = self.db.add_operation(
            op_type="test",
            cipher_type="test_cipher",
            input_text="Test input for user tracking",
            output_text="Test output",
            key_used="test_key",
            score=100,
            user_id=user_id
        )
        
        print(f"Test operation saved: {'✅' if success else '❌'}")
        
        # Test 2: Check what's in the database
        print("\n📊 Checking database contents...")
        history = self.db.get_combined_history(limit=10)
        
        if history:
            print(f"Found {len(history)} operations in database:")
            for i, op in enumerate(history[:5], 1):
                username = "standard"
                if op['user_id']:
                    # Try to get username
                    user = self.db.get_user_by_id(op['user_id'])
                    if user:
                        username = user['username']
                print(f"  {i}. {op['operation_type']} ({op['cipher_type']}) - User: {username} (ID: {op['user_id']})")
        else:
            print("❌ No operations found in database!")
        
        return success

    # Also add this to your setup_ui method or somewhere to verify:
    def verify_database_tracking(self):
        """Verify database is tracking operations properly"""
        print("\n" + "="*60)
        print("🔍 VERIFYING DATABASE TRACKING")
        print("="*60)
        
        user_id = self.get_current_user_id()
        
        # Get statistics for this user
        stats = self.db.get_operation_statistics(days=1, user_id=user_id)
        
        if stats:
            print(f"📊 Your operations (last 24 hours):")
            print(f"  Total operations: {stats.get('total_operations', 0)}")
            print(f"  File operations: {stats.get('file_operations', 0)}")
            print(f"  Hash operations: {stats.get('total_hash_operations', 0)}")
            print(f"  RSA operations: {stats.get('rsa_operations', 0)}")
            
            if stats.get('operations_by_type'):
                print(f"\n📋 Operations by type:")
                for op_type, count in stats['operations_by_type'].items():
                    print(f"  {op_type}: {count}")
        else:
            print("❌ No statistics found. Are operations being saved?")
        
        # Run the database verification
        verification = self.db.verify_all_operations_stored(user_id=user_id)
        
        return verification




def main():
    try:
        root = TkinterDnD.Tk()
    except:
        print("⚠️  TkinterDnD not available. Using regular Tk without drag & drop.")
        root = tk.Tk()
    
    app = CryptoToolApp(root)
    
    root.title("🔐 CryptoTool - Complete Security Toolkit")
    
    root.minsize(1200, 800)
    
    root.mainloop()
    
if __name__ == "__main__":
    main()
    
    
    
   