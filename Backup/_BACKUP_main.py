import sys
from fastapi import FastAPI, UploadFile, File, Form # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
from fastapi.responses import FileResponse  # type: ignore
import json
from datetime import datetime
import uvicorn # type: ignore
import os
import base64
from aes_crypto import AESEncryption # type: ignore
from steganography_utils import ImageSteganography, AudioSteganography  #type: ignore
from database_orm import CryptoDatabaseORM# type: ignore
from hash_cracker import AdvancedHashCracker as HashCracker # type: ignore
from auto_crack_modern import modern_cracker # type: ignore
import atexit
import glob
from cryptography.fernet import Fernet
from cipher_crack import crack_cipher # type: ignore
from cipher_utils import encrypt, decrypt, score_text # type: ignore
app = FastAPI()

# Clean up temp files on exit
@atexit.register
def cleanup_temp_files():
    for f in glob.glob("/tmp/decrypted_*") + glob.glob("decrypted_*"):
        try:
            os.remove(f)
        except:
            pass

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Initialize modules
aes = AESEncryption()
img_stega = ImageSteganography()
audio_stega = AudioSteganography()
db = CryptoDatabaseORM()
hash_cracker = HashCracker(db)

@app.get("/")
async def root():
    return FileResponse("index.html")

# Basic encryption/decryption endpoints - FIXED FOR AES
@app.post("/api/encrypt")
async def encrypt_text(data: dict):
    try:
        cipher_type = data.get("cipher_type")
        text = data.get("text")
        key = data.get("key", "")
        
        # 🚨 FIX: Handle "aes" cipher type separately
        if cipher_type == "aes":
            result = aes.encrypt(text, key)
        else:
            result = encrypt(text, cipher_type, key)
        
        # Determine operation type for database
        is_file_op = cipher_type in ['aes', 'file']
        is_image_op = cipher_type in ['image', 'steganography']
        is_audio_op = cipher_type in ['audio']
        
        db.add_operation("encrypt", cipher_type, text, result, key, score_text(text),
                        is_file_operation=is_file_op, is_image_operation=is_image_op, 
                        is_audio_operation=is_audio_op)
        
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/decrypt")
async def decrypt_text(data: dict):
    try:
        cipher_type = data.get("cipher_type")
        text = data.get("text")
        key = data.get("key", "")
        
        # 🚨 FIX: Handle "aes" cipher type separately
        if cipher_type == "aes":
            result = aes.decrypt(text, key)
        else:
            result = decrypt(text, cipher_type, key)
        
        is_file_op = cipher_type in ['aes', 'file']
        is_image_op = cipher_type in ['image', 'steganography']
        is_audio_op = cipher_type in ['audio']
        
        db.add_operation("decrypt", cipher_type, text, result, key, score_text(result),
                        is_file_operation=is_file_op, is_image_operation=is_image_op,
                        is_audio_operation=is_audio_op)
        
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/auto-crack")
async def auto_crack(data: dict):
    try:
        text = data.get("text")
        results = crack_cipher(text)
        
        db.add_operation("auto-crack", "auto-detect", text, json.dumps(results[:3]), "", 0)
        
        return {"success": True, "results": results[:5]}
    except Exception as e:
        return {"success": False, "error": str(e)}




@app.post("/api/file-encrypt")
async def file_encrypt(file: UploadFile = File(...), password: str = Form(...)):
    try:
        contents = await file.read()
        
        # Encrypt the file data - returns bytes
        encrypted_data = aes.encrypt_file(contents, password)
        
        # Save as binary file
        temp_filename = f"encrypted_{file.filename}.bin"
        with open(temp_filename, "wb") as f:
            f.write(encrypted_data)
        
        db.add_operation("file-encrypt", "AES", file.filename, "File encrypted", password, True,
                        is_file_operation=True, file_name=temp_filename)
        
        return FileResponse(
            temp_filename, 
            media_type="application/octet-stream", 
            filename=temp_filename
        )
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/file-decrypt")
async def file_decrypt(file: UploadFile = File(...), password: str = Form(...)):
    try:
        # Read as bytes
        encrypted_data = await file.read()
        
        # Decrypt the file data
        decrypted = aes.decrypt_file(encrypted_data, password)
        
        # Determine file extension based on content or keep original
        original_name = file.filename.replace('.bin', '').replace('.enc', '')
        temp_filename = f"decrypted_{original_name}"
        
        with open(temp_filename, "wb") as f:
            f.write(decrypted)
        
        db.add_operation("file-decrypt", "AES", file.filename, "File decrypted", password, True,
                        is_file_operation=True, file_name=temp_filename)
        
        return FileResponse(
            temp_filename, 
            media_type="application/octet-stream", 
            filename=temp_filename
        )
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/file-brute-force")
async def file_brute_force(file: UploadFile = File(...)):
    try:
        encrypted_data = await file.read()
        
        print(f"📁 File size: {len(encrypted_data)} bytes")
        print(f"🚀 ULTRA FAST FILE MODE ACTIVATED")
        
        # 🚀 Use the NEW FAST file brute force method
        result = aes.brute_force_file_decrypt_fast(encrypted_data, max_workers=16)
        
        if result['success']:
            # Save the decrypted file
            original_name = file.filename.replace('.bin', '').replace('.enc', '')
            temp_filename = f"decrypted_{original_name}"
            
            with open(temp_filename, "wb") as f:
                f.write(result['file_data'])
            
            result['file_path'] = temp_filename
            result['file_name'] = temp_filename
            
            print(f"✅ File decrypted successfully! Size: {result['file_size']} bytes")
            
            db.add_operation('file-brute-force', 'AES', file.filename, 
                           f"Password found: {result['password']}", result['password'], True,
                           is_file_operation=True, file_name=file.filename)
        else:
            db.add_operation('file-brute-force', 'AES', file.filename, 
                           "Brute force failed", "", False,
                           is_file_operation=True, file_name=file.filename)
        
        return result
        
    except Exception as e:
        print(f"❌ File brute force error: {e}")
        return {"success": False, "error": str(e)}



# Brute force endpoints
@app.post("/api/brute-force-aes")
async def brute_force_aes(data: dict):
    """Brute force AES encryption with multi-threading"""
    try:
        ciphertext = data.get("ciphertext")
        max_workers = data.get("max_workers", 8)
        
        result = aes.brute_force_decrypt(ciphertext, max_workers)
        
        if result['success']:
            db.add_operation('brute-force-aes', 'AES', ciphertext[:50], result.get('text', '')[:50], 
                           result.get('password', ''), score_text(result.get('text', '')),
                           is_file_operation=True)
        
        return {"success": result['success'], **result}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/crack-hash")
async def crack_hash_endpoint(data: dict):
    """Crack a hash"""
    try:
        target_hash = data.get("hash")
        hash_type = data.get("hash_type", "auto")
        timeout = data.get("timeout", 30)
        
        if not target_hash:
            return {"success": False, "error": "Hash is required"}
        
        # Make sure hash_cracker has database connection
        global hash_cracker
        if not hasattr(hash_cracker, 'db') or hash_cracker.db is None:
            hash_cracker = HashCracker(db)  # Re-initialize with db
        
        if hash_type == "auto":
            result = hash_cracker.auto_crack_hash(target_hash, timeout)
        else:
            result = hash_cracker.crack_hash(target_hash, hash_type, timeout=timeout)
        
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/hash-text")
async def hash_text_endpoint(data: dict):
    """Hash text using specified algorithm - THIS IS GENERATION, NOT CRACKING"""
    try:
        text = data.get("text")
        hash_type = data.get("hash_type", "md5")
        
        if not text:
            return {"success": False, "error": "Text is required"}
        
        # Generate the hash
        hash_value = hash_cracker.hash_text(text, hash_type)
        
        # 🎯 CRITICAL: Save as HASH GENERATION (not cracking attempt)
        # Use add_operation directly to avoid confusion with hash cracking
        db.add_operation(
            op_type="hash_generate",  # This is generation, not cracking
            cipher_type=f"hash_{hash_type}",
            input_text=text,
            output_text=hash_value,
            key_used=hash_type,
            score=100,  # Success score for generation
            file_name=None,
            is_file_operation=False,
            is_image_operation=False,
            is_audio_operation=False
        )
        
        print(f"💾 Hash generation saved: '{text}' → {hash_value}")
        
        return {
            "success": True,
            "hash_type": hash_type,
            "hash_value": hash_value,
            "operation_id": "generation"  # Not a crack operation ID
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# Steganography endpoints
@app.post("/api/image-hide")
async def image_hide(file: UploadFile = File(...), message: str = Form(...)):
    try:
        contents = await file.read()
        result_path = img_stega.hide_message(contents, message)
        db.add_operation("image-hide", "LSB", message, "Image encoded", "", 0,
                        is_image_operation=True, file_name=file.filename)
        
        return FileResponse(result_path, media_type="image/png", filename="encoded_image.png")
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/image-extract")
async def image_extract(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        message = img_stega.extract_message(contents)
        db.add_operation("image-extract", "LSB", "Image file", message, "", 0,
                        is_image_operation=True, file_name=file.filename)
        
        return {"success": True, "message": message}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/audio-hide")
async def audio_hide(file: UploadFile = File(...), message: str = Form(...)):
    try:
        contents = await file.read()
        result_path = audio_stega.hide_message(contents, message)
        db.add_operation("audio-hide", "LSB", message, "Audio encoded", "", 0,
                        is_audio_operation=True, file_name=file.filename)
        
        return FileResponse(result_path, media_type="audio/wav", filename="encoded_audio.wav")
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/audio-extract")
async def audio_extract(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        message = audio_stega.extract_message(contents)
        db.add_operation("audio-extract", "LSB", "Audio file", message, "", 0,
                        is_audio_operation=True, file_name=file.filename)
        
        return {"success": True, "message": message}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Modern crack endpoints
@app.post("/api/auto-crack-modern")
async def auto_crack_modern(data: dict):
    """Complete auto-crack endpoint"""
    try:
        text = data.get("text", "").strip()
        
        if not text:
            return {"success": False, "error": "No text provided"}
        
        print(f"\n" + "🚀" * 20)
        print(f"🚀 AUTO-CRACK MODERN ENDPOINT CALLED")
        print(f"🚀" * 20)
        
        # Use the modern cracker
        result = modern_cracker.auto_crack(text)
        
        # Log to database
        if result['success']:
            best_result = result['results'][0] if result['results'] else {}
            result_text = best_result.get('text', '')[:100] if best_result else 'No result'
            db.add_operation("auto-crack-modern", "modern", text[:100], 
                           f"Found {len(result['results'])} results", "", 0)
        else:
            db.add_operation("auto-crack-modern", "modern", text[:100], 
                           "No results found", "", 0)
        
        return result
        
    except Exception as e:
        print(f"❌ Auto-crack modern error: {e}")
        return {"success": False, "error": str(e)}


# PADDING ORACLE ATTACK ENDPOINTS (UPDATED - NO PASSWORDS)
@app.post("/api/padding-oracle-text")
async def padding_oracle_text(data: dict):
    """Pure padding oracle attack on encrypted text - NO PASSWORD"""
    try:
        ciphertext = data.get("ciphertext")
        
        if not ciphertext:
            return {"success": False, "error": "Ciphertext is required"}
        
        # Use pure padding oracle attack only (no password parameter)
        result = aes.pure_padding_oracle_attack(ciphertext)
        
        if result['success']:
            db.add_operation('padding-oracle', 'AES', ciphertext[:50], 
                           f"Decrypted {len(result.get('decrypted_bytes', []))} bytes", "", 
                           len(result.get('decrypted_bytes', [])),
                           is_file_operation=False)
        
        return {"success": result['success'], **result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/padding-oracle-file")
async def padding_oracle_file(file: UploadFile = File(...)):
    """Pure padding oracle attack on encrypted file - NO PASSWORD"""
    try:
        encrypted_data = await file.read()
        
        # Convert file data to appropriate format
        if isinstance(encrypted_data, str):
            ciphertext = encrypted_data
        else:
            # Try to decode as base64 or use as-is
            try:
                ciphertext = base64.urlsafe_b64encode(encrypted_data).decode('ascii')
            except:
                ciphertext = encrypted_data.decode('latin1')
        
        result = aes.pure_padding_oracle_attack(ciphertext)
        
        if result['success']:
            db.add_operation('padding-oracle', 'AES', file.filename, 
                           f"Decrypted {len(result.get('decrypted_bytes', []))} bytes", "", 
                           len(result.get('decrypted_bytes', [])),
                           is_file_operation=True, file_name=file.filename)
        
        return {"success": result['success'], **result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/pure-padding-oracle")
async def pure_padding_oracle(data: dict):
    """Pure padding oracle attack without dictionary - NO PASSWORD"""
    try:
        ciphertext = data.get("ciphertext")
        
        if not ciphertext:
            return {"success": False, "error": "Ciphertext is required"}
        
        result = aes.pure_padding_oracle_attack(ciphertext)
        
        return {"success": result['success'], **result}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/detect-padding-vulnerability")
async def detect_padding_vulnerability(data: dict):
    """Detect padding oracle vulnerability"""
    try:
        ciphertext = data.get("ciphertext")
        
        if not ciphertext:
            return {"success": False, "error": "Ciphertext is required"}
        
        result = aes.detect_padding_vulnerability(ciphertext)
        
        return {"success": True, "vulnerability": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/advanced-timing-attack")
async def advanced_timing_attack(data: dict):
    """Advanced timing attack with statistical analysis"""
    try:
        ciphertext = data.get("ciphertext")
        measurements = data.get("measurements", 50)
        
        if not ciphertext:
            return {"success": False, "error": "Ciphertext is required"}
        
        result = aes.advanced_timing_attack(ciphertext, measurements)
        
        return {"success": result['success'], **result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/modern-crack")
async def modern_crack(data: dict):
    """Modern cracking with method choice"""
    try:
        ciphertext = data.get("ciphertext")
        method = data.get("method", "auto")
        known_prefix = data.get("known_prefix", "")
        target_type = data.get("target_type", "text")  # "text" or "file"
        
        if not ciphertext:
            return {"success": False, "error": "Ciphertext is required"}
        
        if method == "bruteforce":
            if target_type == "file":
                result = aes.brute_force_file_decrypt(ciphertext)
            else:
                result = aes.brute_force_decrypt(ciphertext)
        elif method == "padding_oracle":
            if target_type == "file":
                result = aes.padding_oracle_attack_file(ciphertext, known_prefix)
            else:
                result = aes.padding_oracle_attack_text(ciphertext, known_prefix)
        else:  # auto
            # First try brute force (faster for common passwords)
            print("🔄 AUTO MODE: Trying brute force first...")
            if target_type == "file":
                result = aes.brute_force_file_decrypt(ciphertext)
            else:
                result = aes.brute_force_decrypt(ciphertext)
                
            if not result['success']:
                print("🔄 AUTO MODE: Brute force failed, trying padding oracle...")
                if target_type == "file":
                    result = aes.padding_oracle_attack_file(ciphertext, known_prefix)
                else:
                    result = aes.padding_oracle_attack_text(ciphertext, known_prefix)
        
        return {"success": result['success'], **result}
    except Exception as e:
        return {"success": False, "error": str(e)}

# History endpoints
@app.get("/api/history/advanced")
async def get_advanced_history(
    operation_type: str = None,
    cipher_type: str = None,
    search_text: str = None,
    file_operations: bool = False,
    image_operations: bool = False,
    audio_operations: bool = False,
    start_date: str = None,
    end_date: str = None,
    limit: int = 50
):
    """Get history with advanced filtering"""
    try:
        # Parse dates
        start_dt = datetime.fromisoformat(start_date) if start_date else None
        end_dt = datetime.fromisoformat(end_date) if end_date else None
        
        history = db.get_history(
            limit=limit,
            operation_type=operation_type,
            cipher_type=cipher_type,
            search_text=search_text,
            file_operations_only=file_operations,
            image_operations_only=image_operations,
            audio_operations_only=audio_operations,
            start_date=start_dt,
            end_date=end_dt
        )
        
        return {"success": True, "history": history}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/hash-history")
async def get_hash_history(
    hash_type: str = None,
    cracked_only: bool = False,
    start_date: str = None,
    end_date: str = None,
    limit: int = 50
):
    """Get hash operation history"""
    try:
        start_dt = datetime.fromisoformat(start_date) if start_date else None
        end_dt = datetime.fromisoformat(end_date) if end_date else None
        
        hash_history = db.get_hash_operations(
            limit=limit,
            hash_type=hash_type,
            cracked_only=cracked_only,
            start_date=start_dt,
            end_date=end_dt
        )
        
        return {"success": True, "hash_history": hash_history}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/history/combined")
async def get_combined_history(
    operation_type: str = None,
    show_selected: bool = False,
    show_all: bool = True
):
    """
    Combined history endpoint that includes ALL operations
    """
    try:
        # Get regular operations with filters
        history = db.get_history(
            limit=50,
            operation_type=operation_type
        )
        
        # If specifically asking for hash operations, also get hash history
        if operation_type in ['hash_generate', 'hash_crack', None]:
            hash_history = db.get_hash_operations(limit=20)
            
            # Convert hash operations to the same format as regular operations
            for hash_op in hash_history:
                op_type = "hash_crack" if hash_op['cracked'] else "hash_generate"
                
                # Only include if it matches the filter
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
                        'is_hash_operation': True  # Flag to identify hash operations
                    })
        
        # Sort all by timestamp (newest first)
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Limit results
        history = history[:50]
        
        return {
            "success": True, 
            "history": history
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/statistics")
async def get_statistics(days: int = 30):
    """Get operation statistics"""
    try:
        stats = db.get_operation_statistics(days)
        return {"success": True, "statistics": stats}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Keep your existing endpoints exactly the same
@app.post("/api/hash")
async def hash_text(data: dict):
    try:
        text = data.get("text")
        import hashlib
        hash_result = hashlib.sha256(text.encode()).hexdigest()
        db.add_operation("hash", "SHA-256", text, hash_result, "", 0)
        return {"success": True, "hash": hash_result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/history")
async def get_history():
    try:
        return {"success": True, "operations": db.get_history()}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/suggestions")
async def get_suggestions():
    try:
        return {"success": True, "suggestions": db.get_suggestions()}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Add this debug endpoint to your main.py file:

@app.post("/api/debug-file-format")
async def debug_file_format(file: UploadFile = File(...)):
    """Debug endpoint to check file format"""
    try:
        encrypted_data = await file.read()
        
        result = {
            "file_size": len(encrypted_data),
            "file_type": type(encrypted_data).__name__,
            "first_100_chars": encrypted_data[:100].hex() if isinstance(encrypted_data, bytes) else str(encrypted_data[:100]),
            "is_base64_likely": False,
            "base64_decode_success": False,
            "latin1_decode_success": False
        }
        
        # Check if it's base64
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data)
            result["is_base64_likely"] = True
            result["base64_decode_success"] = True
            result["decoded_size"] = len(decoded)
        except:
            result["is_base64_likely"] = False
            
        # Check latin1 decode
        try:
            latin1_str = encrypted_data.decode('latin1')
            result["latin1_decode_success"] = True
            result["latin1_length"] = len(latin1_str)
        except:
            result["latin1_decode_success"] = False
            
        return {"success": True, "debug_info": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/{file_path:path}")
async def download_file(file_path: str):
    """Serve decrypted files for download"""
    try:
        if os.path.exists(file_path):
            return FileResponse(
                file_path,
                media_type="application/octet-stream",
                filename=file_path
            )
        else:
            return {"success": False, "error": "File not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}
  
  
  
if __name__ == "__main__":
    print("🎯 Server starting on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
   