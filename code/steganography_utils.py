from PIL import Image
import wave
import io
import numpy as np #type: ignore

class ImageSteganography:
    def hide_message(self, image_data, message):
        """Hide message in image using LSB steganography"""
        try:
            image = Image.open(io.BytesIO(image_data))
            image = image.convert('RGB')
            pixels = image.load()
            
            # Convert message to binary with length prefix
            msg_bytes = message.encode()
            msg_len = len(msg_bytes)
            binary_len = format(msg_len, '032b')
            binary_msg = ''.join(format(byte, '08b') for byte in msg_bytes)
            full_binary = binary_len + binary_msg
            
            width, height = image.size
            max_bits = width * height * 3
            
            if len(full_binary) > max_bits:
                raise Exception("Message too large for image")
            
            bit_idx = 0
            for y in range(height):
                for x in range(width):
                    if bit_idx >= len(full_binary):
                        break
                    
                    r, g, b = pixels[x, y][:3]
                    r = (r & 0xFE) | int(full_binary[bit_idx])
                    bit_idx += 1
                    
                    if bit_idx < len(full_binary):
                        g = (g & 0xFE) | int(full_binary[bit_idx])
                        bit_idx += 1
                    
                    if bit_idx < len(full_binary):
                        b = (b & 0xFE) | int(full_binary[bit_idx])
                        bit_idx += 1
                    
                    pixels[x, y] = (r, g, b)
                
                if bit_idx >= len(full_binary):
                    break
            
            output_path = "encoded_image.png"
            image.save(output_path)
            return output_path
        except Exception as e:
            raise Exception(f"Image encoding failed: {str(e)}")
    
    def extract_message(self, image_data):
        """Extract hidden message from image"""
        try:
            image = Image.open(io.BytesIO(image_data))
            image = image.convert('RGB')
            pixels = image.load()
            
            binary = ""
            width, height = image.size
            
            # Extract length
            for y in range(height):
                for x in range(width):
                    if len(binary) < 32:
                        r, g, b = pixels[x, y][:3]
                        binary += str(r & 1)
                        if len(binary) < 32:
                            binary += str(g & 1)
                        if len(binary) < 32:
                            binary += str(b & 1)
            
            msg_len = int(binary[:32], 2)
            total_bits = 32 + (msg_len * 8)
            
            # Extract message
            binary = ""
            for y in range(height):
                for x in range(width):
                    if len(binary) >= total_bits:
                        break
                    r, g, b = pixels[x, y][:3]
                    binary += str(r & 1)
                    if len(binary) < total_bits:
                        binary += str(g & 1)
                    if len(binary) < total_bits:
                        binary += str(b & 1)
                if len(binary) >= total_bits:
                    break
            
            msg_binary = binary[32:32 + (msg_len * 8)]
            message = ""
            for i in range(0, len(msg_binary), 8):
                byte = msg_binary[i:i+8]
                if len(byte) == 8:
                    message += chr(int(byte, 2))
            
            return message
        except Exception as e:
            raise Exception(f"Image decoding failed: {str(e)}")

class AudioSteganography:
    def hide_message(self, audio_data, message):
        """Hide message in audio using LSB"""
        try:
            with wave.open(io.BytesIO(audio_data), 'rb') as wav_file:
                frames = wav_file.readframes(wav_file.getnframes())
                audio_array = np.frombuffer(frames, dtype=np.int16).copy()
                
                msg_bytes = message.encode()
                msg_len = len(msg_bytes)
                binary_len = format(msg_len, '016b')
                binary_msg = ''.join(format(byte, '08b') for byte in msg_bytes)
                full_binary = binary_len + binary_msg
                
                if len(full_binary) > len(audio_array):
                    raise Exception("Message too large for audio")
                
                for i, bit in enumerate(full_binary):
                    audio_array[i] = (audio_array[i] & 0xFFFE) | int(bit)
                
                output_path = "encoded_audio.wav"
                with wave.open(output_path, 'wb') as output_file:
                    output_file.setnchannels(wav_file.getnchannels())
                    output_file.setsampwidth(wav_file.getsampwidth())
                    output_file.setframerate(wav_file.getframerate())
                    output_file.writeframes(audio_array.astype(np.int16).tobytes())
                
                return output_path
        except Exception as e:
            raise Exception(f"Audio encoding failed: {str(e)}")
    
    def extract_message(self, audio_data):
        """Extract hidden message from audio"""
        try:
            with wave.open(io.BytesIO(audio_data), 'rb') as wav_file:
                frames = wav_file.readframes(wav_file.getnframes())
                audio_array = np.frombuffer(frames, dtype=np.int16)
                
                binary = ''.join(str(sample & 1) for sample in audio_array[:10000])
                
                msg_len = int(binary[:16], 2)
                msg_binary = binary[16:16 + (msg_len * 8)]
                
                message = ""
                for i in range(0, len(msg_binary), 8):
                    byte = msg_binary[i:i+8]
                    if len(byte) == 8:
                        message += chr(int(byte, 2))
                
                return message
        except Exception as e:
            raise Exception(f"Audio decoding failed: {str(e)}")
