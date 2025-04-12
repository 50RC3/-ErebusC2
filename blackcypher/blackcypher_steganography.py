"""
BlackCypher Steganography Module
Provides techniques to hide data within other files
"""
import os
import random
import struct
import wave
import numpy as np
from PIL import Image
from typing import Union, Dict, List, Any, Optional, Tuple, BinaryIO
import io
import base64


class ImageSteganography:
    """Hide data within image files using LSB steganography"""
    
    @staticmethod
    def encode_lsb(image_path: str, data: Union[str, bytes], output_path: Optional[str] = None) -> str:
        """Encode data into an image using Least Significant Bit steganography
        
        Args:
            image_path: Path to the carrier image
            data: Data to hide in the image
            output_path: Path to save the output image (defaults to original with '_steg' suffix)
            
        Returns:
            Path to the output image
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Add length prefix to data
        data_with_len = struct.pack('>I', len(data)) + data
        
        # Open the image
        img = Image.open(image_path)
        
        # Convert to RGBA if not already
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
            
        # Get pixel data as a flat array
        pixels = list(img.getdata())
        
        # Calculate max data size
        max_bytes = (img.width * img.height * 3) // 8  # 3 bits per pixel (using RGB channels)
        
        if len(data_with_len) > max_bytes:
            raise ValueError(f"Data too large for image. Max {max_bytes} bytes, got {len(data_with_len)}")
            
        # Convert data bytes to bits
        data_bits = []
        for byte in data_with_len:
            for i in range(7, -1, -1):  # MSB to LSB
                data_bits.append((byte >> i) & 1)
                
        # Pad with zeros if needed
        data_bits.extend([0] * (8 - (len(data_bits) % 8)) if len(data_bits) % 8 != 0 else [])
        
        # Embed bits in pixels
        new_pixels = []
        idx = 0
        
        for pixel in pixels:
            r, g, b, a = pixel
            
            if idx < len(data_bits):
                # Modify R channel
                r = (r & 0xFE) | data_bits[idx]
                idx += 1
                
            if idx < len(data_bits):
                # Modify G channel
                g = (g & 0xFE) | data_bits[idx]
                idx += 1
                
            if idx < len(data_bits):
                # Modify B channel
                b = (b & 0xFE) | data_bits[idx]
                idx += 1
                
            new_pixels.append((r, g, b, a))
            
            if idx >= len(data_bits):
                # We've encoded all the data
                break
                
        # Append remaining pixels unchanged
        new_pixels.extend(pixels[len(new_pixels):])
        
        # Create new image
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        
        # Save image
        if output_path is None:
            base, ext = os.path.splitext(image_path)
            output_path = f"{base}_steg{ext}"
            
        new_img.save(output_path)
        
        return output_path
    
    @staticmethod
    def decode_lsb(image_path: str) -> bytes:
        """Decode data from an image using Least Significant Bit steganography
        
        Args:
            image_path: Path to the image containing hidden data
            
        Returns:
            Hidden data as bytes
        """
        # Open the image
        img = Image.open(image_path)
        
        # Convert to RGBA if not already
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
            
        # Get pixel data
        pixels = list(img.getdata())
        
        # Extract LSBs
        extracted_bits = []
        
        for pixel in pixels:
            r, g, b, _ = pixel
            
            # Extract from RGB channels
            extracted_bits.append(r & 1)
            extracted_bits.append(g & 1)
            extracted_bits.append(b & 1)
            
            # Check if we have enough bits to extract the length
            if len(extracted_bits) >= 32 and len(extracted_bits) % 8 == 0:
                # Convert first 32 bits to an integer (length prefix)
                length_bits = extracted_bits[:32]
                length_bytes = bytearray()
                
                for i in range(0, 32, 8):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | length_bits[i + j]
                    length_bytes.append(byte)
                    
                data_length = struct.unpack('>I', length_bytes)[0]
                
                # Check if we have enough bits for the full data
                required_bits = 32 + (data_length * 8)
                
                if len(extracted_bits) >= required_bits:
                    # We have enough bits, extract the data
                    data_bits = extracted_bits[32:required_bits]
                    data_bytes = bytearray()
                    
                    for i in range(0, len(data_bits), 8):
                        if i + 8 <= len(data_bits):
                            byte = 0
                            for j in range(8):
                                byte = (byte << 1) | data_bits[i + j]
                            data_bytes.append(byte)
                            
                    return bytes(data_bytes)
        
        # If we get here, we didn't find any valid data
        raise ValueError("No hidden data found in the image")
    
    @staticmethod
    def encode_dct(image_path: str, data: Union[str, bytes], output_path: Optional[str] = None,
                 quality: int = 95) -> str:
        """Encode data using DCT coefficient modification (JPEG steganography)
        
        Args:
            image_path: Path to the carrier image
            data: Data to hide in the image
            output_path: Path to save the output image
            quality: JPEG quality (1-100)
            
        Returns:
            Path to the output image
        """
        try:
            import cv2
        except ImportError:
            raise ImportError("OpenCV (cv2) is required for DCT steganography")
            
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Add length prefix to data and convert to bits
        data_with_len = struct.pack('>I', len(data)) + data
        data_bits = []
        for byte in data_with_len:
            for i in range(7, -1, -1):
                data_bits.append((byte >> i) & 1)
        
        # Load image
        img = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError(f"Could not load image: {image_path}")
            
        # Convert to YCrCb color space
        img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        
        # Split into channels
        y, cr, cb = cv2.split(img_ycrcb)
        
        # Divide into 8x8 blocks
        h, w = y.shape
        blocks_h, blocks_w = h // 8, w // 8
        
        if len(data_bits) > blocks_h * blocks_w:
            raise ValueError(f"Data too large for image. Max {blocks_h * blocks_w} bits, got {len(data_bits)}")
        
        # Embed data bits into DCT coefficients
        bit_idx = 0
        modified = False
        
        for i in range(blocks_h):
            for j in range(blocks_w):
                if bit_idx >= len(data_bits):
                    break
                    
                # Extract 8x8 block
                block = y[i*8:(i+1)*8, j*8:(j+1)*8].copy().astype(np.float32)
                
                # Apply DCT
                dct_block = cv2.dct(block)
                
                # Modify a mid-frequency coefficient (4,4)
                # This location is chosen to be less visually noticeable
                coef = dct_block[4, 4]
                bit = data_bits[bit_idx]
                
                # Quantize coefficient
                if bit == 1:
                    dct_block[4, 4] = round(coef / 2) * 2 + 1  # Make odd
                else:
                    dct_block[4, 4] = round(coef / 2) * 2      # Make even
                
                # Apply inverse DCT
                idct_block = cv2.idct(dct_block)
                
                # Replace block in Y channel
                y[i*8:(i+1)*8, j*8:(j+1)*8] = idct_block.astype(np.uint8)
                
                bit_idx += 1
                modified = True
            
            if bit_idx >= len(data_bits):
                break
        
        if not modified:
            raise ValueError("Failed to encode data")
            
        # Merge channels back
        img_encoded = cv2.merge([y, cr, cb])
        
        # Convert back to BGR
        img_encoded_bgr = cv2.cvtColor(img_encoded, cv2.COLOR_YCrCb2BGR)
        
        # Save image
        if output_path is None:
            base, ext = os.path.splitext(image_path)
            output_path = f"{base}_steg_dct.jpg"
            
        cv2.imwrite(output_path, img_encoded_bgr, [cv2.IMWRITE_JPEG_QUALITY, quality])
        
        return output_path
    
    @staticmethod
    def decode_dct(image_path: str) -> bytes:
        """Decode data hidden using DCT coefficient modification
        
        Args:
            image_path: Path to the image with hidden data
            
        Returns:
            Hidden data as bytes
        """
        try:
            import cv2
        except ImportError:
            raise ImportError("OpenCV (cv2) is required for DCT steganography")
            
        # Load image
        img = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError(f"Could not load image: {image_path}")
            
        # Convert to YCrCb color space
        img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        
        # Get Y channel
        y, _, _ = cv2.split(img_ycrcb)
        
        # Divide into 8x8 blocks
        h, w = y.shape
        blocks_h, blocks_w = h // 8, w // 8
        
        # Extract bits from DCT coefficients
        extracted_bits = []
        
        for i in range(blocks_h):
            for j in range(blocks_w):
                # Extract 8x8 block
                block = y[i*8:(i+1)*8, j*8:(j+1)*8].copy().astype(np.float32)
                
                # Apply DCT
                dct_block = cv2.dct(block)
                
                # Extract bit from coefficient (4,4)
                coef = dct_block[4, 4]
                bit = int(round(coef) % 2)  # LSB of rounded coefficient
                extracted_bits.append(bit)
                
                # Check if we have enough bits for the length
                if len(extracted_bits) == 32:
                    # Convert first 32 bits to length
                    length_bytes = bytearray()
                    for k in range(0, 32, 8):
                        byte = 0
                        for l in range(8):
                            byte = (byte << 1) | extracted_bits[k + l]
                        length_bytes.append(byte)
                        
                    data_length = struct.unpack('>I', length_bytes)[0]
                    total_bits_needed = 32 + (data_length * 8)
                    
                if len(extracted_bits) > 32 and 'data_length' in locals():
                    if len(extracted_bits) >= total_bits_needed:
                        # We have all the data
                        break
            
            if 'total_bits_needed' in locals() and len(extracted_bits) >= total_bits_needed:
                break
        
        # Process extracted bits
        if 'data_length' not in locals() or len(extracted_bits) < 32 + (data_length * 8):
            raise ValueError("No valid data found in image")
            
        # Extract data bytes
        data_bits = extracted_bits[32:32 + (data_length * 8)]
        data_bytes = bytearray()
        
        for i in range(0, len(data_bits), 8):
            if i + 8 <= len(data_bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | data_bits[i + j]
                data_bytes.append(byte)
                
        return bytes(data_bytes)


class AudioSteganography:
    """Hide data within audio files"""
    
    @staticmethod
    def encode_lsb_wav(audio_path: str, data: Union[str, bytes], output_path: Optional[str] = None) -> str:
        """Encode data into a WAV file using Least Significant Bit steganography
        
        Args:
            audio_path: Path to the carrier WAV file
            data: Data to hide in the audio
            output_path: Path to save the output WAV file
            
        Returns:
            Path to the output WAV file
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Add length prefix to data
        data_with_len = struct.pack('>I', len(data)) + data
        
        # Open the WAV file
        with wave.open(audio_path, 'rb') as wav:
            # Get WAV parameters
            n_channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            framerate = wav.getframerate()
            n_frames = wav.getnframes()
            
            # Read all frames
            frames = wav.readframes(n_frames)
        
        # Calculate max data size
        max_bytes = (len(frames) // sample_width) // 8  # 1 bit per sample
        
        if len(data_with_len) > max_bytes:
            raise ValueError(f"Data too large for audio file. Max {max_bytes} bytes, got {len(data_with_len)}")
            
        # Convert data bytes to bits
        data_bits = []
        for byte in data_with_len:
            for i in range(7, -1, -1):  # MSB to LSB
                data_bits.append((byte >> i) & 1)
                
        # Embed bits in audio samples
        frames_array = bytearray(frames)
        bit_idx = 0
        
        for i in range(0, len(frames), sample_width):
            if bit_idx >= len(data_bits):
                break
                
            # Modify LSB of first byte of each sample
            frames_array[i] = (frames_array[i] & 0xFE) | data_bits[bit_idx]
            bit_idx += 1
        
        # Create output file
        if output_path is None:
            base, ext = os.path.splitext(audio_path)
            output_path = f"{base}_steg{ext}"
            
        with wave.open(output_path, 'wb') as wav_out:
            wav_out.setparams((n_channels, sample_width, framerate, n_frames, 'NONE', 'not compressed'))
            wav_out.writeframes(frames_array)
            
        return output_path
    
    @staticmethod
    def decode_lsb_wav(audio_path: str) -> bytes:
        """Decode data from a WAV file using Least Significant Bit steganography
        
        Args:
            audio_path: Path to the WAV file containing hidden data
            
        Returns:
            Hidden data as bytes
        """
        # Open the WAV file
        with wave.open(audio_path, 'rb') as wav:
            # Get WAV parameters
            sample_width = wav.getsampwidth()
            n_frames = wav.getnframes()
            
            # Read all frames
            frames = wav.readframes(n_frames)
        
        # Extract LSBs
        extracted_bits = []
        for i in range(0, len(frames), sample_width):
            extracted_bits.append(frames[i] & 1)
            
            # Check if we have enough bits to extract the length
            if len(extracted_bits) >= 32 and len(extracted_bits) % 8 == 0:
                # Convert first 32 bits to an integer (length prefix)
                length_bits = extracted_bits[:32]
                length_bytes = bytearray()
                
                for i in range(0, 32, 8):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | length_bits[i + j]
                    length_bytes.append(byte)
                    
                data_length = struct.unpack('>I', length_bytes)[0]
                
                # Check if we have enough bits for the full data
                required_bits = 32 + (data_length * 8)
                
                if len(extracted_bits) >= required_bits:
                    # We have enough bits, extract the data
                    data_bits = extracted_bits[32:required_bits]
                    data_bytes = bytearray()
                    
                    for i in range(0, len(data_bits), 8):
                        if i + 8 <= len(data_bits):
                            byte = 0
                            for j in range(8):
                                byte = (byte << 1) | data_bits[i + j]
                            data_bytes.append(byte)
                            
                    return bytes(data_bytes)
        
        # If we get here, we didn't find any valid data
        raise ValueError("No hidden data found in the audio file")
    
    @staticmethod
    def encode_echo(audio_path: str, data: Union[str, bytes], output_path: Optional[str] = None, 
                   delay: float = 0.001, decay: float = 0.5) -> str:
        """Encode data in an audio file using echo hiding
        
        Args:
            audio_path: Path to the carrier audio file
            data: Data to hide in the audio
            output_path: Path to save the output audio file
            delay: Echo delay in seconds for bit 1 (bit 0 uses delay/2)
            decay: Echo amplitude decay factor
            
        Returns:
            Path to the output audio file
        """
        try:
            import scipy.io.wavfile as wavfile
        except ImportError:
            raise ImportError("scipy is required for echo hiding steganography")
            
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Add length prefix to data
        data_with_len = struct.pack('>I', len(data)) + data
        
        # Convert data bytes to bits
        data_bits = []
        for byte in data_with_len:
            for i in range(7, -1, -1):  # MSB to LSB
                data_bits.append((byte >> i) & 1)
                
        # Read audio file
        sample_rate, audio_data = wavfile.read(audio_path)
        
        # Convert to mono if stereo
        if len(audio_data.shape) > 1:
            audio_data = audio_data[:, 0]
            
        # Calculate echo parameters in samples
        delay1 = int(delay * sample_rate)  # Delay for bit 1
        delay0 = delay1 // 2               # Delay for bit 0
        
        # Split audio into chunks
        chunk_size = sample_rate // 4  # 0.25 seconds per chunk
        n_chunks = len(audio_data) // chunk_size
        
        if n_chunks < len(data_bits):
            raise ValueError(f"Audio file too short for the data. Need {len(data_bits)} chunks, have {n_chunks}.")
            
        # Create output audio array
        output_audio = np.copy(audio_data)
        
        # Apply echo to each chunk based on bit value
        for i, bit in enumerate(data_bits):
            if i >= n_chunks:
                break
                
            start = i * chunk_size
            end = start + chunk_size
            
            chunk = audio_data[start:end]
            
            # Create echo
            echo_delay = delay1 if bit == 1 else delay0
            echo = np.zeros_like(chunk)
            echo[echo_delay:] = chunk[:len(chunk)-echo_delay] * decay
            
            # Add echo to original
            output_audio[start:end] = chunk + echo
            
        # Normalize to avoid clipping
        max_val = np.iinfo(audio_data.dtype).max
        if output_audio.max() > max_val:
            output_audio = output_audio * (max_val / output_audio.max())
            
        # Create output file
        if output_path is None:
            base, ext = os.path.splitext(audio_path)
            output_path = f"{base}_steg_echo{ext}"
            
        # Save as WAV
        wavfile.write(output_path, sample_rate, output_audio.astype(audio_data.dtype))
        
        return output_path
    
    @staticmethod
    def decode_echo(audio_path: str, delay1: float = 0.001) -> bytes:
        """Decode data hidden using echo hiding
        
        Args:
            audio_path: Path to the audio file with hidden data
            delay1: Echo delay in seconds used for bit 1 (bit 0 uses delay1/2)
            
        Returns:
            Hidden data as bytes
        """
        try:
            import scipy.io.wavfile as wavfile
            from scipy import signal
        except ImportError:
            raise ImportError("scipy is required for echo hiding steganography")
            
        # Read audio file
        sample_rate, audio_data = wavfile.read(audio_path)
        
        # Convert to mono if stereo
        if len(audio_data.shape) > 1:
            audio_data = audio_data[:, 0]
            
        # Calculate echo parameters in samples
        delay1_samples = int(delay1 * sample_rate)
        delay0_samples = delay1_samples // 2
        
        # Split audio into chunks
        chunk_size = sample_rate // 4  # 0.25 seconds per chunk
        n_chunks = len(audio_data) // chunk_size
        
        # Extract bits from each chunk
        extracted_bits = []
        
        for i in range(n_chunks):
            start = i * chunk_size
            end = start + chunk_size
            
            chunk = audio_data[start:end]
            
            # Calculate auto-correlation
            corr = signal.correlate(chunk, chunk, mode='full')
            corr = corr[len(corr)//2:]  # Take only the positive lags
            
            # Look for peaks at delay0 and delay1
            if delay1_samples < len(corr) and delay0_samples < len(corr):
                peak0 = corr[delay0_samples]
                peak1 = corr[delay1_samples]
                
                # Determine bit value based on which peak is stronger
                bit = 1 if peak1 > peak0 else 0
                extracted_bits.append(bit)
                
                # Check if we have enough bits for the length
                if len(extracted_bits) == 32:
                    # Convert first 32 bits to length
                    length_bytes = bytearray()
                    for k in range(0, 32, 8):
                        byte = 0
                        for l in range(8):
                            byte = (byte << 1) | extracted_bits[k + l]
                        length_bytes.append(byte)
                        
                    data_length = struct.unpack('>I', length_bytes)[0]
                    total_bits_needed = 32 + (data_length * 8)
                    
                if len(extracted_bits) > 32 and 'data_length' in locals():
                    if len(extracted_bits) >= total_bits_needed:
                        # We have all the data
                        break
        
        # Process extracted bits
        if 'data_length' not in locals() or len(extracted_bits) < 32 + (data_length * 8):
            raise ValueError("No valid data found in audio file")
            
        # Extract data bytes
        data_bits = extracted_bits[32:32 + (data_length * 8)]
        data_bytes = bytearray()
        
        for i in range(0, len(data_bits), 8):
            if i + 8 <= len(data_bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | data_bits[i + j]
                data_bytes.append(byte)
                
        return bytes(data_bytes)


class DocumentSteganography:
    """Hide data within document files"""
    
    @staticmethod
    def encode_whitespace(text: str, data: Union[str, bytes]) -> str:
        """Encode data in text using whitespace steganography (space, tab, EOL variations)
        
        Args:
            text: Carrier text
            data: Data to hide in the text
            
        Returns:
            Text with hidden data
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Add length prefix to data
        data_with_len = struct.pack('>I', len(data)) + data
        
        # Convert data bytes to bits
        data_bits = []
        for byte in data_with_len:
            for i in range(7, -1, -1):  # MSB to LSB
                data_bits.append((byte >> i) & 1)
                
        # Split text into lines
        lines = text.splitlines()
        
        # Calculate max capacity
        max_bits = sum(1 for line in lines if line.strip())
        
        if len(data_bits) > max_bits:
            raise ValueError(f"Data too large for text. Max {max_bits // 8} bytes, got {len(data_with_len)}")
            
        # Embed bits using line endings
        # 0 = single space at end of line
        # 1 = double space at end of line
        encoded_lines = []
        bit_idx = 0
        
        for line in lines:
            if bit_idx >= len(data_bits):
                # Add remaining lines unchanged
                encoded_lines.append(line.rstrip())
                continue
                
            if line.strip():  # Only use non-empty lines
                # Remove any existing trailing spaces
                line_stripped = line.rstrip()
                
                # Add spaces based on bit value
                if data_bits[bit_idx] == 0:
                    encoded_lines.append(line_stripped + ' ')
                else:
                    encoded_lines.append(line_stripped + '  ')
                    
                bit_idx += 1
            else:
                # Keep empty lines as is
                encoded_lines.append(line)
        
        # Join lines back together
        return '\n'.join(encoded_lines)
    
    @staticmethod
    def decode_whitespace(text: str) -> bytes:
        """Decode data hidden using whitespace steganography
        
        Args:
            text: Text containing hidden data
            
        Returns:
            Hidden data as bytes
        """
        # Split text into lines
        lines = text.splitlines()
        
        # Extract bits from line endings
        extracted_bits = []
        
        for line in lines:
            if not line.strip():
                # Skip empty lines
                continue
                
            # Count trailing spaces
            spaces = len(line) - len(line.rstrip())
            
            if spaces > 0:
                # Extract bit (0 = one space, 1 = two or more spaces)
                bit = 1 if spaces >= 2 else 0
                extracted_bits.append(bit)
                
                # Check if we have enough bits for the length
                if len(extracted_bits) == 32:
                    # Convert first 32 bits to length
                    length_bytes = bytearray()
                    for k in range(0, 32, 8):
                        byte = 0
                        for l in range(8):
                            byte = (byte << 1) | extracted_bits[k + l]
                        length_bytes.append(byte)
                        
                    data_length = struct.unpack('>I', length_bytes)[0]
                    total_bits_needed = 32 + (data_length * 8)
                    
                if len(extracted_bits) > 32 and 'data_length' in locals():
                    if len(extracted_bits) >= total_bits_needed:
                        # We have all the data
                        break
        
        # Process extracted bits
        if 'data_length' not in locals() or len(extracted_bits) < 32 + (data_length * 8):
            raise ValueError("No valid data found in text")
            
        # Extract data bytes
        data_bits = extracted_bits[32:32 + (data_length * 8)]
        data_bytes = bytearray()
        
        for i in range(0, len(data_bits), 8):
            if i + 8 <= len(data_bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | data_bits[i + j]
                data_bytes.append(byte)
                
        return bytes(data_bytes)
    
    @staticmethod
    def encode_unicode(text: str, data: Union[str, bytes]) -> str:
        """Encode data in text using invisible Unicode characters
        
        Args:
            text: Carrier text
            data: Data to hide in the text
            
        Returns:
            Text with hidden data
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Add length prefix to data
        data_with_len = struct.pack('>I', len(data)) + data
        
        # Unicode zero-width characters for encoding:
        # - Zero-width space (U+200B) = 0
        # - Zero-width non-joiner (U+200C) = 1
        zero_width_0 = '\u200B'  # Zero-width space
        zero_width_1 = '\u200C'  # Zero-width non-joiner
        
        # Encode each byte
        hidden_data = ''
        for byte in data_with_len:
            for i in range(7, -1, -1):  # MSB to LSB
                bit = (byte >> i) & 1
                hidden_data += zero_width_1 if bit else zero_width_0
        
        # Insert hidden data at the beginning of the text
        # In a real implementation, you might want to spread it throughout the text
        return hidden_data + text
    
    @staticmethod
    def decode_unicode(text: str) -> bytes:
        """Decode data hidden using invisible Unicode characters
        
        Args:
            text: Text containing hidden data
            
        Returns:
            Hidden data as bytes
        """
        # Unicode zero-width characters used for encoding
        zero_width_0 = '\u200B'  # Zero-width space
        zero_width_1 = '\u200C'  # Zero-width non-joiner
        
        # Extract bits
        extracted_bits = []
        for char in text:
            if char == zero_width_0:
                extracted_bits.append(0)
            elif char == zero_width_1:
                extracted_bits.append(1)
                
        # Check if we have enough bits for the length
        if len(extracted_bits) < 32:
            raise ValueError("No valid data found in text")
            
        # Convert first 32 bits to length
        length_bytes = bytearray()
        for i in range(0, 32, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | extracted_bits[i + j]
            length_bytes.append(byte)
            
        data_length = struct.unpack('>I', length_bytes)[0]
        total_bits_needed = 32 + (data_length * 8)
        
        if len(extracted_bits) < total_bits_needed:
            raise ValueError("Incomplete data found in text")
            
        # Extract data bytes
        data_bits = extracted_bits[32:32 + (data_length * 8)]
        data_bytes = bytearray()
        
        for i in range(0, len(data_bits), 8):
            if i + 8 <= len(data_bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | data_bits[i + j]
                data_bytes.append(byte)
                
        return bytes(data_bytes)


class NetworkSteganography:
    """Hide data within network traffic"""
    
    @staticmethod
    def encode_tcp_header(data: Union[str, bytes], max_size: int = 2048) -> Dict[str, Any]:
        """Encode data into TCP packet headers
        
        Args:
            data: Data to hide in TCP headers
            max_size: Maximum size of data in bytes
            
        Returns:
            Dictionary with encoded packet definitions
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if len(data) > max_size:
            raise ValueError(f"Data too large. Max {max_size} bytes, got {len(data)} bytes")
            
        # Add length prefix
        data_with_len = struct.pack('>I', len(data)) + data
        
        # Each TCP header can hide 32 bits (sequence number) + 32 bits (ack number)
        # = 8 bytes per packet
        packets_needed = (len(data_with_len) + 7) // 8
        packets = []
        
        for i in range(packets_needed):
            # Extract up to 8 bytes for this packet
            start = i * 8
            end = min(start + 8, len(data_with_len))
            packet_data = data_with_len[start:end]
            
            # Pad to 8 bytes if needed
            packet_data = packet_data.ljust(8, b'\x00')
            
            # Split into sequence and ack numbers (4 bytes each)
            seq_num = int.from_bytes(packet_data[:4], byteorder='big')
            ack_num = int.from_bytes(packet_data[4:], byteorder='big')
            
            # Create packet definition
            packet = {
                "index": i,
                "total": packets_needed,
                "seq_num": seq_num,
                "ack_num": ack_num
            }
            
            packets.append(packet)
            
        return {
            "packets": packets,
            "original_size": len(data)
        }
    
    @staticmethod
    def decode_tcp_header(packet_data: Dict[str, Any]) -> bytes:
        """Decode data hidden in TCP packet headers
        
        Args:
            packet_data: Dictionary with encoded packet definitions
            
        Returns:
            Hidden data as bytes
        """
        packets = packet_data["packets"]
        
        # Sort packets by index
        packets.sort(key=lambda p: p["index"])
        
        # Reconstruct data
        data_bytes = bytearray()
        
        for packet in packets:
            # Extract sequence and ack numbers
            seq_bytes = packet["seq_num"].to_bytes(4, byteorder='big')
            ack_bytes = packet["ack_num"].to_bytes(4, byteorder='big')
            
            # Combine bytes
            data_bytes.extend(seq_bytes + ack_bytes)
            
        # Extract length
        data_length = struct.unpack('>I', data_bytes[:4])[0]
        
        # Extract actual data
        return data_bytes[4:4+data_length]
    
    @staticmethod
    def encode_dns_tunneling(data: Union[str, bytes], domain: str) -> List[str]:
        """Encode data for DNS tunneling
        
        Args:
            data: Data to tunnel through DNS
            domain: Domain name to use for tunneling
            
        Returns:
            List of DNS queries with encoded data
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Add length prefix
        data_with_len = struct.pack('>I', len(data)) + data
        
        # Base32 encode the data to make it DNS-safe
        # (case-insensitive, avoids special characters)
        encoded = base64.b32encode(data_with_len).decode('ascii').lower()
        
        # Split into chunks (max 63 chars per DNS label)
        label_size = 63
        chunks = []
        
        for i in range(0, len(encoded), label_size):
            chunks.append(encoded[i:i+label_size])
            
        # Add chunk index and total to help with reassembly
        queries = []
        for i, chunk in enumerate(chunks):
            # Format: <chunk>-<index>-<total>.<domain>
            query = f"{chunk}-{i+1}-{len(chunks)}.{domain}"
            queries.append(query)
            
        return queries
    
    @staticmethod
    def decode_dns_tunneling(queries: List[str]) -> bytes:
        """Decode data from DNS tunneling queries
        
        Args:
            queries: List of DNS queries with encoded data
            
        Returns:
            Hidden data as bytes
        """
        # Extract chunks from queries
        chunks = []
        
        for query in queries:
            # Split at the first dot to separate the data from the domain
            parts = query.split('.', 1)
            if len(parts) < 1:
                continue
                
            # Split the chunk info
            chunk_parts = parts[0].split('-')
            if len(chunk_parts) < 3:
                continue
                
            chunk = chunk_parts[0]
            index = int(chunk_parts[1])
            total = int(chunk_parts[2])
            
            chunks.append((index, chunk))
            
        # Sort chunks by index
        chunks.sort(key=lambda c: c[0])
        
        # Concatenate chunks
        encoded = ''.join(c[1] for c in chunks)
        
        # Base32 decode
        data_with_len = base64.b32decode(encoded.upper())
        
        # Extract length
        data_length = struct.unpack('>I', data_with_len[:4])[0]
        
        # Extract data
        return data_with_len[4:4+data_length]


# Example usage
if __name__ == "__main__":
    # Test image steganography
    img_steg = ImageSteganography()
    secret_data = "This is a secret message for ErebusC2"
    
    try:
        # Hide data in an image
        output_path = img_steg.encode_lsb("cover_image.png", secret_data)
        print(f"Data hidden in image: {output_path}")
        
        # Retrieve data from the image
        decoded = img_steg.decode_lsb(output_path)
        print(f"Decoded data: {decoded.decode('utf-8')}")
    except Exception as e:
        print(f"Image steganography test error: {e}")