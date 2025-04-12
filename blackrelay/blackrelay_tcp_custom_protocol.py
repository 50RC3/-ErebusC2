"""
BlackRelay TCP Custom Protocol
Implementation of custom TCP protocol for covert communications
"""
import socket
import threading
import queue
import time
import struct
import os
import logging
import json
import hashlib
from typing import Dict, Any, Optional, List, Tuple, Union, Callable

try:
    from blackcypher.encryption import SymmetricEncryption, AsymmetricEncryption
except ImportError:
    # Fallback for standalone testing
    from encryptor import SymmetricEncryption, AsymmetricEncryption


class TcpCustomProtocol:
    """Custom TCP protocol implementation for covert communications"""
    
    # Protocol constants
    PROTOCOL_VERSION = 1
    
    # Message types
    MSG_TYPE_HELLO = 0x01
    MSG_TYPE_DATA = 0x02
    MSG_TYPE_ACK = 0x03
    MSG_TYPE_COMMAND = 0x04
    MSG_TYPE_RESPONSE = 0x05
    MSG_TYPE_ERROR = 0xFF
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the TCP custom protocol handler
        
        Args:
            config: Protocol configuration
        """
        self.config = config
        self.logger = logging.getLogger("BlackRelay.TcpCustomProtocol")
        self.running = False
        
        # Extract configuration
        self.listen_address = config.get("listen_address", "0.0.0.0")
        self.port = config.get("port", 8765)
        self.protocol_signature = bytes.fromhex(config.get("protocol_signature", "AE0X").encode().hex())
        self.header_length = config.get("header_length", 8)
        self.encryption_type = config.get("encryption", "aes256")
        
        # Connection management
        self.server_socket = None
        self.connections = {}
        self.connection_lock = threading.RLock()
        
        # Message queues for each connection
        self.send_queues = {}
        self.receive_queue = queue.Queue()
        
        # Callbacks
        self.data_handler = None
        
        # Setup encryption
        self.encryption_keys = {}
        self._setup_encryption()
    
    def _setup_encryption(self):
        """Setup encryption keys"""
        # Generate a master key for this instance
        self.master_key = os.urandom(32)  # 256-bit key for AES-256
    
    def start(self):
        """Start the TCP custom protocol server"""
        if self.running:
            return
            
        self.running = True
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.listen_address, self.port))
            self.server_socket.listen(5)
            
            # Start listener thread
            self.listener_thread = threading.Thread(target=self._listener_loop)
            self.listener_thread.daemon = True
            self.listener_thread.start()
            
            # Start processor thread
            self.processor_thread = threading.Thread(target=self._process_received_messages)
            self.processor_thread.daemon = True
            self.processor_thread.start()
            
            self.logger.info(f"TCP Custom Protocol server started on {self.listen_address}:{self.port}")
        except Exception as e:
            self.logger.error(f"Failed to start TCP Custom Protocol server: {e}")
            self.running = False
    
    def stop(self):
        """Stop the TCP custom protocol server"""
        if not self.running:
            return
            
        self.running = False
        
        # Close all connections
        with self.connection_lock:
            for conn_id, conn_data in list(self.connections.items()):
                try:
                    conn_data["socket"].close()
                except:
                    pass
            
            self.connections.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            
        self.server_socket = None
        
        self.logger.info("TCP Custom Protocol server stopped")
    
    def connect(self, address: str, port: int) -> Optional[str]:
        """Connect to a remote server
        
        Args:
            address: Remote server address
            port: Remote server port
            
        Returns:
            Connection ID if successful, None otherwise
        """
        try:
            # Create client socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)  # 10-second timeout for connection
            
            # Connect to server
            client_socket.connect((address, port))
            
            # Generate connection ID
            connection_id = hashlib.md5(f"{address}:{port}:{time.time()}".encode()).hexdigest()
            
            # Setup connection
            with self.connection_lock:
                self.connections[connection_id] = {
                    "socket": client_socket,
                    "address": address,
                    "port": port,
                    "connected": time.time(),
                    "last_activity": time.time(),
                    "direction": "outbound",
                    "session_key": os.urandom(32),  # Generate session key
                    "sequence": 0
                }
                
                # Create send queue for this connection
                self.send_queues[connection_id] = queue.Queue()
            
            # Start handler thread for this connection
            handler_thread = threading.Thread(
                target=self._connection_handler,
                args=(connection_id,)
            )
            handler_thread.daemon = True
            handler_thread.start()
            
            # Start sender thread for this connection
            sender_thread = threading.Thread(
                target=self._connection_sender,
                args=(connection_id,)
            )
            sender_thread.daemon = True
            sender_thread.start()
            
            # Perform handshake
            self._send_hello(connection_id)
            
            self.logger.info(f"Connected to {address}:{port} (connection ID: {connection_id})")
            
            return connection_id
        except Exception as e:
            self.logger.error(f"Failed to connect to {address}:{port}: {e}")
            return None
    
    def send_data(self, data: Union[str, bytes], connection_id: Optional[str] = None) -> bool:
        """Send data over a connection
        
        Args:
            data: Data to send
            connection_id: Connection ID (optional, if None will send to all)
            
        Returns:
            True if successful, False otherwise
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        with self.connection_lock:
            if connection_id:
                # Send to specific connection
                if connection_id not in self.connections:
                    self.logger.error(f"Unknown connection ID: {connection_id}")
                    return False
                    
                if connection_id not in self.send_queues:
                    self.logger.error(f"No send queue for connection ID: {connection_id}")
                    return False
                    
                # Queue the message
                self.send_queues[connection_id].put({
                    "type": self.MSG_TYPE_DATA,
                    "data": data
                })
            else:
                # Broadcast to all connections
                if not self.connections:
                    self.logger.warning("No active connections to send data to")
                    return False
                    
                # Queue the message for each connection
                for conn_id, queue in self.send_queues.items():
                    queue.put({
                        "type": self.MSG_TYPE_DATA,
                        "data": data
                    })
            
            return True
    
    def send_command(self, command: str, params: Dict[str, Any], 
                    connection_id: Optional[str] = None) -> bool:
        """Send a command over a connection
        
        Args:
            command: Command name
            params: Command parameters
            connection_id: Connection ID (optional, if None will send to all)
            
        Returns:
            True if successful, False otherwise
        """
        # Create command message
        command_data = {
            "cmd": command,
            "params": params,
            "timestamp": time.time()
        }
        
        # Encode as JSON
        encoded_command = json.dumps(command_data).encode('utf-8')
        
        with self.connection_lock:
            if connection_id:
                # Send to specific connection
                if connection_id not in self.connections:
                    self.logger.error(f"Unknown connection ID: {connection_id}")
                    return False
                    
                if connection_id not in self.send_queues:
                    self.logger.error(f"No send queue for connection ID: {connection_id}")
                    return False
                    
                # Queue the message
                self.send_queues[connection_id].put({
                    "type": self.MSG_TYPE_COMMAND,
                    "data": encoded_command
                })
            else:
                # Broadcast to all connections
                if not self.connections:
                    self.logger.warning("No active connections to send command to")
                    return False
                    
                # Queue the message for each connection
                for conn_id, queue in self.send_queues.items():
                    queue.put({
                        "type": self.MSG_TYPE_COMMAND,
                        "data": encoded_command
                    })
            
            return True
    
    def register_data_handler(self, handler: Callable):
        """Register a handler for received data
        
        Args:
            handler: Function to call when data is received
        """
        self.data_handler = handler
    
    def _listener_loop(self):
        """Main loop for accepting new connections"""
        self.server_socket.settimeout(1.0)  # 1-second timeout to check if still running
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                
                # Generate connection ID
                connection_id = hashlib.md5(f"{client_address[0]}:{client_address[1]}:{time.time()}".encode()).hexdigest()
                
                # Setup connection
                with self.connection_lock:
                    self.connections[connection_id] = {
                        "socket": client_socket,
                        "address": client_address[0],
                        "port": client_address[1],
                        "connected": time.time(),
                        "last_activity": time.time(),
                        "direction": "inbound",
                        "session_key": None,  # Will be set during handshake
                        "sequence": 0
                    }
                    
                    # Create send queue for this connection
                    self.send_queues[connection_id] = queue.Queue()
                
                # Start handler thread for this connection
                handler_thread = threading.Thread(
                    target=self._connection_handler,
                    args=(connection_id,)
                )
                handler_thread.daemon = True
                handler_thread.start()
                
                # Start sender thread for this connection
                sender_thread = threading.Thread(
                    target=self._connection_sender,
                    args=(connection_id,)
                )
                sender_thread.daemon = True
                sender_thread.start()
                
                self.logger.info(f"Accepted connection from {client_address[0]}:{client_address[1]} (connection ID: {connection_id})")
                
            except socket.timeout:
                # This is expected for the non-blocking check
                pass
            except Exception as e:
                if self.running:  # Only log if we're still running
                    self.logger.error(f"Error in listener loop: {e}")
    
    def _connection_handler(self, connection_id: str):
        """Handle a connection
        
        Args:
            connection_id: Connection ID
        """
        with self.connection_lock:
            if connection_id not in self.connections:
                self.logger.error(f"Unknown connection ID: {connection_id}")
                return
                
            connection = self.connections[connection_id]
            client_socket = connection["socket"]
        
        try:
            # Set a timeout to check if we're still running
            client_socket.settimeout(1.0)
            
            while self.running:
                try:
                    # Read header
                    header = client_socket.recv(self.header_length)
                    if not header:
                        # Connection closed
                        break
                    
                    # Check protocol signature
                    if not header.startswith(self.protocol_signature):
                        self.logger.warning(f"Invalid protocol signature from {connection['address']}:{connection['port']}")
                        continue
                    
                    # Parse header
                    msg_type = header[4]
                    msg_length = struct.unpack("!H", header[5:7])[0]
                    msg_sequence = header[7]
                    
                    # Read message
                    message = b""
                    bytes_read = 0
                    
                    while bytes_read < msg_length:
                        chunk = client_socket.recv(min(4096, msg_length - bytes_read))
                        if not chunk:
                            # Connection closed mid-message
                            raise ConnectionError("Connection closed while reading message")
                            
                        message += chunk
                        bytes_read += len(chunk)
                    
                    # Process message
                    self._process_message(connection_id, msg_type, message, msg_sequence)
                    
                except socket.timeout:
                    # This is expected for the non-blocking check
                    pass
                except ConnectionError as e:
                    self.logger.error(f"Connection error for {connection_id}: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error handling connection {connection_id}: {e}")
        finally:
            # Clean up connection
            self._close_connection(connection_id)
    
    def _connection_sender(self, connection_id: str):
        """Send queued messages on a connection
        
        Args:
            connection_id: Connection ID
        """
        while self.running:
            try:
                # Check if connection still exists
                with self.connection_lock:
                    if connection_id not in self.connections or connection_id not in self.send_queues:
                        break
                        
                    connection = self.connections[connection_id]
                    send_queue = self.send_queues[connection_id]
                
                try:
                    # Get message from queue with timeout
                    message = send_queue.get(timeout=1.0)
                    
                    # Send message
                    self._send_message(connection_id, message["type"], message["data"])
                    
                    # Mark as done
                    send_queue.task_done()
                    
                except queue.Empty:
                    # No message to send
                    pass
                    
            except Exception as e:
                self.logger.error(f"Error in sender thread for {connection_id}: {e}")
                break
    
    def _process_received_messages(self):
        """Process received messages"""
        while self.running:
            try:
                # Get message from queue with timeout
                try:
                    message = self.receive_queue.get(timeout=1.0)
                    
                    # Extract message data
                    connection_id = message["connection_id"]
                    msg_type = message["type"]
                    data = message["data"]
                    
                    # Handle based on message type
                    if msg_type == self.MSG_TYPE_DATA:
                        # Data message
                        if self.data_handler:
                            with self.connection_lock:
                                if connection_id in self.connections:
                                    connection = self.connections[connection_id]
                                    source = f"{connection['address']}:{connection['port']}"
                                else:
                                    source = "unknown"
                                    
                            self.data_handler(data, source, connection_id)
                            
                    elif msg_type == self.MSG_TYPE_COMMAND:
                        # Command message
                        try:
                            command_data = json.loads(data.decode('utf-8'))
                            self.logger.info(f"Received command: {command_data['cmd']} from {connection_id}")
                            
                            # Process command (implementation depends on specific commands)
                            # ...
                            
                            # Send response
                            response = {
                                "status": "ok",
                                "timestamp": time.time()
                            }
                            
                            self.send_queues[connection_id].put({
                                "type": self.MSG_TYPE_RESPONSE,
                                "data": json.dumps(response).encode('utf-8')
                            })
                            
                        except json.JSONDecodeError:
                            self.logger.error(f"Invalid command format from {connection_id}")
                            
                    elif msg_type == self.MSG_TYPE_HELLO:
                        # Hello message (handshake)
                        self._process_hello(connection_id, data)
                        
                    elif msg_type == self.MSG_TYPE_RESPONSE:
                        # Response message
                        self.logger.debug(f"Received response from {connection_id}")
                        
                    # Mark as done
                    self.receive_queue.task_done()
                    
                except queue.Empty:
                    # No message to process
                    pass
            except Exception as e:
                self.logger.error(f"Error processing received message: {e}")
    
    def _process_message(self, connection_id: str, msg_type: int, message: bytes, sequence: int):
        """Process a received message
        
        Args:
            connection_id: Connection ID
            msg_type: Message type
            message: Message data
            sequence: Message sequence number
        """
        with self.connection_lock:
            if connection_id not in self.connections:
                self.logger.error(f"Unknown connection ID: {connection_id}")
                return
                
            connection = self.connections[connection_id]
            
            # Update last activity
            connection["last_activity"] = time.time()
        
        try:
            # Decrypt message if we have a session key
            session_key = connection.get("session_key")
            
            if session_key:
                # Split into IV and ciphertext
                iv = message[:12]
                ciphertext = message[12:-16]
                tag = message[-16:]
                
                # Decrypt
                try:
                    plaintext = SymmetricEncryption.decrypt({
                        'iv': iv,
                        'ciphertext': ciphertext,
                        'tag': tag
                    }, session_key)
                except Exception as e:
                    self.logger.error(f"Decryption failed for message from {connection_id}: {e}")
                    return
            else:
                # No session key yet (or hello message)
                plaintext = message
            
            # Queue for processing
            self.receive_queue.put({
                "connection_id": connection_id,
                "type": msg_type,
                "data": plaintext,
                "sequence": sequence
            })
            
        except Exception as e:
            self.logger.error(f"Error processing message from {connection_id}: {e}")
    
    def _send_message(self, connection_id: str, msg_type: int, data: bytes) -> bool:
        """Send a message on a connection
        
        Args:
            connection_id: Connection ID
            msg_type: Message type
            data: Message data
            
        Returns:
            True if successful, False otherwise
        """
        with self.connection_lock:
            if connection_id not in self.connections:
                self.logger.error(f"Unknown connection ID: {connection_id}")
                return False
                
            connection = self.connections[connection_id]
            client_socket = connection["socket"]
            
            # Increment sequence number
            sequence = connection["sequence"]
            connection["sequence"] = (connection["sequence"] + 1) % 256
            
            # Get session key
            session_key = connection.get("session_key")
        
        # Encrypt message if we have a session key
        if session_key and msg_type != self.MSG_TYPE_HELLO:  # Don't encrypt hello messages
            # Encrypt the data
            encrypted = SymmetricEncryption.encrypt(data, session_key)
            
            # Combine IV, ciphertext, and tag
            message = encrypted['iv'] + encrypted['ciphertext'] + encrypted['tag']
        else:
            message = data
            
        # Create header
        header = bytearray(self.header_length)
        header[0:4] = self.protocol_signature
        header[4] = msg_type
        header[5:7] = struct.pack("!H", len(message))
        header[7] = sequence
        
        try:
            # Send message
            client_socket.sendall(header)
            client_socket.sendall(message)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to send message to {connection_id}: {e}")
            
            # Close connection on error
            self._close_connection(connection_id)
            
            return False
    
    def _send_hello(self, connection_id: str):
        """Send a hello message (handshake)
        
        Args:
            connection_id: Connection ID
        """
        with self.connection_lock:
            if connection_id not in self.connections:
                self.logger.error(f"Unknown connection ID: {connection_id}")
                return
                
            connection = self.connections[connection_id]
            
            # Create hello message
            hello_data = {
                "version": self.PROTOCOL_VERSION,
                "timestamp": int(time.time()),
                "session_key": connection["session_key"].hex()
            }
            
            # Encode as JSON
            hello_message = json.dumps(hello_data).encode('utf-8')
            
            # Encrypt with master key
            encrypted = SymmetricEncryption.encrypt(hello_message, self.master_key)
            
            # Combine IV, ciphertext, and tag
            message = encrypted['iv'] + encrypted['ciphertext'] + encrypted['tag']
            
            # Send hello message
            self._send_message(connection_id, self.MSG_TYPE_HELLO, message)
    
    def _process_hello(self, connection_id: str, message: bytes):
        """Process a hello message (handshake)
        
        Args:
            connection_id: Connection ID
            message: Hello message data
        """
        try:
            # Split into IV and ciphertext
            iv = message[:12]
            ciphertext = message[12:-16]
            tag = message[-16:]
            
            # Decrypt with master key
            try:
                plaintext = SymmetricEncryption.decrypt({
                    'iv': iv,
                    'ciphertext': ciphertext,
                    'tag': tag
                }, self.master_key)
            except Exception as e:
                self.logger.error(f"Failed to decrypt hello message from {connection_id}: {e}")
                return
            
            # Parse JSON
            hello_data = json.loads(plaintext.decode('utf-8'))
            
            # Extract session key
            session_key_hex = hello_data.get("session_key")
            if not session_key_hex:
                self.logger.error(f"No session key in hello message from {connection_id}")
                return
                
            session_key = bytes.fromhex(session_key_hex)
            
            with self.connection_lock:
                if connection_id not in self.connections:
                    self.logger.error(f"Unknown connection ID: {connection_id}")
                    return
                    
                # Store session key
                self.connections[connection_id]["session_key"] = session_key
                
                # For inbound connections, send hello response
                if self.connections[connection_id]["direction"] == "inbound":
                    # Create hello response
                    resp_data = {
                        "version": self.PROTOCOL_VERSION,
                        "timestamp": int(time.time()),
                        "session_key": os.urandom(32).hex()  # Generate our own session key
                    }
                    
                    # Store our session key
                    self.connections[connection_id]["session_key"] = bytes.fromhex(resp_data["session_key"])
                    
                    # Encode as JSON
                    resp_message = json.dumps(resp_data).encode('utf-8')
                    
                    # Encrypt with master key
                    encrypted = SymmetricEncryption.encrypt(resp_message, self.master_key)
                    
                    # Combine IV, ciphertext, and tag
                    message = encrypted['iv'] + encrypted['ciphertext'] + encrypted['tag']
                    
                    # Send hello response
                    self._send_message(connection_id, self.MSG_TYPE_HELLO, message)
            
            self.logger.info(f"Handshake completed for {connection_id}")
            
        except Exception as e:
            self.logger.error(f"Error processing hello message from {connection_id}: {e}")
    
    def _close_connection(self, connection_id: str):
        """Close and clean up a connection
        
        Args:
            connection_id: Connection ID
        """
        with self.connection_lock:
            if connection_id not in self.connections:
                return
                
            connection = self.connections[connection_id]
            
            # Close socket
            try:
                connection["socket"].close()
            except:
                pass
                
            # Remove from connections
            del self.connections[connection_id]
            
            # Remove send queue
            if connection_id in self.send_queues:
                del self.send_queues[connection_id]
                
        self.logger.info(f"Closed connection {connection_id}")


# Example usage
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO,
                      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Configuration
    config = {
        "listen_address": "0.0.0.0",
        "port": 8765,
        "protocol_signature": "AE0X",
        "header_length": 8,
        "encryption": "aes256"
    }
    
    # Create protocol handler
    tcp_protocol = TcpCustomProtocol(config)
    
    # Define data handler
    def handle_data(data, source, connection_id):
        logging.info(f"Received data from {source} (connection: {connection_id}): {data[:20]}...")
        
        # Echo the data back
        tcp_protocol.send_data(f"Echo: {data.decode('utf-8') if isinstance(data, bytes) else data}".encode(), connection_id)
        
    tcp_protocol.register_data_handler(handle_data)
    
    # Start server
    tcp_protocol.start()
    
    logging.info("TCP Custom Protocol server started. Press Ctrl+C to stop.")
    
    try:
        # Keep the main thread running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping server...")
    finally:
        tcp_protocol.stop()