"""
BlackRelay UDP Custom Protocol
Implementation of custom UDP protocol for covert communications
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
from typing import Dict, Any, Optional, List, Tuple, Union, Callable, Set

try:
    from blackcypher.encryption import SymmetricEncryption, AsymmetricEncryption
except ImportError:
    # Fallback for standalone testing
    from encryptor import SymmetricEncryption, AsymmetricEncryption


class UdpCustomProtocol:
    """Custom UDP protocol implementation for covert communications"""
    
    # Protocol constants
    PROTOCOL_VERSION = 1
    
    # Message types
    MSG_TYPE_HELLO = 0x01
    MSG_TYPE_DATA = 0x02
    MSG_TYPE_ACK = 0x03
    MSG_TYPE_COMMAND = 0x04
    MSG_TYPE_RESPONSE = 0x05
    MSG_TYPE_KEEP_ALIVE = 0x06
    MSG_TYPE_ERROR = 0xFF
    
    # Other constants
    MAX_PACKET_SIZE = 1472  # Typical MTU minus IP and UDP headers
    MAX_RETRIES = 5
    RETRY_TIMEOUT = 2.0     # seconds
    KEEP_ALIVE_INTERVAL = 30.0  # seconds
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the UDP custom protocol handler
        
        Args:
            config: Protocol configuration
        """
        self.config = config
        self.logger = logging.getLogger("BlackRelay.UdpCustomProtocol")
        self.running = False
        
        # Extract configuration
        self.listen_address = config.get("listen_address", "0.0.0.0")
        self.port = config.get("port", 8766)
        self.protocol_signature = bytes.fromhex(config.get("protocol_signature", "BF1X").encode().hex())
        self.encryption_type = config.get("encryption", "aes256")
        self.max_packet_size = config.get("max_packet_size", self.MAX_PACKET_SIZE)
        self.max_retries = config.get("max_retries", self.MAX_RETRIES)
        self.retry_timeout = config.get("retry_timeout", self.RETRY_TIMEOUT)
        self.keep_alive_interval = config.get("keep_alive_interval", self.KEEP_ALIVE_INTERVAL)
        
        # Socket
        self.socket = None
        self.peers = {}     # Mapping of peer addresses to session data
        self.peer_lock = threading.RLock()
        
        # Message tracking
        self.outgoing_messages = {}  # Messages waiting for ACK
        self.message_lock = threading.RLock()
        self.received_ids = set()    # Message IDs we've already processed
        self.received_lock = threading.RLock()
        
        # Message queues
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
        """Start the UDP custom protocol server"""
        if self.running:
            return
            
        self.running = True
        
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.listen_address, self.port))
            
            # Start receiver thread
            self.receiver_thread = threading.Thread(target=self._receiver_loop)
            self.receiver_thread.daemon = True
            self.receiver_thread.start()
            
            # Start processor thread
            self.processor_thread = threading.Thread(target=self._process_received_messages)
            self.processor_thread.daemon = True
            self.processor_thread.start()
            
            # Start retransmission thread
            self.retransmit_thread = threading.Thread(target=self._retransmit_loop)
            self.retransmit_thread.daemon = True
            self.retransmit_thread.start()
            
            # Start keep-alive thread
            self.keepalive_thread = threading.Thread(target=self._keep_alive_loop)
            self.keepalive_thread.daemon = True
            self.keepalive_thread.start()
            
            self.logger.info(f"UDP Custom Protocol server started on {self.listen_address}:{self.port}")
        except Exception as e:
            self.logger.error(f"Failed to start UDP Custom Protocol server: {e}")
            self.running = False
    
    def stop(self):
        """Stop the UDP custom protocol server"""
        if not self.running:
            return
            
        self.running = False
        
        # Close socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            
        self.socket = None
        
        # Clear peer data
        with self.peer_lock:
            self.peers.clear()
            
        # Clear message tracking
        with self.message_lock:
            self.outgoing_messages.clear()
            
        with self.received_lock:
            self.received_ids.clear()
            
        self.logger.info("UDP Custom Protocol server stopped")
    
    def connect(self, address: str, port: int) -> Optional[str]:
        """Establish a connection to a peer
        
        Args:
            address: Peer address
            port: Peer port
            
        Returns:
            Peer ID if successful, None otherwise
        """
        try:
            # Generate peer ID
            peer_id = hashlib.md5(f"{address}:{port}:{time.time()}".encode()).hexdigest()
            
            # Create peer entry
            with self.peer_lock:
                self.peers[peer_id] = {
                    "address": address,
                    "port": port,
                    "session_key": os.urandom(32),  # Generate session key
                    "connected": time.time(),
                    "last_activity": time.time(),
                    "sequence": 0,
                    "established": False
                }
                
                # Create send queue for this peer
                self.send_queues[peer_id] = queue.Queue()
                
            # Start sender thread for this peer
            sender_thread = threading.Thread(
                target=self._peer_sender_loop,
                args=(peer_id,)
            )
            sender_thread.daemon = True
            sender_thread.start()
            
            # Send hello message to establish connection
            self._send_hello(peer_id)
            
            # Wait for connection to be established
            max_wait = 10.0  # seconds
            wait_interval = 0.1
            wait_time = 0.0
            
            while wait_time < max_wait:
                with self.peer_lock:
                    if peer_id in self.peers and self.peers[peer_id]["established"]:
                        self.logger.info(f"Connection established to {address}:{port} (peer ID: {peer_id})")
                        return peer_id
                
                time.sleep(wait_interval)
                wait_time += wait_interval
            
            # Connection timeout
            self.logger.error(f"Timeout establishing connection to {address}:{port}")
            
            # Clean up
            with self.peer_lock:
                if peer_id in self.peers:
                    del self.peers[peer_id]
                    
                if peer_id in self.send_queues:
                    del self.send_queues[peer_id]
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Error connecting to {address}:{port}: {e}")
            return None
    
    def send_data(self, data: Union[str, bytes], peer_id: Optional[str] = None) -> bool:
        """Send data to a peer
        
        Args:
            data: Data to send
            peer_id: Peer ID (optional, if None will send to all)
            
        Returns:
            True if successful, False otherwise
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        with self.peer_lock:
            if peer_id:
                # Send to specific peer
                if peer_id not in self.peers:
                    self.logger.error(f"Unknown peer ID: {peer_id}")
                    return False
                    
                if peer_id not in self.send_queues:
                    self.logger.error(f"No send queue for peer ID: {peer_id}")
                    return False
                    
                # Queue the message
                self.send_queues[peer_id].put({
                    "type": self.MSG_TYPE_DATA,
                    "data": data
                })
            else:
                # Broadcast to all peers
                if not self.peers:
                    self.logger.warning("No connected peers to send data to")
                    return False
                    
                # Queue the message for each peer
                for p_id, queue in self.send_queues.items():
                    queue.put({
                        "type": self.MSG_TYPE_DATA,
                        "data": data
                    })
            
            return True
    
    def send_command(self, command: str, params: Dict[str, Any], 
                    peer_id: Optional[str] = None) -> bool:
        """Send a command to a peer
        
        Args:
            command: Command name
            params: Command parameters
            peer_id: Peer ID (optional, if None will send to all)
            
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
        
        with self.peer_lock:
            if peer_id:
                # Send to specific peer
                if peer_id not in self.peers:
                    self.logger.error(f"Unknown peer ID: {peer_id}")
                    return False
                    
                if peer_id not in self.send_queues:
                    self.logger.error(f"No send queue for peer ID: {peer_id}")
                    return False
                    
                # Queue the message
                self.send_queues[peer_id].put({
                    "type": self.MSG_TYPE_COMMAND,
                    "data": encoded_command
                })
            else:
                # Broadcast to all peers
                if not self.peers:
                    self.logger.warning("No connected peers to send command to")
                    return False
                    
                # Queue the message for each peer
                for p_id, queue in self.send_queues.items():
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
    
    def _receiver_loop(self):
        """Main loop for receiving UDP packets"""
        self.socket.settimeout(1.0)  # 1-second timeout to check if still running
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(self.max_packet_size)
                
                # Process packet
                self._process_packet(data, addr)
                
            except socket.timeout:
                # This is expected for the non-blocking check
                pass
            except Exception as e:
                if self.running:  # Only log if we're still running
                    self.logger.error(f"Error in receiver loop: {e}")
    
    def _peer_sender_loop(self, peer_id: str):
        """Send queued messages to a peer
        
        Args:
            peer_id: Peer ID
        """
        while self.running:
            try:
                # Check if peer still exists
                with self.peer_lock:
                    if peer_id not in self.peers or peer_id not in self.send_queues:
                        break
                        
                    peer = self.peers[peer_id]
                    send_queue = self.send_queues[peer_id]
                
                try:
                    # Get message from queue with timeout
                    message = send_queue.get(timeout=1.0)
                    
                    # Send message
                    self._send_message(peer_id, message["type"], message["data"])
                    
                    # Mark as done
                    send_queue.task_done()
                    
                except queue.Empty:
                    # No message to send
                    pass
                    
            except Exception as e:
                self.logger.error(f"Error in sender thread for {peer_id}: {e}")
                break
    
    def _process_packet(self, data: bytes, addr: Tuple[str, int]):
        """Process a received UDP packet
        
        Args:
            data: Packet data
            addr: Source address (ip, port)
        """
        try:
            # Check minimum packet size
            if len(data) < 8:
                self.logger.warning(f"Packet too small from {addr[0]}:{addr[1]}")
                return
                
            # Check protocol signature
            if not data.startswith(self.protocol_signature):
                self.logger.warning(f"Invalid protocol signature from {addr[0]}:{addr[1]}")
                return
                
            # Parse header
            msg_type = data[4]
            msg_id = struct.unpack("!H", data[5:7])[0]
            flags = data[7]
            
            # Extract message body (everything after the header)
            message = data[8:]
            
            # Check for duplicates
            with self.received_lock:
                if msg_id in self.received_ids and msg_type != self.MSG_TYPE_ACK:
                    # Send ACK for duplicates but don't process again
                    self._send_ack(addr, msg_id)
                    return
                    
                # Add to received IDs
                if msg_type != self.MSG_TYPE_ACK:  # Don't track ACKs
                    self.received_ids.add(msg_id)
                    
                    # Cleanup old IDs to prevent memory leak
                    if len(self.received_ids) > 10000:
                        # Keep the most recent IDs
                        self.received_ids = set(list(self.received_ids)[-5000:])
            
            # Send ACK for messages that require it
            if flags & 0x01 and msg_type != self.MSG_TYPE_ACK:
                self._send_ack(addr, msg_id)
            
            # Find or create peer
            peer_id = self._get_peer_id_by_addr(addr)
            if not peer_id and msg_type != self.MSG_TYPE_HELLO:
                # Unknown peer and not a hello message
                self.logger.warning(f"Message from unknown peer {addr[0]}:{addr[1]}")
                return
                
            # Process based on message type
            if msg_type == self.MSG_TYPE_HELLO:
                # Hello message (handshake)
                self._process_hello(addr, message)
                
            elif msg_type == self.MSG_TYPE_ACK:
                # Acknowledgment
                self._process_ack(peer_id, msg_id)
                
            elif msg_type == self.MSG_TYPE_DATA or msg_type == self.MSG_TYPE_COMMAND or msg_type == self.MSG_TYPE_RESPONSE:
                # Data or command message
                self._process_data_message(peer_id, msg_type, message)
                
            elif msg_type == self.MSG_TYPE_KEEP_ALIVE:
                # Keep-alive message
                self._process_keep_alive(peer_id)
                
            else:
                # Unknown message type
                self.logger.warning(f"Unknown message type {msg_type} from {addr[0]}:{addr[1]}")
            
        except Exception as e:
            self.logger.error(f"Error processing packet from {addr[0]}:{addr[1]}: {e}")
    
    def _process_received_messages(self):
        """Process received messages"""
        while self.running:
            try:
                # Get message from queue with timeout
                try:
                    message = self.receive_queue.get(timeout=1.0)
                    
                    # Extract message data
                    peer_id = message["peer_id"]
                    msg_type = message["type"]
                    data = message["data"]
                    
                    # Handle based on message type
                    if msg_type == self.MSG_TYPE_DATA:
                        # Data message
                        if self.data_handler:
                            with self.peer_lock:
                                if peer_id in self.peers:
                                    peer = self.peers[peer_id]
                                    source = f"{peer['address']}:{peer['port']}"
                                else:
                                    source = "unknown"
                                    
                            self.data_handler(data, source, peer_id)
                            
                    elif msg_type == self.MSG_TYPE_COMMAND:
                        # Command message
                        try:
                            command_data = json.loads(data.decode('utf-8'))
                            self.logger.info(f"Received command: {command_data['cmd']} from {peer_id}")
                            
                            # Process command (implementation depends on specific commands)
                            # ...
                            
                            # Send response
                            response = {
                                "status": "ok",
                                "timestamp": time.time()
                            }
                            
                            self.send_queues[peer_id].put({
                                "type": self.MSG_TYPE_RESPONSE,
                                "data": json.dumps(response).encode('utf-8')
                            })
                            
                        except json.JSONDecodeError:
                            self.logger.error(f"Invalid command format from {peer_id}")
                            
                    elif msg_type == self.MSG_TYPE_RESPONSE:
                        # Response message
                        self.logger.debug(f"Received response from {peer_id}")
                        
                    # Mark as done
                    self.receive_queue.task_done()
                    
                except queue.Empty:
                    # No message to process
                    pass
            except Exception as e:
                self.logger.error(f"Error processing received message: {e}")
    
    def _retransmit_loop(self):
        """Retransmit messages that haven't been acknowledged"""
        while self.running:
            try:
                current_time = time.time()
                
                with self.message_lock:
                    messages_to_remove = []
                    
                    for msg_id, message in self.outgoing_messages.items():
                        # Check if it's time to retry
                        if current_time >= message["next_retry"]:
                            if message["retries"] >= self.max_retries:
                                # Too many retries, give up
                                messages_to_remove.append(msg_id)
                                
                                # Check if peer is still connected
                                peer_id = message["peer_id"]
                                with self.peer_lock:
                                    if peer_id in self.peers:
                                        # Mark peer as potentially disconnected
                                        self.peers[peer_id]["last_activity"] = current_time - self.keep_alive_interval * 2
                                
                                self.logger.warning(f"Message {msg_id} to {message['peer_id']} failed after {self.max_retries} retries")
                            else:
                                # Retry sending
                                try:
                                    self.socket.sendto(message["packet"], (message["address"], message["port"]))
                                    
                                    # Update retry info
                                    message["retries"] += 1
                                    message["next_retry"] = current_time + self.retry_timeout * (1 << min(message["retries"], 5))  # Exponential backoff
                                    
                                    self.logger.debug(f"Retransmitted message {msg_id} to {message['address']}:{message['port']} (retry {message['retries']})")
                                except Exception as e:
                                    self.logger.error(f"Error retransmitting message {msg_id}: {e}")
                                    messages_to_remove.append(msg_id)
                    
                    # Remove expired messages
                    for msg_id in messages_to_remove:
                        self.outgoing_messages.pop(msg_id, None)
                
                # Sleep for a while
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.error(f"Error in retransmit loop: {e}")
                time.sleep(1.0)
    
    def _keep_alive_loop(self):
        """Send keep-alive messages to peers"""
        while self.running:
            try:
                current_time = time.time()
                
                with self.peer_lock:
                    peers_to_remove = []
                    
                    for peer_id, peer in self.peers.items():
                        # Check if peer is still connected
                        if current_time - peer["last_activity"] > self.keep_alive_interval * 3:
                            # Peer is probably disconnected
                            peers_to_remove.append(peer_id)
                            self.logger.info(f"Peer {peer_id} ({peer['address']}:{peer['port']}) timed out")
                        elif current_time - peer["last_activity"] > self.keep_alive_interval:
                            # Send keep-alive
                            try:
                                if peer_id in self.send_queues:
                                    self.send_queues[peer_id].put({
                                        "type": self.MSG_TYPE_KEEP_ALIVE,
                                        "data": struct.pack("!Q", int(current_time))
                                    })
                            except Exception as e:
                                self.logger.error(f"Error sending keep-alive to peer {peer_id}: {e}")
                                
                    # Remove timed out peers
                    for peer_id in peers_to_remove:
                        # Remove from peers
                        self.peers.pop(peer_id, None)
                        
                        # Remove send queue
                        if peer_id in self.send_queues:
                            del self.send_queues[peer_id]
                            
                        # Remove any pending messages
                        with self.message_lock:
                            message_ids = [msg_id for msg_id, msg in self.outgoing_messages.items() 
                                         if msg["peer_id"] == peer_id]
                            for msg_id in message_ids:
                                self.outgoing_messages.pop(msg_id, None)
                
                # Sleep for a while
                time.sleep(self.keep_alive_interval / 3)
                
            except Exception as e:
                self.logger.error(f"Error in keep-alive loop: {e}")
                time.sleep(5.0)
    
    def _get_peer_id_by_addr(self, addr: Tuple[str, int]) -> Optional[str]:
        """Find peer ID by address
        
        Args:
            addr: Peer address (ip, port)
            
        Returns:
            Peer ID if found, None otherwise
        """
        with self.peer_lock:
            for peer_id, peer in self.peers.items():
                if peer["address"] == addr[0] and peer["port"] == addr[1]:
                    return peer_id
        return None
    
    def _send_hello(self, peer_id: str):
        """Send hello message to a peer
        
        Args:
            peer_id: Peer ID
        """
        with self.peer_lock:
            if peer_id not in self.peers:
                self.logger.error(f"Unknown peer ID: {peer_id}")
                return
                
            peer = self.peers[peer_id]
            
            # Create hello message
            hello_data = {
                "version": self.PROTOCOL_VERSION,
                "timestamp": int(time.time()),
                "node_id": self.master_key[:16].hex(),  # Use part of master key as node identifier
                "session_key": peer["session_key"].hex()
            }
            
            # Encode as JSON
            hello_message = json.dumps(hello_data).encode('utf-8')
            
            # Send hello message
            self._send_message(peer_id, self.MSG_TYPE_HELLO, hello_message)
    
    def _process_hello(self, addr: Tuple[str, int], message: bytes):
        """Process a hello message
        
        Args:
            addr: Source address
            message: Hello message data
        """
        try:
            # Parse JSON
            hello_data = json.loads(message.decode('utf-8'))
            
            # Extract info
            version = hello_data.get("version")
            timestamp = hello_data.get("timestamp")
            node_id = hello_data.get("node_id")
            session_key_hex = hello_data.get("session_key")
            
            # Validate message
            if not version or not timestamp or not node_id or not session_key_hex:
                self.logger.warning(f"Invalid hello message from {addr[0]}:{addr[1]}")
                return
                
            # Check protocol version
            if version != self.PROTOCOL_VERSION:
                self.logger.warning(f"Unsupported protocol version {version} from {addr[0]}:{addr[1]}")
                return
                
            # Generate peer ID
            peer_id = hashlib.md5(f"{addr[0]}:{addr[1]}:{node_id}".encode()).hexdigest()
            
            # Check if this is a new peer or an existing one
            with self.peer_lock:
                if peer_id in self.peers:
                    # Existing peer, update session key
                    self.peers[peer_id]["session_key"] = bytes.fromhex(session_key_hex)
                    self.peers[peer_id]["last_activity"] = time.time()
                    self.peers[peer_id]["established"] = True
                    
                    self.logger.info(f"Updated session for peer {peer_id} ({addr[0]}:{addr[1]})")
                else:
                    # New peer
                    self.peers[peer_id] = {
                        "address": addr[0],
                        "port": addr[1],
                        "session_key": bytes.fromhex(session_key_hex),
                        "connected": time.time(),
                        "last_activity": time.time(),
                        "sequence": 0,
                        "established": True
                    }
                    
                    # Create send queue for this peer
                    self.send_queues[peer_id] = queue.Queue()
                    
                    # Start sender thread for this peer
                    sender_thread = threading.Thread(
                        target=self._peer_sender_loop,
                        args=(peer_id,)
                    )
                    sender_thread.daemon = True
                    sender_thread.start()
                    
                    self.logger.info(f"New peer {peer_id} ({addr[0]}:{addr[1]}) connected")
                    
                # Send hello response
                self._send_hello(peer_id)
            
        except Exception as e:
            self.logger.error(f"Error processing hello message from {addr[0]}:{addr[1]}: {e}")
    
    def _process_data_message(self, peer_id: str, msg_type: int, data: bytes):
        """Process a data message
        
        Args:
            peer_id: Peer ID
            msg_type: Message type
            data: Message data
        """
        try:
            with self.peer_lock:
                if peer_id not in self.peers:
                    self.logger.error(f"Unknown peer ID: {peer_id}")
                    return
                    
                peer = self.peers[peer_id]
                
                # Update last activity
                peer["last_activity"] = time.time()
                
                # Get session key
                session_key = peer.get("session_key")
                if not session_key:
                    self.logger.error(f"No session key for peer {peer_id}")
                    return
            
            # Decrypt data
            try:
                # Split into IV, ciphertext, and tag
                iv = data[:12]
                ciphertext = data[12:-16]
                tag = data[-16:]
                
                # Decrypt
                plaintext = SymmetricEncryption.decrypt({
                    'iv': iv,
                    'ciphertext': ciphertext,
                    'tag': tag
                }, session_key)
                
                # Queue for processing
                self.receive_queue.put({
                    "peer_id": peer_id,
                    "type": msg_type,
                    "data": plaintext
                })
                
            except Exception as e:
                self.logger.error(f"Decryption failed for message from {peer_id}: {e}")
                
        except Exception as e:
            self.logger.error(f"Error processing data message from {peer_id}: {e}")
    
    def _process_ack(self, peer_id: str, msg_id: int):
        """Process an acknowledgment
        
        Args:
            peer_id: Peer ID
            msg_id: Message ID being acknowledged
        """
        with self.message_lock:
            if msg_id in self.outgoing_messages:
                # Remove from outgoing messages
                self.outgoing_messages.pop(msg_id, None)
                self.logger.debug(f"Received ACK for message {msg_id} from {peer_id}")
    
    def _process_keep_alive(self, peer_id: str):
        """Process a keep-alive message
        
        Args:
            peer_id: Peer ID
        """
        with self.peer_lock:
            if peer_id in self.peers:
                # Update last activity
                self.peers[peer_id]["last_activity"] = time.time()
                self.logger.debug(f"Received keep-alive from {peer_id}")
    
    def _send_ack(self, addr: Tuple[str, int], msg_id: int):
        """Send an acknowledgment
        
        Args:
            addr: Destination address
            msg_id: Message ID to acknowledge
        """
        # Create ACK message
        header = bytearray(8)
        header[0:4] = self.protocol_signature
        header[4] = self.MSG_TYPE_ACK
        header[5:7] = struct.pack("!H", msg_id)
        header[7] = 0  # No flags for ACK
        
        try:
            self.socket.sendto(header, addr)
        except Exception as e:
            self.logger.error(f"Error sending ACK to {addr[0]}:{addr[1]}: {e}")
    
    def _send_message(self, peer_id: str, msg_type: int, data: bytes) -> bool:
        """Send a message to a peer
        
        Args:
            peer_id: Peer ID
            msg_type: Message type
            data: Message data
            
        Returns:
            True if successful, False otherwise
        """
        with self.peer_lock:
            if peer_id not in self.peers:
                self.logger.error(f"Unknown peer ID: {peer_id}")
                return False
                
            peer = self.peers[peer_id]
            addr = (peer["address"], peer["port"])
            
            # Get session key
            session_key = peer.get("session_key")
            
            # Generate message ID
            msg_id = random.randint(1, 65535)
            
            # Set flags
            flags = 0x01  # Request ACK
            
            # Don't encrypt hello messages (they're already in plaintext)
            if msg_type != self.MSG_TYPE_HELLO and session_key:
                # Encrypt data
                encrypted = SymmetricEncryption.encrypt(data, session_key)
                
                # Combine IV, ciphertext, and tag
                message = encrypted['iv'] + encrypted['ciphertext'] + encrypted['tag']
            else:
                message = data
            
            # Create header
            header = bytearray(8)
            header[0:4] = self.protocol_signature
            header[4] = msg_type
            header[5:7] = struct.pack("!H", msg_id)
            header[7] = flags
            
            # Combine header and message
            packet = header + message
            
            # Check packet size
            if len(packet) > self.max_packet_size:
                self.logger.error(f"Packet too large: {len(packet)} bytes (max {self.max_packet_size})")
                return False
            
        try:
            # Send packet
            self.socket.sendto(packet, addr)
            
            # Track if we need ACK
            if flags & 0x01 and msg_type != self.MSG_TYPE_ACK:
                with self.message_lock:
                    self.outgoing_messages[msg_id] = {
                        "peer_id": peer_id,
                        "address": peer["address"],
                        "port": peer["port"],
                        "type": msg_type,
                        "packet": packet,
                        "retries": 0,
                        "next_retry": time.time() + self.retry_timeout,
                        "timestamp": time.time()
                    }
            
            return True
        except Exception as e:
            self.logger.error(f"Error sending message to {peer_id}: {e}")
            return False