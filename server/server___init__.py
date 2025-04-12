"""
ErebusC2 Server Module
Provides server functionality for the ErebusC2 framework
"""
import logging
import os
import json
import yaml
from typing import Dict, Any, Optional

# Import server components
try:
    from .api import ServerAPI
    from .peer_tracker import PeerTracker
    from .command_queue import CommandQueue
    from .traffic_manager import TrafficManager
    from blackreign.command_center import CommandCenter
except ImportError:
    # This allows partial imports for testing
    pass

# Set up module logger
logger = logging.getLogger("ErebusC2.Server")
logger.setLevel(logging.INFO)


class ErebusC2Server:
    """Main server class for ErebusC2"""
    
    def __init__(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize the ErebusC2 server
        
        Args:
            config_path: Path to configuration file (optional)
            config_dict: Configuration dictionary (optional, takes precedence over config_path)
        """
        self.logger = logger
        
        # Load configuration
        if config_dict:
            self.config = config_dict
        elif config_path:
            self.config = self._load_config(config_path)
        else:
            # Look for default config paths
            default_paths = [
                "server/server_config.yaml",
                "config/server_config.yaml",
                "server_config.yaml"
            ]
            
            for path in default_paths:
                if os.path.exists(path):
                    self.config = self._load_config(path)
                    break
            else:
                # No config found, use default config
                self.config = {
                    "api": {
                        "host": "0.0.0.0",
                        "port": 8000,
                        "debug": False,
                        "ssl": False,
                        "token_secret": "changeme"
                    },
                    "server": {
                        "implant_timeout": 300,  # seconds
                        "command_timeout": 600,  # seconds
                        "max_queue_size": 1000
                    }
                }
                self.logger.warning("No configuration found, using default configuration")
        
        # Initialize components
        self.peer_tracker = PeerTracker(self.config.get("server", {}))
        self.command_queue = CommandQueue(self.config.get("server", {}))
        self.traffic_manager = TrafficManager(self.config.get("server", {}))
        self.command_center = CommandCenter(self.config.get("server", {}))
        self.api = ServerAPI(config_dict=self.config)
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
                    
            self.logger.debug(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Error loading configuration from {config_path}: {e}")
            return {}
    
    def start(self):
        """Start the ErebusC2 server"""
        try:
            self.logger.info("Starting ErebusC2 server...")
            
            # Start components
            self.traffic_manager.register_handler(self._handle_traffic)
            self.command_center.register_handler("example_command", self._handle_example_command)
            self.api.start()
            
            self.logger.info("ErebusC2 server started")
            return True
        except Exception as e:
            self.logger.error(f"Error starting server: {e}")
            return False
    
    def stop(self):
        """Stop the ErebusC2 server"""
        try:
            self.logger.info("Stopping ErebusC2 server...")
            
            # Stop components
            self.api.stop()
            self.peer_tracker.stop()
            self.command_queue.stop()
            self.traffic_manager.stop()
            self.command_center.stop()
            
            self.logger.info("ErebusC2 server stopped")
            return True
        except Exception as e:
            self.logger.error(f"Error stopping server: {e}")
            return False
    
    def _handle_traffic(self, message: Any, source: Optional[str], 
                     protocol_id: Optional[str], session_id: Optional[str]):
        """Handle traffic from the traffic manager
        
        Args:
            message: Message data
            source: Source identifier
            protocol_id: Protocol ID
            session_id: Session ID
        """
        # This is a placeholder for custom traffic handling
        pass
    
    def _handle_example_command(self, command: Dict[str, Any]):
        """Handle example command
        
        Args:
            command: Command dictionary
        """
        self.logger.info(f"Handling example command: {command}")
        # Implement command handling logic here
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get server status
        
        Returns:
            Status information
        """
        return {
            "implants": len(self.peer_tracker.get_implants()),
            "relays": len(self.peer_tracker.get_relays()),
            "commands_queued": len(self.command_queue.get_commands()),
            "traffic_stats": self.traffic_manager.get_stats()
        }


# Create a singleton instance
def create_server(config_path=None, config_dict=None):
    """Create a new ErebusC2 server instance
    
    Args:
        config_path: Path to configuration file (optional)
        config_dict: Configuration dictionary (optional)
        
    Returns:
        ErebusC2Server instance
    """
    return ErebusC2Server(config_path, config_dict)


# For running directly
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levellevelname)s - %(message)s'
    )
    
    # Create and start the server
    server = create_server()
    server.start()
    
    try:
        # Keep running until interrupted
        import time
        print("ErebusC2 Server started, press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        server.stop()