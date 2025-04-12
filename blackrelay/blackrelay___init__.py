"""
BlackRelay Module
Handles communication relay layer with obfuscation and encryption
"""
import logging
import os
import yaml
from typing import Dict, Any, Optional

# Import core components
try:
    from .relay_core import RelayNode
    from .relay_management import RelayManager
    from .stealth_proxy import create_proxy, StealthProxy
    from .tcp_custom_protocol import TcpCustomProtocol
    from .udp_custom_protocol import UdpCustomProtocol
    from .smb_protocol import SmbProtocol
    from .encryptor import SymmetricEncryption, AsymmetricEncryption
except ImportError:
    # This allows partial imports for testing
    pass

# Set up module logger
logger = logging.getLogger("BlackRelay")
logger.setLevel(logging.INFO)


class BlackRelay:
    """Main BlackRelay class for easy initialization and management"""
    
    def __init__(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize the BlackRelay system
        
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
                "blackrelay/relay_config.yaml",
                "config/relay_config.yaml",
                "relay_config.yaml"
            ]
            
            for path in default_paths:
                if os.path.exists(path):
                    self.config = self._load_config(path)
                    break
            else:
                # No config found, use default minimal config
                self.config = {
                    "node": {
                        "role": "edge",
                        "max_connections": 100
                    },
                    "protocols": {
                        "http": {
                            "enabled": True,
                            "port": 8080
                        }
                    }
                }
                self.logger.warning("No configuration found, using minimal default configuration")
        
        # Initialize the relay manager
        self.relay_manager = None
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            self.logger.debug(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Error loading configuration from {config_path}: {e}")
            return {}
    
    def start(self):
        """Start the BlackRelay system"""
        try:
            # Initialize and start relay manager
            self.relay_manager = RelayManager(self.config)
            self.relay_manager.start()
            
            self.logger.info("BlackRelay system started")
            return True
        except Exception as e:
            self.logger.error(f"Error starting BlackRelay: {e}")
            return False
    
    def stop(self):
        """Stop the BlackRelay system"""
        try:
            if self.relay_manager:
                self.relay_manager.stop()
                
            self.logger.info("BlackRelay system stopped")
            return True
        except Exception as e:
            self.logger.error(f"Error stopping BlackRelay: {e}")
            return False
    
    def send_data(self, data, protocol_id=None, session_id=None, metadata=None):
        """Send data through the relay
        
        Args:
            data: Data to send
            protocol_id: Protocol to use (optional)
            session_id: Session ID (optional)
            metadata: Additional metadata (optional)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.relay_manager:
            self.logger.error("Cannot send data, relay manager not initialized")
            return False
            
        return self.relay_manager.send_data(data, protocol_id, session_id, metadata)
    
    def register_data_handler(self, handler):
        """Register a data handler
        
        Args:
            handler: Function to call when data is received
        """
        if not self.relay_manager:
            self.logger.error("Cannot register handler, relay manager not initialized")
            return False
            
        self.relay_manager.register_data_handler(handler)
        return True
    
    def get_status(self):
        """Get system status
        
        Returns:
            Status information
        """
        if not self.relay_manager:
            return {"status": "not_initialized"}
            
        status = self.relay_manager.get_relay_status()
        status["protocols"] = self.relay_manager.get_protocol_status()
        
        return status
    
    def rotate_protocols(self):
        """Rotate communication protocols
        
        Returns:
            Rotation results
        """
        if not self.relay_manager:
            return {"success": False, "error": "Relay manager not initialized"}
            
        return self.relay_manager.rotate_protocols()


# Create a singleton instance
def create_instance(config_path=None, config_dict=None):
    """Create a new BlackRelay instance
    
    Args:
        config_path: Path to configuration file (optional)
        config_dict: Configuration dictionary (optional)
        
    Returns:
        BlackRelay instance
    """
    return BlackRelay(config_path, config_dict)


if __name__ == "__main__":
    # Setup logging for standalone mode
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start the relay
    relay = create_instance()
    relay.start()
    
    try:
        # Keep running until interrupted
        import time
        print("BlackRelay started, press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        relay.stop()