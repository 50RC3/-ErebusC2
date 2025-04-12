"""
ErebusC2 Peer Tracker
Tracks active implants, relay nodes, and their statuses
"""
import time
import json
import uuid
import logging
import threading
import datetime
import copy
from typing import Dict, List, Any, Optional, Union

class PeerTracker:
    """Tracks and manages peers (implants and relays)"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the peer tracker
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger("ErebusC2.PeerTracker")
        self.config = config or {}
        
        # Peer storage
        self.peers = {
            "implant": {},  # Implants by ID
            "relay": {}     # Relays by ID
        }
        
        # Thread lock for peer data
        self.peers_lock = threading.RLock()
        
        # Timeouts
        self.implant_timeout = self.config.get("implant_timeout", 300)  # seconds
        self.relay_timeout = self.config.get("relay_timeout", 300)  # seconds
        
        # Start monitoring thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_peers)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("Peer Tracker initialized")
        
    def register(self, peer_id: str, peer_type: str, peer_data: Dict[str, Any]) -> bool:
        """Register a new peer or update existing one
        
        Args:
            peer_id: Unique identifier for the peer
            peer_type: Type of peer ('implant' or 'relay')
            peer_data: Peer information and metadata
            
        Returns:
            True if successful, False otherwise
        """
        if peer_type not in ["implant", "relay"]:
            self.logger.error(f"Invalid peer type: {peer_type}")
            return False
            
        with self.peers_lock:
            # Check if peer already exists
            if peer_id in self.peers[peer_type]:
                # Update existing peer
                self.peers[peer_type][peer_id].update(peer_data)
                self.logger.debug(f"Updated existing {peer_type}: {peer_id}")
            else:
                # Add new peer
                self.peers[peer_type][peer_id] = peer_data
                self.logger.info(f"Registered new {peer_type}: {peer_id}")
                
            # Ensure timestamps
            if "registered" not in self.peers[peer_type][peer_id]:
                self.peers[peer_type][peer_id]["registered"] = datetime.datetime.now().isoformat()
                
            if "last_seen" not in self.peers[peer_type][peer_id]:
                self.peers[peer_type][peer_id]["last_seen"] = datetime.datetime.now().isoformat()
            
            return True
    
    def unregister(self, peer_id: str, peer_type: str) -> bool:
        """Unregister a peer
        
        Args:
            peer_id: Peer ID
            peer_type: Type of peer ('implant' or 'relay')
            
        Returns:
            True if successful, False otherwise
        """
        if peer_type not in ["implant", "relay"]:
            self.logger.error(f"Invalid peer type: {peer_type}")
            return False
            
        with self.peers_lock:
            if peer_id in self.peers[peer_type]:
                del self.peers[peer_type][peer_id]
                self.logger.info(f"Unregistered {peer_type}: {peer_id}")
                return True
            else:
                self.logger.warning(f"{peer_type.capitalize()} not found: {peer_id}")
                return False
    
    def update_implant(self, implant_id: str, status_update: Dict[str, Any]) -> bool:
        """Update implant status
        
        Args:
            implant_id: Implant ID
            status_update: Updated status information
            
        Returns:
            True if successful, False otherwise
        """
        with self.peers_lock:
            if implant_id in self.peers["implant"]:
                self.peers["implant"][implant_id].update(status_update)
                self.logger.debug(f"Updated implant status: {implant_id}")
                return True
            else:
                self.logger.warning(f"Implant not found: {implant_id}")
                return False
    
    def update_relay(self, relay_id: str, status_update: Dict[str, Any]) -> bool:
        """Update relay status
        
        Args:
            relay_id: Relay ID
            status_update: Updated status information
            
        Returns:
            True if successful, False otherwise
        """
        with self.peers_lock:
            if relay_id in self.peers["relay"]:
                self.peers["relay"][relay_id].update(status_update)
                self.logger.debug(f"Updated relay status: {relay_id}")
                return True
            else:
                self.logger.warning(f"Relay not found: {relay_id}")
                return False
    
    def get_implants(self) -> List[Dict[str, Any]]:
        """Get all implants
        
        Returns:
            List of implants
        """
        with self.peers_lock:
            # Return a copy to prevent modification
            return [copy.deepcopy(implant) for implant in self.peers["implant"].values()]
    
    def get_relays(self) -> List[Dict[str, Any]]:
        """Get all relays
        
        Returns:
            List of relays
        """
        with self.peers_lock:
            # Return a copy to prevent modification
            return [copy.deepcopy(relay) for relay in self.peers["relay"].values()]
    
    def get_implant(self, implant_id: str) -> Optional[Dict[str, Any]]:
        """Get implant by ID
        
        Args:
            implant_id: Implant ID
            
        Returns:
            Implant data or None if not found
        """
        with self.peers_lock:
            if implant_id in self.peers["implant"]:
                return copy.deepcopy(self.peers["implant"][implant_id])
            return None
    
    def get_relay(self, relay_id: str) -> Optional[Dict[str, Any]]:
        """Get relay by ID
        
        Args:
            relay_id: Relay ID
            
        Returns:
            Relay data or None if not found
        """
        with self.peers_lock:
            if relay_id in self.peers["relay"]:
                return copy.deepcopy(self.peers["relay"][relay_id])
            return None
    
    def find_peers_by_criteria(self, peer_type: str, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find peers matching specified criteria
        
        Args:
            peer_type: Type of peer ('implant' or 'relay')
            criteria: Key-value pairs to match
            
        Returns:
            List of matching peers
        """
        if peer_type not in ["implant", "relay"]:
            self.logger.error(f"Invalid peer type: {peer_type}")
            return []
            
        with self.peers_lock:
            results = []
            
            for peer_id, peer_data in self.peers[peer_type].items():
                # Check if peer matches all criteria
                match = True
                for key, value in criteria.items():
                    if key not in peer_data or peer_data[key] != value:
                        match = False
                        break
                
                if match:
                    results.append(copy.deepcopy(peer_data))
            
            return results
    
    def _monitor_peers(self):
        """Monitor peers for timeouts"""
        while self.running:
            try:
                current_time = datetime.datetime.now()
                
                with self.peers_lock:
                    # Check implants
                    for implant_id, implant in list(self.peers["implant"].items()):
                        if implant.get("status") == "active":
                            # Parse last seen timestamp
                            last_seen_str = implant.get("last_seen")
                            if last_seen_str:
                                try:
                                    last_seen = datetime.datetime.fromisoformat(last_seen_str)
                                    time_diff = (current_time - last_seen).total_seconds()
                                    
                                    if time_diff > self.implant_timeout:
                                        # Mark as inactive
                                        implant["status"] = "inactive"
                                        implant["last_status_change"] = current_time.isoformat()
                                        self.logger.info(f"Implant timed out: {implant_id} (No activity for {time_diff:.1f}s)")
                                except ValueError:
                                    pass
                    
                    # Check relays
                    for relay_id, relay in list(self.peers["relay"].items()):
                        if relay.get("status") == "active":
                            # Parse last seen timestamp
                            last_seen_str = relay.get("last_seen")
                            if last_seen_str:
                                try:
                                    last_seen = datetime.datetime.fromisoformat(last_seen_str)
                                    time_diff = (current_time - last_seen).total_seconds()
                                    
                                    if time_diff > self.relay_timeout:
                                        # Mark as inactive
                                        relay["status"] = "inactive"
                                        relay["last_status_change"] = current_time.isoformat()
                                        self.logger.info(f"Relay timed out: {relay_id} (No activity for {time_diff:.1f}s)")
                                except ValueError:
                                    pass
                
                # Sleep for a while
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Error in peer monitor: {e}")
                time.sleep(30)  # Longer sleep on error
    
    def stop(self):
        """Stop the peer tracker"""
        self.running = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
            
        self.logger.info("Peer Tracker stopped")
    
    def export_peers(self) -> Dict[str, Any]:
        """Export all peer data
        
        Returns:
            Dictionary with all peer data
        """
        with self.peers_lock:
            return copy.deepcopy(self.peers)
    
    def import_peers(self, peer_data: Dict[str, Any]) -> bool:
        """Import peer data
        
        Args:
            peer_data: Peer data to import
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.peers_lock:
                # Validate data structure
                if not isinstance(peer_data, dict) or "implant" not in peer_data or "relay" not in peer_data:
                    self.logger.error("Invalid peer data format")
                    return False
                    
                # Import data
                self.peers = copy.deepcopy(peer_data)
                
                self.logger.info(f"Imported {len(peer_data['implant'])} implants and {len(peer_data['relay'])} relays")
                return True
                
        except Exception as e:
            self.logger.error(f"Error importing peer data: {e}")
            return False