"""
BlackPulse Heartbeat Monitor
Monitors the health of the C2 infrastructure
"""
import time
import logging
import threading
import queue
from typing import Dict, List, Any, Optional, Callable, Union
import json
import datetime


class ImplantStatus:
    """Status tracking for a single implant"""
    
    ONLINE = "online"
    DELAYED = "delayed"
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    
    def __init__(self, implant_id: str, heartbeat_interval: int = 60):
        """Initialize implant status
        
        Args:
            implant_id: Implant identifier
            heartbeat_interval: Expected heartbeat interval in seconds
        """
        self.implant_id = implant_id
        self.heartbeat_interval = heartbeat_interval
        self.last_heartbeat = None
        self.history = []
        self.status = self.UNKNOWN
        self.consecutive_misses = 0
        self.cumulative_delay = 0
        
    def record_heartbeat(self, timestamp: Optional[float] = None):
        """Record a new heartbeat
        
        Args:
            timestamp: Heartbeat timestamp (defaults to current time)
        """
        now = timestamp or time.time()
        prev = self.last_heartbeat
        
        self.last_heartbeat = now
        
        # Calculate delay if we have a previous heartbeat
        if prev is not None:
            delay = (now - prev) - self.heartbeat_interval
            
            # Only count positive delays
            if delay > 0:
                self.cumulative_delay += delay
        
        # Reset missed counter
        self.consecutive_misses = 0
        
        # Update status
        self.status = self.ONLINE
        
        # Record in history
        self.history.append({
            "timestamp": now,
            "type": "heartbeat"
        })
        
        # Trim history if needed
        if len(self.history) > 100:
            self.history = self.history[-100:]
    
    def record_missed_heartbeat(self):
        """Record a missed heartbeat"""
        now = time.time()
        
        self.consecutive_misses += 1
        
        # Update status based on consecutive misses
        if self.consecutive_misses >= 3:
            self.status = self.OFFLINE
        else:
            self.status = self.DELAYED
        
        # Record in history
        self.history.append({
            "timestamp": now,
            "type": "missed"
        })
        
        # Trim history if needed
        if len(self.history) > 100:
            self.history = self.history[-100:]
    
    def get_uptime_percentage(self, window_seconds: int = 3600) -> float:
        """Calculate percentage of time the implant was online
        
        Args:
            window_seconds: Time window to consider in seconds
            
        Returns:
            Percentage of uptime (0-100)
        """
        if not self.history:
            return 0.0
            
        now = time.time()
        cutoff = now - window_seconds
        
        # Filter history to the requested time window
        relevant_history = [event for event in self.history if event["timestamp"] >= cutoff]
        
        if not relevant_history:
            return 0.0
            
        # Count heartbeats
        heartbeats = sum(1 for event in relevant_history if event["type"] == "heartbeat")
        
        # Calculate expected heartbeats in this window
        expected = max(1, int(window_seconds / self.heartbeat_interval))
        
        return min(100.0, (heartbeats / expected) * 100)
    
    def get_average_delay(self) -> float:
        """Calculate the average delay between heartbeats
        
        Returns:
            Average delay in seconds
        """
        if not self.history or self.consecutive_misses == 0:
            return 0.0
            
        heartbeat_count = sum(1 for event in self.history if event["type"] == "heartbeat")
        
        if heartbeat_count <= 1:
            return 0.0
            
        return self.cumulative_delay / (heartbeat_count - 1)
    
    def update_from_blacklink_status(self, status_data: Dict[str, Any]):
        """Update implant status from BlackLink heartbeat data
        
        Args:
            status_data: Status data from BlackLink heartbeat
        """
        # Record a heartbeat
        self.record_heartbeat()
        
        # Store additional data if needed
        if "system_info" in status_data:
            self.system_info = status_data["system_info"]
            
        if "status" in status_data:
            # Store link status info
            self.link_status = status_data["status"]
            
            # If there's a queue size, we might want to track it
            if "exfil_queue_size" in status_data["status"]:
                self.exfil_queue_size = status_data["status"]["exfil_queue_size"]
                
        # Store timestamp for convenience
        if "timestamp" in status_data:
            self.last_heartbeat_time = status_data["timestamp"]
    

class HeartbeatMonitor:
    """Monitors heartbeats from implants and triggers alerts"""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        """Initialize the heartbeat monitor
        
        Args:
            alert_callback: Function to call when an alert is triggered
        """
        self.logger = logging.getLogger("BlackPulse.HeartbeatMonitor")
        self.implants: Dict[str, ImplantStatus] = {}
        self.running = False
        self.check_interval = 10  # seconds
        self.default_heartbeat_interval = 60  # seconds
        self.alert_callback = alert_callback
        self.alert_thresholds = {
            "offline": 180,  # seconds without heartbeat before offline alert
            "delayed": 30    # seconds of delay before delayed alert
        }
    
    def start(self):
        """Start the heartbeat monitor"""
        if self.running:
            return
            
        self.running = True
        
        # Start monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("HeartbeatMonitor started")
    
    def stop(self):
        """Stop the heartbeat monitor"""
        self.running = False
        self.logger.info("HeartbeatMonitor stopped")
    
    def register_implant(self, implant_id: str, heartbeat_interval: Optional[int] = None):
        """Register an implant for monitoring
        
        Args:
            implant_id: Implant identifier
            heartbeat_interval: Expected heartbeat interval in seconds
        """
        interval = heartbeat_interval or self.default_heartbeat_interval
        
        self.implants[implant_id] = ImplantStatus(implant_id, interval)
        self.logger.debug(f"Registered implant {implant_id} with interval {interval}s")
    
    def unregister_implant(self, implant_id: str):
        """Unregister an implant from monitoring
        
        Args:
            implant_id: Implant identifier
        """
        if implant_id in self.implants:
            del self.implants[implant_id]
            self.logger.debug(f"Unregistered implant {implant_id}")
    
    def record_heartbeat(self, implant_id: str, timestamp: Optional[float] = None):
        """Record a heartbeat from an implant
        
        Args:
            implant_id: Implant identifier
            timestamp: Heartbeat timestamp (defaults to current time)
        """
        # Auto-register unknown implants
        if implant_id not in self.implants:
            self.register_implant(implant_id)
            
        self.implants[implant_id].record_heartbeat(timestamp)
        self.logger.debug(f"Recorded heartbeat for implant {implant_id}")
    
    def get_implant_status(self, implant_id: str) -> Optional[Dict[str, Any]]:
        """Get status information for an implant
        
        Args:
            implant_id: Implant identifier
            
        Returns:
            Status information dictionary
        """
        if implant_id not in self.implants:
            return None
            
        implant = self.implants[implant_id]
        
        return {
            "implant_id": implant_id,
            "status": implant.status,
            "last_heartbeat": implant.last_heartbeat,
            "consecutive_misses": implant.consecutive_misses,
            "uptime_1h": implant.get_uptime_percentage(3600),
            "uptime_24h": implant.get_uptime_percentage(86400),
            "average_delay": implant.get_average_delay()
        }
    
    def get_all_implant_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get status information for all implants
        
        Returns:
            Dictionary mapping implant IDs to status information
        """
        return {
            implant_id: self.get_implant_status(implant_id)
            for implant_id in self.implants
        }
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_implants()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
    
    def _check_implants(self):
        """Check all implants for missed heartbeats"""
        now = time.time()
        
        for implant_id, implant in list(self.implants.items()):
            # Skip implants with no heartbeats yet
            if implant.last_heartbeat is None:
                continue
                
            # Calculate time since last heartbeat
            elapsed = now - implant.last_heartbeat
            expected = implant.heartbeat_interval
            
            # Check if we've exceeded the expected interval with some tolerance
            if elapsed > expected * 1.5:
                implant.record_missed_heartbeat()
                
                # If we've crossed an alert threshold
                if elapsed >= self.alert_thresholds["offline"] and implant.consecutive_misses >= 3:
                    self._trigger_alert("offline", {
                        "implant_id": implant_id,
                        "elapsed": elapsed,
                        "expected": expected,
                        "consecutive_misses": implant.consecutive_misses
                    })
                elif elapsed >= expected + self.alert_thresholds["delayed"]:
                    self._trigger_alert("delayed", {
                        "implant_id": implant_id,
                        "elapsed": elapsed,
                        "expected": expected,
                        "consecutive_misses": implant.consecutive_misses
                    })
    
    def _trigger_alert(self, alert_type: str, details: Dict[str, Any]):
        """Trigger an alert
        
        Args:
            alert_type: Type of alert
            details: Alert details
        """
        if self.alert_callback:
            try:
                self.alert_callback(alert_type, details)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
        
        self.logger.warning(f"Alert '{alert_type}':