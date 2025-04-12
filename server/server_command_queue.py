"""
ErebusC2 Command Queue
Manages queued commands sent to implants
"""
import time
import json
import uuid
import logging
import threading
import queue
import datetime
import copy
from typing import Dict, List, Any, Optional, Union, Callable

class CommandQueue:
    """Manages command queue for implants"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the command queue
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger("ErebusC2.CommandQueue")
        self.config = config or {}
        
        # Command storage
        self.commands = {}  # All commands by ID
        self.pending_commands = {}  # Pending commands by implant ID
        
        # Thread locks
        self.commands_lock = threading.RLock()
        self.pending_lock = threading.RLock()
        
        # Command timeout
        self.command_timeout = self.config.get("command_timeout", 600)  # seconds
        
        # Cleanup thread
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_stale_commands)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        # Command result callbacks
        self.result_callbacks = {}
        
        self.logger.info("Command Queue initialized")
    
    def add_command(self, implant_id: str, command_type: str, params: Dict[str, Any] = None,
                  callback: Callable = None) -> str:
        """Add a command to the queue
        
        Args:
            implant_id: Target implant ID
            command_type: Command type
            params: Command parameters
            callback: Optional callback function for when result is received
            
        Returns:
            Command ID
        """
        # Generate command ID
        command_id = str(uuid.uuid4())
        
        # Create command object
        command = {
            "id": command_id,
            "implant_id": implant_id,
            "type": command_type,
            "params": params or {},
            "queued": datetime.datetime.now().isoformat(),
            "status": "pending",
            "sent": None,
            "completed": None,
            "result": None,
            "error": None
        }
        
        # Add to commands
        with self.commands_lock:
            self.commands[command_id] = command
            
        # Add to pending commands for implant
        with self.pending_lock:
            if implant_id not in self.pending_commands:
                self.pending_commands[implant_id] = []
                
            self.pending_commands[implant_id].append(command_id)
            
        # Register callback if provided
        if callback:
            self.result_callbacks[command_id] = callback
            
        self.logger.info(f"Added command {command_id} for implant {implant_id}: {command_type}")
        
        return command_id
    
    def mark_sent(self, command_id: str) -> bool:
        """Mark a command as sent
        
        Args:
            command_id: Command ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.commands_lock:
            if command_id not in self.commands:
                self.logger.warning(f"Command not found: {command_id}")
                return False
                
            self.commands[command_id]["status"] = "sent"
            self.commands[command_id]["sent"] = datetime.datetime.now().isoformat()
            
            self.logger.debug(f"Command {command_id} marked as sent")
            return True
    
    def update_command(self, command_id: str, status: str, result: Any = None, 
                      error: str = None) -> bool:
        """Update command status and result
        
        Args:
            command_id: Command ID
            status: New status
            result: Command result (if any)
            error: Error message (if any)
            
        Returns:
            True if successful, False otherwise
        """
        with self.commands_lock:
            if command_id not in self.commands:
                self.logger.warning(f"Command not found: {command_id}")
                return False
                
            command = self.commands[command_id]
            
            # Update command
            command["status"] = status
            command["completed"] = datetime.datetime.now().isoformat()
            
            if result is not None:
                command["result"] = result
                
            if error is not None:
                command["error"] = error
                
            # Remove from pending if completed
            if status in ["completed", "failed", "timeout", "error"]:
                with self.pending_lock:
                    implant_id = command["implant_id"]
                    if implant_id in self.pending_commands and command_id in self.pending_commands[implant_id]:
                        self.pending_commands[implant_id].remove(command_id)
                        
                        # Clean up empty lists
                        if not self.pending_commands[implant_id]:
                            del self.pending_commands[implant_id]
                
                # Call result callback if registered
                if command_id in self.result_callbacks:
                    try:
                        self.result_callbacks[command_id](command)
                    except Exception as e:
                        self.logger.error(f"Error in result callback for command {command_id}: {e}")
                    finally:
                        # Remove callback
                        del self.result_callbacks[command_id]
                
            self.logger.info(f"Updated command {command_id} status: {status}")
            return True
    
    def get_pending_commands(self, implant_id: str) -> List[Dict[str, Any]]:
        """Get pending commands for an implant
        
        Args:
            implant_id: Implant ID
            
        Returns:
            List of pending commands
        """
        with self.pending_lock:
            if implant_id not in self.pending_commands:
                return []
                
            command_ids = self.pending_commands[implant_id]
            
        # Get command details
        commands = []
        with self.commands_lock:
            for command_id in command_ids:
                if command_id in self.commands:
                    command = copy.deepcopy(self.commands[command_id])
                    command["status"] = "sent"  # Mark as sent
                    command["sent"] = datetime.datetime.now().isoformat()
                    self.commands[command_id] = command  # Update in storage
                    
                    # Add to result list
                    commands.append({
                        "id": command["id"],
                        "type": command["type"],
                        "params": command["params"]
                    })
        
        return commands
    
    def get_command_result(self, command_id: str) -> Optional[Dict[str, Any]]:
        """Get command result
        
        Args:
            command_id: Command ID
            
        Returns:
            Command data or None if not found
        """
        with self.commands_lock:
            if command_id in self.commands:
                return copy.deepcopy(self.commands[command_id])
            return None
    
    def get_commands(self, implant_id: Optional[str] = None, status: Optional[str] = None,
                   limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get commands matching criteria
        
        Args:
            implant_id: Filter by implant ID (optional)
            status: Filter by status (optional)
            limit: Maximum number of commands to return (optional)
            
        Returns:
            List of matching commands
        """
        with self.commands_lock:
            # Filter commands
            filtered = []
            for command in self.commands.values():
                if implant_id and command["implant_id"] != implant_id:
                    continue
                    
                if status and command["status"] != status:
                    continue
                    
                filtered.append(copy.deepcopy(command))
            
            # Sort by queued timestamp (most recent first)
            filtered.sort(key=lambda c: c.get("queued", ""), reverse=True)
            
            # Apply limit if specified
            if limit is not None:
                filtered = filtered[:limit]
                
            return filtered
    
    def cancel_command(self, command_id: str) -> bool:
        """Cancel a pending command
        
        Args:
            command_id: Command ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.commands_lock:
            if command_id not in self.commands:
                self.logger.warning(f"Command not found: {command_id}")
                return False
                
            command = self.commands[command_id]
            
            # Only cancel if still pending
            if command["status"] != "pending":
                self.logger.warning(f"Cannot cancel command {command_id} with status {command['status']}")
                return False
                
            # Update command
            command["status"] = "cancelled"
            command["completed"] = datetime.datetime.now().isoformat()
            
            # Remove from pending
            with self.pending_lock:
                implant_id = command["implant_id"]
                if implant_id in self.pending_commands and command_id in self.pending_commands[implant_id]:
                    self.pending_commands[implant_id].remove(command_id)
                    
                    # Clean up empty lists
                    if not self.pending_commands[implant_id]:
                        del self.pending_commands[implant_id]
            
            self.logger.info(f"Cancelled command {command_id}")
            return True
    
    def _cleanup_stale_commands(self):
        """Clean up stale commands"""
        while self.running:
            try:
                current_time = datetime.datetime.now()
                
                with self.commands_lock:
                    for command_id, command in list(self.commands.items()):
                        if command["status"] not in ["completed", "failed", "timeout", "error", "cancelled"]:
                            # Check if sent and timed out
                            if command["status"] == "sent" and command["sent"]:
                                try:
                                    sent_time = datetime.datetime.fromisoformat(command["sent"])
                                    time_diff = (current_time - sent_time).total_seconds()
                                    
                                    if time_diff > self.command_timeout:
                                        # Mark as timed out
                                        self.update_command(command_id, "timeout", error="Command timed out")
                                        self.logger.info(f"Command {command_id} timed out after {time_diff:.1f}s")
                                except ValueError:
                                    pass
                
                # Sleep for a while
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Error in command cleanup: {e}")
                time.sleep(60)  # Longer sleep on error
    
    def stop(self):
        """Stop the command queue"""
        self.running = False
        
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5.0)
            
        self.logger.info("Command Queue stopped")
        
    def export_commands(self) -> Dict[str, Any]:
        """Export command data
        
        Returns:
            Dictionary with command data
        """
        with self.commands_lock:
            return {
                "commands": copy.deepcopy(self.commands),
                "pending": copy.deepcopy(self.pending_commands)
            }
    
    def import_commands(self, command_data: Dict[str, Any]) -> bool:
        """Import command data
        
        Args:
            command_data: Command data to import
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not isinstance(command_data, dict) or "commands" not in command_data or "pending" not in command_data:
                self.logger.error("Invalid command data format")
                return False
                
            with self.commands_lock:
                self.commands = copy.deepcopy(command_data["commands"])
                
            with self.pending_lock:
                self.pending_commands = copy.deepcopy(command_data["pending"])
                
            self.logger.info(f"Imported {len(command_data['commands'])} commands")
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing command data: {e}")
            return False