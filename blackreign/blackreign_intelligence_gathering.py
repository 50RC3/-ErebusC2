"""
BlackReign Intelligence Gathering Module
Collects data, monitors targets, and provides analytics
"""
import logging
import threading
import time
import queue
import json
import os
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
import uuid
import yaml
import base64
import hashlib
import socket
import ipaddress
from datetime import datetime
import random


class IntelligenceGathering:
    """Collects and processes intelligence data"""
    
    def __init__(self, config_path: str = "blackreign/config.yaml"):
        """Initialize the intelligence gathering module
        
        Args:
            config_path: Path to configuration file
        """
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.running = False
        
        # Collection data structures
        self.targets = {}
        self.networks = {}
        self.vulnerabilities = {}
        self.credentials = {}
        self.observed_services = {}
        self.intel_events = []
        
        # Thread synchronization
        self.data_lock = threading.RLock()
        self.event_queue = queue.Queue()
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # Event callbacks
        self.event_callbacks = []
        
        # Initialize collectors
        self.collectors = self._setup_collectors()
        
        self.logger.info("BlackReign Intelligence Gathering module initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the module
        
        Returns:
            Configured logger
        """
        logger = logging.getLogger("BlackReign.IntelligenceGathering")
        logger.setLevel(logging.INFO)
        
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler("blackreign_intel.log")
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
            
            # Extract intelligence-specific config
            intel_config = config.get("intelligence", {})
            
            self.logger.debug(f"Configuration loaded from {config_path}")
            return intel_config
        except Exception as e:
            self.logger.warning(f"Failed to load configuration from {config_path}: {e}")
            
            # Return default configuration
            return {
                "collection_interval": 300,  # seconds
                "max_event_history": 1000,
                "target_timeout": 86400,  # seconds (24 hours)
                "collectors": {
                    "passive_network": {
                        "enabled": True,
                        "interval": 120,
                        "timeout": 30
                    },
                    "service_scanner": {
                        "enabled": True,
                        "interval": 600,
                        "ports": [21, 22, 23, 25, 80, 443, 445, 3389]
                    },
                    "vuln_scanner": {
                        "enabled": True,
                        "interval": 3600,
                        "timeout": 300
                    }
                },
                "analytics": {
                    "risk_threshold": 0.7,
                    "update_interval": 600
                }
            }
    
    def _setup_collectors(self) -> Dict[str, Dict[str, Any]]:
        """Initialize data collectors
        
        Returns:
            Dictionary of configured collectors
        """
        collectors = {}
        
        # Get collector configs
        collector_configs = self.config.get("collectors", {})
        
        # Setup each enabled collector
        for name, config in collector_configs.items():
            if config.get("enabled", True):
                collectors[name] = {
                    "config": config,
                    "last_run": 0,
                    "status": "idle"
                }
                self.logger.debug(f"Initialized collector: {name}")
            
        return collectors
    
    def start(self):
        """Start the intelligence gathering module"""
        if self.running:
            return
            
        self.running = True
        self.start_time = time.time()
        
        # Start the event processor thread
        self.event_thread = threading.Thread(target=self._event_processor_loop)
        self.event_thread.daemon = True
        self.event_thread.start()
        
        # Start the task processor thread
        self.task_thread = threading.Thread(target=self._task_processor_loop)
        self.task_thread.daemon = True
        self.task_thread.start()
        
        # Start the result processor thread
        self.result_thread = threading.Thread(target=self._result_processor_loop)
        self.result_thread.daemon = True
        self.result_thread.start()
        
        # Start the main collection thread
        self.collection_thread = threading.Thread(target=self._collection_loop)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        
        # Start the analytics thread
        self.analytics_thread = threading.Thread(target=self._analytics_loop)
        self.analytics_thread.daemon = True
        self.analytics_thread.start()
        
        self.logger.info("BlackReign Intelligence Gathering module started")
    
    def stop(self):
        """Stop the intelligence gathering module"""
        if not self.running:
            return
            
        self.running = False
        
        # Wait for threads to finish
        if hasattr(self, 'event_thread'):
            self.event_thread.join(timeout=5.0)
            
        if hasattr(self, 'task_thread'):
            self.task_thread.join(timeout=5.0)
            
        if hasattr(self, 'result_thread'):
            self.result_thread.join(timeout=5.0)
            
        if hasattr(self, 'collection_thread'):
            self.collection_thread.join(timeout=5.0)
            
        if hasattr(self, 'analytics_thread'):
            self.analytics_thread.join(timeout=5.0)
        
        self.logger.info("BlackReign Intelligence Gathering module stopped")
    
    def _event_processor_loop(self):
        """Main loop for processing intelligence events"""
        while self.running:
            try:
                # Get event with timeout
                try:
                    event = self.event_queue.get(timeout=1.0)
                    
                    # Process event
                    self._process_intel_event(event)
                    
                    # Mark as done
                    self.event_queue.task_done()
                except queue.Empty:
                    pass
            except Exception as e:
                self.logger.error(f"Error in event processor: {e}")
                time.sleep(5)  # Sleep on error to avoid tight loop
    
    def _task_processor_loop(self):
        """Main loop for processing collection tasks"""
        while self.running:
            try:
                # Get task with timeout
                try:
                    task = self.task_queue.get(timeout=1.0)
                    
                    # Process task
                    result = self._process_collection_task(task)
                    
                    # Put result in result queue
                    if result:
                        self.result_queue.put(result)
                    
                    # Mark as done
                    self.task_queue.task_done()
                except queue.Empty:
                    pass
            except Exception as e:
                self.logger.error(f"Error in task processor: {e}")
                time.sleep(5)  # Sleep on error to avoid tight loop
    
    def _result_processor_loop(self):
        """Main loop for processing collection results"""
        while self.running:
            try:
                # Get result with timeout
                try:
                    result = self.result_queue.get(timeout=1.0)
                    
                    # Process result
                    self._process_collection_result(result)
                    
                    # Mark as done
                    self.result_queue.task_done()
                except queue.Empty:
                    pass
            except Exception as e:
                self.logger.error(f"Error in result processor: {e}")
                time.sleep(5)  # Sleep on error to avoid tight loop
    
    def _collection_loop(self):
        """Main loop for scheduling collection tasks"""
        while self.running:
            try:
                # Check for collectors that need to run
                current_time = time.time()
                
                for name, collector in self.collectors.items():
                    # Skip if not enabled
                    if not collector.get("config", {}).get("enabled", True):
                        continue
                        
                    # Get interval
                    interval = collector.get("config", {}).get("interval", 300)
                    
                    # Check if it's time to run
                    if current_time - collector.get("last_run", 0) >= interval:
                        # Update last run time
                        collector["last_run"] = current_time
                        collector["status"] = "running"
                        
                        # Queue collection task
                        self._queue_collection_task(name)
                
                # Sleep for a bit
                time.sleep(10)
            except Exception as e:
                self.logger.error(f"Error in collection loop: {e}")
                time.sleep(30)  # Sleep on error to avoid tight loop
    
    def _analytics_loop(self):
        """Main loop for running analytics on collected data"""
        while self.running:
            try:
                # Run analytics
                self._run_analytics()
                
                # Sleep for the configured interval
                interval = self.config.get("analytics", {}).get("update_interval", 600)
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error in analytics loop: {e}")
                time.sleep(60)  # Sleep on error to avoid tight loop
    
    def _process_intel_event(self, event: Dict[str, Any]):
        """Process an intelligence event
        
        Args:
            event: Event data
        """
        # Add timestamp if not present
        if "timestamp" not in event:
            event["timestamp"] = time.time()
            
        # Add to event history
        with self.data_lock:
            self.intel_events.append(event)
            
            # Limit history size
            max_events = self.config.get("max_event_history", 1000)
            if len(self.intel_events) > max_events:
                self.intel_events = self.intel_events[-max_events:]
        
        # Call registered callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Error in event callback: {e}")
        
        # Process based on event type
        event_type = event.get("type")
        
        if event_type == "target_discovered":
            self._process_target_discovered(event)
        elif event_type == "network_discovered":
            self._process_network_discovered(event)
        elif event_type == "vulnerability_discovered":
            self._process_vulnerability_discovered(event)
        elif event_type == "credential_discovered":
            self._process_credential_discovered(event)
        elif event_type == "service_discovered":
            self._process_service_discovered(event)
    
    def _process_target_discovered(self, event: Dict[str, Any]):
        """Process a target discovered event
        
        Args:
            event: Event data
        """
        target_id = event.get("target_id")
        target_info = event.get("info", {})
        
        if not target_id:
            self.logger.warning("Target discovered event without target ID")
            return
            
        with self.data_lock:
            # Check if target is already known
            if target_id in self.targets:
                # Update existing target
                self.targets[target_id]["last_updated"] = time.time()
                self.targets[target_id]["info"].update(target_info)
            else:
                # Add new target
                self.targets[target_id] = {
                    "id": target_id,
                    "info": target_info,
                    "discovered": time.time(),
                    "last_updated": time.time(),
                    "status": "active",
                    "services": [],
                    "vulnerabilities": [],
                    "credentials": []
                }
                self.logger.info(f"Added new target: {target_id}")
    
    def _process_network_discovered(self, event: Dict[str, Any]):
        """Process a network discovered event
        
        Args:
            event: Event data
        """
        network_id = event.get("network_id")
        network_info = event.get("info", {})
        
        if not network_id:
            self.logger.warning("Network discovered event without network ID")
            return
            
        with self.data_lock:
            # Check if network is already known
            if network_id in self.networks:
                # Update existing network
                self.networks[network_id]["last_updated"] = time.time()
                self.networks[network_id]["info"].update(network_info)
            else:
                # Add new network
                self.networks[network_id] = {
                    "id": network_id,
                    "info": network_info,
                    "discovered": time.time(),
                    "last_updated": time.time(),
                    "targets": [],
                    "routes": []
                }
                self.logger.info(f"Added new network: {network_id}")
    
    def _process_vulnerability_discovered(self, event: Dict[str, Any]):
        """Process a vulnerability discovered event
        
        Args:
            event: Event data
        """
        vuln_id = event.get("vulnerability_id")
        target_id = event.get("target_id")
        vuln_info = event.get("info", {})
        
        if not vuln_id:
            self.logger.warning("Vulnerability discovered event without vulnerability ID")
            return
            
        with self.data_lock:
            # Check if vulnerability is already known
            if vuln_id in self.vulnerabilities:
                # Update existing vulnerability
                self.vulnerabilities[vuln_id]["last_updated"] = time.time()
                self.vulnerabilities[vuln_id]["info"].update(vuln_info)
            else:
                # Add new vulnerability
                self.vulnerabilities[vuln_id] = {
                    "id": vuln_id,
                    "target_id": target_id,
                    "info": vuln_info,
                    "discovered": time.time(),
                    "last_updated": time.time(),
                    "status": "open",
                    "exploited": False,
                    "exploit_attempts": 0
                }
                self.logger.info(f"Added new vulnerability: {vuln_id} for target {target_id}")
            
            # Associate with target if provided
            if target_id and target_id in self.targets:
                if vuln_id not in self.targets[target_id]["vulnerabilities"]:
                    self.targets[target_id]["vulnerabilities"].append(vuln_id)
    
    def _process_credential_discovered(self, event: Dict[str, Any]):
        """Process a credential discovered event
        
        Args:
            event: Event data
        """
        cred_id = event.get("credential_id")
        target_id = event.get("target_id")
        cred_info = event.get("info", {})
        
        if not cred_id:
            self.logger.warning("Credential discovered event without credential ID")
            return
            
        with self.data_lock:
            # Check if credential is already known
            if cred_id in self.credentials:
                # Update existing credential
                self.credentials[cred_id]["last_updated"] = time.time()
                self.credentials[cred_id]["info"].update(cred_info)
            else:
                # Add new credential
                self.credentials[cred_id] = {
                    "id": cred_id,
                    "target_id": target_id,
                    "info": cred_info,
                    "discovered": time.time(),
                    "last_updated": time.time(),
                    "validated": False,
                    "validation_attempts": 0
                }
                self.logger.info(f"Added new credential: {cred_id} for target {target_id}")
            
            # Associate with target if provided
            if target_id and target_id in self.targets:
                if cred_id not in self.targets[target_id]["credentials"]:
                    self.targets[target_id]["credentials"].append(cred_id)
    
    def _process_service_discovered(self, event: Dict[str, Any]):
        """Process a service discovered event
        
        Args:
            event: Event data
        """
        service_id = event.get("service_id")
        target_id = event.get("target_id")
        service_info = event.get("info", {})
        
        if not service_id:
            self.logger.warning("Service discovered event without service ID")
            return
            
        with self.data_lock:
            # Check if service is already known
            if service_id in self.observed_services:
                # Update existing service
                self.observed_services[service_id]["last_updated"] = time.time()
                self.observed_services[service_id]["info"].update(service_info)
            else:
                # Add new service
                self.observed_services[service_id] = {
                    "id": service_id,
                    "target_id": target_id,
                    "info": service_info,
                    "discovered": time.time(),
                    "last_updated": time.time(),
                    "status": "active"
                }
                self.logger.info(f"Added new service: {service_id} for target {target_id}")
            
            # Associate with target if provided
            if target_id and target_id in self.targets:
                if service_id not in self.targets[target_id]["services"]:
                    self.targets[target_id]["services"].append(service_id)
    
    def _queue_collection_task(self, collector_name: str):
        """Queue a collection task
        
        Args:
            collector_name: Name of the collector to run
        """
        # Create task
        task = {
            "id": str(uuid.uuid4()),
            "collector": collector_name,
            "timestamp": time.time(),
            "parameters": self.collectors[collector_name].get("config", {})
        }
        
        # Queue task
        self.task_queue.put(task)
        self.logger.debug(f"Queued collection task: {collector_name}")
    
    def _process_collection_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process a collection task
        
        Args:
            task: Task data
            
        Returns:
            Task result
        """
        collector_name = task.get("collector")
        task_id = task.get("id")
        
        if not collector_name or collector_name not in self.collectors:
            self.logger.warning(f"Unknown collector: {collector_name}")
            return {
                "id": task_id,
                "collector": collector_name,
                "status": "failed",
                "error": "Unknown collector",
                "timestamp": time.time()
            }
        
        try:
            # Record start time
            start_time = time.time()
            
            # Call the appropriate collector function
            if collector_name == "passive_network":
                result_data = self._run_passive_network_collection(task)
            elif collector_name == "service_scanner":
                result_data = self._run_service_scanner(task)
            elif collector_name == "vuln_scanner":
                result_data = self._run_vuln_scanner(task)
            else:
                raise ValueError(f"Unsupported collector: {collector_name}")
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Update collector status
            self.collectors[collector_name]["status"] = "idle"
            self.collectors[collector_name]["last_duration"] = duration
            
            # Return result
            return {
                "id": task_id,
                "collector": collector_name,
                "status": "completed",
                "timestamp": time.time(),
                "duration": duration,
                "data": result_data
            }
        except Exception as e:
            self.logger.error(f"Error running collector {collector_name}: {e}")
            
            # Update collector status
            self.collectors[collector_name]["status"] = "error"
            self.collectors[collector_name]["last_error"] = str(e)
            
            #