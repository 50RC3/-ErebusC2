"""
BlackLink Module
Provides secure, stealthy communication and data exfiltration capabilities for ErebusC2
"""

from .blacklink_c2_implant import (
    BlackLinkImplant, 
    DataExfiltrationManager, 
    DataCollector, 
    CustomProtocolHandler, 
    DataCompressor
)

from .blacklink_core import (
    BlackLinkConfig,
    HeartbeatManager,
    BlackLinkCryptoUtil
)

from .protocol_handlers import (
    ProtocolManager,
    HTTPHandler,
    DNSHandler,
    ICMPHandler,
    SMBHandler
)

__all__ = [
    'BlackLinkImplant',
    'DataExfiltrationManager',
    'DataCollector',
    'CustomProtocolHandler',
    'DataCompressor',
    'BlackLinkConfig',
    'HeartbeatManager',
    'BlackLinkCryptoUtil',
    'ProtocolManager',
    'HTTPHandler',
    'DNSHandler',
    'ICMPHandler',
    'SMBHandler'
]
