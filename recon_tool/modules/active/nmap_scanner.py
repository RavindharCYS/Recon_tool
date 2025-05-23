"""
Nmap scanner module - performs network scanning using Nmap
"""
import logging
import json
import subprocess
import re
import os
import platform
from typing import Dict, List, Any, Optional, Union

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from ...utils.validators import is_valid_ip, is_valid_domain
from ...utils.network_helpers import get_ip_from_domain

logger = logging.getLogger(__name__)

def scan(target: str, ports: str = "1-1000", scan_type: str = "sT", arguments: str = None) -> Dict[str, Any]:
    """
    Perform an Nmap scan on a target.
    
    Args:
        target: IP address or hostname to scan
        ports: Port range to scan (e.g., "1-1000", "22,80,443")
        scan_type: Type of scan to perform (sT, sS, sU, sV)
        arguments: Additional Nmap arguments
        
    Returns:
        Dictionary containing scan results
    """
    logger.info(f"Starting Nmap scan of {target} with scan type {scan_type} on ports {ports}")
    
    # Check if Nmap is installed
    if not is_nmap_installed():
        logger.error("Nmap not found. Please install Nmap to use this module.")
        return {"error": "Nmap not found. Please install Nmap to use this module."}
    
    # Check if python-nmap is available
    if not NMAP_AVAILABLE:
        logger.error("python-nmap library not installed. Run 'pip install python-nmap'")
        return {"error": "python-nmap library not installed. Run 'pip install python-nmap'"}
    
    # Validate target
    if not is_valid_ip(target) and not is_valid_domain(target):
        logger.error(f"Invalid target format: {target}")
        return {"error": f"Invalid target format: {target}"}
    
    # Resolve domain to IP if needed for logging
    target_ip = None
    if not is_valid_ip(target):
        try:
            target_ip = get_ip_from_domain(target)
            logger.info(f"Resolved {target} to {target_ip}")
        except Exception as e:
            logger.warning(f"Could not resolve domain {target}: {str(e)}")
    
    # Convert scan_type to appropriate argument
    scan_args = f"-{scan_type}"
    
    # Check if scan requires root/admin privileges
    if scan_type in ["sS", "sU"] and not is_admin():
        logger.warning(f"Scan type {scan_type} typically requires root/admin privileges")
        return {
            "error": f"Scan type {scan_type} requires root/admin privileges.",
            "suggestion": "Run this tool with administrator privileges or use scan type 'sT' instead."
        }
    
    # Build Nmap arguments
    if arguments:
        full_args = f"{scan_args} -p {ports} {arguments}"
    else:
        full_args = f"{scan_args} -p {ports}"
    
    try:
        # Initialize Nmap scanner
        nm = nmap.PortScanner()
        
        # Run the scan
        logger.info(f"Running Nmap with arguments: {full_args}")
        nm.scan(hosts=target, arguments=full_args)
        
        # Process scan results
        result = {
            "target": target,
            "target_ip": target_ip or target,
            "scan_type": scan_type,
            "ports_scanned": ports,
            "command": f"nmap {full_args} {target}",
            "hosts": []
        }
        
        # Process each host in the results
        for host in nm.all_hosts():
            host_info = {
                "host": host,
                "status": nm[host].state(),
                "hostnames": nm[host].hostnames(),
                "addresses": nm[host].addresses(),
                "vendor": nm[host].vendor() if hasattr(nm[host], 'vendor') else {},
                "open_ports": [],
                "filtered_ports": [],
                "closed_ports": []
            }
            
            # Process protocol information (tcp, udp, etc.)
            for proto in nm[host].all_protocols():
                host_info["protocol"] = proto
                
                # Get all ports for this protocol
                ports = sorted(nm[host][proto].keys())
                
                # Process each port
                for port in ports:
                    port_info = nm[host][proto][port]
                    port_data = {
                        "port": port,
                        "state": port_info["state"],
                        "service": port_info["name"],
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "reason": port_info.get("reason", ""),
                        "cpe": port_info.get("cpe", "")
                    }
                    
                    # Categorize by state
                    if port_info["state"] == "open":
                        host_info["open_ports"].append(port_data)
                    elif port_info["state"] == "filtered":
                        host_info["filtered_ports"].append(port_data)
                    elif port_info["state"] == "closed":
                        host_info["closed_ports"].append(port_data)
            
            # Add OS detection results if available
            if hasattr(nm[host], 'osclass') and nm[host].osclass():
                host_info["os_detection"] = nm[host].osclass()
            
            # Add host to results
            result["hosts"].append(host_info)
        
        # Add summary
        result["summary"] = {
            "total_hosts": len(nm.all_hosts()),
            "up_hosts": len([h for h in nm.all_hosts() if nm[h].state() == 'up']),
            "total_open_ports": sum(len(host["open_ports"]) for host in result["hosts"])
        }
        
        logger.info(f"Nmap scan completed. Found {result['summary']['total_open_ports']} open ports.")
        return result
        
    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan error: {str(e)}")
        return {"error": f"Nmap scan error: {str(e)}"}
    
    except Exception as e:
        logger.error(f"Error performing Nmap scan: {str(e)}")
        return {"error": f"Error performing Nmap scan: {str(e)}"}

def is_nmap_installed() -> bool:
    """
    Check if Nmap is installed on the system.
    
    Returns:
        True if Nmap is installed, False otherwise
    """
    try:
        # Try to run nmap -V to check if it's installed
        process = subprocess.Popen(
            ["nmap", "-V"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        
        # Check if the command ran successfully
        if process.returncode == 0:
            logger.debug("Nmap is installed.")
            return True
        else:
            logger.debug("Nmap installation check failed.")
            return False
    except Exception as e:
        logger.debug(f"Error checking Nmap installation: {str(e)}")
        return False

def is_admin() -> bool:
    """
    Check if the script is running with administrator/root privileges.
    
    Returns:
        True if running with admin privileges, False otherwise
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix-based systems
            return os.geteuid() == 0
    except Exception as e:
        logger.debug(f"Error checking admin privileges: {str(e)}")
        return False

def get_nmap_version() -> Optional[str]:
    """
    Get the installed Nmap version.
    
    Returns:
        Nmap version string or None if not found
    """
    try:
        process = subprocess.Popen(
            ["nmap", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        
        output = stdout.decode("utf-8", errors="ignore")
        
        # Extract version number
        match = re.search(r"Nmap version (\d+\.\d+\S*)", output)
        if match:
            version = match.group(1)
            logger.debug(f"Nmap version: {version}")
            return version
        else:
            logger.debug("Could not determine Nmap version.")
            return None
    except Exception as e:
        logger.debug(f"Error getting Nmap version: {str(e)}")
        return None

def scan_service_versions(target: str, ports: str) -> Dict[str, Any]:
    """
    Perform a service version detection scan.
    
    Args:
        target: IP address or hostname to scan
        ports: Port range to scan
        
    Returns:
        Dictionary containing scan results
    """
    logger.info(f"Starting service version detection for {target} on ports {ports}")
    
    # Use the main scan function with service detection enabled
    return scan(target, ports=ports, scan_type="sV", arguments="-sV --version-intensity 7")

def scan_os_detection(target: str) -> Dict[str, Any]:
    """
    Perform OS detection scan.
    
    Args:
        target: IP address or hostname to scan
        
    Returns:
        Dictionary containing scan results
    """
    logger.info(f"Starting OS detection for {target}")
    
    # Check for admin privileges
    if not is_admin():
        logger.warning("OS detection typically requires root/admin privileges")
        return {
            "error": "OS detection requires root/admin privileges.",
            "suggestion": "Run this tool with administrator privileges."
        }
    
    # Use the main scan function with OS detection enabled
    return scan(target, scan_type="sS", arguments="-O")