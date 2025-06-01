# recon_tool/modules/active/port_scanner.py
"""
Port Scanner Module - Scan for open ports using native Python sockets.
Provides a basic TCP and UDP port scanning capability.
"""
import socket
import logging
import threading
import queue # For managing ports in threaded scanning
import time
from typing import Dict, List, Any, Optional, Set, Tuple # Added Set, Tuple
import ipaddress # For IP range scanning
from datetime import datetime # <--- ADDED THIS LINE

from ...config import DEFAULT_TIMEOUT, QUICK_TIMEOUT # UPDATED: Relative import, added QUICK_TIMEOUT
from ...utils.validators import is_valid_ip, is_valid_domain # UPDATED: Relative import
from ...utils.network_helpers import get_ip_from_domain # UPDATED: Relative import

logger = logging.getLogger(__name__)

# --- Helper to parse port strings ---
def _parse_ports_string(ports_str: str) -> Optional[List[int]]:
    """
    Parses a port string (e.g., "1-1000", "22,80,443", "all") into a list of integers.
    "all" will produce ports 1-65535 (use with caution).
    """
    if not ports_str:
        return None
    if ports_str.lower() == "all":
        return list(range(1, 65536))

    parsed_ports: Set[int] = set()
    parts = ports_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start_port, end_port = map(int, part.split('-', 1))
                if 1 <= start_port <= end_port <= 65535:
                    parsed_ports.update(range(start_port, end_port + 1))
                else:
                    logger.warning(f"Invalid port range part: {part}")
            except ValueError:
                logger.warning(f"Malformed port range part: {part}")
        else:
            try:
                port_num = int(part)
                if 1 <= port_num <= 65535:
                    parsed_ports.add(port_num)
                else:
                    logger.warning(f"Invalid port number: {port_num}")
            except ValueError:
                logger.warning(f"Malformed port number: {part}")
    
    if not parsed_ports:
        return None
    return sorted(list(parsed_ports))

# --- Core Scan Functions ---
def _check_tcp_port(target_ip: str, port: int, timeout: float) -> bool:
    """Checks if a single TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # connect_ex returns 0 on success, error indicator otherwise
            if sock.connect_ex((target_ip, port)) == 0:
                return True
    except socket.gaierror: # Address-related error
        logger.debug(f"Address-related error connecting to {target_ip}:{port} (TCP). Host may not exist or DNS issue.")
        return False # Treat as closed if host cannot be resolved here (should be IP already)
    except socket.timeout:
        logger.debug(f"Timeout connecting to {target_ip}:{port} (TCP).")
    except ConnectionRefusedError:
        logger.debug(f"Connection refused by {target_ip}:{port} (TCP).")
    except Exception as e:
        logger.debug(f"Error checking TCP port {target_ip}:{port} - {type(e).__name__}: {e}")
    return False

def _check_udp_port(target_ip: str, port: int, timeout: float) -> bool:
    """
    Checks if a single UDP port is open or filtered.
    UDP scanning is inherently unreliable. A lack of response usually means open|filtered.
    A response means open. An ICMP port unreachable means closed.
    This basic check assumes open|filtered if no ICMP error/timeout.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # Send a small, empty UDP packet. Some services might respond.
            # For many, no response means open|filtered.
            # An ICMP Port Unreachable error (socket.error/OSError with specific errno) means closed.
            sock.sendto(b'', (target_ip, port))
            try:
                # Attempt to receive a response. If we get one, it's definitely open.
                sock.recvfrom(1024) # Buffer size
                return True # Response received -> port is open
            except socket.timeout:
                # Timeout means port is likely open or filtered (no ICMP error received).
                # This is the common case for open|filtered UDP ports.
                return True 
            except socket.error as se: # Catches ICMP Port Unreachable on some systems
                 # Check for specific error numbers indicating port unreachable
                 # (e.g., 111 on Linux for ECONNREFUSED, 10054 on Windows for WSAECONNRESET)
                 # This part is OS-dependent and tricky for UDP.
                if hasattr(se, 'errno') and se.errno in [111, 10054, 113, 10051]: # ECONNREFUSED, WSAECONNRESET, EHOSTUNREACH, WSAENETUNREACH
                    logger.debug(f"UDP port {target_ip}:{port} likely closed (ICMP error or connection refused). Errno: {se.errno}")
                    return False # Port is closed
                logger.debug(f"Socket error for UDP {target_ip}:{port}: {se}")
                return True # Assume open|filtered on other socket errors
    except Exception as e:
        logger.debug(f"Error checking UDP port {target_ip}:{port} - {type(e).__name__}: {e}")
    return True # Default to open|filtered for UDP if any other exception

def _get_service_name(port: int, protocol: str) -> str:
    """Attempts to get a service name for a port and protocol."""
    try:
        return socket.getservbyport(port, protocol)
    except (OSError, socket.error): # socket.error for older pythons
        # Fallback for common ports not in services file
        common: Dict[Tuple[int, str], str] = {
            (80, "tcp"): "http", (443, "tcp"): "https", (22, "tcp"): "ssh",
            (21, "tcp"): "ftp", (25, "tcp"): "smtp", (53, "udp"): "domain",
            (53, "tcp"): "domain-tcp", (110, "tcp"): "pop3", (143, "tcp"): "imap",
        }
        return common.get((port, protocol), "unknown")


def scan_ports_threaded(target_ip: str, ports_to_scan: List[int], protocol: str, num_threads: int, timeout: float) -> List[Dict[str, Any]]:
    """Manages threaded scanning for a list of ports."""
    open_ports_details: List[Dict[str, Any]] = []
    port_queue: queue.Queue[int] = queue.Queue()
    results_lock = threading.Lock()

    for p_num in ports_to_scan: # Renamed port to p_num
        port_queue.put(p_num)

    def worker():
        while not port_queue.empty():
            try:
                current_port = port_queue.get_nowait()
            except queue.Empty:
                break # Should not happen if queue is checked first
            
            is_open = False
            state = "closed" # Default state
            reason = "no-response" # Default reason

            if protocol == "tcp":
                if _check_tcp_port(target_ip, current_port, timeout):
                    is_open = True
                    state = "open"
                    reason = "syn-ack" # Inferred
            elif protocol == "udp":
                if _check_udp_port(target_ip, current_port, timeout):
                    is_open = True # For UDP, this usually means open|filtered
                    state = "open|filtered"
                    # Reason for UDP is hard to determine reliably without more advanced techniques
            
            if is_open:
                with results_lock:
                    open_ports_details.append({
                        "port": current_port,
                        "protocol": protocol,
                        "state": state,
                        "service": _get_service_name(current_port, protocol),
                        "reason": reason
                        # Banner grabbing could be added here, but makes scans much slower
                    })
            port_queue.task_done()

    threads_list: List[threading.Thread] = [] # Renamed
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, daemon=True)
        threads_list.append(thread)
        thread.start()

    port_queue.join() # Wait for all tasks in the queue to be processed

    # Wait for all threads to actually finish (though join() on queue should suffice)
    # for t_item in threads_list: # Renamed t to t_item
    #     t_item.join()

    return sorted(open_ports_details, key=lambda x: x["port"])


def scan(target: str, ports: str = "1-1000", method: str = "tcp", threads: int = 10) -> Dict[str, Any]:
    """
    Scan for open ports on a target.
    
    Args:
        target: IP address or hostname to scan.
        ports: Port string (e.g., "1-1000", "22,80,443", "all").
        method: Scan method ("tcp", "udp", "both").
        threads: Number of threads to use for scanning.
        
    Returns:
        Dictionary containing scan results or an error.
    """
    logger.info(f"Starting port scan for {target} (Ports: {ports}, Method: {method}, Threads: {threads})")
    
    target_ip_resolved: Optional[str] = None # Renamed
    if is_valid_domain(target):
        try:
            target_ip_resolved = get_ip_from_domain(target)
            logger.info(f"Resolved domain {target} to IP {target_ip_resolved}")
        except Exception as e:
            logger.error(f"Could not resolve domain {target}: {str(e)}")
            return {"target_input": target, "error": f"DNS resolution failed: {str(e)}"}
    elif is_valid_ip(target):
        target_ip_resolved = target
    else:
        logger.error(f"Invalid target format: {target}. Expected IP or domain.")
        return {"target_input": target, "error": "Invalid target format."}

    if not target_ip_resolved:
        return {"target_input": target, "error": "Failed to determine IP address for scanning."}

    port_list = _parse_ports_string(ports)
    if port_list is None or not port_list:
        logger.error(f"No valid ports specified from string: '{ports}'")
        return {"target_input": target, "target_ip": target_ip_resolved, "error": f"Invalid or empty port specification: {ports}"}

    scan_results: Dict[str, Any] = { # Renamed result to scan_results
        "target_input": target,
        "target_ip": target_ip_resolved,
        "port_specification": ports,
        "scan_method": method,
        "total_ports_in_spec": len(port_list),
        "open_ports": {"tcp": [], "udp": []}, # Initialize structure
        "scan_start_time": datetime.now().isoformat(),
        "scan_end_time": None,
        "scan_duration_seconds": None
    }
    
    start_time = time.monotonic()
    
    # Determine scan timeout (quicker for more ports)
    # Timeout is per-port.
    scan_timeout = QUICK_TIMEOUT if len(port_list) > 200 else DEFAULT_TIMEOUT / 2

    protocols_to_scan: List[str] = [] # Renamed
    if method.lower() == "tcp" or method.lower() == "both":
        protocols_to_scan.append("tcp")
    if method.lower() == "udp" or method.lower() == "both":
        protocols_to_scan.append("udp")

    if not protocols_to_scan:
        scan_results["error"] = "Invalid scan method specified."
        return scan_results

    for proto in protocols_to_scan: # Renamed protocol to proto
        logger.info(f"Scanning {len(port_list)} {proto.upper()} ports on {target_ip_resolved} with {threads} threads (timeout: {scan_timeout:.1f}s/port).")
        # Adjust threads: no more threads than ports
        actual_threads = min(threads, len(port_list)) 
        if actual_threads < 1: actual_threads = 1 # Ensure at least one thread

        open_for_proto = scan_ports_threaded(target_ip_resolved, port_list, proto, actual_threads, scan_timeout)
        scan_results["open_ports"][proto] = open_for_proto
    
    end_time = time.monotonic()
    scan_results["scan_end_time"] = datetime.now().isoformat()
    scan_results["scan_duration_seconds"] = round(end_time - start_time, 2)
    
    # Add summary
    tcp_open_count = len(scan_results["open_ports"].get("tcp", []))
    udp_open_count = len(scan_results["open_ports"].get("udp", []))
    scan_results["summary"] = {
        "total_ports_scanned_tcp": len(port_list) if "tcp" in protocols_to_scan else 0,
        "total_ports_scanned_udp": len(port_list) if "udp" in protocols_to_scan else 0,
        "open_tcp_ports_count": tcp_open_count,
        "open_udp_ports_count": udp_open_count,
        "total_open_ports_found": tcp_open_count + udp_open_count
    }
    
    logger.info(f"Port scan for {target_ip_resolved} complete. Found {tcp_open_count} TCP and {udp_open_count} UDP open ports "
                f"in {scan_results['scan_duration_seconds']:.2f} seconds.")
    return scan_results

# --- Additional functions (e.g., single port scan, IP range scan) can be added similarly ---

def scan_single_port(target: str, port: int, protocol: str = "tcp", timeout: float = QUICK_TIMEOUT) -> Dict[str, Any]:
    """Scans a single port on a target."""
    logger.info(f"Scanning single port {protocol.upper()}/{port} on {target}")
    
    target_ip_resolved: Optional[str] = None
    if is_valid_domain(target):
        try:
            target_ip_resolved = get_ip_from_domain(target)
        except Exception as e:
            return {"target_input": target, "port": port, "protocol": protocol, "error": f"DNS resolution failed: {e}"}
    elif is_valid_ip(target):
        target_ip_resolved = target
    else:
        return {"target_input": target, "port": port, "protocol": protocol, "error": "Invalid target format."}

    if not target_ip_resolved: # Should be caught above
        return {"target_input": target, "port": port, "protocol": protocol, "error": "IP resolution failed."}

    if not (1 <= port <= 65535):
        return {"target_input": target, "target_ip": target_ip_resolved, "port": port, "protocol": protocol, "error": "Invalid port number."}

    protocol = protocol.lower()
    is_open = False
    state = "closed"
    reason = "no-response"

    if protocol == "tcp":
        if _check_tcp_port(target_ip_resolved, port, timeout):
            is_open = True
            state = "open"
            reason = "syn-ack"
    elif protocol == "udp":
        if _check_udp_port(target_ip_resolved, port, timeout):
            is_open = True
            state = "open|filtered"
    else:
        return {"target_input": target, "target_ip": target_ip_resolved, "port": port, "protocol": protocol, "error": "Invalid protocol. Use 'tcp' or 'udp'."}

    return {
        "target_input": target,
        "target_ip": target_ip_resolved,
        "port": port,
        "protocol": protocol,
        "state": state,
        "is_open": is_open, # Simplified boolean for quick check
        "service": _get_service_name(port, protocol),
        "reason": reason
    }