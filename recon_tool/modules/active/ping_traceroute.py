"""
Ping and Traceroute Module - Check host reachability and network path using system utilities.
"""
import subprocess
import socket # For gethostbyname if needed, though network_helpers is preferred
import logging
import platform
import re
import time # Not directly used here, but good for potential future extensions
import ipaddress # For IP validation if needed
from typing import Dict, List, Any, Optional, Union

from ...config import DEFAULT_TIMEOUT, QUICK_TIMEOUT # UPDATED: Relative import
from ...utils.validators import is_valid_ip, is_valid_domain # UPDATED: Relative import
from ...utils.network_helpers import get_ip_from_domain # UPDATED: Relative import

logger = logging.getLogger(__name__)

def _is_tool_available(name: str) -> bool:
    """Checks if a command-line tool is available in the system's PATH."""
    try:
        # For Windows, 'where' command can check. For Unix, 'which' or 'command -v'.
        # Simpler check: try to run with a version flag or help flag.
        if platform.system().lower() == "windows":
            # On Windows, ping and tracert are usually built-in.
            # For other tools, one might need `subprocess.call(['where', name], ...)`
            # For ping/tracert, assume available if Windows.
            if name in ["ping", "tracert"]:
                return True
            process = subprocess.Popen([name, '/?'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) # shell=True for builtins sometimes needed
        else:
            process = subprocess.Popen(['command', '-v', name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        process.communicate(timeout=QUICK_TIMEOUT) # Short timeout for this check
        return process.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    except Exception as e:
        logger.debug(f"Error checking tool availability for '{name}': {e}")
        return False


def ping(target: str, count: int = 4, timeout_seconds: int = 2) -> Dict[str, Any]: # timeout_seconds per ping packet
    """
    Ping a host to check if it's reachable using the system's ping utility.
    
    Args:
        target: IP address or hostname to ping.
        count: Number of ICMP Echo requests to send.
        timeout_seconds: Timeout in seconds for each ping packet (for -W or -w flags).
        
    Returns:
        Dictionary containing ping results or an error.
    """
    logger.info(f"Pinging {target} with {count} packets (timeout: {timeout_seconds}s/packet).")
    
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
         return {"target_input": target, "error": "Failed to determine IP address for ping."}

    system_os = platform.system().lower() # Renamed
    
    # Construct ping command
    # -c count (Unix-like), -n count (Windows)
    # -W timeout_seconds (Linux for round-trip), -w timeout_milliseconds (Windows/macOS for overall)
    if system_os == "windows":
        if not _is_tool_available("ping"): # Should always be true for Windows
            return {"target_input": target, "target_ip": target_ip_resolved, "error": "ping command not found on Windows."}
        # Windows -w uses milliseconds for overall timeout. We want per-packet if possible.
        # Standard ping doesn't have per-packet timeout easily. This -w is for total.
        cmd = ["ping", "-n", str(count), "-w", str(timeout_seconds * 1000 * count), target_ip_resolved]
    elif system_os == "darwin": # macOS
        if not _is_tool_available("ping"):
            return {"target_input": target, "target_ip": target_ip_resolved, "error": "ping command not found on macOS."}
        # macOS -t for individual packet timeout
        cmd = ["ping", "-c", str(count), "-t", str(timeout_seconds), target_ip_resolved]
    else: # Linux and other Unix-like
        if not _is_tool_available("ping"):
            return {"target_input": target, "target_ip": target_ip_resolved, "error": "ping command not found on this system."}
        # Linux -W for round-trip timeout in seconds.
        cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds), target_ip_resolved]

    ping_result: Dict[str, Any] = { # Renamed result to ping_result
        "target_input": target,
        "target_ip": target_ip_resolved,
        "reachable": False,
        "packets_sent": count,
        "packets_received": 0,
        "packet_loss_percent": 100.0,
        "rtt_min_ms": None,
        "rtt_avg_ms": None,
        "rtt_max_ms": None,
        "rtt_mdev_ms": None, # For Linux
        "raw_output": ""
    }

    try:
        # Execute the ping command. Overall timeout slightly more than count * packet_timeout + buffer
        process_timeout = (count * timeout_seconds) + 5 # Add a 5s buffer
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True)
        stdout, stderr = process.communicate(timeout=process_timeout)
        ping_result["raw_output"] = stdout + stderr # Combine stdout and stderr for raw output

        if process.returncode == 0: # Success usually means some packets returned
            ping_result["reachable"] = True # Mark as reachable if command succeeds

        # Parse output (this is OS-dependent)
        if system_os == "windows":
            sent_match = re.search(r"Sent = (\d+)", stdout)
            recv_match = re.search(r"Received = (\d+)", stdout)
            loss_match = re.search(r"Lost = \d+ \((\d+)% loss\)", stdout) # Corrected regex for loss percentage
            if sent_match: ping_result["packets_sent"] = int(sent_match.group(1)) # Update with actual sent if available
            if recv_match: ping_result["packets_received"] = int(recv_match.group(1))
            if loss_match: ping_result["packet_loss_percent"] = float(loss_match.group(1))
            
            rtt_match = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", stdout)
            if rtt_match:
                ping_result["rtt_min_ms"] = float(rtt_match.group(1))
                ping_result["rtt_max_ms"] = float(rtt_match.group(2))
                ping_result["rtt_avg_ms"] = float(rtt_match.group(3))
        else: # Linux/macOS
            # Example: "5 packets transmitted, 5 received, 0% packet loss, time 4005ms"
            pkt_match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:received|packets received)", stdout, re.IGNORECASE)
            if pkt_match:
                ping_result["packets_sent"] = int(pkt_match.group(1)) # Update with actual sent
                ping_result["packets_received"] = int(pkt_match.group(2))
            
            loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", stdout, re.IGNORECASE)
            if loss_match:
                ping_result["packet_loss_percent"] = float(loss_match.group(1))
            
            # Example: "rtt min/avg/max/mdev = 0.283/0.338/0.410/0.051 ms" (Linux)
            # Example: "round-trip min/avg/max/stddev = 10.513/11.154/12.103/0.557 ms" (macOS)
            rtt_stats_match = re.search(r"(?:min/avg/max/(?:mdev|stddev))\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", stdout, re.IGNORECASE)
            if rtt_stats_match:
                ping_result["rtt_min_ms"] = float(rtt_stats_match.group(1))
                ping_result["rtt_avg_ms"] = float(rtt_stats_match.group(2))
                ping_result["rtt_max_ms"] = float(rtt_stats_match.group(3))
                ping_result["rtt_mdev_ms"] = float(rtt_stats_match.group(4)) # mdev or stddev
        
        # Refine reachability based on received packets
        if ping_result["packets_received"] > 0:
            ping_result["reachable"] = True
        else:
            ping_result["reachable"] = False # No packets received means not reachable

        if ping_result["reachable"]:
             logger.info(f"Ping to {target_ip_resolved} successful. Avg RTT: {ping_result['rtt_avg_ms']} ms, Loss: {ping_result['packet_loss_percent']}%")
        else:
             logger.warning(f"Ping to {target_ip_resolved} failed or all packets lost.")
             if process.returncode != 0 and not stderr: # if command failed but no stderr, populate with stdout
                 ping_result["error_details"] = stdout.strip() if stdout else "Ping command failed with no specific error output."
             elif stderr:
                 ping_result["error_details"] = stderr.strip()


    except subprocess.TimeoutExpired:
        logger.error(f"Ping command to {target_ip_resolved} timed out after {process_timeout}s.")
        ping_result["error"] = "Ping command timed out."
        ping_result["raw_output"] = (stdout if 'stdout' in locals() else "") + (stderr if 'stderr' in locals() else "")
    except FileNotFoundError:
        logger.error(f"Ping command not found on this system. Cannot ping {target_ip_resolved}.")
        ping_result["error"] = "Ping command not found."
    except Exception as e:
        logger.error(f"Error pinging {target_ip_resolved}: {type(e).__name__} - {str(e)}")
        ping_result["error"] = f"Unexpected error: {str(e)}"
        ping_result["raw_output"] = (stdout if 'stdout' in locals() else "") + (stderr if 'stderr' in locals() else "")
        
    return ping_result


def traceroute(target: str, max_hops: int = 30, timeout_seconds: int = 2) -> Dict[str, Any]: # timeout_seconds per hop
    """
    Trace the route to a host using system's traceroute/tracert utility.
    
    Args:
        target: IP address or hostname to trace.
        max_hops: Maximum number of hops to trace.
        timeout_seconds: Timeout in seconds for probes to each hop.
        
    Returns:
        Dictionary containing traceroute results or an error.
    """
    logger.info(f"Tracing route to {target} (max_hops: {max_hops}, timeout: {timeout_seconds}s/hop).")

    target_ip_resolved: Optional[str] = None
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
         return {"target_input": target, "error": "Failed to determine IP address for traceroute."}

    system_os = platform.system().lower()
    cmd_tool_name = "tracert" if system_os == "windows" else "traceroute"
    
    if not _is_tool_available(cmd_tool_name):
        return {"target_input": target, "target_ip": target_ip_resolved, "error": f"{cmd_tool_name} command not found."}

    if system_os == "windows":
        # tracert -d (no DNS resolve), -h max_hops, -w timeout_ms
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_seconds * 1000), target_ip_resolved]
    else: # Linux/macOS
        # traceroute -n (no DNS resolve), -m max_hops, -w wait_time_seconds (Linux) or -q queries -w wait_time (macOS needs -q 1 for faster single probe)
        # For simplicity, using a common set. -q 1 for faster probes.
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", "1", "-w", str(timeout_seconds), target_ip_resolved]


    traceroute_result: Dict[str, Any] = { # Renamed result to traceroute_result
        "target_input": target,
        "target_ip": target_ip_resolved,
        "max_hops_set": max_hops,
        "hops": [],
        "trace_completed": False, # Whether the target was reached
        "raw_output": ""
    }

    try:
        # Estimate overall timeout: max_hops * (num_probes_usually_3 * timeout_seconds_per_probe) + buffer
        # Since we use -q 1 for Unix, it's simpler: max_hops * timeout_seconds + buffer
        process_timeout = (max_hops * timeout_seconds) + 15 # 15s buffer
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True)
        stdout, stderr = process.communicate(timeout=process_timeout)
        traceroute_result["raw_output"] = stdout + stderr

        current_hops: List[Dict[str, Any]] = [] # Renamed hops to current_hops
        lines = stdout.splitlines()

        for line_num, line_str in enumerate(lines): # Renamed line to line_str
            line_str = line_str.strip()
            if not line_str: continue

            # Skip header lines
            if system_os == "windows":
                if "Tracing route to" in line_str or "Over a maximum of" in line_str or not line_str : continue
                if "Trace complete." in line_str: 
                    traceroute_result["trace_completed"] = True
                    break
            else: # Linux/macOS
                if line_str.startswith("traceroute to") or line_str.startswith("Warning:"): continue
                if line_num == 1 and re.match(r"\d+ hops max", line_str): continue # Skip "X hops max, Y byte packets"
            
            hop_info: Dict[str, Any] = {"hop_number": None, "ip_address": None, "hostname": None, "rtt_ms": [], "timed_out": False}
            
            # Regex for Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1" or "  1     *        *        *     Request timed out."
            # Regex for Linux/macOS: " 1  192.168.1.1 (192.168.1.1)  0.350 ms  0.300 ms  0.250 ms" or " 1  * * *"
            
            # Try to parse hop number first
            hop_num_match = re.match(r"^\s*(\d+)", line_str)
            if not hop_num_match: continue # Not a hop line
            hop_info["hop_number"] = int(hop_num_match.group(1))

            if "*" in line_str or "Request timed out" in line_str:
                hop_info["timed_out"] = True
            else:
                ip_match = re.search(r"((?:\d{1,3}\.){3}\d{1,3})", line_str) # Basic IPv4 regex
                if ip_match:
                    hop_info["ip_address"] = ip_match.group(1)
                    # Attempt to get hostname if not using -d/-n (though we are)
                    # For now, hostname resolution is skipped by -d/-n flags.
                    # If needed, it would be done here:
                    # try:
                    #    hop_info["hostname"] = socket.gethostbyaddr(hop_info["ip_address"])[0]
                    # except socket.herror: pass
                
                # Extract RTTs
                # Windows: <1 ms, 10 ms
                # Linux/macOS: 0.350 ms
                rtt_values_ms = re.findall(r"([\d.]+)\s*ms|<1\s*ms", line_str, re.IGNORECASE)
                for rtt_val_str in rtt_values_ms: # Renamed rtt to rtt_val_str
                    if "<1" in rtt_val_str.lower():
                        hop_info["rtt_ms"].append(1.0) # Approximate <1ms as 1.0ms for simplicity
                    elif rtt_val_str.replace('.', '', 1).isdigit(): # Check if it's a number
                        hop_info["rtt_ms"].append(float(rtt_val_str))
            
            current_hops.append(hop_info)
            if hop_info["ip_address"] == target_ip_resolved:
                traceroute_result["trace_completed"] = True
                break # Reached destination

        traceroute_result["hops"] = current_hops
        if traceroute_result["trace_completed"]:
             logger.info(f"Traceroute to {target_ip_resolved} completed.")
        else:
             logger.warning(f"Traceroute to {target_ip_resolved} may be incomplete.")
             if stderr: traceroute_result["error_details"] = stderr.strip()


    except subprocess.TimeoutExpired:
        logger.error(f"Traceroute command to {target_ip_resolved} timed out after {process_timeout}s.")
        traceroute_result["error"] = "Traceroute command timed out."
        traceroute_result["raw_output"] = (stdout if 'stdout' in locals() else "") + (stderr if 'stderr' in locals() else "")
    except FileNotFoundError:
        logger.error(f"{cmd_tool_name} command not found. Cannot trace route to {target_ip_resolved}.")
        traceroute_result["error"] = f"{cmd_tool_name} command not found."
    except Exception as e:
        logger.error(f"Error tracing route to {target_ip_resolved}: {type(e).__name__} - {str(e)}")
        traceroute_result["error"] = f"Unexpected error: {str(e)}"
        traceroute_result["raw_output"] = (stdout if 'stdout' in locals() else "") + (stderr if 'stderr' in locals() else "")

    return traceroute_result

# MTR function can be complex to implement with subprocess parsing due to its interactive nature.
# It's often better to use a dedicated Python MTR library or have users run MTR tool separately if needed.
# For now, we'll omit a direct MTR subprocess function here to keep it manageable.

