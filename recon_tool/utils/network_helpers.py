"""
Network Helpers Module - Common network utility functions.
"""
import socket
import dns.resolver # type: ignore
import logging
from typing import List, Dict, Any, Optional, Union
import re # For MAC address validation, though not used in get_mac_vendor
import ipaddress

logger = logging.getLogger(__name__)

def get_ip_from_domain(domain: str) -> str:
    """
    Resolve a domain name to its primary IPv4 address.
    
    Args:
        domain: Domain name to resolve.
        
    Returns:
        IP address as string.
        
    Raises:
        socket.gaierror: If the domain cannot be resolved.
    """
    try:
        # gethostbyname typically returns an IPv4 address.
        # For more control (e.g., preferring IPv6 or getting all IPs),
        # socket.getaddrinfo would be used.
        ip_address = socket.gethostbyname(domain)
        logger.debug(f"Resolved {domain} to {ip_address}")
        return ip_address
    except socket.gaierror as e:
        logger.error(f"Error resolving domain '{domain}': {e}")
        raise # Re-raise the exception to be handled by the caller

def get_domain_from_ip(ip_address: str) -> Optional[str]: # Renamed ip to ip_address
    """
    Attempt to get a hostname from an IP address (reverse DNS lookup).
    
    Args:
        ip_address: IP address string to lookup.
        
    Returns:
        Hostname string or None if not found or error occurs.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        logger.debug(f"Reverse DNS for {ip_address} resolved to {hostname}")
        return hostname
    except socket.herror as e: # Host not found
        logger.debug(f"No hostname found for IP {ip_address} (herror): {e}")
        return None
    except socket.gaierror as e: # Address-related error
        logger.debug(f"Address-related error during reverse DNS for {ip_address} (gaierror): {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error during reverse DNS lookup for {ip_address}: {e}")
        return None

def is_port_open(target_ip: str, port: int, timeout: float = 1.0, protocol: str = "tcp") -> bool: # Renamed ip to target_ip
    """
    Check if a specific TCP or UDP port is open on a host.
    
    Args:
        target_ip: IP address to check.
        port: Port number to check.
        timeout: Connection timeout in seconds.
        protocol: "tcp" or "udp".
        
    Returns:
        True if the port is considered open (or open|filtered for UDP), False otherwise.
    """
    protocol = protocol.lower()
    try:
        if protocol == "tcp":
            sock_type = socket.SOCK_STREAM
        elif protocol == "udp":
            sock_type = socket.SOCK_DGRAM
        else:
            logger.warning(f"Unsupported protocol '{protocol}' for port check.")
            return False

        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(timeout)
            if protocol == "tcp":
                result_code = sock.connect_ex((target_ip, port)) # Renamed result to result_code
                return result_code == 0
            elif protocol == "udp":
                # UDP is connectionless. Sending data and not getting an ICMP error
                # often means open|filtered. A response confirms open.
                sock.sendto(b'', (target_ip, port)) # Send empty datagram
                try:
                    sock.recvfrom(1024) # Attempt to receive a response
                    return True # Response means open
                except socket.timeout:
                    return True # Timeout usually means open|filtered for UDP
                except socket.error as e_udp: # Renamed e to e_udp
                    # Check for ICMP Port Unreachable (OS-dependent error codes)
                    if hasattr(e_udp, 'errno') and e_udp.errno in [111, 10054, 10061]: # ECONNREFUSED, WSAECONNRESET, WSAECONNREFUSED
                        return False # Definitely closed
                    return True # Other errors, assume open|filtered
    except socket.gaierror:
        logger.debug(f"Hostname {target_ip} could not be resolved for port check.")
        return False # Cannot connect if hostname doesn't resolve
    except Exception as e:
        logger.debug(f"Error checking {protocol.upper()} port {port} on {target_ip}: {type(e).__name__} - {e}")
        return False # If TCP, any error means not open. If UDP, this is more ambiguous.


def get_ip_type(ip_address: str) -> Optional[str]: # Renamed ip to ip_address
    """Determines if an IP is IPv4 or IPv6."""
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return f"IPv{ip_obj.version}"
    except ValueError:
        return None

def is_private_ip(ip_address: str) -> Optional[bool]: # Renamed ip to ip_address
    """Checks if an IP address is private."""
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return None # Invalid IP string

def get_ip_info(ip_address: str) -> Dict[str, Any]: # Renamed ip to ip_address
    """
    Get consolidated information about an IP address.
    
    Args:
        ip_address: IP address string.
        
    Returns:
        Dictionary with IP information (type, hostname, is_private).
    """
    ip_info_result: Dict[str, Any] = { # Renamed result to ip_info_result
        "ip_address": ip_address,
        "version": get_ip_type(ip_address),
        "is_private": is_private_ip(ip_address),
        "hostname": None # Initialize
    }
    if ip_info_result["version"] is None:
        ip_info_result["error"] = "Invalid IP address format."
        return ip_info_result
        
    ip_info_result["hostname"] = get_domain_from_ip(ip_address)
    return ip_info_result


def resolve_dns_records(domain: str, record_type: str = 'A') -> List[str]: # Renamed from resolve_dns
    """
    Resolve specific DNS records for a domain.
    
    Args:
        domain: Domain name to resolve.
        record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA etc.).
        
    Returns:
        List of record values as strings.
    """
    logger.debug(f"Resolving {record_type} records for {domain}")
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 6
        answers = resolver.resolve(domain, record_type.upper())
        
        records_list: List[str] = [] # Renamed result to records_list
        
        for rdata in answers:
            if record_type.upper() in ['A', 'AAAA']:
                records_list.append(str(rdata.address))
            elif record_type.upper() == 'MX':
                records_list.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
            elif record_type.upper() in ['NS', 'CNAME', 'PTR']:
                records_list.append(str(rdata.target).rstrip('.'))
            elif record_type.upper() == 'TXT':
                # TXT records can be multi-string, join them. Also decode bytes.
                full_txt_data = b"".join(rdata.strings).decode('utf-8', 'replace')
                records_list.append(full_txt_data)
            elif record_type.upper() == 'SOA':
                records_list.append(f"MNAME:{str(rdata.mname).rstrip('.')} RNAME:{str(rdata.rname).rstrip('.')} SERIAL:{rdata.serial}")
            else:
                records_list.append(str(rdata)) # Generic representation
        
        return records_list
    except dns.resolver.NXDOMAIN:
        logger.debug(f"Domain {domain} does not exist (NXDOMAIN) for {record_type} query.")
        return []
    except dns.resolver.NoAnswer:
        logger.debug(f"No {record_type} records found for {domain}.")
        return []
    except dns.exception.Timeout:
        logger.warning(f"DNS query for {record_type} records for {domain} timed out.")
        return []
    except Exception as e:
        logger.error(f"Error resolving {record_type} records for {domain}: {type(e).__name__} - {str(e)}")
        return []

def parse_ip_range_or_cidr(ip_input: str, max_ips_return: int = 256) -> Optional[List[str]]: # Renamed from parse_cidr
    """
    Parses an IP range (e.g., 192.168.1.1-192.168.1.10) or CIDR notation.
    Returns a list of IP addresses, limited by max_ips_return.
    """
    ips: List[str] = []
    try:
        if '/' in ip_input: # Assume CIDR
            network = ipaddress.ip_network(ip_input, strict=False)
            if network.num_addresses > max_ips_return * 2 and network.num_addresses > 1024 : # Heuristic to avoid huge lists
                logger.warning(f"CIDR {ip_input} is very large ({network.num_addresses}). Returning only network and broadcast if applicable.")
                ips.append(str(network.network_address))
                if network.num_addresses > 1:
                     ips.append(str(network.broadcast_address))
                return ips

            count = 0
            for ip_addr_obj in network.hosts(): # Use .hosts() for usable IPs, or .network for all
                ips.append(str(ip_addr_obj))
                count += 1
                if count >= max_ips_return:
                    logger.info(f"IP list from CIDR {ip_input} truncated to {max_ips_return} addresses.")
                    break
        elif '-' in ip_input: # Assume IP range
            start_ip_str, end_ip_str = ip_input.split('-', 1)
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())
            
            if start_ip.version != end_ip.version:
                logger.error("Start and end IP addresses in range must be of the same version.")
                return None
            if start_ip > end_ip:
                logger.error("Start IP address cannot be greater than end IP address in range.")
                return None

            count = 0
            current_ip_int = int(start_ip)
            end_ip_int = int(end_ip)
            
            while current_ip_int <= end_ip_int:
                ips.append(str(ipaddress.ip_address(current_ip_int)))
                current_ip_int += 1
                count += 1
                if count >= max_ips_return:
                    logger.info(f"IP list from range {ip_input} truncated to {max_ips_return} addresses.")
                    break
        else: # Assume single IP
            if ipaddress.ip_address(ip_input): # Validate single IP
                 ips.append(ip_input)

        return ips if ips else None
    except ValueError as e:
        logger.error(f"Invalid IP range or CIDR notation: {ip_input} - {e}")
        return None
    except Exception as e: # Catch-all for other ipaddress or unexpected errors
        logger.error(f"Error parsing IP input '{ip_input}': {type(e).__name__} - {e}")
        return None


def is_ip_in_cidrs(ip_to_check: str, cidr_list: List[str]) -> bool: # Renamed from is_ip_in_range
    """Checks if an IP address is within any of the provided CIDR ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_to_check)
        for cidr_network_str in cidr_list: # Renamed cidr to cidr_network_str
            network = ipaddress.ip_network(cidr_network_str, strict=False)
            if ip_obj in network:
                return True
        return False
    except ValueError:
        logger.warning(f"Invalid IP ('{ip_to_check}') or CIDR in list for range check.")
        return False

# get_mac_vendor was removed as it required an external DB/API which is out of scope for this simple helper.
# calculate_subnet_info was similar to what ipaddress.ip_network offers, so removed for brevity.
