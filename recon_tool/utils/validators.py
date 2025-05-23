"""
Validators module - validate various inputs
"""
import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Union

def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address.
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Domain regex pattern
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except:
        return False

def is_valid_email(email: str) -> bool:
    """
    Check if a string is a valid email address.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def is_valid_port(port: Union[str, int]) -> bool:
    """
    Check if a value is a valid port number.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_mac(mac: str) -> bool:
    """
    Check if a string is a valid MAC address.
    
    Args:
        mac: MAC address to validate
        
    Returns:
        True if valid, False otherwise
    """
    # MAC address regex patterns (various formats)
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # XX:XX:XX:XX:XX:XX
        r'^([0-9A-Fa-f]{4}[.]){2}([0-9A-Fa-f]{4})$'     # XXXX.XXXX.XXXX
    ]
    
    return any(re.match(pattern, mac) for pattern in patterns)

def is_valid_ipv4_cidr(cidr: str) -> bool:
    """
    Check if a string is a valid IPv4 CIDR notation.
    
    Args:
        cidr: CIDR notation to validate (e.g., 192.168.1.0/24)
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False

def is_valid_ipv6_cidr(cidr: str) -> bool:
    """
    Check if a string is a valid IPv6 CIDR notation.
    
    Args:
        cidr: CIDR notation to validate (e.g., 2001:db8::/32)
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.IPv6Network(cidr, strict=False)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    """
    Check if a string is a valid CIDR notation (IPv4 or IPv6).
    
    Args:
        cidr: CIDR notation to validate
        
    Returns:
        True if valid, False otherwise
    """
    return is_valid_ipv4_cidr(cidr) or is_valid_ipv6_cidr(cidr)

def is_valid_username(username: str) -> bool:
    """
    Check if a string is a valid username.
    
    Args:
        username: Username to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Username regex pattern
    pattern = r'^[a-zA-Z0-9_\.-]{3,32}$'
    return bool(re.match(pattern, username))

def is_valid_file_path(path: str) -> bool:
    """
    Check if a string is a valid file path.
    
    Args:
        path: File path to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        # This is a basic check for valid path characters
        # It doesn't check if the file exists
        import os
        return os.path.normpath(path) == path
    except:
        return False

def validate_ip_or_domain(target: str) -> Optional[str]:
    """
    Validate if a string is an IP address or domain and return its type.
    
    Args:
        target: Target to validate
        
    Returns:
        'ip', 'domain', or None if invalid
    """
    if is_valid_ip(target):
        return 'ip'
    elif is_valid_domain(target):
        return 'domain'
    else:
        return None