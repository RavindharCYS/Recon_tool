"""
Banner Grabber Module - Connect to services on specified ports and retrieve banners.
Handles various common protocols for more accurate banner grabbing.
"""
import socket
import ssl
import logging
import time
from typing import Dict, List, Any, Optional, Union
import re
# import telnetlib # For Telnet <--- REMOVE THIS LINE
from ftplib import FTP, error_perm, error_temp, error_proto # For FTP

from ...config import DEFAULT_TIMEOUT, QUICK_TIMEOUT, DEFAULT_USER_AGENT # UPDATED
from ...utils.validators import is_valid_ip, is_valid_domain # UPDATED
from ...utils.network_helpers import get_ip_from_domain # UPDATED

logger = logging.getLogger(__name__)

def _clean_banner_text(banner_bytes: bytes) -> Optional[str]:
    """Decodes banner bytes to string, cleans control characters, and limits length."""
    if not banner_bytes:
        return None
    try:
        # Try UTF-8, replace errors. Then try latin-1 as a common fallback.
        try:
            text = banner_bytes.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            text = banner_bytes.decode('latin-1', errors='replace')
        
        # Remove most control characters except for common whitespace like \t, \n, \r
        # Allow ASCII 32-126 (printable) and 9,10,13 (tab, LF, CR)
        cleaned_text = "".join(char for char in text if 32 <= ord(char) <= 126 or ord(char) in [9, 10, 13])
        
        # Normalize whitespace (multiple spaces to one, strip leading/trailing)
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()
        
        # Limit length for sanity
        return cleaned_text[:1024] if len(cleaned_text) > 1024 else cleaned_text
    except Exception as e:
        logger.debug(f"Error cleaning banner bytes: {e}. Raw: {banner_bytes[:50]!r}")
        # Fallback for truly problematic byte strings
        return "".join(chr(b) for b in banner_bytes if 32 <= b <= 126 or b in [9,10,13])[:1024]


def _get_common_service_name(port: int, protocol: str) -> str:
    """Gets common service name, similar to network_helpers but can be specialized here."""
    try:
        return socket.getservbyport(port, protocol.lower())
    except (OSError, socket.error):
        # Add more common fallbacks if necessary
        common_map = {
            (80, "tcp"): "http", (443, "tcp"): "https", (21, "tcp"): "ftp",
            (22, "tcp"): "ssh", (23, "tcp"): "telnet", (25, "tcp"): "smtp",
            (110, "tcp"): "pop3", (143, "tcp"): "imap", (53, "udp"): "dns",
            (8080, "tcp"): "http-alt", (8443, "tcp"): "https-alt",
        }
        return common_map.get((port, protocol.lower()), "unknown")

def _identify_service_from_banner_text(banner_text: Optional[str], port: int) -> Optional[str]:
    """Tries to identify a service from its banner text (simple heuristics)."""
    if not banner_text:
        return None
    
    b_lower = banner_text.lower() # Renamed banner to b_lower
    # More specific checks first
    if "ssh-" in b_lower: return "ssh"
    if "ftp" in b_lower or "file transfer protocol" in b_lower: return "ftp"
    if "smtp" in b_lower or "esmtp" in b_lower or "mail server" in b_lower: return "smtp"
    if "pop3" in b_lower: return "pop3"
    if "imap" in b_lower: return "imap"
    if "http/" in b_lower and ("server:" in b_lower or "content-type:" in b_lower): return "http" # Could be https if over SSL
    if "telnet" in b_lower: return "telnet"
    if "mysql" in b_lower and ("protocol version" in b_lower or "connection id" in b_lower): return "mysql"
    if "postgresql" in b_lower: return "postgresql"
    if "redis" in b_lower: return "redis"
    if "mongodb server" in b_lower: return "mongodb"
    
    # Generic checks
    if "welcome to" in b_lower and port in [23, 21]: return _get_common_service_name(port, "tcp")
    if "version" in b_lower and "server" in b_lower: return "unknown-server"
    
    return None # No confident identification

def grab_banner(target: str, port: int, protocol: str = "tcp") -> Dict[str, Any]:
    """
    Connect to a service on a target/port and attempt to grab its banner.
    Uses protocol-specific methods where appropriate.
    
    Args:
        target: IP address or hostname.
        port: Port number to connect to.
        protocol: Protocol ("tcp" or "udp"). Case-insensitive.
        
    Returns:
        Dictionary containing banner information or an error.
    """
    protocol_lower = protocol.lower()
    logger.info(f"Grabbing banner from {target}:{port} ({protocol_lower.upper()})")

    target_ip: Optional[str] = None
    if is_valid_domain(target):
        try:
            target_ip = get_ip_from_domain(target)
            logger.info(f"Resolved domain {target} to IP {target_ip}")
        except Exception as e:
            return {"target_input": target, "port": port, "protocol": protocol_lower, "error": f"DNS resolution failed: {e}"}
    elif is_valid_ip(target):
        target_ip = target
    else:
        return {"target_input": target, "port": port, "protocol": protocol_lower, "error": "Invalid target format."}

    if not target_ip: # Should be caught above
        return {"target_input": target, "port": port, "protocol": protocol_lower, "error": "IP resolution failed."}

    if not (1 <= port <= 65535):
        return {"target_input": target, "target_ip": target_ip, "port": port, "protocol": protocol_lower, "error": "Invalid port number."}

    base_result: Dict[str, Any] = { # Renamed result to base_result
        "target_input": target, "target_ip": target_ip, "port": port, 
        "protocol_used": protocol_lower,
        "service_guess_by_port": _get_common_service_name(port, protocol_lower),
        "banner_text": None, "banner_hex": None, "is_ssl_tls": False, 
        "ssl_tls_info": None, "additional_info": {}, "error": None
    }

    # Use QUICK_TIMEOUT for banner grabbing attempts
    timeout = QUICK_TIMEOUT 

    handler_result: Optional[Dict[str, Any]] = None # Renamed specific_result to handler_result

    if protocol_lower == "tcp":
        # Protocol-specific handlers
        if port in [80, 8000, 8080]:
            handler_result = _grab_http_banner_protocol(target_ip, port, use_ssl=False, timeout=timeout, original_host=target)
        elif port in [443, 8443]:
            handler_result = _grab_http_banner_protocol(target_ip, port, use_ssl=True, timeout=timeout, original_host=target)
            base_result["is_ssl_tls"] = True # Mark SSL regardless of handler_result success
        elif port == 21:
            handler_result = _grab_ftp_banner_protocol(target_ip, port, timeout=timeout)
        elif port == 22:
            handler_result = _grab_ssh_banner_protocol(target_ip, port, timeout=timeout)
        elif port == 23:
            handler_result = _grab_telnet_banner_protocol(target_ip, port, timeout=timeout)
        elif port in [25, 587]: # SMTP
             handler_result = _grab_smtp_banner_protocol(target_ip, port, timeout=timeout)
        elif port == 110: # POP3
             handler_result = _grab_pop3_banner_protocol(target_ip, port, timeout=timeout)
        elif port == 143: # IMAP
             handler_result = _grab_imap_banner_protocol(target_ip, port, timeout=timeout)
        else:
            # Generic TCP grab if no specific handler
            handler_result = _grab_generic_tcp_banner(target_ip, port, timeout=timeout)
    elif protocol_lower == "udp":
        # Generic UDP grab (very unreliable for banners)
        handler_result = _grab_generic_udp_banner(target_ip, port, timeout=timeout)
    else:
        base_result["error"] = f"Unsupported protocol: {protocol}"
        return base_result

    if handler_result:
        base_result.update(handler_result) # Merge results from specific handler

    # Try to identify service from banner if not already identified by handler
    if base_result["banner_text"] and not base_result.get("identified_service_from_banner"):
        base_result["identified_service_from_banner"] = _identify_service_from_banner_text(base_result["banner_text"], port)

    if base_result.get("error"):
         logger.warning(f"Banner grab for {target_ip}:{port} ({protocol_lower.upper()}) failed: {base_result['error']}")
    else:
         logger.info(f"Banner grab for {target_ip}:{port} ({protocol_lower.upper()}) successful.")
         
    return base_result


# --- Protocol Specific Grabbers ---

def _grab_generic_tcp_banner(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {} # Renamed result to output
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            # Some services send banner immediately, others after a newline or probe
            banner_bytes = sock.recv(2048) # Increased buffer
            if not banner_bytes: # If no immediate banner, send a newline
                sock.sendall(b"\r\n\r\n") # Common probe
                time.sleep(0.2) # Short wait
                banner_bytes = sock.recv(2048)
            
            if banner_bytes:
                output["banner_text"] = _clean_banner_text(banner_bytes)
                output["banner_hex"] = banner_bytes.hex()
    except socket.timeout:
        output["error"] = "Timeout"
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except Exception as e:
        output["error"] = f"Generic TCP error: {type(e).__name__} - {str(e)}"
    return output

def _grab_generic_udp_banner(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    # UDP is connectionless; sending a small payload might elicit a response or error.
    # This is highly unreliable for banners.
    # Common probes for DNS (port 53), NTP (port 123), SNMP (port 161) might be specific.
    # For a generic attempt:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b'\x00\x00\x00\x00', (ip, port)) # Simple null payload
            banner_bytes, _ = sock.recvfrom(1024)
            if banner_bytes:
                output["banner_text"] = _clean_banner_text(banner_bytes)
                output["banner_hex"] = banner_bytes.hex()
    except socket.timeout:
        output["additional_info"] = {"status": "No response (typical for UDP, may be open|filtered or firewalled)"}
    except Exception as e:
        output["error"] = f"Generic UDP error: {type(e).__name__} - {str(e)}"
    return output

def _grab_http_banner_protocol(ip: str, port: int, use_ssl: bool, timeout: float, original_host: str) -> Dict[str, Any]:
    output: Dict[str, Any] = {"is_ssl_tls": use_ssl, "ssl_tls_info": None, "additional_info": {}}
    context = None
    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False # Don't verify hostname for banner grabbing
        context.verify_mode = ssl.CERT_NONE # Don't verify cert
    
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            conn_stream = sock # Renamed
            if use_ssl and context: # Ensure context is not None
                conn_stream = context.wrap_socket(sock, server_hostname=original_host if is_valid_domain(original_host) else None)
                # Get SSL cert info
                try:
                    cert = conn_stream.getpeercert()
                    output["ssl_tls_info"] = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "cipher_suite": conn_stream.cipher()[0] if conn_stream.cipher() else None
                    }
                except Exception as ssl_e:
                    logger.debug(f"Could not get SSL cert details for {ip}:{port}: {ssl_e}")
                    output["ssl_tls_info"] = {"error": f"Could not retrieve cert details: {ssl_e}"}

            # Use the original target (domain) for the Host header if it was a domain
            host_header_val = original_host if is_valid_domain(original_host) else ip
            http_request = f"HEAD / HTTP/1.1\r\nHost: {host_header_val}\r\nUser-Agent: {DEFAULT_USER_AGENT}\r\nConnection: close\r\n\r\n"
            conn_stream.sendall(http_request.encode('utf-8'))
            
            response_data = b"" # Renamed
            while True:
                chunk = conn_stream.recv(4096)
                if not chunk: break
                response_data += chunk
                if len(response_data) > 8192: break # Limit response size
            
            if response_data:
                # HTTP response includes headers and potentially body (though HEAD shouldn't have body)
                # The first line is the status line, headers follow.
                output["banner_text"] = _clean_banner_text(response_data) # Full response as banner
                output["banner_hex"] = response_data.hex()

                # Parse headers from banner_text
                if output["banner_text"]:
                    headers_part = output["banner_text"].split('\r\n\r\n', 1)[0]
                    parsed_headers: Dict[str, str] = {} # Renamed
                    status_line = ""
                    for i, line in enumerate(headers_part.split('\r\n')):
                        if i == 0: # Status line
                            status_line = line
                            parsed_headers["Status-Line"] = status_line
                            status_match = re.match(r"HTTP/\d\.\d\s+(\d{3})", status_line)
                            if status_match:
                                 parsed_headers["Status-Code"] = status_match.group(1)
                        else:
                            if ':' in line:
                                key, val = line.split(':', 1)
                                parsed_headers[key.strip()] = val.strip()
                    output["additional_info"]["http_headers"] = parsed_headers
                    server_soft = parsed_headers.get("Server") or parsed_headers.get("server") # Renamed
                    if server_soft:
                        output["identified_service_from_banner"] = server_soft


    except ssl.SSLError as e:
        output["error"] = f"SSL error: {type(e).__name__} - {str(e)}"
        if "CERTIFICATE_VERIFY_FAILED" in str(e) and output.get("ssl_tls_info"):
             output["ssl_tls_info"]["verification_error"] = str(e) # Add specific verification error
    except socket.timeout:
        output["error"] = "Timeout"
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except Exception as e:
        output["error"] = f"HTTP(S) error: {type(e).__name__} - {str(e)}"
    return output

def _grab_ftp_banner_protocol(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    try:
        # ftplib.FTP can be more robust for FTP
        with FTP(timeout=timeout) as ftp: # Use context manager
            ftp.connect(ip, port) # connect already gives welcome
            output["banner_text"] = _clean_banner_text(ftp.getwelcome().encode('utf-8', 'replace')) # Welcome message
            try:
                # Try to get system type
                syst_response = ftp.sendcmd('SYST')
                output["additional_info"] = {"system_type": syst_response}
            except (error_perm, error_temp, error_proto) as ftp_err: # Catch FTP specific errors
                logger.debug(f"FTP SYST command failed for {ip}:{port}: {ftp_err}")
            ftp.quit()
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except (error_perm, error_temp, error_proto) as ftp_err:
         output["error"] = f"FTP protocol error: {ftp_err}"
         # Sometimes the error itself contains the banner
         if str(ftp_err): output["banner_text"] = _clean_banner_text(str(ftp_err).encode('utf-8','replace'))
    except socket.timeout:
        output["error"] = "Timeout"
    except Exception as e: # General catch for other socket errors, etc.
        output["error"] = f"FTP error: {type(e).__name__} - {str(e)}"
        # Fallback to basic socket if ftplib fails unexpectedly
        if not output.get("banner_text"):
             generic_res = _grab_generic_tcp_banner(ip, port, timeout)
             if generic_res.get("banner_text"): output["banner_text"] = generic_res["banner_text"]
             if generic_res.get("banner_hex"): output["banner_hex"] = generic_res["banner_hex"]
             if not output.get("error") and generic_res.get("error"): output["error"] = generic_res.get("error") # Keep original error if any

    return output

def _grab_ssh_banner_protocol(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner_bytes = sock.recv(1024) # SSH banner is usually sent immediately
            if banner_bytes:
                output["banner_text"] = _clean_banner_text(banner_bytes)
                output["banner_hex"] = banner_bytes.hex()
                # SSH banner format: SSH-protocolversion-softwareversion comments
                ssh_match = re.match(r"SSH-(\d+\.\d+)-([^\s]+)", output["banner_text"])
                if ssh_match:
                    output["additional_info"] = {
                        "ssh_protocol_version": ssh_match.group(1),
                        "ssh_software_version": ssh_match.group(2)
                    }
    except socket.timeout:
        output["error"] = "Timeout"
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except Exception as e:
        output["error"] = f"SSH error: {type(e).__name__} - {str(e)}"
    return output

def _grab_telnet_banner_protocol(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    telnetlib = None # Initialize to None
    try:
        import telnetlib # Try to import telnetlib for Python 2 or if available
    except ImportError:
        logger.warning("telnetlib module not found (Python 2 stdlib). Telnet banner grabbing will use generic TCP.")
        # Fallback to generic TCP immediately if telnetlib is not found
        generic_res = _grab_generic_tcp_banner(ip, port, timeout)
        if generic_res.get("banner_text"): output["banner_text"] = generic_res["banner_text"]
        if generic_res.get("banner_hex"): output["banner_hex"] = generic_res["banner_hex"]
        if not output.get("error") and generic_res.get("error"): output["error"] = generic_res.get("error")
        return output

    try:
        # This block will only be reached if 'import telnetlib' above was successful
        with telnetlib.Telnet(ip, port, timeout) as tn_conn: # Renamed tn to tn_conn
            try:
                banner_bytes = tn_conn.read_until(b"login:", timeout=timeout/2) 
                if not banner_bytes: 
                    banner_bytes = tn_conn.read_very_eager() 
                if not banner_bytes: 
                    tn_conn.write(b"\n")
                    time.sleep(0.2)
                    banner_bytes = tn_conn.read_very_eager()

                if banner_bytes:
                    output["banner_text"] = _clean_banner_text(banner_bytes)
                    output["banner_hex"] = banner_bytes.hex()
            except EOFError: 
                 output["additional_info"] = {"status": "Connection closed by remote host during banner grab."}
    except socket.timeout:
        output["error"] = "Timeout"
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except AttributeError: # If telnetlib was imported but is not the expected Python 2 version
        logger.warning("telnetlib was imported but seems incompatible. Falling back to generic TCP for Telnet.")
        generic_res = _grab_generic_tcp_banner(ip, port, timeout)
        if generic_res.get("banner_text"): output["banner_text"] = generic_res["banner_text"]
        if generic_res.get("banner_hex"): output["banner_hex"] = generic_res["banner_hex"]
        if not output.get("error") and generic_res.get("error"): output["error"] = generic_res.get("error")
    except Exception as e:
        output["error"] = f"Telnet error: {type(e).__name__} - {str(e)}"
        if not output.get("banner_text"): # Fallback if telnetlib specific code failed
             generic_res = _grab_generic_tcp_banner(ip, port, timeout)
             if generic_res.get("banner_text"): output["banner_text"] = generic_res["banner_text"]
             if generic_res.get("banner_hex"): output["banner_hex"] = generic_res["banner_hex"]
             if not output.get("error") and generic_res.get("error"): output["error"] = generic_res.get("error")

    return output

def _grab_smtp_banner_protocol(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner_bytes = sock.recv(1024) # SMTP welcome
            if banner_bytes:
                output["banner_text"] = _clean_banner_text(banner_bytes)
                output["banner_hex"] = banner_bytes.hex()
                # SMTP usually starts with 220
                if output["banner_text"] and output["banner_text"].startswith("220"):
                     output["additional_info"] = {"smtp_greeting": True}
    except socket.timeout:
        output["error"] = "Timeout"
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except Exception as e:
        output["error"] = f"SMTP error: {type(e).__name__} - {str(e)}"
    return output

def _grab_pop3_banner_protocol(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner_bytes = sock.recv(1024) # POP3 welcome
            if banner_bytes:
                output["banner_text"] = _clean_banner_text(banner_bytes)
                output["banner_hex"] = banner_bytes.hex()
                # POP3 usually starts with +OK
                if output["banner_text"] and output["banner_text"].startswith("+OK"):
                     output["additional_info"] = {"pop3_greeting": True}
    except socket.timeout:
        output["error"] = "Timeout"
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except Exception as e:
        output["error"] = f"POP3 error: {type(e).__name__} - {str(e)}"
    return output

def _grab_imap_banner_protocol(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner_bytes = sock.recv(1024) # IMAP welcome
            if banner_bytes:
                output["banner_text"] = _clean_banner_text(banner_bytes)
                output["banner_hex"] = banner_bytes.hex()
                # IMAP usually starts with * OK
                if output["banner_text"] and output["banner_text"].startswith("* OK"):
                     output["additional_info"] = {"imap_greeting": True}
    except socket.timeout:
        output["error"] = "Timeout"
    except ConnectionRefusedError:
        output["error"] = "Connection refused"
    except Exception as e:
        output["error"] = f"IMAP error: {type(e).__name__} - {str(e)}"
    return output