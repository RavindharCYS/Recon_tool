"""
DNS Enumeration module - retrieves DNS records for domains
"""
import dns.resolver # type: ignore
import dns.zone # type: ignore
import dns.query # type: ignore
from typing import Dict, List, Any, Optional, Union
import logging
import socket

from ...utils.validators import is_valid_domain # UPDATED: Relative import
# from ...utils.network_helpers import get_ip_from_domain # Not directly used, but good to keep for consistency if needed later

logger = logging.getLogger(__name__)

def lookup(domain: str, record_types: Optional[List[str]] = None) -> Dict[str, Any]: # Added Optional to record_types
    """
    Perform DNS lookups for specified record types.
    
    Args:
        domain: Target domain name
        record_types: List of DNS record types to query (A, AAAA, MX, NS, TXT, SOA, CNAME, etc.)
                      Defaults to ['A', 'AAAA', 'MX', 'NS', 'TXT'] if None.
        
    Returns:
        Dictionary with DNS records for each type
    """
    logger.info(f"Performing DNS lookup for {domain}")
    
    if not is_valid_domain(domain):
        logger.error(f"Invalid domain format: {domain}")
        return {"error": f"Invalid domain format: {domain}"}
    
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    # Dictionary to store results
    results: Dict[str, Any] = { # Added type hint for results
        "domain": domain,
        "records": {}
    }
    
    # Perform lookups for each record type
    for record_type in record_types:
        try:
            records = query_dns(domain, record_type.upper()) # Ensure record_type is uppercase
            # Only add if records were found or if an error didn't occur during query_dns
            if records or not isinstance(records, dict) or "error" not in records:
                 results["records"][record_type.upper()] = records # Store with uppercase key
        except Exception as e: # Catch exceptions from query_dns itself
            logger.warning(f"Error querying {record_type} records for {domain}: {str(e)}")
            results["records"][record_type.upper()] = {"error": str(e)}
    
    # Attempt zone transfer if NS records are available and valid
    ns_records_data = results["records"].get('NS')
    if isinstance(ns_records_data, list) and ns_records_data:
        # Extract valid nameserver values
        nameservers = [ns_entry.get("value") for ns_entry in ns_records_data if isinstance(ns_entry, dict) and ns_entry.get("value")]
        if nameservers:
            try:
                zone_results = attempt_zone_transfer(domain, nameservers)
                if zone_results: # Only add if zone transfer was attempted and returned something
                    results["zone_transfer"] = zone_results
            except Exception as e: # Catch exceptions from attempt_zone_transfer
                logger.info(f"Zone transfer attempt for {domain} failed: {str(e)}")
                results["zone_transfer"] = {"status": "failed", "error": str(e)} # Record the failure
    
    return results

def query_dns(domain: str, record_type: str) -> List[Dict[str, Any]]: # Return type hint
    """
    Query specific DNS record type.
    
    Args:
        domain: Domain to query
        record_type: Type of DNS record (A, AAAA, MX, etc.)
    
    Returns:
        List of dictionaries containing the records, or an error dict
    """
    records_data: List[Dict[str, Any]] = [] # Renamed and type hinted
    
    try:
        # Use a default resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5 # Set a timeout for resolver
        resolver.lifetime = 10

        answers = resolver.resolve(domain, record_type)
        
        for rdata in answers:
            record: Dict[str, Any] = {"type": record_type} # Type hinted
            
            if record_type == 'A' or record_type == 'AAAA':
                record["value"] = str(rdata.address)
            
            elif record_type == 'MX':
                record["preference"] = rdata.preference
                record["value"] = str(rdata.exchange).rstrip('.')
            
            elif record_type == 'NS':
                record["value"] = str(rdata.target).rstrip('.')
            
            elif record_type == 'TXT':
                txt_data_parts = rdata.strings # Renamed
                # Ensure all parts are decoded if they are bytes
                decoded_parts = [item.decode('utf-8', errors='replace') if isinstance(item, bytes) else str(item) for item in txt_data_parts]
                record["value"] = ''.join(decoded_parts)
            
            elif record_type == 'SOA':
                record["mname"] = str(rdata.mname).rstrip('.')
                record["rname"] = str(rdata.rname).rstrip('.')
                record["serial"] = rdata.serial
                record["refresh"] = rdata.refresh
                record["retry"] = rdata.retry
                record["expire"] = rdata.expire
                record["minimum"] = rdata.minimum
            
            elif record_type == 'CNAME':
                record["value"] = str(rdata.target).rstrip('.')
            
            else:
                record["value"] = str(rdata)
            
            if hasattr(answers, 'ttl'): # Check if ttl attribute exists
                record["ttl"] = answers.ttl

            records_data.append(record)
        
        return records_data
    
    except dns.resolver.NoAnswer:
        logger.info(f"No {record_type} records found for {domain}")
        return [] # Return empty list, not an error dict, for consistency
    
    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
        # This is a valid DNS response, not an error of the query itself
        return []
    
    except dns.exception.Timeout:
        logger.error(f"DNS query for {record_type} records for {domain} timed out.")
        raise # Re-raise to be caught by the main lookup function
        
    except Exception as e:
        logger.error(f"Error querying {record_type} records for {domain}: {type(e).__name__} - {str(e)}")
        raise # Re-raise to be caught by the main lookup function

def attempt_zone_transfer(domain: str, nameservers: List[str]) -> Optional[Dict[str, Any]]:
    """
    Attempt a zone transfer from the domain's name servers.
    
    Args:
        domain: Target domain
        nameservers: List of nameserver hostnames to try
        
    Returns:
        Dictionary with zone transfer results if successful, or error/status info.
    """
    logger.info(f"Attempting zone transfer for {domain} using nameservers: {', '.join(nameservers)}")
    
    for ns_host in nameservers: # Renamed ns to ns_host
        try:
            # Resolve NS hostname to IP if needed
            try:
                ns_ip = socket.gethostbyname(ns_host)
            except socket.gaierror:
                logger.warning(f"Could not resolve nameserver {ns_host} to IP. Skipping for zone transfer.")
                continue

            logger.debug(f"Attempting AXFR from {ns_host} ({ns_ip}) for {domain}")
            
            # Try to perform a zone transfer with a timeout
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            
            # If we get here, zone transfer was successful
            records: List[Dict[str, Any]] = [] # Type hinted
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    for rdata in rdataset:
                        # Sanitize rdata string representation
                        rdata_str = str(rdata)
                        if rdataset.rdtype == dns.rdatatype.TXT:
                             # For TXT records, rdata.strings is a tuple of bytes
                             rdata_str = b"".join(rdata.strings).decode('utf-8', 'replace')

                        records.append({
                            "name": str(name),
                            "ttl": rdataset.ttl,
                            "class": dns.rdataclass.to_text(rdataset.rdclass),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "data": rdata_str
                        })
            
            logger.info(f"Zone transfer successful for {domain} from {ns_host} ({ns_ip})")
            return {
                "nameserver_used": f"{ns_host} ({ns_ip})",
                "records_count": len(records),
                "records": records, # Consider limiting this if it can be huge
                "status": "successful"
            }
            
        except dns.exception.FormError as e: # Server might deny AXFR
            logger.info(f"Zone transfer denied or failed for {domain} from {ns_host}: {type(e).__name__} - {str(e)}")
            # Continue to try other nameservers
        except dns.exception.Timeout:
            logger.info(f"Zone transfer timed out for {domain} from {ns_host}")
            # Continue
        except Exception as e: # Catch other exceptions like connection refused, etc.
            logger.info(f"Zone transfer failed for {domain} from {ns_host}: {type(e).__name__} - {str(e)}")
            # Continue
    
    # If all zone transfers failed or were denied
    logger.info(f"Zone transfer attempts completed for {domain}, none were successful.")
    return {"status": "failed_all_servers", "message": "Could not perform zone transfer from any authoritative nameserver."}


def find_subdomains(domain: str, wordlist: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Attempt to discover subdomains through brute force using a wordlist.
    
    Args:
        domain: Base domain to check
        wordlist: List of potential subdomain prefixes. 
                  If None, a default list is used.
        
    Returns:
        List of dictionaries containing found subdomains and their IP addresses
    """
    logger.info(f"Attempting subdomain brute-force for {domain}")

    if not is_valid_domain(domain):
        logger.error(f"Invalid domain format for subdomain search: {domain}")
        return []

    if wordlist is None:
        # Default minimal wordlist if none provided
        wordlist = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
                   'smtp', 'secure', 'vpn', 'api', 'dev', 'test', 'portal', 'admin',
                   'ftp', 'cpanel', 'owa', 'autodiscover', 'shop', 'store', 'app', 'stage']
    
    found_subdomains: List[Dict[str, Any]] = [] # Renamed and type hinted
    
    for prefix in wordlist:
        if not prefix.strip(): # Skip empty prefixes
            continue
        subdomain_to_check = f"{prefix}.{domain}" # Renamed
        try:
            # Using dns.resolver for more control and consistency with other functions
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2 # Shorter timeout for brute-forcing
            resolver.lifetime = 5

            # Primarily interested in A records for subdomain existence
            answers = resolver.resolve(subdomain_to_check, 'A')
            ips = [str(rdata.address) for rdata in answers]
            
            if ips:
                found_subdomains.append({
                    "subdomain": subdomain_to_check,
                    "ip_addresses": ips # Can be multiple IPs
                })
                logger.info(f"Found subdomain: {subdomain_to_check} -> {', '.join(ips)}")
        except dns.resolver.NXDOMAIN:
            # Subdomain doesn't exist, common case, no need to log verbosely
            logger.debug(f"Subdomain {subdomain_to_check} not found (NXDOMAIN).")
        except dns.resolver.NoAnswer:
            # No A records, but domain might exist (e.g. only CNAME or MX)
            logger.debug(f"Subdomain {subdomain_to_check} found but no A records.")
        except dns.exception.Timeout:
            logger.warning(f"DNS query for subdomain {subdomain_to_check} timed out.")
        except Exception as e: # Catch other DNS or socket errors
            logger.error(f"Error checking subdomain {subdomain_to_check}: {type(e).__name__} - {str(e)}")
    
    logger.info(f"Subdomain brute-force for {domain} complete. Found {len(found_subdomains)} subdomains.")
    return found_subdomains
