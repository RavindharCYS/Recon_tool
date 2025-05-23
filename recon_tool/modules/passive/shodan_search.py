"""
Shodan search module - searches Shodan for information about a target
"""
import shodan # type: ignore
import socket # Used for gethostbyname if needed, though network_helpers is preferred
import logging
from typing import Dict, List, Any, Union, Optional

from ...config import get_api_key # UPDATED: Relative import
from ...utils.validators import is_valid_ip, is_valid_domain # UPDATED: Relative import
from ...utils.network_helpers import get_ip_from_domain # UPDATED: Relative import

logger = logging.getLogger(__name__)

# Initialize Shodan API instance globally but lazily
_SHODAN_API: Optional[shodan.Shodan] = None

def _get_shodan_api() -> Optional[shodan.Shodan]:
    """
    Initializes and returns the Shodan API client.
    Returns None if API key is not configured.
    """
    global _SHODAN_API
    if _SHODAN_API is None:
        api_key = get_api_key("shodan")
        if not api_key:
            logger.error("Shodan API key is not configured. Cannot initialize Shodan API.")
            return None
        try:
            _SHODAN_API = shodan.Shodan(api_key)
            # Test the API key with a simple info call
            _SHODAN_API.info() 
            logger.debug("Shodan API client initialized and key validated.")
        except shodan.APIError as e:
            logger.error(f"Failed to initialize Shodan API or invalid API key: {str(e)}")
            _SHODAN_API = None # Reset if initialization failed
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred during Shodan API initialization: {str(e)}")
            _SHODAN_API = None
            return None
    return _SHODAN_API


def search_ip(target: str) -> Dict[str, Any]:
    """
    Search Shodan for information about an IP address.
    
    Args:
        target: IP address or domain to search
        
    Returns:
        Dictionary containing Shodan information about the IP
    """
    logger.info(f"Searching Shodan for IP information: {target}")
    
    ip_address: Optional[str] = None
    if is_valid_domain(target):
        try:
            ip_address = get_ip_from_domain(target)
            logger.info(f"Resolved domain {target} to IP {ip_address}")
        except Exception as e:
            logger.error(f"Could not resolve domain {target}: {str(e)}")
            return {"target": target, "error": f"Could not resolve domain: {str(e)}"}
    elif is_valid_ip(target):
        ip_address = target
    else:
        logger.error(f"Invalid target format: {target}. Expected IP address or domain.")
        return {"target": target, "error": "Invalid target format. Expected IP address or domain."}

    if not ip_address: # Should not happen if logic above is correct
        return {"target": target, "error": "Failed to determine IP address for Shodan search."}

    api = _get_shodan_api()
    if not api:
        return {"target": target, "ip": ip_address, "error": "Shodan API key not configured or invalid."}
    
    try:
        host_info = api.host(ip_address)
        
        # Process and structure the results
        result: Dict[str, Any] = { # Type hint
            "target_input": target, # Original input
            "ip": ip_address,
            "hostnames": host_info.get('hostnames', []),
            "domains": host_info.get('domains', []), # Shodan often provides this
            "country_code": host_info.get('country_code'),
            "country_name": host_info.get('country_name'),
            "city": host_info.get('city'),
            "region_code": host_info.get('region_code'),
            "postal_code": host_info.get('postal_code'),
            "latitude": host_info.get('latitude'),
            "longitude": host_info.get('longitude'),
            "organization": host_info.get('org'),
            "isp": host_info.get('isp'),
            "asn": host_info.get('asn'),
            "last_update": host_info.get('last_update'),
            "open_ports": sorted(host_info.get('ports', [])), # 'ports' is a list of open port numbers
            "vulnerabilities_cves": host_info.get('vulns', []), # CVEs
            "tags": host_info.get('tags', []),
            "services_data": [] # Detailed service information
        }
        
        # Process detailed service data
        for service_item in host_info.get('data', []): # Renamed service to service_item
            port_detail = { # Renamed port_info to port_detail
                "port": service_item.get('port'),
                "transport_protocol": service_item.get('transport', 'tcp'), # Default to tcp
                "module": service_item.get('_shodan', {}).get('module'), # Shodan module used
                "product": service_item.get('product'),
                "version": service_item.get('version'),
                "cpe": service_item.get('cpe'),
                "info": service_item.get('info'), # Misc info
                "banner_hex": service_item.get('banner_hex'), # Raw banner in hex
                "banner": service_item.get('data', '').strip(), # Decoded banner
                "http_info": service_item.get('http'), # HTTP specific data
                "ssl_info": service_item.get('ssl'),   # SSL/TLS specific data
                "timestamp": service_item.get('timestamp')
            }
            # Clean up None values from port_detail
            port_detail = {k:v for k,v in port_detail.items() if v is not None}
            result["services_data"].append(port_detail)
        
        logger.info(f"Successfully retrieved Shodan host data for {ip_address}")
        return result
        
    except shodan.APIError as e:
        error_msg = str(e)
        if "No information available" in error_msg or "not found" in error_msg.lower():
            logger.info(f"No Shodan information available for IP {ip_address}")
            return {
                "target_input": target,
                "ip": ip_address,
                "info": "No information available in Shodan for this IP."
            }
        else:
            logger.error(f"Shodan API error for IP {ip_address}: {error_msg}")
            return {"target_input": target, "ip": ip_address, "error": f"Shodan API error: {error_msg}"}
    
    except Exception as e:
        logger.error(f"Error searching Shodan for IP {ip_address}: {str(e)}")
        return {"target_input": target, "ip": ip_address, "error": f"Unexpected error during Shodan IP search: {str(e)}"}

def search_query(query: str, limit: int = 10, page: int = 1, facets: Optional[str] = None, minify: bool = True) -> Dict[str, Any]:
    """
    Search Shodan using a custom query.
    
    Args:
        query: Shodan search query (e.g., "hostname:example.com", "org:\"Google LLC\"")
        limit: Maximum number of results to return per page (Shodan API default/max usually 100).
        page: Page number of the results to retrieve.
        facets: A comma-separated list of properties to get summary information on.
        minify: True to minimize the data returned by Shodan, False for full data.
        
    Returns:
        Dictionary containing search results
    """
    logger.info(f"Executing Shodan search query: '{query}' (limit={limit}, page={page})")
    
    api = _get_shodan_api()
    if not api:
        return {"query": query, "error": "Shodan API key not configured or invalid."}
    
    try:
        # Execute search
        # Note: Shodan library's search() method handles pagination with `page` param
        # The `limit` in api.search is more like `per_page` if you implement iteration.
        # For a single call, it effectively limits results.
        search_results = api.search(query, page=page, limit=limit, facets=facets, minify=minify)
        
        # Process and structure the results
        results: Dict[str, Any] = { # Type hint
            "query": query,
            "page": page,
            "limit_per_page": limit,
            "total_results": search_results.get('total', 0),
            "matches": [],
            "facets": search_results.get('facets') # Include facets if requested
        }
        
        for match_item in search_results.get('matches', []): # Renamed match to match_item
            processed_match = { # Renamed result to processed_match
                "ip_str": match_item.get('ip_str'),
                "port": match_item.get('port'),
                "transport_protocol": match_item.get('transport', 'tcp'),
                "hostnames": match_item.get('hostnames', []),
                "domains": match_item.get('domains', []),
                "organization": match_item.get('org'),
                "isp": match_item.get('isp'),
                "asn": match_item.get('asn'),
                "location": {
                    "country_code": match_item.get('location', {}).get('country_code'),
                    "country_name": match_item.get('location', {}).get('country_name'),
                    "city": match_item.get('location', {}).get('city'),
                    "latitude": match_item.get('location', {}).get('latitude'),
                    "longitude": match_item.get('location', {}).get('longitude'),
                },
                "timestamp": match_item.get('timestamp'),
                "product": match_item.get('product'), # Available if minify=False or certain data present
                "version": match_item.get('version'),
                "cpe": match_item.get('cpe'),
                "tags": match_item.get('tags', []),
                "vulns": match_item.get('vulns', []), # CVEs, if available
                "http_info": match_item.get('http'), # if http data is present
                "ssl_info": match_item.get('ssl'),   # if ssl data is present
                "banner_data": match_item.get('data', '').strip() # Renamed banner to banner_data
            }
            # Clean up None values
            processed_match = {k:v for k,v in processed_match.items() if v is not None and (not isinstance(v, (dict, list)) or v) }
            processed_match["location"] = {k:v for k,v in processed_match.get("location",{}).items() if v is not None}
            if not processed_match["location"]: del processed_match["location"]


            results["matches"].append(processed_match)
        
        logger.info(f"Shodan query '{query}' returned {len(results['matches'])} matches for page {page} (total: {results['total_results']}).")
        return results
        
    except shodan.APIError as e:
        logger.error(f"Shodan API error for query '{query}': {str(e)}")
        return {"query": query, "error": f"Shodan API error: {str(e)}"}
    
    except Exception as e:
        logger.error(f"Error executing Shodan search for query '{query}': {str(e)}")
        return {"query": query, "error": f"Unexpected error during Shodan query: {str(e)}"}

def get_shodan_api_info() -> Dict[str, Any]:
    """
    Get information about the Shodan API plan and query credits.
    
    Returns:
        Dictionary with API plan information.
    """
    logger.info("Fetching Shodan API plan information.")
    api = _get_shodan_api()
    if not api:
        return {"error": "Shodan API key not configured or invalid."}

    try:
        api_info = api.info()
        return {
            "scan_credits": api_info.get("scan_credits"),
            "query_credits": api_info.get("query_credits"),
            "plan": api_info.get("plan"),
            "usage_limits": api_info.get("usage_limits"),
            "unlocked": api_info.get("unlocked"),
            "monitored_ips": api_info.get("monitored_ips"),
            "unlocked_left": api_info.get("unlocked_left"), # Deprecated but some old keys might have it
            "telnet": api_info.get("telnet")
        }
    except shodan.APIError as e:
        logger.error(f"Shodan API error while fetching API info: {str(e)}")
        return {"error": f"Shodan API error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error fetching Shodan API info: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}"}
