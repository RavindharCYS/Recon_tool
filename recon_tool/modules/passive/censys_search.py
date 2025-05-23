"""
Censys search module - searches Censys for information about a target
"""
import logging
from typing import Dict, List, Any, Optional, Union
import ipaddress # For IP validation if needed, though utils.validators is primary
import socket # For gethostbyname if needed, though network_helpers is primary

# Try to import Censys library
try:
    from censys.search import CensysHosts, CensysCerts, CensysData # type: ignore
    from censys.common.exceptions import ( # type: ignore
        CensysException, CensysRateLimitExceededException, 
        CensysNotFoundException, CensysUnauthorizedException
    )
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False
    # Define dummy exceptions if censys is not installed, so the rest of the code can type-check
    class CensysException(Exception): pass
    class CensysRateLimitExceededException(CensysException): pass
    class CensysNotFoundException(CensysException): pass
    class CensysUnauthorizedException(CensysException): pass


from ...config import get_api_key # UPDATED: Relative import
from ...utils.validators import is_valid_ip, is_valid_domain # UPDATED: Relative import
from ...utils.network_helpers import get_ip_from_domain # UPDATED: Relative import

logger = logging.getLogger(__name__)

# Global Censys API clients, initialized lazily
_CENSYS_HOSTS_API: Optional[CensysHosts] = None
_CENSYS_CERTS_API: Optional[CensysCerts] = None
_CENSYS_DATA_API: Optional[CensysData] = None # For v2 data access if needed later

def _initialize_censys_apis() -> bool:
    """
    Initializes Censys API clients if not already done.
    Returns True if successful, False otherwise.
    """
    global _CENSYS_HOSTS_API, _CENSYS_CERTS_API, _CENSYS_DATA_API
    
    if not CENSYS_AVAILABLE:
        logger.error("Censys library not installed. Run 'pip install censys>=2.0.0'")
        return False

    # Check if already initialized
    if _CENSYS_HOSTS_API and _CENSYS_CERTS_API: # _CENSYS_DATA_API optional for now
        return True

    api_id = get_api_key("censys", "api_id") # Use key_name for multi-key services
    api_secret = get_api_key("censys", "api_secret")
    
    if not api_id or not api_secret:
        logger.error("Censys API ID or Secret not configured.")
        return False
    
    try:
        # Censys Search V2 client initialization (recommended)
        _CENSYS_HOSTS_API = CensysHosts(api_id=api_id, api_secret=api_secret)
        _CENSYS_CERTS_API = CensysCerts(api_id=api_id, api_secret=api_secret)
        # _CENSYS_DATA_API = CensysData(api_id=api_id, api_secret=api_secret) # If using v2 data endpoints
        
        # Optionally, test the connection, e.g., by fetching account info
        # _CENSYS_HOSTS_API.account() # This might consume quota, use carefully
        logger.debug("Censys API clients initialized.")
        return True
    except CensysUnauthorizedException:
        logger.error("Censys API authentication failed. Check your API ID and Secret.")
        return False
    except CensysException as e:
        logger.error(f"Failed to initialize Censys API clients: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during Censys API initialization: {str(e)}")
        return False


def search_ip(target: str) -> Dict[str, Any]:
    """
    Search Censys for information about an IP address using the Hosts API.
    
    Args:
        target: IP address or domain to search
        
    Returns:
        Dictionary containing Censys information about the IP
    """
    logger.info(f"Searching Censys Hosts API for: {target}")
    
    if not _initialize_censys_apis() or not _CENSYS_HOSTS_API:
        return {"target": target, "error": "Censys API client not available or not initialized."}

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
        return {"target": target, "error": "Invalid target format. Expected IP or domain."}
    
    if not ip_address:
         return {"target": target, "error": "Failed to determine IP address for Censys search."}

    try:
        # Fetch host data from Censys
        host_data = _CENSYS_HOSTS_API.view(ip_address) # type: ignore
        
        # Process and structure the results (similar to Shodan for consistency where applicable)
        result: Dict[str, Any] = {
            "target_input": target,
            "ip": ip_address,
            "last_updated_at": host_data.get("last_updated_at"),
            "location_updated_at": host_data.get("location_updated_at"),
            "location": host_data.get("location", {}), # Keep the whole location object
            "autonomous_system": host_data.get("autonomous_system", {}), # Keep the whole AS object
            "dns": host_data.get("dns", {}), # DNS records observed by Censys
            "services": [], # Detailed service information
            "open_ports_observed": sorted(list(set(svc.get("port") for svc in host_data.get("services", []) if svc.get("port"))))
        }
        
        for service_item in host_data.get("services", []): # Renamed service to service_item
            service_detail = { # Renamed
                "port": service_item.get("port"),
                "protocol": service_item.get("protocol"),
                "transport_protocol": service_item.get("transport_protocol"), # e.g. TCP, UDP
                "service_name": service_item.get("service_name"), # IANA service name
                "observed_at": service_item.get("observed_at"),
                "certificate": service_item.get("tls", {}).get("certificates", {}).get("leaf_data", {}).get("fingerprint_sha256") if service_item.get("tls") else None,
                # You can expand this to include more details from the service object
                # For example, banner for specific protocols if available in Censys data
                # "banner": service_item.get("banner"), # If available
                # "http": service_item.get("http"), # If http service
                # "tls": service_item.get("tls") # Full TLS details
            }
            service_detail = {k:v for k,v in service_detail.items() if v is not None}
            result["services"].append(service_detail)
        
        logger.info(f"Successfully retrieved Censys host data for {ip_address}")
        return result
        
    except CensysNotFoundException:
        logger.info(f"No Censys host information available for IP {ip_address}")
        return {"target_input": target, "ip": ip_address, "info": "No information available in Censys for this IP."}
    except CensysRateLimitExceededException as e:
        logger.error(f"Censys API rate limit exceeded: {str(e)}")
        return {"target_input": target, "ip": ip_address, "error": f"Censys API rate limit exceeded: {str(e)}"}
    except CensysUnauthorizedException as e:
        logger.error(f"Censys API authentication error: {str(e)}")
        return {"target_input": target, "ip": ip_address, "error": f"Censys API authentication error: {str(e)}"}
    except CensysException as e:
        logger.error(f"Censys API error for IP {ip_address}: {str(e)}")
        return {"target_input": target, "ip": ip_address, "error": f"Censys API error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error searching Censys for IP {ip_address}: {str(e)}")
        return {"target_input": target, "ip": ip_address, "error": f"Unexpected error searching Censys: {str(e)}"}

def search_certificates(query_domain: str, limit: int = 10, page: int = 1) -> Dict[str, Any]: # Renamed domain to query_domain
    """
    Search Censys for certificates related to a domain using the Certificates API.
    
    Args:
        query_domain: Domain to search for in certificate names/SANs.
        limit: Maximum number of certificates to return per page.
        page: Page number to retrieve. (Note: Censys SDK search iterates, direct page not typical)
        
    Returns:
        Dictionary containing certificate information
    """
    logger.info(f"Searching Censys Certificates API for domain: {query_domain}")
    
    if not _initialize_censys_apis() or not _CENSYS_CERTS_API:
        return {"domain": query_domain, "error": "Censys API client not available or not initialized."}

    if not is_valid_domain(query_domain):
        logger.error(f"Invalid domain format for certificate search: {query_domain}")
        return {"domain": query_domain, "error": "Invalid domain format."}
    
    # Censys search query for certificates matching the domain in names or SANs
    censys_query = f"names: {query_domain}"
    
    try:
        # The Censys SDK search method is an iterator.
        # To get a specific page or limit, we'd typically iterate.
        # For simplicity here, we'll fetch up to `limit` results.
        
        certs_found: List[Dict[str, Any]] = [] # Renamed
        # The `pages` parameter in Censys SDK search means number of pages to iterate over.
        # `per_page` can be set. Let's aim for `limit` total results.
        # If limit is 10 and per_page is 10, pages=1. If limit is 25, per_page=25, pages=1.
        # Or iterate with a smaller per_page until limit is reached.
        
        # Simpler: Get one page of up to `limit` results.
        # The search method itself in Censys SDK v2 returns an iterator.
        # We can convert it to a list, but it might fetch many results if not careful.
        # Let's use the `limit` parameter of the search function itself if available
        # or iterate and break.
        
        # The `search` method takes `query`, `per_page`, `cursor`, `pages`
        # Let's fetch one page with `per_page` set to `limit`
        
        # For Censys SDK >= 2.0, search() returns an iterator.
        search_iterator = _CENSYS_CERTS_API.search(censys_query, per_page=limit) # type: ignore
        
        count = 0
        for cert_data in search_iterator: # Renamed cert to cert_data
            if count >= limit:
                break
            
            parsed_cert = cert_data.get("parsed", {}) # Renamed
            
            cert_info = {
                "fingerprint_sha256": cert_data.get("fingerprint_sha256"),
                "issuer_dn": parsed_cert.get("issuer_dn"), # Distinguished Name
                "subject_dn": parsed_cert.get("subject_dn"),
                "names": parsed_cert.get("names", []), # Includes CN and SANs
                "validity_period": {
                    "not_before": parsed_cert.get("validity", {}).get("start"),
                    "not_after": parsed_cert.get("validity", {}).get("end")
                },
                "signature_algorithm": parsed_cert.get("signature", {}).get("signature_algorithm", {}).get("name"),
                "self_signed": parsed_cert.get("signature", {}).get("self_signed", False),
                "validation_level": cert_data.get("validation", {}).get("level") # e.g. "DV"
            }
            cert_info = {k:v for k,v in cert_info.items() if v is not None}
            cert_info["validity_period"] = {k:v for k,v in cert_info.get("validity_period",{}).items() if v is not None}
            if not cert_info["validity_period"]: del cert_info["validity_period"]

            certs_found.append(cert_info)
            count += 1
            
        result = {
            "domain_queried": query_domain,
            "censys_query": censys_query,
            "certificates_found_count": len(certs_found),
            "certificates": certs_found
        }
        
        logger.info(f"Found {len(certs_found)} certificates related to {query_domain} (limit {limit})")
        return result
        
    except CensysRateLimitExceededException as e:
        logger.error(f"Censys API rate limit exceeded for certificate search: {str(e)}")
        return {"domain": query_domain, "error": f"Censys API rate limit exceeded: {str(e)}"}
    except CensysUnauthorizedException as e:
        logger.error(f"Censys API authentication error for certificate search: {str(e)}")
        return {"domain": query_domain, "error": f"Censys API authentication error: {str(e)}"}
    except CensysException as e: # Catch other Censys specific errors
        logger.error(f"Censys API error during certificate search for {query_domain}: {str(e)}")
        return {"domain": query_domain, "error": f"Censys API error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error searching Censys certificates for {query_domain}: {str(e)}")
        return {"domain": query_domain, "error": f"Unexpected error searching Censys certificates: {str(e)}"}


def search_host_query(query: str, limit: int = 10, page: int = 1, virtual_hosts: bool = False) -> Dict[str, Any]: # Renamed from search_query to be specific
    """
    Execute a custom search query against Censys Hosts API.
    
    Args:
        query: Censys search query for hosts (e.g., "services.http.response.headers.server: nginx")
        limit: Maximum number of results to return.
        page: Page number for results (1-indexed).
        virtual_hosts: Whether to include virtual hosts in the results (INCLUDE or EXCLUDE or ONLY).
                       Censys SDK default is EXCLUDE for /hosts/search.
        
    Returns:
        Dictionary containing search results
    """
    logger.info(f"Executing Censys Hosts query: '{query}' (limit={limit}, page={page})")
    
    if not _initialize_censys_apis() or not _CENSYS_HOSTS_API:
        return {"query": query, "error": "Censys API client not available or not initialized."}

    try:
        # The Censys SDK search for hosts is an iterator.
        # To implement pagination as typically understood (get page X of Y results):
        # We need to use the cursor manually if we want to jump to a specific "page".
        # Or, for simplicity, fetch `page * limit` results and take the last `limit`.
        # However, the CensysHosts.search() method takes a `cursor` and `pages` (number of pages to iterate)
        
        # For this function, let's interpret `page` and `limit` to fetch a specific segment.
        # We'll fetch up to `page * limit` and then slice, or use cursor if more direct.
        # The Censys SDK's `pages` parameter for search means "how many pages (of size per_page) to iterate over".
        
        # Let's fetch results using the iterator and manually implement a form of paging.
        # This is not true server-side pagination for a specific page number without cursors.
        
        hosts_found: List[Dict[str, Any]] = [] # Renamed
        
        # The CensysHosts.search method takes `virtual_hosts` as 'INCLUDE', 'EXCLUDE', 'ONLY'
        vh_option = "INCLUDE" if virtual_hosts else "EXCLUDE"

        # Using the iterator and collecting results.
        # This is not efficient for fetching a specific page deep into results.
        # True pagination would require cursor management which is more complex.
        # For now, we'll fetch a block of results.
        
        # Correct approach for SDK v2 to get a "page" is to iterate.
        # If we want to simulate pages, we have to skip initial results.
        results_to_skip = (page - 1) * limit
        total_to_fetch = page * limit
        
        count = 0
        # The search method returns an iterator of hits.
        search_iterator = _CENSYS_HOSTS_API.search(query, per_page=total_to_fetch, virtual_hosts=vh_option) # type: ignore

        current_hit_index = 0
        for hit_data in search_iterator: # Renamed hit to hit_data
            if current_hit_index >= results_to_skip and count < limit:
                host_details = { # Renamed
                    "ip": hit_data.get("ip"),
                    "services_summary": [{ "port": s.get("port"), "protocol": s.get("protocol")} 
                                         for s in hit_data.get("services", [])[:5]], # Summary of first 5 services
                    "location": hit_data.get("location", {}),
                    "autonomous_system": hit_data.get("autonomous_system", {})
                }
                hosts_found.append(host_details)
                count += 1
            current_hit_index += 1
            if count >= limit: # Stop if we've collected enough for the current page
                break
        
        # To get total results, a separate aggregate query is often needed or info from response.
        # For simplicity, we'll rely on the knowledge that the iterator is exhausted or limit reached.
        # A full count usually requires ` CensysHosts().aggregate(...)`
        
        result = {
            "query": query,
            "page_requested": page,
            "limit_per_page": limit,
            "hosts_on_page": len(hosts_found),
            # "total_estimated_results": "?", # Hard to get accurately without aggregate or if iterator is not exhausted
            "hosts": hosts_found
        }
        
        logger.info(f"Censys Hosts query '{query}' returned {len(hosts_found)} hosts for page {page}.")
        return result
        
    except CensysRateLimitExceededException as e:
        logger.error(f"Censys API rate limit exceeded for host query: {str(e)}")
        return {"query": query, "error": f"Censys API rate limit exceeded: {str(e)}"}
    except CensysUnauthorizedException as e:
        logger.error(f"Censys API authentication error for host query: {str(e)}")
        return {"query": query, "error": f"Censys API authentication error: {str(e)}"}
    except CensysException as e:
        logger.error(f"Censys API error during host query '{query}': {str(e)}")
        return {"query": query, "error": f"Censys API error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error executing Censys host query '{query}': {str(e)}")
        return {"query": query, "error": f"Unexpected error executing Censys host query: {str(e)}"}

def get_censys_account_info() -> Dict[str, Any]:
    """
    Retrieves account information from Censys (quota, etc.).
    """
    logger.info("Fetching Censys account information.")
    if not _initialize_censys_apis() or not _CENSYS_HOSTS_API: # Use Hosts API for account info
        return {"error": "Censys API client not available or not initialized."}

    try:
        account_info = _CENSYS_HOSTS_API.account() # type: ignore
        return {
            "email": account_info.get("email"),
            "api_key_name": account_info.get("api_key_name"),
            "first_login": account_info.get("first_login"),
            "last_login": account_info.get("last_login"),
            "quota": account_info.get("quota", {}),
            "api_rate_limit": account_info.get("api_rate_limit")
        }
    except CensysException as e:
        logger.error(f"Censys API error while fetching account info: {str(e)}")
        return {"error": f"Censys API error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error fetching Censys account info: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}"}
