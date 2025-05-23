
"""
WHOIS lookup module - retrieves registration information for domains
"""
import whois # type: ignore
import socket
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

from ...utils.validators import is_valid_domain # UPDATED: Relative import
from ...utils.network_helpers import get_ip_from_domain # UPDATED: Relative import

logger = logging.getLogger(__name__)

def lookup(domain: str) -> Dict[str, Any]:
    """
    Perform a WHOIS lookup on a domain.
    
    Args:
        domain: The domain to lookup
        
    Returns:
        Dictionary containing WHOIS information
    """
    logger.info(f"Performing WHOIS lookup for {domain}")
    
    if not is_valid_domain(domain):
        logger.error(f"Invalid domain format: {domain}")
        return {"error": f"Invalid domain format: {domain}"}
    
    ip_address: Optional[str] = None # Initialize ip_address
    try:
        # Get IP address for the domain
        ip_address = get_ip_from_domain(domain)
        
        # Perform WHOIS lookup
        w = whois.whois(domain) # type: ignore
        
        if not w or not hasattr(w, 'domain_name'): # Check if whois object is empty or lacks essential attributes
            logger.warning(f"WHOIS lookup for {domain} returned incomplete or no data.")
            return {
                "domain": domain,
                "ip_address": ip_address,
                "error": "WHOIS lookup returned incomplete or no data."
            }

        # Process dates to ensure they're serializable
        creation_date = _process_date(w.creation_date)
        expiration_date = _process_date(w.expiration_date)
        updated_date = _process_date(w.updated_date)
        
        # Ensure lists are always lists, even if None or single string
        name_servers = _ensure_list(w.name_servers)
        status = _ensure_list(w.status)
        emails = _ensure_list(w.emails)

        # Build result dictionary
        result = {
            "domain": domain,
            "ip_address": ip_address,
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,
            "name_servers": [str(ns).rstrip('.') for ns in name_servers if ns] if name_servers else [],
            "status": status,
            "emails": emails,
            "dnssec": w.dnssec,
            "registrant": {
                "name": getattr(w, 'name', None) or getattr(w, 'registrant_name', None), # 'name' is sometimes used
                "organization": w.org,
                "country": getattr(w, 'country', None) or getattr(w, 'registrant_country', None) # 'country' sometimes used
            },
            "admin": {
                "name": getattr(w, "admin_name", None),
                "organization": getattr(w, "admin_organization", None),
                "email": getattr(w, "admin_email", None),
                "phone": getattr(w, "admin_phone", None),
                "country": getattr(w, "admin_country", None)
            },
            "tech": {
                "name": getattr(w, "tech_name", None),
                "organization": getattr(w, "tech_organization", None),
                "email": getattr(w, "tech_email", None),
                "phone": getattr(w, "tech_phone", None),
                "country": getattr(w, "tech_country", None)
            },
            "raw": str(w) if w else None # Convert WHOIS object to string for raw output
        }
        
        # Remove None values from contact dicts for cleaner output
        for contact_type in ["registrant", "admin", "tech"]:
            if contact_type in result:
                result[contact_type] = {k: v for k, v in result[contact_type].items() if v is not None}
                if not result[contact_type]: # If dict becomes empty, remove it
                    del result[contact_type]
        
        # Remove top-level None values
        result = {k: v for k, v in result.items() if v is not None and (not isinstance(v, (dict, list)) or v)}


        logger.debug(f"WHOIS lookup successful for {domain}")
        return result
        
    except whois.parser.PywhoisError as e: # Catch specific whois errors
        logger.error(f"WHOIS parsing error for {domain}: {str(e)}")
        return {
            "domain": domain,
            "error": f"WHOIS parsing error: {str(e)}",
            "ip_address": ip_address
        }
    except socket.gaierror as e:
        logger.error(f"Could not resolve domain {domain} for WHOIS lookup: {str(e)}")
        return {
            "domain": domain,
            "error": f"Could not resolve domain: {str(e)}",
            "ip_address": None
        }
    except Exception as e:
        logger.error(f"Error performing WHOIS lookup for {domain}: {str(e)}")
        return {
            "domain": domain,
            "error": str(e),
            "ip_address": ip_address
        }

def _process_date(date_obj: Any) -> Optional[str]:
    """
    Process a date object or list of date objects to ensure it's serializable.
    Returns the ISO format of the first valid date found.
    
    Args:
        date_obj: Date object or list of date objects from WHOIS response
        
    Returns:
        Formatted date string or None
    """
    if not date_obj:
        return None
        
    if isinstance(date_obj, list):
        # Iterate through the list and use the first valid datetime object
        for item in date_obj:
            if isinstance(item, (datetime, datetime.date)): # python-whois often returns datetime.datetime
                return item.isoformat()
        return None # No valid datetime object found in the list
        
    if isinstance(date_obj, (datetime, datetime.date)):
        return date_obj.isoformat()
        
    # If it's a string, try to parse it (though python-whois usually returns datetime objects)
    if isinstance(date_obj, str):
        try:
            # Attempt common formats, this might need to be more robust
            # For now, assume it's already in a good string format if not datetime
            return date_obj
        except ValueError:
            return str(date_obj) # Fallback to string representation

    return str(date_obj) # Fallback for other types

def _ensure_list(value: Any) -> List[str]:
    """
    Ensures the value is a list of strings.
    If None, returns an empty list. If a single string, wraps it in a list.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None] # Ensure all items are strings
    return [str(value)] # Fallback for other types
