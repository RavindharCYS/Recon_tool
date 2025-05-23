"""
Wayback Machine module - retrieve historical versions of websites from the Internet Archive.
"""
import requests
import logging
import json
import time
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta # For date calculations
from urllib.parse import quote_plus, urlparse

from ...config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT, DEFAULT_DELAY # UPDATED: Relative import
from ...utils.validators import is_valid_url, is_valid_domain # UPDATED: Relative import

logger = logging.getLogger(__name__)

WAYBACK_CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_WEB_URL_PREFIX = "https://web.archive.org/web"

def _validate_and_clean_target(target: str) -> Optional[str]:
    """Validates target and cleans it for CDX API (removes scheme, keeps domain/path)."""
    if is_valid_url(target):
        parsed_url = urlparse(target)
        # CDX API prefers domain/path without scheme for wildcard searches,
        # but can accept full URLs for specific page lookups.
        # For general snapshot listing, domain/* or domain/path/* is common.
        # We'll use domain and path.
        clean_target = parsed_url.netloc + parsed_url.path
        if parsed_url.query:
            clean_target += "?" + parsed_url.query
        return clean_target.rstrip('/') # Remove trailing slash for consistency
    elif is_valid_domain(target):
        return target # Domain is fine as is for wildcard search
    else:
        logger.error(f"Invalid target format for Wayback Machine: {target}. Expected URL or domain.")
        return None

def _validate_date_format(date_str: str, expected_length: int = 8) -> bool:
    """Validates if a string is in YYYYMMDD (8) or YYYYMMDDHHMMSS (14) format."""
    if not date_str or not date_str.isdigit() or len(date_str) != expected_length:
        return False
    try:
        if expected_length == 8: # YYYYMMDD
            datetime.strptime(date_str, "%Y%m%d")
        elif expected_length == 14: # YYYYMMDDHHMMSS
            datetime.strptime(date_str, "%Y%m%d%H%M%S")
        else:
            return False # Should not happen with current usage
        return True
    except ValueError:
        return False

def format_wayback_timestamp(timestamp: str) -> str: # Renamed from format_timestamp
    """
    Format a Wayback Machine timestamp (YYYYMMDDHHMMSS) into a human-readable ISO-like format.
    """
    if not _validate_date_format(timestamp, 14):
        return timestamp # Return as is if not valid 14-digit timestamp
    try:
        dt_obj = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
        return dt_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        logger.warning(f"Could not parse Wayback timestamp: {timestamp}")
        return timestamp # Fallback

def get_snapshots(target: str, from_date: Optional[str] = None, to_date: Optional[str] = None, 
                  limit: int = 20, collapse: Optional[str] = "timestamp:6") -> Dict[str, Any]:
    """
    Get historical snapshots of a website from the Wayback Machine CDX Server API.
    
    Args:
        target: URL or domain to search.
        from_date: Start date in YYYYMMDD format (optional).
        to_date: End date in YYYYMMDD format (optional).
        limit: Maximum number of snapshots to return (approximate due to API behavior).
        collapse: Field to collapse results on (e.g., "timestamp:4" for daily, 
                  "timestamp:6" for monthly, "digest" for unique content). 
                  Use None for no collapsing. Default is monthly.
                  
    Returns:
        Dictionary containing snapshots information or an error.
    """
    logger.info(f"Retrieving Wayback Machine snapshots for: {target} (limit: {limit}, collapse: {collapse})")
    
    clean_target = _validate_and_clean_target(target)
    if not clean_target:
        return {"target_input": target, "error": "Invalid target format."}

    params: Dict[str, Union[str, int]] = { # Type hint
        "url": f"{clean_target}*", # Add wildcard to get all pages under the domain/path
        "output": "json",
        "limit": limit # Note: limit can be positive (first N) or negative (last N)
    }
    if collapse:
        params["collapse"] = collapse
    
    if from_date:
        if not _validate_date_format(from_date):
            err_msg = f"Invalid from_date format: {from_date}. Expected YYYYMMDD."
            logger.error(err_msg)
            return {"target_input": target, "error": err_msg}
        params["from"] = from_date
    
    if to_date:
        if not _validate_date_format(to_date):
            err_msg = f"Invalid to_date format: {to_date}. Expected YYYYMMDD."
            logger.error(err_msg)
            return {"target_input": target, "error": err_msg}
        params["to"] = to_date

    http_headers = {"User-Agent": DEFAULT_USER_AGENT} # Renamed

    try:
        response = requests.get(WAYBACK_CDX_API_URL, params=params, headers=http_headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        
        # The API sometimes returns an empty list `[]` or `[[]]` for no results,
        # or a list where the first item is the header row.
        raw_data = response.json() # Renamed data to raw_data
        
        if not raw_data or (isinstance(raw_data, list) and len(raw_data) <= 1 and (not raw_data[0] if raw_data else True)):
            logger.info(f"No Wayback Machine snapshots found for {clean_target} with current filters.")
            return {
                "target_input": target,
                "api_query_url": response.url, # Show the actual URL queried
                "snapshot_count": 0,
                "snapshots": []
            }
        
        # First row is usually headers, subsequent rows are data
        header_row = raw_data[0]
        snapshots_data = raw_data[1:] # Renamed
        
        processed_snapshots: List[Dict[str, Any]] = [] # Renamed and type hint
        
        for entry_row in snapshots_data: # Renamed row to entry_row
            if len(entry_row) != len(header_row):
                logger.warning(f"Skipping malformed snapshot entry: {entry_row}")
                continue

            snapshot_detail: Dict[str, Any] = dict(zip(header_row, entry_row)) # Renamed
            
            if 'timestamp' in snapshot_detail:
                snapshot_detail['datetime_utc'] = format_wayback_timestamp(snapshot_detail['timestamp'])
                snapshot_detail['archive_url'] = f"{WAYBACK_WEB_URL_PREFIX}/{snapshot_detail['timestamp']}/{snapshot_detail.get('original', clean_target)}"
            
            processed_snapshots.append(snapshot_detail)
        
        result = {
            "target_input": target,
            "api_query_url": response.url,
            "snapshot_count": len(processed_snapshots),
            "snapshots": processed_snapshots
        }
        
        logger.info(f"Found {len(processed_snapshots)} Wayback Machine snapshots for {clean_target}.")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to Wayback Machine CDX API: {str(e)}")
        return {"target_input": target, "error": f"Wayback API connection error: {str(e)}"}
    except json.JSONDecodeError: # Handle cases where response is not valid JSON
        logger.error(f"Error parsing Wayback Machine CDX API JSON response for {target}. Response: {response.text[:200]}")
        return {"target_input": target, "error": "Invalid JSON response from Wayback API."}
    except Exception as e:
        logger.error(f"Unexpected error retrieving Wayback Machine snapshots for {target}: {str(e)}")
        return {"target_input": target, "error": f"Unexpected error: {str(e)}"}


def get_snapshot_content(archive_url: str) -> Dict[str, Any]:
    """
    Retrieve the content of a specific Wayback Machine snapshot URL.
    
    Args:
        archive_url: The full Wayback Machine URL (e.g., https://web.archive.org/web/TIMESTAMP/URL)
        
    Returns:
        Dictionary containing snapshot content or an error.
    """
    logger.info(f"Retrieving content from Wayback Machine URL: {archive_url}")

    if not archive_url.startswith(WAYBACK_WEB_URL_PREFIX):
        err_msg = f"Invalid archive URL format. Must start with {WAYBACK_WEB_URL_PREFIX}."
        logger.error(err_msg)
        return {"archive_url_input": archive_url, "error": err_msg}

    # Try to parse timestamp and original URL from archive_url
    # Example: https://web.archive.org/web/20230101000000id_/http://example.com/
    match = re.match(rf"{WAYBACK_WEB_URL_PREFIX}/(\d{{14}})(?:[a-z_]{{0,3}})?/(.*)", archive_url)
    if not match:
        err_msg = "Could not parse timestamp and original URL from archive URL."
        logger.error(err_msg)
        return {"archive_url_input": archive_url, "error": err_msg}
    
    timestamp, original_url_from_archive = match.groups()

    http_headers = {"User-Agent": DEFAULT_USER_AGENT}
    try:
        # Request with 'id_' flag to get the original capture without Wayback modifications
        # However, sometimes this doesn't work, so we might try without it as a fallback.
        # For now, let's just use the provided URL.
        response = requests.get(archive_url, headers=http_headers, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        response.raise_for_status()
        
        # Content might be very large, so offer a preview
        content_preview_limit = 2000 # characters
        content_text = response.text
        
        result = {
            "archive_url_input": archive_url,
            "final_url_fetched": response.url, # In case of internal Wayback redirects
            "timestamp_from_url": timestamp,
            "original_url_from_archive": original_url_from_archive,
            "datetime_utc": format_wayback_timestamp(timestamp),
            "status_code": response.status_code,
            "content_type": response.headers.get('Content-Type', ''),
            "content_length_bytes": len(response.content),
            "content_preview": content_text[:content_preview_limit] + ('...' if len(content_text) > content_preview_limit else '')
            # "full_content": content_text # Optionally include full content, but be wary of size
        }
        
        logger.info(f"Successfully retrieved content from {archive_url}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving content from {archive_url}: {str(e)}")
        return {"archive_url_input": archive_url, "error": f"Request error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error retrieving content from {archive_url}: {str(e)}")
        return {"archive_url_input": archive_url, "error": f"Unexpected error: {str(e)}"}

# --- Additional utility functions can be added below as needed ---

def get_domain_change_history(domain: str, num_snapshots_per_year: int = 4, years_to_check: int = 5) -> Dict[str, Any]:
    """
    Fetches a selection of snapshots over several years to observe changes.
    This is a simplified version; true change detection is complex.
    
    Args:
        domain: The domain to analyze.
        num_snapshots_per_year: How many snapshots to try and get per year.
        years_to_check: How many past years to check.
        
    Returns:
        Dictionary with a timeline of selected snapshots.
    """
    logger.info(f"Fetching change history for {domain} over {years_to_check} years.")
    
    clean_domain = _validate_and_clean_target(domain)
    if not clean_domain:
        return {"domain_input": domain, "error": "Invalid domain format."}

    current_year = datetime.now().year
    history_timeline: List[Dict[str, Any]] = []

    for i in range(years_to_check):
        year_to_fetch = current_year - i
        from_date = f"{year_to_fetch}0101" # January 1st
        to_date = f"{year_to_fetch}1231"   # December 31st
        
        logger.debug(f"Fetching snapshots for {domain} in year {year_to_fetch}")
        time.sleep(DEFAULT_DELAY) # Respect API rate limits between calls

        # Collapse by month (timestamp:6) or day (timestamp:4) to get varied snapshots
        # For num_snapshots_per_year=4, collapsing by timestamp:6 (monthly) might be good
        # then we pick from those results.
        collapse_period = "timestamp:6" # Monthly
        if num_snapshots_per_year > 12 : collapse_period = "timestamp:4" # Daily if many requested
        if num_snapshots_per_year == 1: collapse_period = "timestamp:2" # Yearly if only one


        # Fetch more than needed to allow for selection
        fetch_limit = num_snapshots_per_year * 3 if num_snapshots_per_year > 1 else 5

        year_snapshots_data = get_snapshots(
            target=domain, # Pass original domain for user context, clean_domain is used internally by get_snapshots
            from_date=from_date, 
            to_date=to_date, 
            limit=fetch_limit, # Fetch a bit more to choose from
            collapse=collapse_period
        )
        
        if year_snapshots_data.get("snapshots"):
            # Simple selection: pick evenly spaced snapshots, or first N
            selected_for_year = year_snapshots_data["snapshots"][:num_snapshots_per_year]
            for snap in selected_for_year:
                history_timeline.append({
                    "year": str(year_to_fetch),
                    "timestamp": snap.get("timestamp"),
                    "datetime_utc": snap.get("datetime_utc"),
                    "archive_url": snap.get("archive_url"),
                    "original_url": snap.get("original"),
                    "status_code": snap.get("statuscode"),
                    "mime_type": snap.get("mimetype"),
                    "digest": snap.get("digest") # Useful for content change detection
                })
    
    return {
        "domain_input": domain,
        "years_checked": years_to_check,
        "snapshots_per_year_requested": num_snapshots_per_year,
        "change_history_timeline": sorted(history_timeline, key=lambda x: x.get("timestamp",""), reverse=True) # Newest first
    }

