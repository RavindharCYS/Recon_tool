"""
Web Vulnerabilities Module - Basic checks for common web application vulnerabilities and misconfigurations.
WARNING: Active scanning can be intrusive. Use responsibly and with explicit permission.
This is NOT a replacement for thorough manual testing or dedicated vulnerability scanners.
"""
import requests
from bs4 import BeautifulSoup, Comment # type: ignore
import re
import time
import random
import string
from typing import Dict, List, Any, Optional, Union, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, quote

from ...config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT, DEFAULT_DELAY, QUICK_TIMEOUT, get_api_key # UPDATED
from ...utils.validators import is_valid_url, is_valid_domain # UPDATED
# from ...utils.network_helpers import get_ip_from_domain # Not directly used here

import logging
logger = logging.getLogger(__name__)

# --- Helper Functions ---
def _make_request_vuln(url: str, method: str = "GET", params: Optional[Dict[str, str]] = None,
                       data: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None,
                       timeout: float = QUICK_TIMEOUT, allow_redirects: bool = True) -> Tuple[Optional[requests.Response], Optional[str]]:
    """Shared request helper for this module."""
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)
    
    try:
        response = requests.request(method, url, params=params, data=data, headers=req_headers,
                                    timeout=timeout, allow_redirects=allow_redirects, verify=True)
        return response, None
    except requests.exceptions.Timeout:
        return None, "Timeout"
    except requests.exceptions.ConnectionError:
        return None, "Connection error"
    except requests.exceptions.RequestException as e:
        return None, f"Request exception: {type(e).__name__}"

def _add_finding(findings_list: List[Dict[str, Any]], name: str, risk: str, description: str,
                 evidence: str, recommendation: str, cwe: Optional[str] = None,
                 confidence: str = "Medium", url_tested: Optional[str] = None):
    """Helper to add a vulnerability or informational finding."""
    finding = {
        "name": name, "risk": risk.lower(), "description": description,
        "evidence": evidence, "recommendation": recommendation,
        "confidence": confidence, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    if cwe: finding["cwe"] = cwe
    if url_tested: finding["url_tested"] = url_tested
    findings_list.append(finding)

# --- Vulnerability Check Functions ---

def check_security_headers_active(url: str, findings: List[Dict[str, Any]]):
    """Checks for presence and configuration of important security headers."""
    logger.debug(f"Checking security headers for {url}")
    response, error = _make_request_vuln(url, timeout=DEFAULT_TIMEOUT)
    if error or not response:
        logger.warning(f"Could not fetch {url} for security header check: {error}")
        return

    headers_to_check = {
        "Strict-Transport-Security": {"missing_risk": "medium", "rec": "Implement HSTS to enforce HTTPS.", "cwe": "CWE-319"},
        "Content-Security-Policy": {"missing_risk": "medium", "rec": "Implement CSP to mitigate XSS and data injection attacks.", "cwe": "CWE-693"},
        "X-Content-Type-Options": {"missing_risk": "low", "rec": "Set to 'nosniff' to prevent MIME-sniffing.", "cwe": "CWE-693"},
        "X-Frame-Options": {"missing_risk": "medium", "rec": "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking.", "cwe": "CWE-1021"},
        # "X-XSS-Protection" is deprecated and often not recommended now if strong CSP is in place.
        "Referrer-Policy": {"missing_risk": "low", "rec": "Set an appropriate Referrer-Policy (e.g., 'strict-origin-when-cross-origin')."},
        "Permissions-Policy": {"missing_risk": "low", "rec": "Implement Permissions-Policy (Feature-Policy) to control browser features."},
    }

    for header_name, details in headers_to_check.items():
        if not response.headers.get(header_name):
            _add_finding(findings, f"Missing Security Header: {header_name}", details["missing_risk"],
                         f"The HTTP header '{header_name}' is not set.",
                         f"Response headers for {url} did not include {header_name}.",
                         details["rec"], cwe=details.get("cwe"), url_tested=url)
        # else: # Could add checks for weak configurations if header is present
            # pass 
    
    # Check for information disclosure headers
    info_disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
    for h_name in info_disclosure_headers: # Renamed h to h_name
        if response.headers.get(h_name):
             _add_finding(findings, f"Information Disclosure: {h_name}", "low",
                         f"The '{h_name}' header reveals server/technology information: {response.headers[h_name]}",
                         f"Header '{h_name}: {response.headers[h_name]}' found.",
                         f"Consider removing or obfuscating the '{h_name}' header.", cwe="CWE-200", url_tested=url)


def check_http_methods(url: str, findings: List[Dict[str, Any]]):
    """Checks for potentially unsafe HTTP methods like PUT, DELETE, TRACE if enabled."""
    logger.debug(f"Checking HTTP methods for {url}")
    # TRACE can be used in XST attacks if HttpOnly cookies are not used.
    # PUT/DELETE are dangerous if not properly secured.
    # OPTIONS reveals allowed methods.
    methods_to_test = ["OPTIONS", "TRACE"] # Add "PUT", "DELETE" with caution

    for method in methods_to_test:
        time.sleep(DEFAULT_DELAY / 2)
        response, error = _make_request_vuln(url, method=method)
        if error or not response:
            logger.warning(f"Request for HTTP method {method} on {url} failed: {error}")
            continue

        if method == "OPTIONS" and response.status_code == 200:
            allowed_methods = response.headers.get("Allow", "").upper()
            _add_finding(findings, "Allowed HTTP Methods", "informational",
                         f"Allowed HTTP methods: {allowed_methods}",
                         f"OPTIONS request returned: {allowed_methods}",
                         "Review allowed methods. Disable unnecessary ones like TRACE, PUT, DELETE if not used or secured.",
                         url_tested=url)
            if "TRACE" in allowed_methods:
                 _add_finding(findings, "HTTP TRACE Method Enabled", "low",
                             "The HTTP TRACE method is enabled. This could potentially be used in Cross-Site Tracing (XST) attacks.",
                             "OPTIONS response included TRACE in 'Allow' header.",
                             "Disable the TRACE method on the web server unless specifically required.", cwe="CWE-693", url_tested=url)

        elif method == "TRACE" and response.status_code == 200 and url.lower() in response.text.lower(): # TRACE reflects request
            _add_finding(findings, "HTTP TRACE Method Enabled (Reflected)", "low",
                         "The HTTP TRACE method is enabled and reflects the request, confirming XST potential.",
                         f"TRACE request to {url} was successful and reflected input.",
                         "Disable the TRACE method on the web server.", cwe="CWE-693", url_tested=url)


def check_common_path_exposures(base_url: str, findings: List[Dict[str, Any]]):
    """Checks for common sensitive paths/files."""
    logger.debug(f"Checking for common path exposures at {base_url}")
    paths_to_check = [
        ".git/config", ".svn/entries", ".DS_Store", "robots.txt", "sitemap.xml",
        "wp-config.php.bak", "config.json.old", ".env", "appsettings.json",
        "WEB-INF/web.xml", # Java
        "admin/", "administrator/", "backup/", "logs/" # Directories (check for 200 or 403 listing)
    ]
    # More advanced: add specific tech stack files like composer.lock, package-lock.json, etc.

    for path_item in paths_to_check: # Renamed path to path_item
        time.sleep(DEFAULT_DELAY / 2)
        test_url = urljoin(base_url, path_item)
        response, error = _make_request_vuln(test_url, timeout=QUICK_TIMEOUT)

        if error or not response:
            # logger.debug(f"Path {path_item} not found or error: {error}")
            continue
        
        # Exposed .git, .svn, .env are high risk
        if response.status_code == 200:
            risk = "low" # Default for informational files like robots.txt
            cwe_val = "CWE-538" # File and Directory Information Exposure
            if any(p in path_item for p in [".git", ".svn", ".env", "wp-config", "web.xml", "appsettings"]):
                risk = "high"
                cwe_val = "CWE-200" # Information Exposure
            elif any(p in path_item for p in ["backup", ".bak", ".old", "config.json", "logs/"]):
                risk = "medium"
            
            _add_finding(findings, f"Potentially Sensitive Path Exposed: {path_item}", risk,
                         f"The path '{path_item}' is accessible and returned HTTP {response.status_code}.",
                         f"URL: {test_url}, Status: {response.status_code}, Content-Length: {len(response.content)}",
                         "Ensure sensitive files and directories are not publicly accessible. Review web server and application configurations.",
                         cwe=cwe_val, url_tested=test_url)
        elif response.status_code == 403 and path_item.endswith('/'): # Directory listing forbidden for a dir
             _add_finding(findings, f"Directory Listing Forbidden: {path_item}", "informational",
                         f"Access to directory '{path_item}' is forbidden (HTTP 403).",
                         f"URL: {test_url}, Status: 403",
                         "This is generally good. Ensure no sensitive index files exist if listing were enabled.",
                         url_tested=test_url)


def check_basic_xss_reflection(url: str, findings: List[Dict[str, Any]]):
    """Very basic check for reflected XSS in URL parameters."""
    logger.debug(f"Performing basic XSS reflection check for {url}")
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if not query_params: return # No params to test

    # Simple XSS payload, unlikely to be missed by modern browsers/WAFs if truly vulnerable
    xss_payload = "<script>alert('reconXSS')</script>" 
    # More subtle payload for reflection check
    reflection_marker = f"ReconPyReflectTest{random.randint(1000,9999)}"

    for param_name in list(query_params.keys()): # Iterate over a copy of keys
        original_value = query_params[param_name][0]
        
        # Test with reflection marker
        test_params_reflect = query_params.copy()
        test_params_reflect[param_name] = [reflection_marker]
        
        # Rebuild URL carefully
        # query_string_reflect = urlencode(test_params_reflect, doseq=True) # this can over-encode
        query_parts_reflect = []
        for k, v_list in test_params_reflect.items():
            for v_single in v_list: # Renamed v to v_single
                query_parts_reflect.append(f"{quote(k)}={quote(v_single)}")
        query_string_reflect = "&".join(query_parts_reflect)

        test_url_reflect = parsed_url._replace(query=query_string_reflect).geturl()

        time.sleep(DEFAULT_DELAY / 2)
        response, error = _make_request_vuln(test_url_reflect)

        if response and response.text and reflection_marker in response.text:
            if xss_payload.replace("reconXSS", reflection_marker[8:]) in response.text.replace(reflection_marker, reflection_marker[8:]):
                 # This check is very naive; proper XSS needs more context
                 pass # More sophisticated check needed

            # Check if the marker is reflected without escaping critical HTML characters
            # This is a simplified check. Real XSS detection is complex.
            if re.search(f"[^a-zA-Z0-9]{reflection_marker}[^a-zA-Z0-9]", response.text) or \
               re.search(f"(?<!&[a-zA-Z0-9#]+;){reflection_marker}", response.text): # Reflected not as part of an entity
                _add_finding(findings, "Potential Reflected XSS", "medium",
                             f"Parameter '{param_name}' reflects input '{reflection_marker}' back into the page. Investigate for XSS.",
                             f"URL: {test_url_reflect}\nReflected: {reflection_marker}",
                             "Ensure all user-supplied input is contextually sanitized/escaped on output. Use a Content Security Policy.",
                             cwe="CWE-79", confidence="Low", url_tested=test_url_reflect)
                # Don't test further params on this URL after one reflection for this basic check
                break 


# --- Main Scan Function ---
def scan(target_url_str: str, full_scan: bool = False) -> Dict[str, Any]: # Renamed url to target_url_str, full to full_scan
    """
    Performs a basic web vulnerability scan on the target URL.
    
    Args:
        target_url_str: The base URL to scan.
        full_scan: If True, performs more checks (can be slower/noisier).
        
    Returns:
        Dictionary containing scan results and findings.
    """
    logger.info(f"Starting web vulnerability scan for: {target_url_str} (Full Scan: {full_scan})")

    if not is_valid_url(target_url_str):
        parsed_check = urlparse(target_url_str)
        if not parsed_check.scheme and parsed_check.netloc: # Missing scheme
            target_url_str = "https://" + target_url_str
        elif not parsed_check.scheme and not parsed_check.netloc and is_valid_domain(target_url_str): # Is domain
             target_url_str = "https://" + target_url_str
        else:
            logger.error(f"Invalid URL format for web vulnerability scan: {target_url_str}")
            return {"target_url": target_url_str, "error": "Invalid URL format."}

    scan_report: Dict[str, Any] = { # Renamed result to scan_report
        "target_url": target_url_str,
        "scan_type": "full" if full_scan else "basic",
        "scan_start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_end_time": None,
        "duration_seconds": None,
        "findings": [], # List of vulnerability/informational findings
        "summary": {"high": 0, "medium": 0, "low": 0, "informational": 0}
    }
    
    start_time_mono = time.monotonic() # For duration calculation

    try:
        # Initial request to ensure target is up and get base info
        response_initial, error_initial = _make_request_vuln(target_url_str, timeout=DEFAULT_TIMEOUT)
        if error_initial or not response_initial:
            scan_report["error"] = f"Initial connection to {target_url_str} failed: {error_initial or 'No response'}"
            return scan_report
        
        scan_report["initial_status_code"] = response_initial.status_code
        if response_initial.status_code >= 400:
            logger.warning(f"Initial request to {target_url_str} returned status {response_initial.status_code}. Some checks may fail.")


        # === Perform Checks ===
        check_security_headers_active(target_url_str, scan_report["findings"])
        
        # Check for clickjacking defense (more specific than just X-Frame-Options)
        if not response_initial.headers.get("X-Frame-Options") and \
           not ("frame-ancestors" in response_initial.headers.get("Content-Security-Policy", "")):
            _add_finding(scan_report["findings"], "Clickjacking Defense Missing", "medium",
                         "Neither X-Frame-Options nor CSP frame-ancestors directive is set.",
                         "Response headers lack X-Frame-Options or CSP frame-ancestors.",
                         "Implement X-Frame-Options (e.g., 'SAMEORIGIN' or 'DENY') or CSP frame-ancestors to prevent clickjacking.",
                         cwe="CWE-1021", url_tested=target_url_str)

        check_http_methods(target_url_str, scan_report["findings"])
        check_common_path_exposures(target_url_str, scan_report["findings"])
        
        # Basic XSS reflection check on initial URL if it has parameters
        if '?' in target_url_str:
            check_basic_xss_reflection(target_url_str, scan_report["findings"])

        # Example of a VirusTotal URL scan (if API key is present)
        vt_api_key = get_api_key("virustotal", "api_key")
        if vt_api_key:
            logger.info("VirusTotal API key found, attempting URL scan.")
            vt_result = _scan_url_with_virustotal(target_url_str, vt_api_key)
            if vt_result:
                scan_report["virustotal_scan"] = vt_result # Add VT results to report
                if vt_result.get("positives", 0) > 0:
                     _add_finding(scan_report["findings"], "URL Flagged by VirusTotal", "medium",
                                 f"VirusTotal reported {vt_result['positives']}/{vt_result['total']} engines flagging this URL as potentially malicious.",
                                 f"Scan ID: {vt_result.get('scan_id')}, Positives: {vt_result.get('positives')}",
                                 "Review the VirusTotal report for details. The URL may be associated with malware or phishing.",
                                 url_tested=target_url_str)


        if full_scan:
            logger.info("Full scan enabled, performing additional checks...")
            # Add more intensive checks here, e.g., trying more XSS payloads,
            # checking for directory listings on common paths, simple SQLi probes.
            # These should be added with care and clear logging.
            # Example: _check_directory_listing_full(target_url_str, scan_report["findings"])
            # Example: _check_more_xss_payloads(target_url_str, scan_report["findings"])
            pass

    except Exception as e:
        logger.error(f"Major error during web vulnerability scan for {target_url_str}: {str(e)}")
        scan_report["error"] = f"Scan aborted due to unexpected error: {str(e)}"
    
    # Finalize report
    scan_report["scan_end_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    scan_report["duration_seconds"] = round(time.monotonic() - start_time_mono, 2)

    for finding in scan_report["findings"]:
        risk_level = finding.get("risk", "informational")
        if risk_level in scan_report["summary"]:
            scan_report["summary"][risk_level] += 1
        else: # Should not happen if risk is always one of the keys
            scan_report["summary"]["informational"] +=1


    logger.info(f"Web vulnerability scan for {target_url_str} completed in {scan_report['duration_seconds']:.2f}s. "
                f"Findings: H={scan_report['summary']['high']}, M={scan_report['summary']['medium']}, "
                f"L={scan_report['summary']['low']}, I={scan_report['summary']['informational']}")
    
    return scan_report


def _scan_url_with_virustotal(url_to_scan: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Scans a URL using the VirusTotal API v3."""
    vt_api_url_scan = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key, "User-Agent": DEFAULT_USER_AGENT}
    
    # Step 1: Submit URL for scanning
    try:
        payload = {"url": url_to_scan}
        response_submit = requests.post(vt_api_url_scan, headers=headers, data=payload, timeout=DEFAULT_TIMEOUT)
        response_submit.raise_for_status()
        submit_data = response_submit.json()
        analysis_id = submit_data.get("data", {}).get("id")
        if not analysis_id:
            logger.error("VirusTotal submission did not return an analysis ID.")
            return {"error": "Failed to get analysis ID from VirusTotal submission."}
        
        logger.debug(f"URL {url_to_scan} submitted to VirusTotal. Analysis ID: {analysis_id}")

        # Step 2: Retrieve scan report (may need to wait and poll)
        # For simplicity in a CLI tool, we'll try a few times with delays.
        # A more robust solution would involve polling.
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        for attempt in range(3): # Try up to 3 times
            time.sleep(10 + attempt * 5) # Exponential backoff-like delay (10s, 15s, 20s)
            logger.debug(f"Fetching VirusTotal report (attempt {attempt + 1})...")
            response_report = requests.get(report_url, headers=headers, timeout=DEFAULT_TIMEOUT)
            if response_report.status_code == 200:
                report_data = response_report.json().get("data", {}).get("attributes", {})
                if report_data.get("status") == "completed":
                    stats = report_data.get("stats", {})
                    return {
                        "scan_id": analysis_id.split('-')[1] if '-' in analysis_id else analysis_id, # Get the part after 'u-'
                        "status": "completed",
                        "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                        "total_engines": sum(stats.values()),
                        "scan_date": report_data.get("date"),
                        "permalink": f"https://www.virustotal.com/gui/url/{hashlib.sha256(url_to_scan.encode()).hexdigest()}/detection" if 'hashlib' in sys.modules else None # Requires hashlib and sys
                    }
                else:
                    logger.debug(f"VirusTotal scan status for {analysis_id}: {report_data.get('status')}")
            else:
                logger.warning(f"Failed to retrieve VirusTotal report (attempt {attempt+1}), status: {response_report.status_code}")
        
        return {"error": "VirusTotal scan did not complete in time or report retrieval failed.", "status": "pending_or_failed"}

    except requests.exceptions.HTTPError as e:
        err_content = e.response.text[:200] if e.response else "No response content"
        logger.error(f"VirusTotal API HTTP error: {e.response.status_code} - {err_content}")
        return {"error": f"VirusTotal API HTTP error: {e.response.status_code}", "details": err_content}
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal request error: {str(e)}")
        return {"error": f"VirusTotal request error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error during VirusTotal scan: {str(e)}")
        return {"error": f"Unexpected error with VirusTotal: {str(e)}"}
    return None # Should not be reached if errors are handled

# Import hashlib and sys only if used in _scan_url_with_virustotal
import hashlib
import sys