"""
Web scraper module - extracts information from web pages
"""
import requests
from bs4 import BeautifulSoup # type: ignore
import re
from typing import Dict, List, Any, Set, Optional, Union
import logging
from urllib.parse import urljoin, urlparse, unquote
import time

from ...config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT, DEFAULT_DELAY # UPDATED: Relative import
from ...utils.validators import is_valid_url # UPDATED: Relative import

logger = logging.getLogger(__name__)

# Global set to keep track of URLs visited across multiple depths for a single scrape call
# This needs to be managed carefully if you plan to make this class-based or allow concurrent scrapes.
# For a simple function call, it's reset each time scrape() is called.
_VISITED_URLS_SESSION: Set[str] = set()


def scrape(url: str, depth: int = 1, max_pages: int = 10) -> Dict[str, Any]:
    """
    Scrape a website for information, following links to a certain depth.
    
    Args:
        url: Target URL to start scraping from
        depth: How many levels of links to follow (default: 1, 0 means only the starting URL)
        max_pages: Maximum number of pages to scrape in total (default: 10)
        
    Returns:
        Dictionary containing aggregated extracted information from all scraped pages.
    """
    logger.info(f"Initiating web scrape for: {url} (depth={depth}, max_pages={max_pages})")
    
    global _VISITED_URLS_SESSION
    _VISITED_URLS_SESSION = set() # Reset for each new scrape call

    if not is_valid_url(url):
        logger.error(f"Invalid URL format for scraping: {url}")
        return {"error": f"Invalid URL format: {url}"}
    
    # Ensure URL starts with a scheme
    parsed_initial_url = urlparse(url)
    if not parsed_initial_url.scheme:
        url = "https://" + url # Default to HTTPS
        parsed_initial_url = urlparse(url)
    
    base_domain = parsed_initial_url.netloc

    # Aggregated results
    aggregated_results: Dict[str, Any] = {
        "start_url": url,
        "base_domain": base_domain,
        "scraped_pages_count": 0,
        "all_emails": set(),
        "all_phones": set(),
        "all_internal_links": set(),
        "all_external_links": set(),
        "all_social_media_links": set(),
        "technologies_detected": {}, # Will store tech from the first page
        "pages_data": [] # Store individual page data
    }

    # Queue of (URL, current_depth)
    queue: List[tuple[str, int]] = [(url, 0)]

    processed_pages_count = 0

    while queue and processed_pages_count < max_pages:
        current_url, current_depth_level = queue.pop(0)

        if current_url in _VISITED_URLS_SESSION:
            continue
        _VISITED_URLS_SESSION.add(current_url)
        
        # Ensure we are still on the same domain if current_depth > 0
        # For depth 0, we always process the initial URL
        if current_depth_level > 0:
            parsed_current = urlparse(current_url)
            if parsed_current.netloc != base_domain:
                logger.debug(f"Skipping external URL during crawl: {current_url}")
                continue
        
        logger.info(f"Scraping page: {current_url} at depth {current_depth_level}")

        try:
            page_data = scrape_single_page(current_url)
            if "error" in page_data:
                logger.warning(f"Failed to scrape {current_url}: {page_data['error']}")
                aggregated_results["pages_data"].append({"url": current_url, "error": page_data['error']})
                continue

            processed_pages_count += 1
            aggregated_results["scraped_pages_count"] = processed_pages_count
            aggregated_results["pages_data"].append(page_data) # Store individual page data

            # Aggregate data
            aggregated_results["all_emails"].update(page_data.get("emails", set()))
            aggregated_results["all_phones"].update(page_data.get("phones", set()))

            # Detect technologies only from the first successfully scraped page
            if not aggregated_results["technologies_detected"] and page_data.get("technologies"):
                aggregated_results["technologies_detected"] = page_data["technologies"]

            # Add new links to the queue if within depth
            if current_depth_level < depth:
                for link_url_str in page_data.get("links", set()): # Renamed link to link_url_str
                    # Normalize and validate link
                    parsed_link = urlparse(link_url_str)
                    if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc:
                        # Only add internal links for further crawling
                        if parsed_link.netloc == base_domain and link_url_str not in _VISITED_URLS_SESSION:
                            queue.append((link_url_str, current_depth_level + 1))
                        elif parsed_link.netloc != base_domain:
                            if _is_social_media_link(link_url_str):
                                aggregated_results["all_social_media_links"].add(link_url_str)
                            else:
                                aggregated_results["all_external_links"].add(link_url_str)
                        else: # Internal link already visited or queued
                            aggregated_results["all_internal_links"].add(link_url_str)
                    elif parsed_link.scheme == 'mailto': # Add mailto links to emails
                        email_from_mailto = parsed_link.path
                        if email_from_mailto:
                             aggregated_results["all_emails"].add(email_from_mailto)
                    elif parsed_link.scheme == 'tel': # Add tel links to phones
                         phone_from_tel = parsed_link.path
                         if phone_from_tel:
                              aggregated_results["all_phones"].add(phone_from_tel)


            # Respectful delay
            time.sleep(DEFAULT_DELAY)

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {current_url}: {str(e)}")
            aggregated_results["pages_data"].append({"url": current_url, "error": f"Request failed: {str(e)}"})
        except Exception as e:
            logger.error(f"Unexpected error scraping {current_url}: {str(e)}")
            aggregated_results["pages_data"].append({"url": current_url, "error": f"Unexpected error: {str(e)}"})
            
    # Convert sets to lists for the final result
    aggregated_results["all_emails"] = sorted(list(aggregated_results["all_emails"]))
    aggregated_results["all_phones"] = sorted(list(aggregated_results["all_phones"]))
    # Internal links were already added to the queue if they were to be processed,
    # here we just list all internal links found on scraped pages.
    internal_links_found_on_pages = set()
    for page_d in aggregated_results["pages_data"]:
        if "links" in page_d: # ensure links key exists
            for link_item in page_d["links"]: # ensure link_item is string
                if isinstance(link_item, str) and urlparse(link_item).netloc == base_domain:
                    internal_links_found_on_pages.add(link_item)
    aggregated_results["all_internal_links"] = sorted(list(internal_links_found_on_pages.union(aggregated_results["all_internal_links"])))


    aggregated_results["all_external_links"] = sorted(list(aggregated_results["all_external_links"]))
    aggregated_results["all_social_media_links"] = sorted(list(aggregated_results["all_social_media_links"]))

    logger.info(f"Web scrape for {url} completed. Scraped {aggregated_results['scraped_pages_count']} pages.")
    return aggregated_results


def scrape_single_page(url: str) -> Dict[str, Any]:
    """
    Scrape a single web page for information.
    
    Args:
        url: URL to scrape
    
    Returns:
        Dictionary containing page information, or an error dictionary.
    """
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1", # Do Not Track
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        # Update URL to the final URL after redirects
        final_url = response.url 
        response.raise_for_status() 
    except requests.exceptions.RequestException as e:
        return {"url": url, "error": str(e)}

    page_info: Dict[str, Any] = {
        "url": final_url, # Use final URL
        "status_code": response.status_code,
        "title": None,
        "meta_description": None,
        "meta_keywords": [],
        "emails": set(),
        "phones": set(),
        "links": set(),
        "forms": [],
        "comments": [],
        "technologies": {} # Tech detection for this specific page
    }
    
    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        page_info["error"] = f"Content-Type is not HTML ({content_type})"
        logger.debug(f"Skipping non-HTML content at {final_url}")
        return page_info # Return basic info for non-HTML pages

    soup = BeautifulSoup(response.content, 'lxml') # Use response.content for correct encoding handling by BS4
    
    # Extract title
    title_tag = soup.find('title')
    if title_tag and title_tag.string:
        page_info["title"] = title_tag.string.strip()
    
    # Extract meta description
    meta_desc = soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)})
    if meta_desc and meta_desc.get('content'):
        page_info["meta_description"] = meta_desc['content'].strip()

    # Extract meta keywords
    meta_keys = soup.find('meta', attrs={'name': re.compile(r'^keywords$', re.I)})
    if meta_keys and meta_keys.get('content'):
        page_info["meta_keywords"] = [k.strip() for k in meta_keys['content'].split(',')]
    
    # Extract emails
    # More robust email regex:
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    try:
        # Search in text and also in mailto links
        text_content = soup.get_text(separator=" ")
        emails_in_text = re.findall(email_pattern, text_content)
        page_info["emails"].update(emails_in_text)
        
        for a_tag in soup.find_all('a', href=True):
            href_val = a_tag['href'] # Renamed href
            if href_val.lower().startswith('mailto:'):
                email_match = re.search(email_pattern, href_val[7:]) # Search after "mailto:"
                if email_match:
                    page_info["emails"].add(email_match.group(0))

    except Exception as e: # Broad catch due to potential regex/text processing errors
        logger.warning(f"Could not extract emails from {final_url}: {e}")


    # Extract phone numbers (more comprehensive regex)
    # This regex attempts to capture various international formats
    phone_pattern = r'(?:(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{1,5}\)|(?:\d{1,5}))[-.\s]?\d{1,5}[-.\s]?\d{1,9}\b|(?:tel:([+\d().\s-]*)))'
    try:
        text_content_for_phones = soup.get_text(separator=" ") # Re-get text if modified by email search
        phones_in_text = re.findall(phone_pattern, text_content_for_phones)
        # The regex might return tuples if the (tel:...) group matches
        for p_match in phones_in_text: # Renamed p to p_match
            if isinstance(p_match, tuple):
                # The second element of the tuple is from the (tel:...) group
                phone_num = p_match[1] if p_match[1] else p_match[0]
            else:
                phone_num = p_match
            
            # Basic cleanup: remove "tel:", strip whitespace, etc.
            cleaned_phone = phone_num.lower().replace("tel:", "").strip()
            if cleaned_phone: # Add if not empty after cleaning
                page_info["phones"].add(cleaned_phone)
    except Exception as e:
        logger.warning(f"Could not extract phone numbers from {final_url}: {e}")
    
    # Extract links
    for a_tag in soup.find_all('a', href=True):
        link_val = a_tag['href'] # Renamed link
        if link_val and not link_val.startswith('#') and not link_val.lower().startswith('javascript:'):
            try:
                absolute_link = urljoin(final_url, link_val.strip()) # Use final_url as base
                page_info["links"].add(absolute_link)
            except ValueError: # Handle malformed URLs from urljoin
                logger.debug(f"Skipping malformed link: {link_val} on page {final_url}")
    
    # Extract forms
    for form_tag in soup.find_all('form'): # Renamed form to form_tag
        form_info = {
            "action": urljoin(final_url, form_tag.get('action', '')), # Use final_url
            "method": form_tag.get('method', 'GET').upper(),
            "inputs": []
        }
        for input_tag in form_tag.find_all(['input', 'textarea', 'select', 'button']): # Added button
            input_details = { # Renamed input_info to input_details
                "tag": input_tag.name,
                "type": input_tag.get('type', 'text' if input_tag.name == 'input' else None),
                "name": input_tag.get('name'),
                "id": input_tag.get('id'),
                "value": input_tag.get('value')
            }
            # Remove None values from input_details
            input_details = {k:v for k,v in input_details.items() if v is not None}
            form_info["inputs"].append(input_details)
        page_info["forms"].append(form_info)

    # Extract HTML comments
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for cmt in comments: # Renamed c to cmt
        page_info["comments"].append(cmt.strip())

    # Detect technologies on this page
    page_info["technologies"] = _detect_technologies_on_page(response.headers, response.text)
    
    return page_info


def _is_social_media_link(url_str: str) -> bool: # Renamed url to url_str
    """Checks if a URL is a known social media link."""
    social_domains = [
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'youtube.com', 'pinterest.com', 'tiktok.com', 'snapchat.com',
        'reddit.com', 'tumblr.com', 'medium.com', 'github.com',
        'wa.me', 't.me', # WhatsApp, Telegram
    ]
    try:
        parsed = urlparse(url_str)
        domain = parsed.netloc.lower().replace('www.', '')
        return any(sd in domain for sd in social_domains)
    except:
        return False


def _detect_technologies_on_page(headers: requests.structures.CaseInsensitiveDict, html_content: str) -> Dict[str, List[str]]:
    """
    Detects technologies based on HTTP headers and HTML content of a single page.
    More specific than the initial detect_technologies.
    """
    detected_tech: Dict[str, List[str]] = {
        "server_software": [], "frameworks": [], "cms": [],
        "programming_languages": [], "javascript_libraries": [], "analytics_and_tracking": [],
        "cdn": [], "security_headers_found": []
    }

    # Analyze headers
    server_header = headers.get('Server')
    if server_header: detected_tech["server_software"].append(server_header)
    
    x_powered_by = headers.get('X-Powered-By')
    if x_powered_by: detected_tech["programming_languages"].append(x_powered_by)

    # Check for common CDN headers
    cdn_headers = {
        'CF-RAY': 'Cloudflare', 'X-CDN': 'Multiple Potential CDNs',
        'X-Cache': 'Varnish/Squid/Other Caches', 'Fastly-Debug-Digest': 'Fastly',
        'X-Akamai-Transformed': 'Akamai' 
    }
    for h_name, cdn_name in cdn_headers.items(): # Renamed h, cdn
        if headers.get(h_name):
            if cdn_name not in detected_tech["cdn"]:
                 detected_tech["cdn"].append(cdn_name)
    
    # List security headers actually present
    sec_headers_to_check = [
        "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
        "X-Frame-Options", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy"
    ]
    for sec_h in sec_headers_to_check: # Renamed sh
        if headers.get(sec_h):
            detected_tech["security_headers_found"].append(sec_h)


    # Analyze HTML content (case-insensitive checks)
    html_lower = html_content.lower()

    # CMS
    if 'wp-content' in html_lower or 'wp-includes' in html_lower or 'wordpress' in html_lower:
        if "WordPress" not in detected_tech["cms"]: detected_tech["cms"].append("WordPress")
    if 'sites/default/files' in html_lower or 'drupal.settings' in html_lower:
        if "Drupal" not in detected_tech["cms"]: detected_tech["cms"].append("Drupal")
    if 'joomla' in html_lower or '/media/com_' in html_lower:
        if "Joomla" not in detected_tech["cms"]: detected_tech["cms"].append("Joomla")
    if 'shopify' in html_lower or '.myshopify.com' in html_lower:
         if "Shopify" not in detected_tech["cms"]: detected_tech["cms"].append("Shopify")

    # JavaScript Libraries/Frameworks
    js_patterns = {
        "jQuery": r'jquery\.(min\.)?js|jquery\.js|jquery-[0-9\.]*\.js',
        "React": r'react(-dom)?\.(min\.)?js|react\.js|_react=',
        "AngularJS": r'angular\.(min\.)?js|angular\.js', # Older Angular
        "Angular": r' ng-version=', # Newer Angular
        "Vue.js": r'vue\.(min\.)?js|vue\.js|data-v-=',
        "Bootstrap": r'bootstrap\.(min\.)?js|bootstrap\.(min\.)?css',
        "Next.js": r'/_next/static/',
        "Nuxt.js": r'/_nuxt/'
    }
    for tech_name, pattern in js_patterns.items(): # Renamed name,p to tech_name, pattern
        if re.search(pattern, html_content, re.IGNORECASE): # Search in original case content for some patterns
            if tech_name not in detected_tech["javascript_libraries"]:
                 detected_tech["javascript_libraries"].append(tech_name)

    # Analytics and Tracking
    analytics_patterns = {
        "Google Analytics (UA)": r"ua-\d{4,10}-\d{1,4}",
        "Google Analytics (GA4)": r"gtag\(.*config.*g-\w+",
        "Google Tag Manager": r"googletagmanager\.com/gtm\.js",
        "Facebook Pixel": r"connect\.facebook\.net/signals/plugins/identity",
        "Hotjar": r"static\.hotjar\.com",
        "Matomo/Piwik": r"matomo\.js|piwik\.js"
    }
    for tool_name, pattern in analytics_patterns.items(): # Renamed name,p to tool_name, pattern
        if re.search(pattern, html_content, re.IGNORECASE):
             if tool_name not in detected_tech["analytics_and_tracking"]:
                  detected_tech["analytics_and_tracking"].append(tool_name)

    # Remove empty lists from detected_tech
    final_detected_tech = {k: v for k, v in detected_tech.items() if v}
    return final_detected_tech

# Example of how you might use BeautifulSoup's Comment type if needed elsewhere
from bs4 import Comment # type: ignore 
# This is just to show where Comment would be imported from if used directly.
# In this file, it's used via soup.find_all(string=lambda text: isinstance(text, Comment))
