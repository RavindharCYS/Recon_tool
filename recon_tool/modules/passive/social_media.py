"""
Social media OSINT module - gather publicly available information by searching for usernames and emails.
Note: This module relies on web scraping and public search engine results.
Effectiveness can vary based on platform changes and privacy settings.
"""
import requests
from bs4 import BeautifulSoup, Comment # type: ignore
import re
import time
from typing import Dict, List, Any, Optional, Set
from urllib.parse import quote_plus, urlparse, urljoin
import hashlib # For Gravatar

from ...config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT, DEFAULT_DELAY # UPDATED: Relative import
from ...utils.validators import is_valid_username, is_valid_email # UPDATED: Relative import
# No direct use of network_helpers, but good to be aware of.

import logging
logger = logging.getLogger(__name__)

# Common social media platforms and their URL patterns
# check_string can be a unique string or regex pattern expected on a valid profile page
# title_check can be a regex pattern to match in the <title> tag for confirmation
SOCIAL_PLATFORMS = [
    {"name": "Twitter", "url_template": "https://twitter.com/{}", "check_string": None, "title_check": r".*on Twitter$"},
    {"name": "Instagram", "url_template": "https://www.instagram.com/{}/", "check_string": "og:type\" content=\"profile\"", "title_check": r".*Instagram photos and videos$"},
    {"name": "Facebook", "url_template": "https://www.facebook.com/{}", "check_string": "profile.php?id=", "title_check": r".*Facebook$"}, # Hard to confirm existence without login
    {"name": "LinkedIn (Profile)", "url_template": "https://www.linkedin.com/in/{}", "check_string": "linkedin.com/in/", "title_check": r".*LinkedIn$"},
    {"name": "LinkedIn (Company)", "url_template": "https://www.linkedin.com/company/{}", "check_string": "linkedin.com/company/", "title_check": r".*LinkedIn$"},
    {"name": "GitHub", "url_template": "https://github.com/{}", "check_string": "contributions", "title_check": r"GitHub$"},
    {"name": "Reddit", "url_template": "https://www.reddit.com/user/{}", "check_string": "Karma", "title_check": r"u/.*Reddit"},
    {"name": "Pinterest", "url_template": "https://www.pinterest.com/{}/", "check_string": "og:type\" content=\"profile\"", "title_check": r"Pinterest$"},
    {"name": "TikTok", "url_template": "https://www.tiktok.com/@{}", "check_string": "uniqueId", "title_check": r".*TikTok$"}, # TikTok can be tricky
    {"name": "YouTube (User)", "url_template": "https://www.youtube.com/user/{}", "check_string": "subscriberCount", "title_check": r"YouTube$"},
    {"name": "YouTube (Channel)", "url_template": "https://www.youtube.com/c/{}", "check_string": "subscriberCount", "title_check": r"YouTube$"},
    {"name": "Medium", "url_template": "https://medium.com/@{}", "check_string": "og:type\" content=\"profile\"", "title_check": r"Medium$"},
    {"name": "Telegram (Channel/User)", "url_template": "https://t.me/{}", "check_string": "tgme_page_title", "title_check": r"Telegram$"} # Checks if page exists
]

def search_profiles(username: str) -> Dict[str, Any]:
    """
    Search for social media profiles by username across multiple platforms.
    
    Args:
        username: Username to search for.
        
    Returns:
        Dictionary containing potential profile matches and search engine results.
    """
    logger.info(f"Searching for social media profiles with username: {username}")
    
    if not is_valid_username(username): # Assumes is_valid_username from utils.validators
        logger.error(f"Invalid username format provided: {username}")
        return {"username": username, "error": "Invalid username format."}
    
    results: Dict[str, Any] = {
        "username_searched": username,
        "direct_platform_checks": [],
        "search_engine_mentions": [],
        "errors_encountered": 0
    }
    
    http_headers = { # Renamed headers to http_headers
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1", # Do Not Track
    }
    
    for platform_config in SOCIAL_PLATFORMS: # Renamed platform to platform_config
        # Skip company-specific LinkedIn URL for username search
        if platform_config["name"] == "LinkedIn (Company)": 
            continue
            
        profile_url = platform_config["url_template"].format(username)
        platform_name = platform_config["name"]
        logger.debug(f"Checking {platform_name} for user {username} at {profile_url}")
        
        platform_result = {"platform_name": platform_name, "url": profile_url, "status": "not_found"}
        
        try:
            time.sleep(DEFAULT_DELAY) # Be respectful to services
            response = requests.get(profile_url, headers=http_headers, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            
            # Update URL if redirected
            platform_result["final_url"] = response.url 
            
            # Check status and content
            # A 200 OK doesn't always mean a profile exists (e.g., generic search page).
            # We need more specific checks.
            profile_exists = False
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'lxml')
                title_tag = soup.find('title')
                page_title = title_tag.string.strip() if title_tag and title_tag.string else ""

                if platform_config.get("check_string") and re.search(platform_config["check_string"], response.text, re.IGNORECASE):
                    profile_exists = True
                elif platform_config.get("title_check") and re.search(platform_config["title_check"], page_title, re.IGNORECASE):
                    # Check if username is in title or URL to avoid false positives on generic pages
                    if username.lower() in page_title.lower() or username.lower() in response.url.lower():
                        profile_exists = True
                elif platform_name == "GitHub" and f"/{username}" in response.url and "Page not found" not in page_title: # GitHub specific
                     profile_exists = True


            if profile_exists:
                platform_result["status"] = "found"
                platform_result["profile_details"] = _extract_basic_profile_details(soup, platform_name, response.url)
                logger.info(f"Found {platform_name} profile for {username}.")
            else:
                logger.debug(f"{platform_name} profile not confirmed for {username} (status: {response.status_code}).")
                
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout checking {platform_name} for {username}.")
            platform_result["status"] = "error_timeout"
            results["errors_encountered"] += 1
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error checking {platform_name} for {username}: {str(e)}")
            # 404 often means not found, which is not an "error" in our context
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
                platform_result["status"] = "not_found_404"
            else:
                platform_result["status"] = "error_request"
                platform_result["error_message"] = str(e)
                results["errors_encountered"] += 1
        except Exception as e:
            logger.error(f"Unexpected error checking {platform_name} for {username}: {str(e)}")
            platform_result["status"] = "error_unexpected"
            platform_result["error_message"] = str(e)
            results["errors_encountered"] += 1
            
        results["direct_platform_checks"].append(platform_result)

    # Perform search engine lookup for the username
    logger.info(f"Performing search engine query for username: {username}")
    results["search_engine_mentions"] = _search_duckduckgo(f'"{username}" social media profile OR site:linkedin.com/in "{username}" OR site:github.com "{username}"')
    
    return results


def _extract_basic_profile_details(soup: BeautifulSoup, platform_name: str, profile_url: str) -> Dict[str, Any]:
    """Helper to extract some common details from a profile's BeautifulSoup object."""
    details: Dict[str, Any] = {}
    
    # Title
    title_tag = soup.find('title')
    if title_tag and title_tag.string:
        details["page_title"] = title_tag.string.strip()

    # Meta Description
    meta_desc = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
    if meta_desc and meta_desc.get('content'):
        details["meta_description"] = meta_desc['content'].strip()

    # OpenGraph (og:) tags often contain useful info
    og_title = soup.find('meta', property='og:title')
    if og_title and og_title.get('content'): details["og_title"] = og_title['content']
    
    og_description = soup.find('meta', property='og:description')
    if og_description and og_description.get('content'): details["og_description"] = og_description['content']

    og_site_name = soup.find('meta', property='og:site_name')
    if og_site_name and og_site_name.get('content'): details["og_site_name"] = og_site_name['content']

    # Platform-specific extraction hints (very basic)
    if platform_name == "GitHub":
        name_element = soup.find('span', class_='p-name')
        if name_element: details["display_name"] = name_element.text.strip()
        
        bio_element = soup.find('div', class_='p-note')
        if bio_element: details["bio"] = bio_element.text.strip()
    
    elif platform_name == "Twitter": # X
        # Twitter is heavily JS-driven, scraping is unreliable
        # Meta tags might offer some clues
        if "meta_description" in details and details["meta_description"]:
             # Example: "100 Followers, 50 Following, 10 Tweets"
            followers_match = re.search(r'([\d,KkMm]+)\s*Followers', details["meta_description"])
            if followers_match: details["followers_approx"] = followers_match.group(1)

    # Add more platform specific details here if reliable selectors are found.
    return details


def find_profiles_by_email(email: str) -> Dict[str, Any]:
    """
    Search for social media profiles potentially associated with an email address.
    This primarily leverages Gravatar and username-based search from the email's local part.
    
    Args:
        email: Email address to search for.
        
    Returns:
        Dictionary containing potential profile matches and Gravatar info.
    """
    logger.info(f"Searching for social media profiles associated with email: {email}")

    if not is_valid_email(email): # Assumes is_valid_email from utils.validators
        logger.error(f"Invalid email format provided: {email}")
        return {"email_searched": email, "error": "Invalid email format."}

    email_local_part = email.split('@')[0]
    email_domain_part = email.split('@')[1]

    results: Dict[str, Any] = {
        "email_searched": email,
        "email_local_part": email_local_part,
        "email_domain": email_domain_part,
        "gravatar_info": {},
        "username_based_profiles": {}, # Results from searching the local part as a username
        "email_search_engine_mentions": []
    }

    # Check Gravatar
    logger.debug(f"Checking Gravatar for {email}")
    results["gravatar_info"] = check_gravatar(email)

    # Search using the local part of the email as a username
    if is_valid_username(email_local_part):
        logger.info(f"Searching for username '{email_local_part}' (derived from email).")
        username_search_results = search_profiles(email_local_part)
        # We only want the direct platform checks from this username search
        results["username_based_profiles"] = {
            "username_searched": email_local_part,
            "direct_platform_checks": username_search_results.get("direct_platform_checks", [])
        }
    else:
        logger.info(f"Local part '{email_local_part}' is not a valid username format for platform search.")
        results["username_based_profiles"] = {
             "username_searched": email_local_part,
             "info": "Local part not searched as username due to invalid format."
        }


    # Perform search engine lookup for the full email address
    logger.info(f"Performing search engine query for email: {email}")
    results["email_search_engine_mentions"] = _search_duckduckgo(f'"{email}"') # Exact email search

    return results


def check_gravatar(email: str) -> Dict[str, Any]:
    """
    Checks Gravatar for a profile associated with the email.
    
    Args:
        email: The email address to check.
        
    Returns:
        A dictionary with Gravatar information or an error.
    """
    email_lower = email.strip().lower()
    email_hash = hashlib.md5(email_lower.encode('utf-8')).hexdigest()
    
    gravatar_base_url = "https://www.gravatar.com"
    avatar_check_url = f"{gravatar_base_url}/avatar/{email_hash}?d=404" # d=404 returns 404 if no avatar
    profile_json_url = f"{gravatar_base_url}/{email_hash}.json"

    gravatar_data: Dict[str, Any] = {
        "email_hashed": email_hash,
        "has_avatar": False,
        "avatar_url": f"{gravatar_base_url}/avatar/{email_hash}", # Generic URL, might not exist
        "has_profile_json": False,
        "profile_json_url": profile_json_url,
        "profile_data": None
    }
    
    http_headers = {"User-Agent": DEFAULT_USER_AGENT}

    try:
        # Check for avatar existence
        response_avatar = requests.head(avatar_check_url, headers=http_headers, timeout=DEFAULT_TIMEOUT/2)
        if response_avatar.status_code == 200:
            gravatar_data["has_avatar"] = True
        
        # Attempt to fetch JSON profile
        time.sleep(DEFAULT_DELAY / 2) # Small delay
        response_profile = requests.get(profile_json_url, headers=http_headers, timeout=DEFAULT_TIMEOUT)
        if response_profile.status_code == 200:
            try:
                profile_content = response_profile.json()
                gravatar_data["has_profile_json"] = True
                gravatar_data["profile_data"] = profile_content.get("entry", [{}])[0] # Take the first entry
            except ValueError: # JSONDecodeError
                logger.warning(f"Gravatar profile for {email} did not return valid JSON.")
                gravatar_data["profile_data"] = {"error": "Invalid JSON response from Gravatar profile."}
        elif response_profile.status_code == 404:
            logger.debug(f"No public Gravatar JSON profile found for {email}.")
        else:
            logger.warning(f"Gravatar profile check for {email} returned status {response_profile.status_code}.")

    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking Gravatar for {email}: {str(e)}")
        gravatar_data["error"] = str(e)
    
    return gravatar_data

def _search_duckduckgo(query: str, max_results: int = 5) -> List[Dict[str, str]]:
    """
    Helper function to perform a search on DuckDuckGo HTML version.
    
    Args:
        query: The search query string.
        max_results: Maximum number of results to return.
        
    Returns:
        A list of search result dictionaries (title, url, snippet).
    """
    encoded_query = quote_plus(query)
    search_url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
    http_headers = {"User-Agent": DEFAULT_USER_AGENT}
    
    found_results: List[Dict[str, str]] = []
    try:
        time.sleep(DEFAULT_DELAY) # Respectful delay
        response = requests.get(search_url, headers=http_headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'lxml')
        
        for result_item_ddg in soup.select('div.result, div.web-result'): # Renamed result_item to result_item_ddg
            title_tag_ddg = result_item_ddg.select_one('h2.result__title a, a.result__a') # Renamed
            url_tag_ddg = result_item_ddg.select_one('a.result__url') # Renamed
            snippet_tag_ddg = result_item_ddg.select_one('a.result__snippet, td.result__snippet') # Renamed
            
            if title_tag_ddg and url_tag_ddg:
                title = title_tag_ddg.text.strip()
                # DDG HTML urls are often relative or mangled, try to clean them
                raw_url = url_tag_ddg.get('href', url_tag_ddg.text.strip())
                
                # Attempt to clean DDG's rewritten URLs
                if raw_url.startswith("/l/"): # Redirect link
                    parsed_qs = urlparse(raw_url).query
                    uddg_param = re.search(r'uddg=([^&]+)', parsed_qs)
                    if uddg_param:
                        actual_url = unquote(uddg_param.group(1))
                    else:
                        actual_url = raw_url # Fallback
                elif raw_url.startswith("//"): # Protocol-relative, assume https
                    actual_url = "https:" + raw_url
                elif not raw_url.startswith("http"): # Possibly just domain or needs scheme
                    actual_url = "https://" + raw_url.strip() # Best guess
                else:
                    actual_url = raw_url.strip()

                snippet = snippet_tag_ddg.text.strip() if snippet_tag_ddg else ""
                
                found_results.append({"title": title, "url": actual_url, "snippet": snippet})
                if len(found_results) >= max_results:
                    break
        
    except requests.exceptions.RequestException as e:
        logger.error(f"DuckDuckGo search failed for query '{query}': {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during DuckDuckGo search for '{query}': {str(e)}")
        
    return found_results

# --- Functions below are examples and might require significant refinement or external libraries/APIs for reliability ---

def find_company_profiles(company_name: str) -> Dict[str, Any]:
    """
    Find social media profiles for a company. (Basic Implementation)
    """
    logger.info(f"Searching for social media profiles for company: {company_name}")
    
    company_name_clean = company_name.strip().lower().replace(' ', '') # Basic cleaning for URL generation
    if not company_name_clean:
        return {"company_name": company_name, "error": "Empty company name provided."}

    results: Dict[str, Any] = {
        "company_name_searched": company_name,
        "direct_platform_checks": [],
        "search_engine_mentions": []
    }
    http_headers = {"User-Agent": DEFAULT_USER_AGENT}

    for platform_config in SOCIAL_PLATFORMS:
        # Focus on platforms likely to have company pages
        if "LinkedIn" in platform_config["name"] or \
           "Facebook" in platform_config["name"] or \
           "Twitter" in platform_config["name"] or \
           "YouTube" in platform_config["name"] or \
           "Instagram" in platform_config["name"]:
            
            # Adjust username based on platform type (e.g. LinkedIn (Company))
            search_term = company_name_clean
            if platform_config["name"] == "LinkedIn (Company)":
                 # LinkedIn company URLs are often slugs, company_name_clean might work for some
                 pass # Use company_name_clean directly

            profile_url = platform_config["url_template"].format(search_term)
            platform_name = platform_config["name"]
            logger.debug(f"Checking {platform_name} for company {company_name} at {profile_url}")
            
            platform_result = {"platform_name": platform_name, "url": profile_url, "status": "not_found"}
            # ... (similar try-except block as in search_profiles) ...
            # This part needs the same request logic as search_profiles
            try:
                time.sleep(DEFAULT_DELAY)
                response = requests.get(profile_url, headers=http_headers, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                platform_result["final_url"] = response.url
                
                profile_exists = False
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'lxml')
                    title_tag = soup.find('title')
                    page_title = title_tag.string.strip() if title_tag and title_tag.string else ""

                    if platform_config.get("check_string") and re.search(platform_config["check_string"], response.text, re.IGNORECASE):
                        profile_exists = True
                    elif platform_config.get("title_check") and re.search(platform_config["title_check"], page_title, re.IGNORECASE):
                         if company_name.lower() in page_title.lower() or company_name_clean in response.url.lower():
                            profile_exists = True
                
                if profile_exists:
                    platform_result["status"] = "found"
                    platform_result["profile_details"] = _extract_basic_profile_details(soup, platform_name, response.url)
                    logger.info(f"Found {platform_name} company profile for {company_name}.")
                else:
                     logger.debug(f"{platform_name} company profile not confirmed for {company_name} (status: {response.status_code}).")

            except requests.exceptions.RequestException as e:
                 if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
                    platform_result["status"] = "not_found_404"
                 else:
                    platform_result["status"] = "error_request"
                    platform_result["error_message"] = str(e)
            except Exception as e:
                platform_result["status"] = "error_unexpected"
                platform_result["error_message"] = str(e)
            
            results["direct_platform_checks"].append(platform_result)

    results["search_engine_mentions"] = _search_duckduckgo(f'"{company_name}" official social media')
    return results


def extract_social_links_from_website(url: str) -> Dict[str, Any]:
    """
    Extract social media links from a given website URL.
    """
    logger.info(f"Extracting social media links from website: {url}")

    if not is_valid_url(url):
        parsed_check = urlparse(url)
        if not parsed_check.scheme and parsed_check.netloc: # Missing scheme, assume https
            url = "https://" + url
        elif not parsed_check.scheme and not parsed_check.netloc and is_valid_domain(url): # Is domain, assume https
            url = "https://" + url
        else:
            logger.error(f"Invalid URL format for social link extraction: {url}")
            return {"url_analyzed": url, "error": "Invalid URL format."}
            
    results: Dict[str, Any] = {
        "url_analyzed": url,
        "found_social_links": {} # platform_name: [urls]
    }
    http_headers = {"User-Agent": DEFAULT_USER_AGENT}

    try:
        response = requests.get(url, headers=http_headers, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml')

        found_links: Dict[str, Set[str]] = {}

        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            if not href: continue

            full_link = urljoin(response.url, href) # Use response.url as base in case of redirects
            parsed_link = urlparse(full_link)
            
            if parsed_link.scheme not in ['http', 'https']: continue

            link_domain = parsed_link.netloc.lower().replace('www.', '')

            for platform_config in SOCIAL_PLATFORMS:
                platform_domain_base = urlparse(platform_config["url_template"]).netloc.lower().replace('www.', '')
                if platform_domain_base in link_domain:
                    platform_name = platform_config["name"]
                    if platform_name not in found_links:
                        found_links[platform_name] = set()
                    found_links[platform_name].add(full_link)
                    break # Found a platform for this link

        results["found_social_links"] = {k: sorted(list(v)) for k, v in found_links.items()}

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch website {url} for social link extraction: {str(e)}")
        results["error"] = f"Failed to fetch website: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error extracting social links from {url}: {str(e)}")
        results["error"] = f"Unexpected error: {str(e)}"
        
    return results
