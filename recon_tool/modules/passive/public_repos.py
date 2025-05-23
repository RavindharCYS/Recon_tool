"""
Public Repositories Module - Search for information in public code repositories, primarily GitHub.
"""
import requests
import logging
import json
import time
import re
import base64 # For decoding file content from GitHub API
from typing import Dict, List, Any, Optional, Union
from urllib.parse import quote_plus, urljoin, urlparse

from ...config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT, DEFAULT_DELAY, get_api_key # UPDATED
from ...utils.validators import is_valid_domain # UPDATED

logger = logging.getLogger(__name__)

GITHUB_API_BASE_URL = "https://api.github.com"

def _get_github_headers() -> Dict[str, str]:
    """Constructs standard headers for GitHub API requests, including Authorization if available."""
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "application/vnd.github.v3+json" # Specify API version
    }
    api_key = get_api_key("github", "api_token") # Get the 'api_token' for GitHub
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    else:
        logger.warning("GitHub API token not configured. Requests will be unauthenticated and heavily rate-limited.")
    return headers

def _handle_github_rate_limit(response: requests.Response) -> Optional[Dict[str, Any]]:
    """Checks for and handles GitHub rate limit errors."""
    if response.status_code == 403 and 'rate limit exceeded' in response.text.lower():
        ratelimit_reset = response.headers.get('X-RateLimit-Reset')
        if ratelimit_reset:
            reset_time = int(ratelimit_reset)
            wait_seconds = max(0, reset_time - int(time.time()))
            logger.warning(f"GitHub API rate limit exceeded. Wait {wait_seconds} seconds or add/check API token.")
            return {
                "error": "GitHub API rate limit exceeded",
                "reset_timestamp": reset_time,
                "wait_seconds": wait_seconds
            }
        else: # Should not happen if it's a rate limit error
            logger.warning("GitHub API rate limit exceeded, but no reset time found in headers.")
            return {"error": "GitHub API rate limit exceeded (no reset time)."}
    return None


def search_github_code(query: str, per_page: int = 30, page: int = 1) -> Dict[str, Any]:
    """
    Search GitHub for code snippets matching the query.
    
    Args:
        query: Search query (e.g., "example.com password", "org:myorg api_key").
        per_page: Number of results per page (max 100).
        page: Page number of results to fetch.
        
    Returns:
        Dictionary containing code search results or an error.
    """
    logger.info(f"Searching GitHub code for: '{query}' (page {page}, per_page {per_page})")
    
    api_url = f"{GITHUB_API_BASE_URL}/search/code"
    params = {"q": query, "per_page": min(per_page, 100), "page": page}
    headers = _get_github_headers()

    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
        
        rate_limit_error = _handle_github_rate_limit(response)
        if rate_limit_error:
            return rate_limit_error
            
        response.raise_for_status() # Raise HTTPError for bad responses (4XX, 5XX)
        data = response.json()
        
        processed_items: List[Dict[str, Any]] = [] # Renamed items to processed_items
        for item_data in data.get('items', []): # Renamed item to item_data
            repo_info = item_data.get('repository', {})
            processed_items.append({
                "file_name": item_data.get('name'),
                "path": item_data.get('path'),
                "sha": item_data.get('sha'),
                "html_url": item_data.get('html_url'),
                "api_url": item_data.get('url'), # URL to get file content
                "score": item_data.get('score'),
                "repository": {
                    "name": repo_info.get('name'),
                    "full_name": repo_info.get('full_name'),
                    "html_url": repo_info.get('html_url'),
                    "description": repo_info.get('description'),
                    "owner_login": repo_info.get('owner', {}).get('login')
                },
                # text_matches are only included if requested with specific media type,
                # or sometimes by default.
                "text_matches": item_data.get('text_matches', []) 
            })
        
        results = {
            "query": query,
            "total_count": data.get('total_count', 0),
            "incomplete_results": data.get('incomplete_results', False),
            "items_returned_this_page": len(processed_items),
            "page": page,
            "per_page": per_page,
            "items": processed_items
        }
        
        logger.info(f"GitHub code search for '{query}' found {data.get('total_count', 0)} total results. Returned {len(processed_items)} for page {page}.")
        return results
        
    except requests.exceptions.HTTPError as e:
        logger.error(f"GitHub API HTTP error for code search '{query}': {e.response.status_code} - {e.response.text[:200]}")
        return {"query": query, "error": f"GitHub API HTTP error: {e.response.status_code}", "details": e.response.text[:200]}
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during GitHub code search for '{query}': {str(e)}")
        return {"query": query, "error": f"Network error: {str(e)}"}
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON response from GitHub code search for '{query}'.")
        return {"query": query, "error": "Invalid JSON response from GitHub."}
    except Exception as e:
        logger.error(f"Unexpected error searching GitHub code for '{query}': {str(e)}")
        return {"query": query, "error": f"Unexpected error: {str(e)}"}


def search_github_repositories(query: str, per_page: int = 30, page: int = 1, sort: Optional[str] = None, order: Optional[str] = None) -> Dict[str, Any]:
    """
    Search GitHub for repositories matching the query.
    
    Args:
        query: Search query (e.g., "org:myorg language:python", "topic:security").
        per_page: Results per page.
        page: Page number.
        sort: Field to sort by (stars, forks, help-wanted-issues, updated). Default: best match.
        order: Sort order (asc, desc). Default: desc.
        
    Returns:
        Dictionary containing repository search results or an error.
    """
    logger.info(f"Searching GitHub repositories for: '{query}' (page {page}, per_page {per_page})")

    api_url = f"{GITHUB_API_BASE_URL}/search/repositories"
    params: Dict[str, Union[str, int]] = {"q": query, "per_page": min(per_page, 100), "page": page}
    if sort: params["sort"] = sort
    if order: params["order"] = order
    headers = _get_github_headers()

    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
        rate_limit_error = _handle_github_rate_limit(response)
        if rate_limit_error: return rate_limit_error
        response.raise_for_status()
        data = response.json()

        processed_repos: List[Dict[str, Any]] = [] # Renamed
        for repo_data in data.get('items', []): # Renamed repo to repo_data
            owner_info = repo_data.get('owner', {})
            license_info = repo_data.get('license', {}) # Can be None
            processed_repos.append({
                "name": repo_data.get('name'),
                "full_name": repo_data.get('full_name'),
                "html_url": repo_data.get('html_url'),
                "description": repo_data.get('description'),
                "is_fork": repo_data.get('fork'),
                "created_at": repo_data.get('created_at'),
                "updated_at": repo_data.get('updated_at'),
                "pushed_at": repo_data.get('pushed_at'),
                "stargazers_count": repo_data.get('stargazers_count'),
                "watchers_count": repo_data.get('watchers_count'),
                "forks_count": repo_data.get('forks_count'),
                "open_issues_count": repo_data.get('open_issues_count'),
                "language": repo_data.get('language'),
                "topics": repo_data.get('topics', []),
                "license_name": license_info.get('name') if license_info else None,
                "owner": {
                    "login": owner_info.get('login'),
                    "type": owner_info.get('type'),
                    "html_url": owner_info.get('html_url')
                }
            })
        
        results = {
            "query": query, "total_count": data.get('total_count', 0),
            "incomplete_results": data.get('incomplete_results', False),
            "items_returned_this_page": len(processed_repos), "page": page, "per_page": per_page,
            "repositories": processed_repos
        }
        logger.info(f"GitHub repository search for '{query}' found {data.get('total_count',0)} total. Returned {len(processed_repos)} for page {page}.")
        return results

    except requests.exceptions.HTTPError as e:
        logger.error(f"GitHub API HTTP error for repository search '{query}': {e.response.status_code} - {e.response.text[:200]}")
        return {"query": query, "error": f"GitHub API HTTP error: {e.response.status_code}", "details": e.response.text[:200]}
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during GitHub repository search for '{query}': {str(e)}")
        return {"query": query, "error": f"Network error: {str(e)}"}
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON response from GitHub repository search for '{query}'.")
        return {"query": query, "error": "Invalid JSON response from GitHub."}
    except Exception as e:
        logger.error(f"Unexpected error searching GitHub repositories for '{query}': {str(e)}")
        return {"query": query, "error": f"Unexpected error: {str(e)}"}


def search_repositories_for_domain(domain: str, max_code_results: int = 10, max_repo_results: int = 5) -> Dict[str, Any]:
    """
    Search public GitHub repositories for mentions of a domain, both in code and repo names/descriptions.
    
    Args:
        domain: Domain to search for.
        max_code_results: Max code results to fetch.
        max_repo_results: Max repository results to fetch.
        
    Returns:
        Dictionary containing aggregated search results.
    """
    logger.info(f"Searching GitHub for domain: {domain}")
    if not is_valid_domain(domain):
        logger.error(f"Invalid domain format for repository search: {domain}")
        return {"domain_searched": domain, "error": "Invalid domain format."}

    results: Dict[str, Any] = {"domain_searched": domain, "code_matches": {}, "repository_matches": {}}
    
    # Search in code
    # Using a more targeted query: domain + common config/sensitive file extensions
    # Or just the domain to find any mention.
    code_query = f'"{domain}"' # Exact match for the domain in code
    results["code_matches"] = search_github_code(code_query, per_page=max_code_results)
    
    time.sleep(DEFAULT_DELAY) # Be respectful

    # Search in repository names and descriptions
    repo_query = f'{domain} in:name,description,readme'
    results["repository_matches"] = search_github_repositories(repo_query, per_page=max_repo_results)
    
    return results


def search_for_leaked_credentials(target_keyword: str, max_results_per_pattern: int = 5) -> Dict[str, Any]:
    """
    Search GitHub code for potentially leaked API keys, passwords, or other credentials
    related to a target keyword (e.g., a domain or company name).
    
    Args:
        target_keyword: The keyword to associate with credential leaks (e.g., "example.com", "MyCompany").
        max_results_per_pattern: Max code results to fetch for each credential pattern.
        
    Returns:
        Dictionary containing potential credential leaks found.
    """
    logger.info(f"Searching GitHub for leaked credentials related to: {target_keyword}")

    # Common credential-related keywords and patterns. Be careful with overly broad terms.
    credential_patterns = [
        "api_key", "apikey", "api-key",
        "secret_key", "secretkey", "secret-key",
        "access_key", "accesskey", "access-key",
        "password", "passwd", "pwd",
        "token", "auth_token", "authorization_bearer",
        "credentials", "config", "connection_string",
        ".env", "id_rsa", "private_key" # File names
    ]
    
    # Filename specific searches
    filename_patterns = [
        "filename:.env", "filename:credentials", "filename:config.json", 
        "filename:settings.py", "filename:id_rsa"
    ]

    results: Dict[str, Any] = {"target_keyword": target_keyword, "potential_leaks": []}

    # Search combining target keyword with credential patterns
    for pattern in credential_patterns:
        query = f'"{target_keyword}" "{pattern}"' # Both must be present
        logger.debug(f"Searching GitHub code with query: {query}")
        time.sleep(DEFAULT_DELAY)
        search_result = search_github_code(query, per_page=max_results_per_pattern)
        
        if search_result.get("items"):
            results["potential_leaks"].append({
                "query_type": "keyword_and_pattern",
                "query": query,
                "matches_count": search_result.get("total_count"),
                "items": search_result.get("items")
            })

    # Search for specific filenames associated with the target keyword
    for fn_pattern in filename_patterns:
        query = f'"{target_keyword}" {fn_pattern}' # Target keyword in context of these files
        logger.debug(f"Searching GitHub code with query: {query}")
        time.sleep(DEFAULT_DELAY)
        search_result = search_github_code(query, per_page=max_results_per_pattern)

        if search_result.get("items"):
            results["potential_leaks"].append({
                "query_type": "keyword_and_filename",
                "query": query,
                "matches_count": search_result.get("total_count"),
                "items": search_result.get("items")
            })
            
    logger.info(f"Credential leak search for '{target_keyword}' complete. Found {len(results['potential_leaks'])} sets of potential leaks.")
    return results


def get_repo_file_content(owner: str, repo: str, file_path: str) -> Dict[str, Any]:
    """
    Retrieves the content of a specific file from a GitHub repository.
    
    Args:
        owner: Repository owner.
        repo: Repository name.
        file_path: Path to the file within the repository.
        
    Returns:
        Dictionary with file content or an error.
    """
    logger.info(f"Fetching content of {file_path} from {owner}/{repo}")
    api_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents/{file_path}"
    headers = _get_github_headers()
    # Add specific media type to get raw content if it's too large for JSON response
    # headers['Accept'] = 'application/vnd.github.raw' # For raw content
    # Or stick to JSON and decode base64

    try:
        response = requests.get(api_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        rate_limit_error = _handle_github_rate_limit(response)
        if rate_limit_error: return rate_limit_error
        
        if response.status_code == 404:
            logger.warning(f"File not found: {file_path} in {owner}/{repo}")
            return {"error": "File not found", "status_code": 404}
            
        response.raise_for_status()
        file_data = response.json()

        content = None
        encoding = file_data.get('encoding')
        if encoding == 'base64':
            try:
                content = base64.b64decode(file_data.get('content', '')).decode('utf-8', errors='replace')
            except Exception as e:
                logger.error(f"Error decoding base64 content for {file_path}: {e}")
                content = "[Error decoding content]"
        elif file_data.get('content'): # If not base64 but content exists (should not happen for files via this endpoint)
            content = file_data.get('content')
        elif file_data.get('download_url'): # For very large files, content might not be in JSON
            logger.info(f"File content not in JSON, attempting download from {file_data['download_url']}")
            time.sleep(DEFAULT_DELAY)
            raw_response = requests.get(file_data['download_url'], headers=_get_github_headers(), timeout=DEFAULT_TIMEOUT)
            if raw_response.ok:
                content = raw_response.text
            else:
                content = f"[Error downloading from raw URL: {raw_response.status_code}]"
        else:
             content = "[Content not available in API response]"


        return {
            "owner": owner, "repo": repo, "file_path": file_path,
            "sha": file_data.get('sha'), "size_bytes": file_data.get('size'),
            "html_url": file_data.get('html_url'), "download_url": file_data.get('download_url'),
            "type": file_data.get('type'), "encoding": encoding,
            "content": content
        }

    except requests.exceptions.HTTPError as e:
        logger.error(f"GitHub API HTTP error fetching file {file_path}: {e.response.status_code} - {e.response.text[:100]}")
        return {"error": f"GitHub API HTTP error: {e.response.status_code}", "details": e.response.text[:100]}
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error fetching file {file_path}: {str(e)}")
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error fetching file {file_path}: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}"}

# Add other GitHub related OSINT functions as needed, e.g.,
# - get_user_details(username)
# - get_organization_details(org_name)
# - get_repo_contributors(owner, repo)
# - get_repo_commits(owner, repo)
