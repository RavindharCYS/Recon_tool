#!/usr/bin/env python3
"""
Configuration settings for the reconnaissance tool.
Contains API keys, default settings, and other configurable parameters.
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import getpass
from cryptography.fernet import Fernet
import base64

# Tool information
TOOL_NAME = "ReconPy"
VERSION = "0.1.0"
AUTHOR = "Your Name"
DESCRIPTION = "A cross-platform Python CLI reconnaissance tool for ethical hacking and security research"

# Default User-Agent string for web requests
DEFAULT_USER_AGENT = f"{TOOL_NAME}/{VERSION}"

# Timeout settings (in seconds)
DEFAULT_TIMEOUT = 30
QUICK_TIMEOUT = 5

# Rate limiting to be respectful
DEFAULT_DELAY = 1.0  # seconds between requests

# File paths
CONFIG_DIR = Path.home() / ".reconpy"
RESULTS_DIR = CONFIG_DIR / "results"
API_KEYS_FILE = CONFIG_DIR / "api_keys.json"
ENCRYPTION_KEY_FILE = CONFIG_DIR / ".key"

# Create directories if they don't exist
CONFIG_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# Verbosity levels
class VerbosityLevel:
    QUIET = 0
    NORMAL = 1
    VERBOSE = 2
    DEBUG = 3

# Default configuration
DEFAULT_CONFIG: Dict[str, Any] = {
    "verbosity": VerbosityLevel.NORMAL,
    "output_format": "text",  # Options: text, json, csv
    "max_threads": 10,
    "save_results": True,
    "verify_ssl": True,
    "use_color": True, # Added for color output control
}

# API Definitions - all supported APIs with their details
API_DEFINITIONS = {
    "shodan": {
        "name": "Shodan",
        "description": "Search engine for Internet-connected devices",
        "website": "https://shodan.io",
        "env_var": "SHODAN_API_KEY",
        "required_for": ["reconpy.modules.passive.shodan_search"], # Adjusted path
        "keys": ["api_key"],
        "key_descriptions": {
            "api_key": "API Key from your Shodan account"
        }
    },
    "censys": {
        "name": "Censys",
        "description": "Search engine for Internet-connected devices and certificates",
        "website": "https://censys.io",
        "env_var_prefix": "CENSYS_API_",
        "required_for": ["reconpy.modules.passive.censys_search"], # Adjusted path
        "keys": ["api_id", "api_secret"],
        "key_descriptions": {
            "api_id": "API ID from your Censys account",
            "api_secret": "API Secret from your Censys account"
        }
    },
    "github": {
        "name": "GitHub",
        "description": "Platform for code hosting and collaboration",
        "website": "https://github.com",
        "env_var": "GITHUB_API_TOKEN",
        "required_for": ["reconpy.modules.passive.public_repos"], # Adjusted path
        "keys": ["api_token"],
        "key_descriptions": {
            "api_token": "Personal Access Token with repo and user scope"
        }
    },
    "virustotal": {
        "name": "VirusTotal",
        "description": "Service for analyzing suspicious files and URLs",
        "website": "https://www.virustotal.com",
        "env_var": "VIRUSTOTAL_API_KEY",
        "required_for": ["reconpy.modules.active.web_vulnerabilities"], # Adjusted path
        "keys": ["api_key"],
        "key_descriptions": {
            "api_key": "API Key from your VirusTotal account"
        }
    },
    "securitytrails": {
        "name": "SecurityTrails",
        "description": "Historical DNS and domain data",
        "website": "https://securitytrails.com",
        "env_var": "SECURITYTRAILS_API_KEY",
        "required_for": ["reconpy.modules.passive.dns_enum"], # Adjusted path
        "keys": ["api_key"],
        "key_descriptions": {
            "api_key": "API Key from your SecurityTrails account"
        }
    }
    # Add more API definitions as needed
}

def _get_encryption_key() -> bytes:
    """
    Get or create an encryption key for securing API keys.
    
    Returns:
        Encryption key as bytes
    """
    try:
        if ENCRYPTION_KEY_FILE.exists():
            with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
                key = key_file.read()
        else:
            # Generate a new key
            key = Fernet.generate_key()
            # Save the key to a file with restricted permissions
            with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
                key_file.write(key)
            # Set file permissions to be readable only by the owner
            ENCRYPTION_KEY_FILE.chmod(0o600)
        return key
    except Exception as e:
        logging.error(f"Error with encryption key: {str(e)}")
        # Return a fallback key derived from the machine name
        # This is less secure but allows the program to continue functioning
        import socket
        hostname = socket.gethostname().encode()
        # Ensure the key is 32 bytes long for Fernet by padding and truncating
        return base64.urlsafe_b64encode(hostname.ljust(32, b'\0')[:32])


def _encrypt_value(value: str) -> str:
    """
    Encrypt a value using Fernet symmetric encryption.
    
    Args:
        value: String to encrypt
        
    Returns:
        Encrypted string in base64 format
    """
    try:
        key = _get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(value.encode())
        return encrypted.decode()
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        # Return a simple obfuscation as fallback
        return base64.b64encode(value.encode()).decode()

def _decrypt_value(value: str) -> str:
    """
    Decrypt a value using Fernet symmetric encryption.
    
    Args:
        value: Encrypted string in base64 format
        
    Returns:
        Decrypted string
    """
    try:
        key = _get_encryption_key()
        f = Fernet(key)
        decrypted = f.decrypt(value.encode())
        return decrypted.decode()
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        try:
            # Try to handle the case where simple obfuscation was used
            return base64.b64decode(value.encode()).decode()
        except:
            logging.error(f"Completely failed to decrypt value for key related to error: {e}")
            return ""

def load_api_keys() -> Dict[str, Dict[str, str]]:
    """
    Load API keys from the stored configuration file or environment variables.
    
    Returns:
        Dictionary containing API keys by service
    """
    api_keys = {}
    
    # Try to load from file first
    if API_KEYS_FILE.exists():
        try:
            with open(API_KEYS_FILE, 'r') as f:
                encrypted_keys = json.load(f)
                
                # Decrypt each key
                for service, keys in encrypted_keys.items():
                    api_keys[service] = {}
                    for key_name, encrypted_value in keys.items():
                        api_keys[service][key_name] = _decrypt_value(encrypted_value)
        except Exception as e:
            logging.error(f"Error loading API keys from file: {str(e)}")
    
    # Check environment variables for any missing keys
    for service, info in API_DEFINITIONS.items():
        if service not in api_keys:
            api_keys[service] = {}
            
        # Handle single environment variable
        if "env_var" in info:
            env_key = os.environ.get(info["env_var"], "")
            # Only set from env if not already loaded from file or if file value is empty
            if env_key and not api_keys[service].get(info["keys"][0]):
                api_keys[service][info["keys"][0]] = env_key
        
        # Handle multiple environment variables with prefix
        elif "env_var_prefix" in info:
            for key_name in info["keys"]:
                env_var = f"{info['env_var_prefix']}{key_name.upper()}"
                env_key = os.environ.get(env_var, "")
                 # Only set from env if not already loaded from file or if file value is empty
                if env_key and not api_keys[service].get(key_name):
                    api_keys[service][key_name] = env_key
    
    return api_keys

def save_api_keys(api_keys: Dict[str, Dict[str, str]]) -> bool:
    """
    Save API keys to a local configuration file.
    
    Args:
        api_keys: Dictionary containing API keys by service
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Encrypt keys for storage
        encrypted_keys = {}
        for service, keys in api_keys.items():
            encrypted_keys[service] = {}
            for key_name, value in keys.items():
                if value:  # Only encrypt non-empty values
                    encrypted_keys[service][key_name] = _encrypt_value(value)
        
        # Save to file
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(encrypted_keys, f, indent=2)
        
        # Set file permissions to be readable only by the owner
        API_KEYS_FILE.chmod(0o600)
        return True
    except Exception as e:
        logging.error(f"Error saving API keys: {str(e)}")
        return False

def get_api_key(service: str, key_name: Optional[str] = None) -> str:
    """
    Get an API key for a specific service.
    
    Args:
        service: Service name (e.g., 'shodan', 'censys')
        key_name: Name of the specific key if the service has multiple keys
        
    Returns:
        API key as string, or empty string if not found
    """
    api_keys_loaded = load_api_keys() # Renamed to avoid conflict with outer scope var
    
    if service not in api_keys_loaded:
        return ""
    
    if not key_name:
        if service in API_DEFINITIONS and API_DEFINITIONS[service].get("keys"): # Check if "keys" exists and is not empty
            key_name = API_DEFINITIONS[service]["keys"][0]
        elif service in api_keys_loaded and api_keys_loaded[service]: # Check if api_keys_loaded[service] is not empty
             key_name = next(iter(api_keys_loaded[service]), "")
        else:
            return "" # No keys defined or found
            
    return api_keys_loaded[service].get(key_name, "")


def set_api_key(service: str, key_name: str, value: str) -> bool:
    """
    Set an API key for a specific service.
    
    Args:
        service: Service name (e.g., 'shodan', 'censys')
        key_name: Name of the specific key
        value: API key value
        
    Returns:
        True if successful, False otherwise
    """
    # Validate service
    if service not in API_DEFINITIONS:
        logging.error(f"Unknown service: {service}")
        return False
    
    # Validate key name
    if key_name not in API_DEFINITIONS[service]["keys"]:
        logging.error(f"Unknown key name '{key_name}' for service {service}")
        return False
    
    # Load existing keys
    api_keys_loaded = load_api_keys() # Renamed
    
    # Ensure service entry exists
    if service not in api_keys_loaded:
        api_keys_loaded[service] = {}
    
    # Set the new key value
    api_keys_loaded[service][key_name] = value
    
    # Save keys
    return save_api_keys(api_keys_loaded)

def list_api_services() -> List[Dict[str, Any]]:
    """
    List all supported API services and their configuration status.
    
    Returns:
        List of dictionaries with service information
    """
    # Load current API keys
    api_keys_loaded = load_api_keys() # Renamed
    
    services = []
    for service_id, info in API_DEFINITIONS.items():
        # Check if keys are configured
        configured_keys = api_keys_loaded.get(service_id, {})
        keys_status = []
        
        for key_name in info["keys"]:
            status = {
                "name": key_name,
                "description": info["key_descriptions"].get(key_name, ""),
                "configured": bool(configured_keys.get(key_name)),
                "value_preview": mask_api_key(configured_keys.get(key_name, ""))
            }
            keys_status.append(status)
        
        service_info = {
            "id": service_id,
            "name": info["name"],
            "description": info["description"],
            "website": info["website"],
            "keys": keys_status,
            "fully_configured": all(key.get("configured") for key in keys_status),
            "required_for": info["required_for"]
        }
        
        services.append(service_info)
    
    return services

def mask_api_key(key: str) -> str:
    """
    Mask an API key for display purposes.
    
    Args:
        key: API key to mask
        
    Returns:
        Masked API key (e.g., "abc123def" -> "abc***def")
    """
    if not key:
        return ""
    
    if len(key) <= 8:
        return "****"
    else:
        # Ensure visible_chars is at least 1 if key is long enough, but not too large
        visible_chars = max(1, min(4, len(key) // 3))
        # Ensure we don't show more than half the key if it's short
        if len(key) - visible_chars * 2 < 1 and len(key) > 1: # if no asterisks would be shown for a short key
            if len(key) <= 3: return "*" * len(key)
            visible_chars = 1


        return f"{key[:visible_chars]}{'*' * (len(key) - visible_chars * 2)}{key[-visible_chars:]}"


def check_api_requirements(module_name: str) -> Dict[str, Any]:
    """
    Check if all required API keys are configured for a specific module.
    
    Args:
        module_name: Full module name (e.g., 'reconpy.modules.passive.shodan_search')
        
    Returns:
        Dictionary with status information
    """
    # Find all services required for this module
    required_services = []
    for service_id, info in API_DEFINITIONS.items():
        if module_name in info["required_for"]:
            required_services.append(service_id)
    
    if not required_services:
        return {
            "module": module_name,
            "required_services": [],
            "all_configured": True,
            "missing_services": []
        }
    
    # Check configuration status
    api_keys_loaded = load_api_keys() # Renamed
    missing_services = []
    
    for service_id in required_services:
        info = API_DEFINITIONS[service_id]
        required_keys = info["keys"]
        
        # Check if all required keys are configured
        service_keys = api_keys_loaded.get(service_id, {})
        if not all(key in service_keys and service_keys[key] for key in required_keys):
            missing_services.append(service_id)
    
    return {
        "module": module_name,
        "required_services": required_services,
        "all_configured": len(missing_services) == 0,
        "missing_services": missing_services
    }

def validate_api_keys() -> Dict[str, bool]:
    """
    Check which API services are fully configured.
    
    Returns:
        Dictionary mapping service IDs to boolean configured status
    """
    api_keys_loaded = load_api_keys() # Renamed
    services_status = {}
    
    for service_id, info in API_DEFINITIONS.items():
        required_keys = info["keys"]
        service_keys = api_keys_loaded.get(service_id, {})
        
        # Service is configured if all required keys are present
        services_status[service_id] = all(
            key in service_keys and service_keys[key] for key in required_keys
        )
    
    return services_status

def prompt_for_api_key(service_id: str) -> bool:
    """
    Prompt the user to enter API keys for a service.
    
    Args:
        service_id: Service identifier (e.g., 'shodan', 'censys')
        
    Returns:
        True if keys were successfully configured, False otherwise
    """
    if service_id not in API_DEFINITIONS:
        print(f"Unknown service: {service_id}")
        return False
    
    service_info = API_DEFINITIONS[service_id]
    print(f"\n--- {service_info['name']} API Configuration ---")
    print(f"Description: {service_info['description']}")
    print(f"Website: {service_info['website']}")
    print("\nRequired API keys:")
    
    # Load existing keys
    api_keys_loaded = load_api_keys() # Renamed
    if service_id not in api_keys_loaded:
        api_keys_loaded[service_id] = {}
    
    # Prompt for each key
    keys_changed = False
    for key_name in service_info["keys"]:
        description = service_info["key_descriptions"].get(key_name, "")
        current_value = api_keys_loaded[service_id].get(key_name, "")
        
        print(f"\n{key_name}: {description}")
        if current_value:
            print(f"Current value: {mask_api_key(current_value)}")
            change = input("Change this key? (y/N): ").strip().lower()
            
            if change == 'y':
                new_value = getpass.getpass(f"Enter new value for {key_name} (leave blank to keep current): ")
                if new_value: # Only update if new value is provided
                    api_keys_loaded[service_id][key_name] = new_value
                    keys_changed = True
            # If not 'y', current value is kept
        else:
            new_value = getpass.getpass(f"Enter value for {key_name}: ")
            if new_value:
                api_keys_loaded[service_id][key_name] = new_value
                keys_changed = True
    
    # Save the updated keys only if something changed
    if keys_changed:
        if save_api_keys(api_keys_loaded):
            print(f"\n{service_info['name']} API keys saved successfully.")
            return True
        else:
            print(f"\nError saving {service_info['name']} API keys.")
            return False
    else:
        print(f"\nNo changes made to {service_info['name']} API keys.")
        return True # No changes, but operation is "successful" in not failing