# ReconPy - Cross-Platform Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-cross--platform-lightgrey?style=flat-square)

```
 ____                     ____        
|  _ \ ___  ___ ___  _ __ |  _ \ _   _ 
| |_) / _ \/ __/ _ \| '_ \| |_) | | | |
|  _ <  __/ (_| (_) | | | |  __/| |_| |
|_| \_\___|\___\___/|_| |_|_|    \__, |
                                 |___/ 
```

**ReconPy** is a versatile, cross-platform command-line reconnaissance toolkit designed for security professionals, penetration testers, and bug bounty hunters. It automates various information-gathering tasks, covering both passive and active reconnaissance techniques.

## Table of Contents

1. [Purpose](#purpose)
2. [Features](#features)
3. [Disclaimer](#disclaimer)
4. [Setup and Installation](#setup-and-installation)
   - [Prerequisites](#prerequisites)
   - [Installation Steps](#installation-steps)
5. [API Key Configuration](#api-key-configuration)
6. [How to Use ReconPy Effectively](#how-to-use-reconpy-effectively)
   - [Global Options](#global-options)
   - [Main Commands](#main-commands)
   - [Usage Examples](#usage-examples)
7. [Modules Overview](#modules-overview)
   - [Passive Modules](#passive-modules)
   - [Active Modules](#active-modules)
8. [Output](#output)
9. [Project Structure](#project-structure)
10. [Extending ReconPy](#extending-reconpy)
11. [Contributing](#contributing)
12. [License](#license)

## Purpose

The primary goal of ReconPy is to streamline the initial phase of security assessments by:

- **Automating** common reconnaissance tasks
- **Aggregating** data from various sources and tools
- Providing **flexible output** formats for reporting and further analysis
- Offering a **modular structure** that can be extended
- Ensuring **cross-platform compatibility**

Whether you're investigating a domain, IP address, or URL, ReconPy aims to provide a comprehensive overview to kickstart your security analysis.

## Features

- **All-in-One Reconnaissance:** A single command (`recon`) to run a comprehensive set of passive and active modules
- **Modular Design:** Separate modules for different reconnaissance tasks
  - **Passive Recon:** WHOIS, DNS enumeration, Web Scraping, Shodan, Censys, Social Media Search, Wayback Machine, GitHub searches, EXIF Metadata Extraction
  - **Active Recon:** Port Scanning, Nmap Integration, Ping, Traceroute, Banner Grabbing, WAF Detection, Web Vulnerability Scanning
- **API Integration:** Leverages APIs from Shodan, Censys, GitHub, VirusTotal, and SecurityTrails
- **API Key Management:** Securely store and manage API keys with encryption
- **Flexible Output:** Supports text, JSON, and CSV output formats
- **Reporting:** Generate consolidated JSON reports for all-in-one scans
- **Workflow Engine:** Define and run custom sequences of reconnaissance modules
- **Cross-Platform:** Designed to work on Linux, macOS, and Windows
- **Utilities:** Includes tools for target validation and data format conversion
- **Customizable:** Options for verbosity, color output, and module-specific parameters

## Disclaimer

⚠️ **ReconPy is intended for educational purposes and ethical security assessments only.** Unauthorized scanning or testing of systems is illegal. The user is responsible for ensuring they have explicit permission from the target system's owner before performing any active reconnaissance or testing. The developers of ReconPy assume no liability and are not responsible for any misuse or damage caused by this tool.

### Always Remember To:
- Only scan systems you own or have explicit permission to test
- Follow responsible disclosure procedures for any vulnerabilities discovered
- Adhere to all applicable laws and regulations in your jurisdiction
- Be mindful of rate limiting and don't overwhelm target systems
- Respect robots.txt and website terms of service
- Use the tool responsibly and ethically

## Setup and Installation

### Prerequisites

1. **Python 3.8 or newer:** Download from [python.org](https://www.python.org/downloads/)
2. **Pip:** Python's package installer (usually comes with Python)
3. **Git (Optional):** If cloning from a repository
4. **Nmap (External Dependency):** For the Nmap scanning module
   - **Linux (Debian/Ubuntu):** `sudo apt update && sudo apt install nmap`
   - **Linux (Fedora/CentOS):** `sudo dnf install nmap` or `sudo yum install nmap`
   - **macOS (using Homebrew):** `brew install nmap`
   - **Windows:** Download from [nmap.org](https://nmap.org/download.html) and ensure it's in your PATH

### Installation Steps

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/RavindharCYS/Recon_tool.git
   cd Recon_tool
   ```

2. **Create and Activate a Virtual Environment (Recommended):**
   ```bash
   python3 -m venv venv
   ```
   - **Linux/macOS:** `source venv/bin/activate`
   - **Windows:** `.\venv\Scripts\activate`

3. **Install ReconPy and Dependencies:**
   ```bash
   pip install -e .
   # OR
   pip install -r requirements.txt
   ```

The `reconpy` command will then be available in your terminal.

## API Key Configuration

Several modules leverage external APIs for enhanced data gathering. Configure API keys for these services:

**Supported Services:** Shodan, Censys, GitHub, VirusTotal, SecurityTrails

### Basic API Management

```bash
# List available services and status
reconpy api list

# Show currently configured keys (masked)
reconpy api list --show-keys

# Configure API keys for a service
reconpy api configure shodan

# Check API requirements for modules
reconpy api check

# Clear API keys
reconpy api clear shodan --confirm
```

### Environment Variables (Alternative)

You can also set API keys as environment variables:

```bash
# For Shodan
export SHODAN_API_KEY="your_api_key"

# For Censys
export CENSYS_API_ID="your_api_id"
export CENSYS_API_SECRET="your_api_secret"

# For GitHub
export GITHUB_API_TOKEN="your_github_token"
```

API keys are stored encrypted in `~/.reconpy/api_keys.json`.

## How to Use ReconPy Effectively

The main command is `reconpy`. Get help for any command using `--help`:

```bash
reconpy --help
reconpy recon --help
reconpy passive dns --help
```

### Global Options

- `--verbose` or `-v`: Increase output verbosity (use `-vv` for debug)
- `--quiet` or `-q`: Suppress non-error output
- `--output {text|json|csv}` or `-o`: Output format (default: text)
- `--no-color`: Disable colored output

### Main Commands

#### All-in-One Recon (`recon`)

Run comprehensive passive and active reconnaissance:

```bash
reconpy recon <TARGET> [OPTIONS...]
```

**Key Options:**
- `--passive-only`: Only run passive modules
- `--active-only`: Only run active modules
- `--output-dir <DIR>` or `-d <DIR>`: Save results to directory
- `--report` or `-r`: Generate consolidated reports
- `--ports <RANGE>` or `-p <RANGE>`: Port range for scans (default: "1-1000")
- `--threads <NUM>` or `-t <NUM>`: Number of threads (default: 10)

#### API Key Management (`api`)

```bash
reconpy api list [--show-keys]
reconpy api configure [SERVICE_ID]
reconpy api check [MODULE_NAME]
reconpy api clear <SERVICE_ID> [--confirm]
```

#### Passive Reconnaissance (`passive`)

Gather information without direct target interaction:

- `whois <DOMAIN>`: WHOIS lookup
- `dns <DOMAIN> [--type <RECORD_TYPE>]...`: DNS enumeration
- `web <URL> [--depth <NUM>]`: Web scraping
- `shodan <TARGET> [--query]`: Shodan search
- `censys <TARGET> [--certificates]`: Censys search
- `social <USERNAME_OR_EMAIL> [--email]`: Social media search
- `wayback <DOMAIN>`: Wayback Machine snapshots
- `repos <DOMAIN_OR_KEYWORD> [--check-leaks]`: GitHub repository search
- `exif <IMAGE_URL_OR_FILE> [--analyze]`: EXIF metadata extraction

#### Active Reconnaissance (`active`)

Directly interact with target systems (use with permission only):

- `scan <TARGET>`: Port scanning
- `nmap <TARGET>`: Nmap integration
- `ping <TARGET> [--count <NUM>]`: ICMP ping
- `traceroute <TARGET> [--max-hops <NUM>]`: Network path tracing
- `banner <TARGET> --port <NUM>`: Service banner grabbing
- `waf <URL>`: WAF detection
- `webscan <URL> [--full]`: Basic web vulnerability scanning

#### Utilities (`util`)

- `validate <TARGET> [--type {ip|domain|url|email}]`: Validate target format
- `format <INPUT_FILE>`: Convert data file formats

#### Workflows (`workflow`)

Define custom sequences of reconnaissance modules:

```bash
# List available workflows
reconpy workflow list

# Run a workflow
reconpy workflow run <WORKFLOW_NAME> <TARGET> [--output-dir <DIR>]
```

### Usage Examples

**Comprehensive scan with reports:**
```bash
reconpy recon example.com --report -d ./results_example
```

**Passive reconnaissance only:**
```bash
reconpy recon 192.168.1.100 --passive-only
```

**DNS enumeration with specific record types:**
```bash
reconpy passive dns example.com --type MX --type NS --type TXT
```

**Advanced port scanning:**
```bash
reconpy active scan 192.168.1.1 --ports 1-1000 --method tcp
```

**Nmap scan with service detection:**
```bash
reconpy active nmap example.com --ports 1-100 --scan-type sV
```

**Shodan search with custom query:**
```bash
reconpy passive shodan "apache country:US" --query
```

**Social media search:**
```bash
reconpy passive social johndoe
reconpy passive social user@example.com --email
```

**EXIF analysis:**
```bash
reconpy passive exif https://example.com/image.jpg --analyze
```

**Web vulnerability scanning:**
```bash
reconpy active webscan https://example.com --full
```

## Modules Overview

### Passive Modules

- **WHOIS Lookup:** Domain registration information
- **DNS Enumeration:** Various DNS record types, zone transfer attempts
- **Web Scraper:** Extract links, emails, phone numbers, forms, and technologies
- **Shodan Search:** Query Shodan for IP information or custom searches
- **Censys Search:** Query Censys for host or certificate information
- **Social Media Search:** Find profiles across platforms using usernames/emails
- **Wayback Machine:** Retrieve historical website snapshots
- **Public Repositories:** Search GitHub for code and potential credential leaks
- **EXIF Metadata:** Extract metadata from images and analyze privacy risks

### Active Modules

- **Port Scanner:** Scan for open TCP/UDP ports using Python sockets
- **Nmap Scanner:** Advanced network scanning (requires Nmap installation)
- **Ping & Traceroute:** Check reachability and network paths
- **Banner Grabber:** Retrieve service banners from open ports
- **WAF Detector:** Identify Web Application Firewalls
- **Web Vulnerabilities:** Basic web application security checks

## Output

### Console Output
- **Text (default):** Human-readable, colorized output
- **JSON:** Raw JSON for tool integration
- **CSV:** Comma-separated values for spreadsheet import

### File Output
- Individual module results: `<target>_<module_name>_<timestamp>.json`
- Full reports: `_full_report_<timestamp>.json`
- Summary reports: `_summary_<timestamp>.json`

## Project Structure

```
project_root_directory/
├── recon_tool/                       # Main Python package directory
│   ├── __init__.py                   # Makes 'recon_tool' a package
│   ├── main.py                       # Main CLI logic (with 'main_entry' function)
│   ├── config.py                     # Configuration, API keys, settings
│   │
│   ├── modules/                      # Directory for reconnaissance modules
│   │   ├── __init__.py               # Makes 'modules' a sub-package
│   │   │
│   │   ├── active/                   # Active reconnaissance modules
│   │   │   ├── __init__.py
│   │   │   ├── banner_grabber.py
│   │   │   ├── nmap_scanner.py
│   │   │   ├── ping_traceroute.py
│   │   │   ├── port_scanner.py
│   │   │   ├── waf_detector.py
│   │   │   └── web_vulnerabilities.py
│   │   │
│   │   └── passive/                  # Passive reconnaissance modules
│   │       ├── __init__.py
│   │       ├── censys_search.py
│   │       ├── dns_enum.py
│   │       ├── exif_metadata.py
│   │       ├── public_repos.py
│   │       ├── shodan_search.py
│   │       ├── social_media.py
│   │       ├── wayback_machine.py
│   │       ├── web_scraper.py
│   │       └── whois_lookup.py
│   │
│   ├── utils/                        # Utility functions
│   │   ├── __init__.py               # Makes 'utils' a sub-package
│   │   ├── formatters.py
│   │   ├── logger.py
│   │   ├── network_helpers.py
│   │   └── validators.py
│   │
│   └── workflows/                    # Directory for predefined JSON workflows
│       └── (example_workflow.json)   # Example workflow file(s)
│
├── .git/                             # Git directory (if using version control)
├── .gitignore                        # Specifies intentionally untracked files for Git
├── venv/                             # Virtual environment directory (if created)
│
├── README.md                         # Project documentation
├── requirements.txt                  # Python package dependencies
├── setup.py                          # Script for packaging and distribution
├── run_recon.py                      # Development runner script
└── LICENSE                           # License file (e.g., MIT.txt)
```

## Extending ReconPy

ReconPy is designed to be modular and extensible. You can add new modules by:

1. Creating a new Python file in the appropriate directory (`modules/passive/` or `modules/active/`)
2. Implementing the required functions following the existing module patterns
3. Adding a new command in `main.py` that calls your module
4. Testing your module thoroughly

### Example Module Structure

```python
# modules/passive/example_module.py
import argparse
from typing import Dict, Any

def run(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Main function for the module
    Args:
        args: Parsed command line arguments
    Returns:
        Dict containing results
    """
    # Your implementation here
    pass

def add_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add module-specific arguments to the parser
    Args:
        parser: ArgumentParser instance
    """
    parser.add_argument('--example-arg', help='Example argument')
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Write tests for your changes if applicable
5. Ensure code lints and passes existing tests
6. Commit your changes (`git commit -am 'Add some feature'`)
7. Push to the branch (`git push origin feature/your-feature-name`)
8. Create a Pull Request

### Contribution Guidelines:
- Follow Python PEP 8 style guidelines
- Add appropriate documentation and comments
- Include tests for new functionality
- Update the README if necessary

Please adhere to the existing coding style and provide clear descriptions of your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Shodan](https://www.shodan.io/) - IoT search engine
- [Censys](https://censys.io/) - Internet-wide scanner
- [Wayback Machine](https://web.archive.org/) - Website history archive
- [Nmap](https://nmap.org/) - Network scanning tool
- All the open-source libraries that make this tool possible

## Contact

If you have questions, feedback, or need support:

- **Email**: ravindhar.upm@gmail.com
- **LinkedIn**: [LinkedIn](https://www.linkedin.com/in/ravindhar-cy/)
- **Portfolio**: https://ravindharcys.github.io/Portfolio/

---

**Star ⭐ this repository if you find it useful!**
