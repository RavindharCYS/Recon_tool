#!/usr/bin/env python3
"""
ReconPy: A cross-platform Python CLI reconnaissance tool
Main entry point for the application
"""
import sys
import click
from typing import Optional
import importlib
import os
import json
import datetime # Changed from datetime.datetime to just datetime
from tabulate import tabulate
from urllib.parse import urlparse # Added for robust domain extraction
import re # Already imported, just confirming

# Import configuration
from . import config # Adjusted for package structure

# Import utilities
from .utils.logger import setup_logger, get_logger
from .utils.validators import is_valid_ip, is_valid_domain, is_valid_url, is_valid_email # Added email validator

# Initialize logger
# Moved setup_logger call into cli() to ensure it's called after verbosity options are processed
logger = get_logger(__name__) # Using __name__ for better log organization

# Banner for the CLI
BANNER = r"""
 _____                      _____
|  __ \                    |  __ \
| |__) |___  ___ ___  _ __ | |__) |   _
|  _  // _ \/ __/ _ \| '_ \|  ___/ | | |
| | \ \  __/ (_| (_) | | | | |   | |_| |
|_|  \_\___|\___\___/|_| |_|_|    \__, |
                                   __/ |
                                  |___/
"""

@click.group()
@click.version_option(version=config.VERSION)
@click.option('--verbose', '-v', count=True, help='Increase verbosity')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-error output')
@click.option('--output', '-o', type=click.Choice(['text', 'json', 'csv']),
              default=config.DEFAULT_CONFIG["output_format"], help='Output format')
@click.option('--no-color', is_flag=True, help='Disable colored output')
def cli(verbose: int, quiet: bool, output: str, no_color: bool):
    """
    ReconPy: A cross-platform reconnaissance toolkit for security professionals

    Use this tool responsibly and only on systems you have permission to test.
    """
    # Set verbosity level
    if quiet:
        verbosity = config.VerbosityLevel.QUIET
    elif verbose == 1:
        verbosity = config.VerbosityLevel.VERBOSE
    elif verbose >= 2: # -vv or more
        verbosity = config.VerbosityLevel.DEBUG
    else:
        verbosity = config.VerbosityLevel.NORMAL

    config.DEFAULT_CONFIG["verbosity"] = verbosity
    config.DEFAULT_CONFIG["output_format"] = output
    config.DEFAULT_CONFIG["use_color"] = not no_color

    # Initialize logger after verbosity is set
    setup_logger(verbosity)

    if not quiet:
        if config.DEFAULT_CONFIG["use_color"]:
            click.echo(click.style(BANNER, fg='blue', bold=True))
        else:
            click.echo(BANNER)
        click.echo(f"Version: {config.VERSION}\n")

# All-in-one reconnaissance command
@cli.command('recon')
@click.argument('target')
@click.option('--passive-only', is_flag=True, help='Only perform passive reconnaissance')
@click.option('--active-only', is_flag=True, help='Only perform active reconnaissance')
@click.option('--output-dir', '-d', type=click.Path(file_okay=False, dir_okay=True, writable=True, resolve_path=True), help='Directory to save results')
@click.option('--report', '-r', is_flag=True, help='Generate a consolidated report')
@click.option('--ports', '-p', default='1-1000', help='Port range for scanning')
@click.option('--threads', '-t', type=int, default=config.DEFAULT_CONFIG["max_threads"], help='Number of threads for scanning')
def all_in_one_recon(target, passive_only, active_only, output_dir, report, ports, threads):
    """
    Perform comprehensive reconnaissance on a target

    This command executes multiple reconnaissance modules in sequence to gather
    extensive information about the target. It automatically determines the target
    type (domain, IP, URL) and runs appropriate modules.

    Example: reconpy recon example.com --report
    """

    # Create timestamp for report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Determine target type and extract domain if URL
    target_type = None
    domain = None # Initialize domain

    if is_valid_ip(target):
        target_type = "ip"
        click.echo(f"[+] Target {target} identified as an IP address")
        # For IP targets, domain might be resolved via reverse DNS if needed by modules
    elif is_valid_url(target):
        target_type = "url"
        click.echo(f"[+] Target {target} identified as a URL")
        try:
            parsed_url = urlparse(target)
            domain = parsed_url.netloc
            if ':' in domain: # Remove port if present in netloc
                domain = domain.split(':')[0]
        except Exception as e:
            logger.error(f"Could not parse domain from URL {target}: {e}")
            click.echo(f"[!] Error parsing domain from URL {target}. Some domain-specific modules might fail.")
            domain = target # Fallback, might not be a valid domain
    elif is_valid_domain(target):
        target_type = "domain"
        domain = target
        click.echo(f"[+] Target {target} identified as a domain name")
    else:
        click.echo(f"[!] Unable to determine target type for {target}")
        if not click.confirm("Continue anyway?"):
            sys.exit(1)

    # Set up output directory
    effective_output_dir = output_dir
    if not effective_output_dir and config.DEFAULT_CONFIG.get("save_results", False):
        effective_output_dir = os.path.join(config.RESULTS_DIR, f"{target.replace('/', '_')}_{timestamp}")
        click.echo(f"[+] Defaulting output to: {effective_output_dir}")

    if effective_output_dir:
        try:
            os.makedirs(effective_output_dir, exist_ok=True)
        except OSError as e:
            click.echo(f"[!] Error creating output directory {effective_output_dir}: {e}. Results will not be saved to files.")
            effective_output_dir = None # Disable file saving

    # Initialize report data
    report_data = {
        "target": target,
        "target_type": target_type,
        "timestamp": timestamp,
        "modules_run": [],
        "results": {}
    }

    def save_module_result(module_name, result_data): # Renamed 'result' to 'result_data'
        """Helper function to save module results to report and file"""
        report_data["results"][module_name] = result_data
        report_data["modules_run"].append(module_name)

        if effective_output_dir and config.DEFAULT_CONFIG.get("save_results", True):
            # Sanitize target name for filename
            safe_target_name = re.sub(r'[^\w\-_\.]', '_', target)
            result_file = os.path.join(effective_output_dir, f"{safe_target_name}_{module_name}_{timestamp}.json")
            try:
                with open(result_file, 'w') as f:
                    json.dump(result_data, f, indent=2, default=str) # Added default=str for non-serializable types
                click.echo(f"[+] {module_name.capitalize()} results saved to: {result_file}")
            except IOError as e:
                 click.echo(f"[!] Error saving {module_name} results to {result_file}: {e}")

    # Perform passive reconnaissance
    if not active_only:
        click.echo("\n" + click.style("=== PASSIVE RECONNAISSANCE ===", fg="green" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))

        # WHOIS lookup (for domains/URLs with extracted domain)
        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running WHOIS lookup...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.whois_lookup import lookup
                whois_result = lookup(domain)
                _display_result(whois_result)
                save_module_result("whois", whois_result)
            except Exception as e:
                click.echo(f"[!] WHOIS lookup failed: {str(e)}")

        # DNS lookup (for domains/URLs with extracted domain)
        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running DNS enumeration...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.dns_enum import lookup
                dns_result = lookup(domain, record_types=['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA'])
                _display_result(dns_result)
                save_module_result("dns", dns_result)

                # Extract IP addresses for further scanning if available
                # Ensure dns_result and 'records' key exist before accessing
                if dns_result and 'records' in dns_result and 'A' in dns_result['records']:
                    # dns_result['records']['A'] is a list of dicts
                    a_records_list = dns_result['records']['A']
                    if isinstance(a_records_list, list) and a_records_list:
                        ip_address = a_records_list[0].get('value') # Use specific var name
                        if ip_address:
                             click.echo(f"[+] Primary IP address from DNS: {ip_address}")
            except Exception as e:
                click.echo(f"[!] DNS enumeration failed: {str(e)}")

        # Web scraping (for URLs)
        if target_type == "url":
            click.echo("\n" + click.style("Running web scraping...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.web_scraper import scrape
                web_result = scrape(target, depth=1)
                _display_result(web_result)
                save_module_result("web_scrape", web_result)
            except Exception as e:
                click.echo(f"[!] Web scraping failed: {str(e)}")

        # Shodan search
        click.echo("\n" + click.style("Running Shodan search...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        api_check = config.check_api_requirements("reconpy.modules.passive.shodan_search")
        if api_check["all_configured"]:
            try:
                from .modules.passive.shodan_search import search_ip, search_query

                if target_type == "ip":
                    shodan_result = search_ip(target)
                elif domain: # Only search if domain is available
                    shodan_result = search_query(f"hostname:{domain}")
                else:
                    shodan_result = {"info": "Domain not available for Shodan query."}

                _display_result(shodan_result)
                save_module_result("shodan", shodan_result)
            except Exception as e:
                click.echo(f"[!] Shodan search failed: {str(e)}")
        else:
            click.echo("[!] Shodan search skipped (API key not configured). Use 'recon-tool api configure shodan' to set it up.")

        # Censys search
        click.echo("\n" + click.style("Running Censys search...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        api_check = config.check_api_requirements("reconpy.modules.passive.censys_search")
        if api_check["all_configured"]:
            try:
                from .modules.passive.censys_search import search_ip, search_certificates

                if target_type == "ip":
                    censys_result = search_ip(target)
                elif domain: # Only search if domain is available
                    censys_result = search_certificates(domain)
                else:
                    censys_result = {"info": "Domain not available for Censys certificate search."}

                _display_result(censys_result)
                save_module_result("censys", censys_result)
            except Exception as e:
                click.echo(f"[!] Censys search failed: {str(e)}")
        else:
            click.echo("[!] Censys search skipped (API keys not configured). Use 'recon-tool api configure censys' to set it up.")

        # Wayback Machine search (for domains/URLs with extracted domain)
        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running Wayback Machine search...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.wayback_machine import get_snapshots
                wayback_result = get_snapshots(domain, limit=20)
                _display_result(wayback_result)
                save_module_result("wayback", wayback_result)
            except Exception as e:
                click.echo(f"[!] Wayback Machine search failed: {str(e)}")

        # Repository search (for domains/URLs with extracted domain)
        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running repository search...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            api_check = config.check_api_requirements("reconpy.modules.passive.public_repos")
            if api_check["all_configured"]:
                try:
                    from .modules.passive.public_repos import search_repositories_for_domain
                    repo_result = search_repositories_for_domain(domain)
                    _display_result(repo_result)
                    save_module_result("repos", repo_result)
                except Exception as e:
                    click.echo(f"[!] Repository search failed: {str(e)}")
            else:
                click.echo("[!] Repository search may be limited or fail (GitHub API key not configured). Use 'recon-tool api configure github' to set it up.")


    # Perform active reconnaissance
    if not passive_only:
        click.echo("\n" + click.style("=== ACTIVE RECONNAISSANCE ===", fg="yellow" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))

        target_for_active_scan = target
        if target_type == "url" and domain:
            target_for_active_scan = domain # Use domain for ping, traceroute, port scan if original target was URL
        elif target_type == "domain":
            target_for_active_scan = target # Already a domain or IP

        # Ping test
        click.echo("\n" + click.style("Running ping test...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        try:
            from .modules.active.ping_traceroute import ping
            ping_result = ping(target_for_active_scan, count=4)
            _display_result(ping_result)
            save_module_result("ping", ping_result)
        except Exception as e:
            click.echo(f"[!] Ping test failed: {str(e)}")

        # Traceroute
        click.echo("\n" + click.style("Running traceroute...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        try:
            from .modules.active.ping_traceroute import traceroute
            traceroute_result = traceroute(target_for_active_scan, max_hops=20)
            _display_result(traceroute_result)
            save_module_result("traceroute", traceroute_result)
        except Exception as e:
            click.echo(f"[!] Traceroute failed: {str(e)}")

        # Port scanning
        click.echo("\n" + click.style("Running port scan...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        try:
            from .modules.active.port_scanner import scan as port_scan_func # Renamed to avoid conflict
            port_scan_result = port_scan_func(target_for_active_scan, ports=ports, method='tcp', threads=threads)
            _display_result(port_scan_result)
            save_module_result("port_scan", port_scan_result)

            # Banner grabbing for open ports
            # Ensure port_scan_result and relevant keys exist
            if port_scan_result and "open_ports" in port_scan_result and "tcp" in port_scan_result["open_ports"] and port_scan_result["open_ports"]["tcp"]:
                open_tcp_ports_info = port_scan_result["open_ports"]["tcp"]
                open_tcp_ports = [p_info["port"] for p_info in open_tcp_ports_info if "port" in p_info]

                if open_tcp_ports:
                    click.echo("\n" + click.style("Running banner grabbing on open TCP ports...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
                    banner_results = {"target": target_for_active_scan, "banners": {}}

                    from .modules.active.banner_grabber import grab_banner
                    for port_num in open_tcp_ports[:5]:  # Limit to first 5 ports to avoid too much time
                        click.echo(f"  Grabbing banner from port {port_num}...")
                        try:
                            port_result = grab_banner(target_for_active_scan, port=port_num, protocol='tcp')
                            banner_results["banners"][str(port_num)] = port_result.get("banner_text", port_result.get("error", "No banner/Error")) # Changed from banner to banner_text
                        except Exception as e:
                            banner_results["banners"][str(port_num)] = f"Error: {str(e)}"

                    _display_result(banner_results)
                    save_module_result("banners", banner_results)
        except Exception as e:
            click.echo(f"[!] Port scanning or banner grabbing failed: {str(e)}")

        # Nmap scanning if available
        click.echo("\n" + click.style("Running Nmap scan...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        try:
            from .modules.active.nmap_scanner import scan as nmap_scan_func # Renamed
            nmap_result = nmap_scan_func(target_for_active_scan, ports=ports, scan_type='sT')
            _display_result(nmap_result)
            save_module_result("nmap", nmap_result)
        except ImportError: # This will catch if python-nmap is not installed or Nmap binary is missing
            click.echo("[!] Nmap scanning skipped (Nmap library or Nmap itself not available/installed).")
        except Exception as e: # Catch other errors during Nmap scan execution
            click.echo(f"[!] Nmap scanning failed: {str(e)}")

        # Web-specific tests for URLs
        if target_type == "url":
            # WAF detection
            click.echo("\n" + click.style("Detecting Web Application Firewall...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.active.waf_detector import detect
                waf_result = detect(target) # Use original URL target for WAF
                _display_result(waf_result)
                save_module_result("waf", waf_result)
            except Exception as e:
                click.echo(f"[!] WAF detection failed: {str(e)}")

            # Web vulnerability scan
            click.echo("\n" + click.style("Running web vulnerability scan...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            api_check_vt = config.check_api_requirements("reconpy.modules.active.web_vulnerabilities") # VirusTotal for some checks
            if not api_check_vt["all_configured"]:
                 click.echo("[!] Some web vulnerability checks might be limited (VirusTotal API key not configured).")
            try:
                from .modules.active.web_vulnerabilities import scan as web_vuln_scan_func # Renamed
                web_vuln_result = web_vuln_scan_func(target, full_scan=False) # Changed full to full_scan
                _display_result(web_vuln_result)
                save_module_result("web_vulns", web_vuln_result)
            except Exception as e:
                click.echo(f"[!] Web vulnerability scan failed: {str(e)}")

    # Generate consolidated report if requested
    if report and effective_output_dir:
        click.echo("\n" + click.style("=== GENERATING RECONNAISSANCE REPORT ===", fg="blue" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))

        # Sanitize target name for filename
        safe_target_name = re.sub(r'[^\w\-_\.]', '_', target)
        report_file_path = os.path.join(effective_output_dir, f"{safe_target_name}_full_report_{timestamp}.json")

        try:
            with open(report_file_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            click.echo(f"[+] Full report saved to: {report_file_path}")
        except IOError as e:
            click.echo(f"[!] Error saving full report to {report_file_path}: {e}")

        # Generate summary report with key findings
        summary = {
            "target": target,
            "target_type": target_type,
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modules_run": report_data["modules_run"],
            "key_findings": {}
        }

        # Extract key information from module results
        if "whois" in report_data["results"] and report_data["results"]["whois"] and "error" not in report_data["results"]["whois"]:
            whois_data = report_data["results"]["whois"]
            summary["key_findings"]["whois"] = {
                "registrar": whois_data.get("registrar", "Unknown"),
                "creation_date": whois_data.get("creation_date", "Unknown"),
                "expiration_date": whois_data.get("expiration_date", "Unknown")
            }

        if "dns" in report_data["results"] and report_data["results"]["dns"] and "error" not in report_data["results"]["dns"]:
            dns_data = report_data["results"]["dns"].get("records", {})
            summary["key_findings"]["dns"] = {
                "a_records": [r.get('value') for r in dns_data.get("A", []) if r.get('value')],
                "mx_records": [f"{r.get('preference')} {r.get('value')}" for r in dns_data.get("MX", []) if r.get('value')],
                "ns_records": [r.get('value') for r in dns_data.get("NS", []) if r.get('value')]
            }

        if "port_scan" in report_data["results"] and report_data["results"]["port_scan"] and "error" not in report_data["results"]["port_scan"]:
            scan_data = report_data["results"]["port_scan"]
            open_tcp = [p["port"] for p in scan_data.get("open_ports", {}).get("tcp", []) if "port" in p]
            summary["key_findings"]["open_ports_tcp"] = open_tcp

        if "waf" in report_data["results"] and report_data["results"]["waf"] and "error" not in report_data["results"]["waf"]:
            waf_data = report_data["results"]["waf"]
            summary["key_findings"]["waf_detected"] = waf_data.get("waf_detected", False)
            if waf_data.get("waf_detected", False):
                summary["key_findings"]["waf_name"] = waf_data.get("identified_waf_name", "Unknown") # Changed from waf_name

        if "web_vulns" in report_data["results"] and report_data["results"]["web_vulns"] and "error" not in report_data["results"]["web_vulns"]:
            vuln_data = report_data["results"]["web_vulns"]
            if "findings" in vuln_data: # Changed from vulnerabilities to findings to match web_vulnerabilities.py
                summary["key_findings"]["vulnerabilities"] = vuln_data["findings"]

        summary_file_path = os.path.join(effective_output_dir, f"{safe_target_name}_summary_{timestamp}.json")
        try:
            with open(summary_file_path, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            click.echo(f"[+] Summary report saved to: {summary_file_path}")
        except IOError as e:
            click.echo(f"[!] Error saving summary report to {summary_file_path}: {e}")

        # Display key findings
        click.echo("\n" + click.style("=== RECONNAISSANCE SUMMARY ===", fg="green" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))
        click.echo(f"Target: {target} ({target_type or 'Unknown'})") # Added 'Unknown' fallback
        click.echo(f"Modules run: {len(report_data['modules_run'])}")

        if "dns" in summary["key_findings"] and summary["key_findings"]["dns"].get("a_records"):
            ip_list = ", ".join(summary["key_findings"]["dns"]["a_records"])
            click.echo(f"IP Addresses: {ip_list}")

        if "open_ports_tcp" in summary["key_findings"] and summary["key_findings"]["open_ports_tcp"]:
            ports_list_str = ", ".join(map(str, summary["key_findings"]["open_ports_tcp"])) # Renamed
            click.echo(f"Open TCP ports: {ports_list_str}")

        if "waf_detected" in summary.get("key_findings", {}):
            waf_status_val = summary["key_findings"]["waf_detected"]
            waf_status_text = "Detected" if waf_status_val else "Not detected"
            waf_name_val = summary["key_findings"].get("waf_name", "Unknown WAF") if waf_status_val else "N/A"
            click.echo(f"Web Application Firewall: {waf_status_text} ({waf_name_val})")

        if "vulnerabilities" in summary.get("key_findings", {}):
            vulns = summary["key_findings"]["vulnerabilities"]
            vuln_count = len(vulns)
            click.echo(f"Web Vulnerabilities found: {vuln_count}")
            if vuln_count > 0:
                for i, vuln in enumerate(vulns[:3], 1):  # Show top 3
                    severity = vuln.get("risk", "Unknown").upper() # Changed from severity to risk
                    name = vuln.get("name", "Unknown vulnerability")
                    if config.DEFAULT_CONFIG["use_color"]:
                        if severity in ["HIGH", "CRITICAL"]:
                            severity = click.style(severity, fg="red", bold=True)
                        elif severity == "MEDIUM":
                            severity = click.style(severity, fg="yellow")
                    click.echo(f"  {i}. [{severity}] {name}")

                if vuln_count > 3:
                    click.echo(f"  ... and {vuln_count - 3} more (see full report for details)")
    elif report and not effective_output_dir:
        click.echo("[!] Reporting skipped as output directory could not be created or was not specified.")

    click.echo("\n" + click.style("=== RECONNAISSANCE COMPLETE ===", fg="green" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))

# API Key Management Commands
@cli.group('api')
def api_group():
    """Manage API keys for various services"""
    pass

@api_group.command('list')
@click.option('--show-keys', is_flag=True, help='Show masked API key values')
def list_apis(show_keys: bool):
    """List all supported API services and their configuration status"""
    services = config.list_api_services()

    if not services:
        click.echo("No API services defined.")
        return

    if config.DEFAULT_CONFIG["output_format"] == "json":
        click.echo(json.dumps(services, indent=2))
    else:
        table_data = []
        headers = ["Service", "Description", "Status"]

        if show_keys:
            headers.append("Keys")

        for service in services:
            status_text = "✓ Configured" if service["fully_configured"] else "✗ Not Configured"

            if config.DEFAULT_CONFIG["use_color"]:
                status_style = click.style(status_text, fg='green' if service["fully_configured"] else 'red')
            else:
                status_style = status_text

            row = [
                f"{service['name']} ({service['id']})",
                service['description'],
                status_style
            ]

            if show_keys:
                keys_info_parts = []
                for key_status_item in service["keys"]: # Renamed 'key' to avoid conflict
                    if key_status_item["configured"]:
                        key_value = key_status_item["value_preview"] # Already masked
                        if config.DEFAULT_CONFIG["use_color"]:
                            key_display_status = click.style(f"{key_status_item['name']}: {key_value}", fg='green')
                        else:
                            key_display_status = f"{key_status_item['name']}: {key_value}"
                    else:
                        key_display_status = f"{key_status_item['name']}: ✗"
                        if config.DEFAULT_CONFIG["use_color"]:
                            key_display_status = click.style(key_display_status, fg='red')

                    keys_info_parts.append(key_display_status)

                row.append('\n'.join(keys_info_parts))

            table_data.append(row)

        click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))

@api_group.command('configure')
@click.argument('service_id_arg', metavar='SERVICE_ID', required=False) # Renamed to avoid conflict
def configure_api(service_id_arg: Optional[str]):
    """Configure API keys for a service (e.g., shodan, censys)"""
    if service_id_arg:
        if service_id_arg not in config.API_DEFINITIONS:
            available_services = ', '.join(config.API_DEFINITIONS.keys())
            click.echo(f"Unknown service: {service_id_arg}")
            click.echo(f"Available services: {available_services}")
            return

        if config.prompt_for_api_key(service_id_arg):
            pass # Message is printed by prompt_for_api_key
        else:
            click.echo("API key configuration was cancelled or failed.")
    else:
        services = config.list_api_services()
        if not services:
            click.echo("No API services available for configuration.")
            return

        click.echo("Available API services:")
        for i, service_item in enumerate(services, 1): # Renamed
            status_text = "Configured" if service_item["fully_configured"] else "Not Configured"
            if config.DEFAULT_CONFIG["use_color"]:
                status_style = click.style(status_text, fg='green' if service_item["fully_configured"] else 'red')
            else:
                status_style = status_text
            click.echo(f"{i}. {service_item['name']} ({service_item['id']}) - {status_style}")

        try:
            choice = click.prompt("Select a service to configure (or 0 to cancel)", type=int, default=0)
            if 0 < choice <= len(services):
                selected_service_id = services[choice-1]["id"]
                if config.prompt_for_api_key(selected_service_id):
                    pass # Message is printed by prompt_for_api_key
                else:
                    click.echo("API key configuration was cancelled or failed.")
            elif choice == 0:
                click.echo("Configuration cancelled.")
            else:
                click.echo("Invalid selection.")
        except click.exceptions.Abort:
            click.echo("\nConfiguration aborted.")
        except Exception as e:
            click.echo(f"Error during selection: {str(e)}")

@api_group.command('check')
@click.argument('module_name_arg', metavar='MODULE_NAME', required=False) # Renamed
def check_api_requirements_cmd(module_name_arg: Optional[str]): # Renamed command function
    """Check API requirements for a module or all modules.
    MODULE_NAME should be the full Python path, e.g., reconpy.modules.passive.shodan_search
    """
    if module_name_arg:
        result_check = config.check_api_requirements(module_name_arg) # Renamed

        if not result_check["required_services"]:
            click.echo(f"Module '{module_name_arg}' does not require any API keys.")
            return

        click.echo(f"API requirements for module '{module_name_arg}':")

        for service_id_item in result_check["required_services"]: # Renamed
            service_info = config.API_DEFINITIONS.get(service_id_item, {})
            service_name = service_info.get("name", service_id_item)

            status_text = "Configured" if service_id_item not in result_check["missing_services"] else "Not Configured"
            if config.DEFAULT_CONFIG["use_color"]:
                status_style = click.style(status_text, fg='green' if service_id_item not in result_check["missing_services"] else 'red')
            else:
                status_style = status_text
            click.echo(f"- {service_name} ({service_id_item}): {status_style}")

        if result_check["all_configured"]:
            click.echo(click.style("\nAll required API keys are configured.", fg="green" if config.DEFAULT_CONFIG["use_color"] else None))
        else:
            missing = [config.API_DEFINITIONS.get(s, {}).get("name", s) for s in result_check["missing_services"]]
            missing_str = ", ".join(missing)
            click.echo(click.style(f"\nMissing API keys for: {missing_str}", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
            click.echo("Configure them with: recon-tool api configure <service_id>")
    else:
        # List all modules and their API requirements
        modules_with_api = []

        for service_id_item, info in config.API_DEFINITIONS.items(): # Renamed
            for mn in info.get("required_for", []): # Renamed module_name
                # Check if module already added to prevent duplicates if multiple APIs used by one module
                if not any(m["module"] == mn for m in modules_with_api):
                    check_result = config.check_api_requirements(mn)
                    if check_result["required_services"]: # Only add if it actually requires services
                         modules_with_api.append(check_result)

        if not modules_with_api:
            click.echo("No modules found with API requirements.")
            return

        if config.DEFAULT_CONFIG["output_format"] == "json":
            click.echo(json.dumps(modules_with_api, indent=2))
        else:
            table_data = []
            headers = ["Module", "Required APIs", "Status"]

            for module_info_item in modules_with_api: # Renamed
                # Extract simple module name, e.g., "shodan_search" from "reconpy.modules.passive.shodan_search"
                simple_module_name = module_info_item["module"].split(".")[-1]

                api_services_display = []
                for service_id_disp in module_info_item["required_services"]: # Renamed
                    service_name_disp = config.API_DEFINITIONS.get(service_id_disp, {}).get("name", service_id_disp)

                    if service_id_disp in module_info_item["missing_services"]:
                        if config.DEFAULT_CONFIG["use_color"]:
                            api_services_display.append(click.style(service_name_disp, fg='red'))
                        else:
                            api_services_display.append(f"{service_name_disp} (missing)")
                    else:
                        if config.DEFAULT_CONFIG["use_color"]:
                            api_services_display.append(click.style(service_name_disp, fg='green'))
                        else:
                            api_services_display.append(service_name_disp)

                status_text_disp = "Ready" if module_info_item["all_configured"] else "Missing Keys"
                if config.DEFAULT_CONFIG["use_color"]:
                    status_style_disp = click.style(status_text_disp, fg='green' if module_info_item["all_configured"] else 'red')
                else:
                    status_style_disp = status_text_disp

                table_data.append([
                    simple_module_name,
                    ", ".join(api_services_display),
                    status_style_disp
                ])

            if table_data:
                click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))
            else:
                click.echo("No modules with API requirements found.")

@api_group.command('clear')
@click.argument('service_id_arg', metavar='SERVICE_ID') # Renamed
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def clear_api_keys(service_id_arg: str, confirm: bool):
    """Clear API keys for a specific service"""
    if service_id_arg not in config.API_DEFINITIONS:
        available_services = ', '.join(config.API_DEFINITIONS.keys())
        click.echo(f"Unknown service: {service_id_arg}")
        click.echo(f"Available services: {available_services}")
        return

    service_name = config.API_DEFINITIONS[service_id_arg]["name"]

    if not confirm:
        if not click.confirm(f"Are you sure you want to clear all API keys for {service_name}? This cannot be undone."):
            click.echo("Operation cancelled.")
            return

    api_keys_loaded = config.load_api_keys()

    if service_id_arg in api_keys_loaded:
        # Clear keys for the service by setting them to empty strings
        for key_name in config.API_DEFINITIONS[service_id_arg]["keys"]:
            if key_name in api_keys_loaded[service_id_arg]:
                api_keys_loaded[service_id_arg][key_name] = "" # Set to empty to clear

        if config.save_api_keys(api_keys_loaded): # This will save empty strings, effectively clearing them from encrypted file
            click.echo(f"API keys for {service_name} have been cleared.")
        else:
            click.echo(f"Error clearing API keys for {service_name}.")
    else:
        click.echo(f"No API keys found configured for {service_name}.")

# --- Passive reconnaissance commands ---
@cli.group('passive')
def passive_group():
    """Passive reconnaissance commands that don't interact with the target"""
    pass

@passive_group.command('whois')
@click.argument('domain_arg', metavar='DOMAIN') # Renamed
def whois_lookup(domain_arg: str):
    """Perform WHOIS lookup on a domain"""
    from .modules.passive.whois_lookup import lookup
    result_data = lookup(domain_arg) # Renamed
    _display_result(result_data)

@passive_group.command('dns')
@click.argument('domain_arg', metavar='DOMAIN') # Renamed
@click.option('--type', '-t', 'record_types_arg', multiple=True,  # Renamed
              type=click.Choice(['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'ALL'], case_sensitive=False), # Added CNAME
              default=['A'], help='DNS record type to query')
def dns_lookup(domain_arg: str, record_types_arg: tuple):
    """Perform DNS lookups on a domain"""
    from .modules.passive.dns_enum import lookup

    final_record_types = list(record_types_arg)
    if 'ALL' in final_record_types:
        final_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

    result_data = lookup(domain_arg, record_types=final_record_types) # Renamed
    _display_result(result_data)

@passive_group.command('web')
@click.argument('url_arg', metavar='URL') # Renamed
@click.option('--depth', '-d', type=int, default=1, help='Crawling depth')
def web_scrape(url_arg: str, depth: int):
    """Extract information from a website"""
    from .modules.passive.web_scraper import scrape
    result_data = scrape(url_arg, depth=depth) # Renamed
    _display_result(result_data)

@passive_group.command('shodan')
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--query', '-q', 'is_query_mode', is_flag=True, help='Perform a custom Shodan query instead of IP lookup') # Renamed
def shodan_search_cmd(target_arg: str, is_query_mode: bool): # Renamed
    """Search Shodan for information about a target"""
    api_check = config.check_api_requirements("reconpy.modules.passive.shodan_search")
    if not api_check["all_configured"]:
        click.echo(click.style("Shodan API key is not configured.", fg="yellow" if config.DEFAULT_CONFIG["use_color"] else None))
        if click.confirm("Would you like to configure it now?"):
            if not config.prompt_for_api_key("shodan"):
                 click.echo(click.style("Shodan API key configuration failed or was cancelled. Cannot proceed.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
                 return
            # Re-check after attempting configuration
            api_check = config.check_api_requirements("reconpy.modules.passive.shodan_search")
            if not api_check["all_configured"]:
                click.echo(click.style("Shodan API key still not configured. Cannot proceed.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
                return
        else:
            click.echo(click.style("Shodan search cannot proceed without an API key.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
            return

    from .modules.passive.shodan_search import search_ip, search_query

    if is_query_mode:
        result_data = search_query(target_arg) # Renamed
    else:
        result_data = search_ip(target_arg) # Renamed

    _display_result(result_data)

@passive_group.command('censys')
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--certificates', '-c', 'search_certs_mode', is_flag=True, help='Search for certificates instead of host information') # Renamed
def censys_search_cmd(target_arg: str, search_certs_mode: bool): # Renamed
    """Search Censys for information about a target"""
    api_check = config.check_api_requirements("reconpy.modules.passive.censys_search")
    if not api_check["all_configured"]:
        click.echo(click.style("Censys API keys are not configured.", fg="yellow" if config.DEFAULT_CONFIG["use_color"] else None))
        if click.confirm("Would you like to configure them now?"):
            if not config.prompt_for_api_key("censys"):
                click.echo(click.style("Censys API key configuration failed or was cancelled. Cannot proceed.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
                return
            api_check = config.check_api_requirements("reconpy.modules.passive.censys_search")
            if not api_check["all_configured"]:
                click.echo(click.style("Censys API keys still not configured. Cannot proceed.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
                return
        else:
            click.echo(click.style("Censys search cannot proceed without API keys.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
            return

    from .modules.passive.censys_search import search_ip, search_certificates

    if search_certs_mode:
        result_data = search_certificates(target_arg) # Renamed
    else:
        result_data = search_ip(target_arg) # Renamed

    _display_result(result_data)

@passive_group.command('social')
@click.argument('query_arg', metavar='USERNAME_OR_EMAIL') # Renamed
@click.option('--email', '-e', 'is_email_search', is_flag=True, help='Search for profiles associated with an email') # Renamed
def social_media_search(query_arg: str, is_email_search: bool):
    """Search for social media profiles by username or email"""
    from .modules.passive.social_media import search_profiles, find_profiles_by_email

    if is_email_search:
        if not is_valid_email(query_arg):
            click.echo(click.style(f"Invalid email format: {query_arg}", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
            return
        result_data = find_profiles_by_email(query_arg) # Renamed
    else:
        if not query_arg.strip(): # Basic check for empty username
            click.echo(click.style("Username cannot be empty.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
            return
        result_data = search_profiles(query_arg) # Renamed

    _display_result(result_data)

@passive_group.command('wayback')
@click.argument('domain_arg', metavar='DOMAIN') # Renamed
@click.option('--from-date', '-f', help='Start date (YYYYMMDD)')
@click.option('--to-date', '-t', help='End date (YYYYMMDD)')
@click.option('--limit', '-l', type=int, default=10, help='Maximum number of snapshots')
def wayback_search(domain_arg: str, from_date: Optional[str], to_date: Optional[str], limit: int):
    """Retrieve historical versions of a website from Wayback Machine"""
    from .modules.passive.wayback_machine import get_snapshots
    result_data = get_snapshots(domain_arg, from_date=from_date, to_date=to_date, limit=limit) # Renamed
    _display_result(result_data)

@passive_group.command('repos')
@click.argument('target_arg', metavar='DOMAIN_OR_KEYWORD') # Renamed
@click.option('--check-leaks', '-c', 'check_leaks_mode', is_flag=True, help='Check for potential credential leaks related to the target') # Renamed
def repo_search(target_arg: str, check_leaks_mode: bool):
    """Search public code repositories for a domain or check for leaks"""
    api_check = config.check_api_requirements("reconpy.modules.passive.public_repos")
    if not api_check["all_configured"]:
        click.echo(click.style("GitHub API key is not configured. Some functionality may be limited or fail.", fg="yellow" if config.DEFAULT_CONFIG["use_color"] else None))
        if click.confirm("Would you like to configure it now?"):
            if not config.prompt_for_api_key("github"):
                click.echo(click.style("GitHub API key configuration failed or was cancelled.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))

    from .modules.passive.public_repos import search_repositories_for_domain, search_for_leaked_credentials

    if check_leaks_mode:
        result_data = search_for_leaked_credentials(target_arg) # Renamed
    else:
        if not is_valid_domain(target_arg):
            click.echo(click.style(f"Invalid domain for repository search: {target_arg}. If checking leaks, use --check-leaks.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
            return
        result_data = search_repositories_for_domain(target_arg) # Renamed

    _display_result(result_data)

@passive_group.command('exif')
@click.argument('target_arg', metavar='IMAGE_URL_OR_FILE') # Renamed
@click.option('--analyze', '-a', 'analyze_mode', is_flag=True, help='Perform security analysis on metadata') # Renamed
def exif_extraction(target_arg: str, analyze_mode: bool):
    """Extract EXIF metadata from images (URL or local file)"""
    from .modules.passive.exif_metadata import extract_from_url, extract_from_file, analyze_image_security

    result_data = None # Renamed

    if os.path.isfile(target_arg):
        if analyze_mode:
            result_data = analyze_image_security(target_arg)
        else:
            result_data = extract_from_file(target_arg)
    elif is_valid_url(target_arg): # Check if it's a URL
        if analyze_mode:
            result_data = analyze_image_security(target_arg)
        else:
            result_data = extract_from_url(target_arg)
    else:
        click.echo(click.style(f"Invalid target: '{target_arg}'. Must be a valid file path or URL.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
        return

    _display_result(result_data)

# --- Active reconnaissance commands ---
@cli.group('active')
def active_group():
    """Active reconnaissance commands that interact with the target"""
    pass

@active_group.command('scan')
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--ports', '-p', default='1-1000', help='Port range to scan (e.g., 1-1000, 22,80,443)')
@click.option('--method', type=click.Choice(['tcp', 'udp', 'both'], case_sensitive=False), default='tcp', help='Scan method')
@click.option('--threads', '-t', type=int, default=config.DEFAULT_CONFIG["max_threads"], help='Number of threads')
def port_scan_cmd(target_arg: str, ports: str, method: str, threads: int): # Renamed
    """Scan for open ports on a target"""
    try:
        from .modules.active.port_scanner import scan as port_scan_func # Renamed
        result_data = port_scan_func(target_arg, ports=ports, method=method, threads=threads) # Renamed
        _display_result(result_data)
    except ImportError:
        logger.error("Port scanner module not available (check dependencies).")
        click.echo(click.style("Port scanner module not available.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
    except Exception as e:
        logger.error(f"Port scan command failed: {e}")
        click.echo(click.style(f"Port scan failed: {e}", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))


@active_group.command('nmap')
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--ports', '-p', default='1-1000', help='Port range to scan')
@click.option('--scan-type', '-s', type=click.Choice(['sT', 'sS', 'sU', 'sV'], case_sensitive=False), default='sT',
              help='Nmap scan type')
@click.option('--args', 'nmap_args', help='Additional Nmap arguments (e.g., "-O -A")') # Added option for more args
def nmap_scan_cmd(target_arg: str, ports: str, scan_type: str, nmap_args: Optional[str]): # Renamed
    """Run Nmap scan (requires Nmap to be installed)"""
    try:
        from .modules.active.nmap_scanner import scan as nmap_scan_func # Renamed
        result_data = nmap_scan_func(target_arg, ports=ports, scan_type=scan_type, arguments=nmap_args) # Renamed
        _display_result(result_data)
    except ImportError:
        logger.error("Nmap scanner module not available or Nmap not installed.")
        click.echo(click.style("Nmap scanner module not available or Nmap not installed.", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
    except Exception as e:
        logger.error(f"Nmap scan command failed: {e}")
        click.echo(click.style(f"Nmap scan failed: {e}", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))


@active_group.command('ping')
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--count', '-c', type=int, default=4, help='Number of packets to send')
def ping_cmd(target_arg: str, count: int): # Renamed
    """Check if a host is reachable using ICMP Echo"""
    from .modules.active.ping_traceroute import ping as ping_host_func # Renamed
    result_data = ping_host_func(target_arg, count=count) # Renamed
    _display_result(result_data)

@active_group.command('traceroute')
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--max-hops', type=int, default=30, help='Maximum number of hops')
def traceroute_cmd(target_arg: str, max_hops: int): # Renamed
    """Trace route to a host"""
    from .modules.active.ping_traceroute import traceroute as trace_route_func # Renamed
    result_data = trace_route_func(target_arg, max_hops=max_hops) # Renamed
    _display_result(result_data)

@active_group.command('banner')
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--port', '-p', type=int, required=True, help='Port to connect to')
@click.option('--protocol', type=click.Choice(['tcp', 'udp'], case_sensitive=False), default='tcp', help='Protocol to use')
def grab_banner_cmd(target_arg: str, port: int, protocol: str): # Renamed
    """Grab banner from a service"""
    from .modules.active.banner_grabber import grab_banner as grab_banner_func # Renamed
    result_data = grab_banner_func(target_arg, port=port, protocol=protocol) # Renamed
    _display_result(result_data)

@active_group.command('waf')
@click.argument('url_arg', metavar='URL') # Renamed
def detect_waf_cmd(url_arg: str): # Renamed
    """Detect Web Application Firewall on a website"""
    from .modules.active.waf_detector import detect as detect_waf_func # Renamed
    result_data = detect_waf_func(url_arg) # Renamed
    _display_result(result_data)

@active_group.command('webscan')
@click.argument('url_arg', metavar='URL') # Renamed
@click.option('--full', '-f', is_flag=True, help='Perform a full scan (slower but more thorough)')
def scan_web_vulnerabilities_cmd(url_arg: str, full: bool): # Renamed
    """Scan for common web vulnerabilities"""
    from .modules.active.web_vulnerabilities import scan as web_vuln_scan_func # Renamed
    result_data = web_vuln_scan_func(url_arg, full_scan=full) # Renamed # Changed full to full_scan
    _display_result(result_data)

# --- Utility commands ---
@cli.group('util')
def util_group():
    """Utility commands for various tasks"""
    pass

@util_group.command('validate')
@click.argument('target_arg', metavar='TARGET_TO_VALIDATE') # Renamed
@click.option('--type', '-t', 'type_to_validate', # Renamed
              type=click.Choice(['ip', 'domain', 'url', 'email'], case_sensitive=False),
              help='Type of target to validate')
def validate_target_cmd(target_arg: str, type_to_validate: Optional[str]): # Renamed
    """Validate a target (IP, domain, URL, email)"""
    result_val = {"target": target_arg, "type_validated_as": None, "is_valid": False} # Renamed

    if type_to_validate:
        # Validate specific type
        result_val["type_validated_as"] = type_to_validate
        if type_to_validate == 'ip':
            result_val["is_valid"] = is_valid_ip(target_arg)
        elif type_to_validate == 'domain':
            result_val["is_valid"] = is_valid_domain(target_arg)
        elif type_to_validate == 'url':
            result_val["is_valid"] = is_valid_url(target_arg)
        elif type_to_validate == 'email':
            result_val["is_valid"] = is_valid_email(target_arg)
    else:
        # Auto-detect type
        if is_valid_ip(target_arg):
            result_val["is_valid"] = True
            result_val["type_validated_as"] = "ip"
        elif is_valid_url(target_arg): # Check URL before domain, as valid URLs can contain valid domains
            result_val["is_valid"] = True
            result_val["type_validated_as"] = "url"
        elif is_valid_domain(target_arg):
            result_val["is_valid"] = True
            result_val["type_validated_as"] = "domain"
        elif is_valid_email(target_arg):
            result_val["is_valid"] = True
            result_val["type_validated_as"] = "email"
        else:
            result_val["is_valid"] = False
            result_val["type_validated_as"] = "unknown"

    _display_result(result_val)

@util_group.command('format')
@click.argument('input_file', type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option('--output-format', '-of', 'output_format_arg', # Renamed and metavar added
              type=click.Choice(['json', 'csv', 'text'], case_sensitive=False), default='json',
              help='Output format')
@click.option('--output-file', '-f', type=click.Path(dir_okay=False, writable=True),
              help='Output file (stdout if not specified)')
def format_conversion(input_file: str, output_format_arg: str, output_file: Optional[str]):
    """Convert reconnaissance data files between formats (JSON, CSV, Text)"""
    from .utils.formatters import convert_file_format
    result_data = convert_file_format(input_file, output_format=output_format_arg, output_file=output_file) # Renamed
    if "error" in result_data:
        click.echo(click.style(f"Error: {result_data['error']}", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
    elif result_data.get("message"):
        click.echo(click.style(result_data["message"], fg="green" if config.DEFAULT_CONFIG["use_color"] else None))
        if result_data.get("output_content"): # If writing to stdout
            click.echo(result_data["output_content"])

# --- Workflow commands ---
@cli.group('workflow')
def workflow_group():
    """Manage and run reconnaissance workflows"""
    pass

@workflow_group.command('list')
def list_workflows():
    """List available reconnaissance workflows"""
    # Assuming workflows are in a 'workflows' directory relative to this script/package
    # For a package, this path needs to be handled carefully, e.g., using importlib.resources
    base_path = os.path.dirname(os.path.abspath(__file__))
    workflows_dir = os.path.join(base_path, 'workflows')

    if not os.path.exists(workflows_dir) or not os.path.isdir(workflows_dir):
        click.echo(f"Workflows directory not found at {workflows_dir}")
        click.echo("Create a 'workflows' directory in the same location as main.py and add JSON workflow files.")
        return

    workflows = []
    for filename in os.listdir(workflows_dir):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(workflows_dir, filename), 'r') as f:
                    workflow_data = json.load(f) # Renamed
                    workflows.append({
                        "name": workflow_data.get("name", os.path.splitext(filename)[0]), # Use filename without ext if no name
                        "description": workflow_data.get("description", "No description"),
                        "modules_count": len(workflow_data.get("modules", [])), # Renamed for clarity
                        "filename": filename
                    })
            except json.JSONDecodeError:
                logger.warning(f"Skipping invalid JSON workflow file: {filename}")
            except Exception as e:
                logger.warning(f"Error loading workflow file {filename}: {e}")

    if not workflows:
        click.echo("No valid workflows found in the 'workflows' directory.")
        return

    if config.DEFAULT_CONFIG["output_format"] == "json":
        click.echo(json.dumps(workflows, indent=2))
    else:
        table_data = [[wf["name"], wf["description"], wf["modules_count"], wf["filename"]] for wf in workflows]
        headers = ["Name", "Description", "Modules", "Filename"]
        click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))

@workflow_group.command('run')
@click.argument('workflow_name_or_path', metavar='WORKFLOW_NAME_OR_PATH') # Renamed
@click.argument('target_arg', metavar='TARGET') # Renamed
@click.option('--output-dir', '-d', type=click.Path(file_okay=False, dir_okay=True, writable=True, resolve_path=True), help='Directory to save results')
def run_workflow(workflow_name_or_path: str, target_arg: str, output_dir: Optional[str]):
    """Run a predefined reconnaissance workflow on a target"""
    base_path = os.path.dirname(os.path.abspath(__file__))
    workflows_dir = os.path.join(base_path, 'workflows')

    workflow_file = None
    # Check if it's an absolute or relative path
    if os.path.exists(workflow_name_or_path) and workflow_name_or_path.endswith('.json'):
        workflow_file = workflow_name_or_path
    else:
        # Try to find it in the workflows directory
        potential_file = os.path.join(workflows_dir, f"{workflow_name_or_path}.json")
        if os.path.exists(potential_file):
            workflow_file = potential_file
        else: # Try without .json extension if user provided it
            potential_file_no_ext = os.path.join(workflows_dir, workflow_name_or_path)
            if os.path.exists(potential_file_no_ext) and workflow_name_or_path.endswith('.json'):
                 workflow_file = potential_file_no_ext

    if not workflow_file:
        click.echo(f"Workflow '{workflow_name_or_path}' not found in {workflows_dir} or as a direct path.")
        return

    try:
        with open(workflow_file, 'r') as f:
            workflow_data = json.load(f) # Renamed

        click.echo(f"Running workflow: {workflow_data.get('name', os.path.basename(workflow_file))}")
        click.echo(f"Description: {workflow_data.get('description', 'No description')}")

        # Validate target
        target_type_wf = None # Renamed
        if is_valid_ip(target_arg): target_type_wf = "ip"
        elif is_valid_url(target_arg): target_type_wf = "url"
        elif is_valid_domain(target_arg): target_type_wf = "domain"

        if not target_type_wf:
            click.echo(f"Invalid target for workflow: {target_arg}")
            return

        # Set up output directory for workflow run
        effective_wf_output_dir = output_dir
        if not effective_wf_output_dir and config.DEFAULT_CONFIG.get("save_results", False):
            safe_target_name_wf = re.sub(r'[^\w\-_\.]', '_', target_arg)
            wf_name_for_dir = os.path.splitext(os.path.basename(workflow_file))[0]
            effective_wf_output_dir = os.path.join(config.RESULTS_DIR, f"{safe_target_name_wf}_workflow_{wf_name_for_dir}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
            click.echo(f"[+] Defaulting workflow output to: {effective_wf_output_dir}")

        if effective_wf_output_dir:
            try:
                os.makedirs(effective_wf_output_dir, exist_ok=True)
            except OSError as e:
                click.echo(f"[!] Error creating workflow output directory {effective_wf_output_dir}: {e}. Results will not be saved to files.")
                effective_wf_output_dir = None

        # Run workflow modules
        modules_to_run = workflow_data.get("modules", [])
        for module_spec in modules_to_run: # Renamed
            module_name_wf = module_spec.get("name") # Renamed
            module_type_wf = module_spec.get("type", "passive").lower() # Renamed
            module_options_wf = module_spec.get("options", {}) # Renamed

            if not module_name_wf:
                click.echo(f"  Skipping module with no name in workflow.")
                continue

            click.echo(f"\nRunning {module_type_wf} module: {module_name_wf}")

            try:
                # Construct full module path (e.g., reconpy.modules.passive.shodan_search)
                full_module_path = f"reconpy.modules.{module_type_wf}.{module_name_wf}"

                # Check API requirements
                api_check_wf = config.check_api_requirements(full_module_path)
                if not api_check_wf["all_configured"]:
                    missing_apis = ", ".join(api_check_wf.get("missing_services", ["Unknown"]))
                    click.echo(click.style(f"  Skipping module {module_name_wf} due to missing API keys for: {missing_apis}", fg="yellow" if config.DEFAULT_CONFIG["use_color"] else None))
                    continue

                # Dynamically import the module
                module_obj = importlib.import_module(f".modules.{module_type_wf}.{module_name_wf}", package="recon_tool") # Corrected package name

                # Determine the function to call (scan, lookup, search are common patterns)
                action_func = None
                if hasattr(module_obj, "scan"): action_func = module_obj.scan
                elif hasattr(module_obj, "lookup"): action_func = module_obj.lookup
                elif hasattr(module_obj, "search"): action_func = module_obj.search
                elif hasattr(module_obj, "detect"): action_func = module_obj.detect # For waf_detector
                # Add more common function names if needed

                if not action_func:
                    click.echo(f"  Module {module_name_wf} does not have a compatible interface (scan, lookup, search, detect).")
                    continue

                # Call the function with target and options
                # Some modules might not take **module_options_wf if they are simple
                try:
                    if module_options_wf:
                        result_data_wf = action_func(target_arg, **module_options_wf) # Renamed
                    else:
                        result_data_wf = action_func(target_arg) # Renamed
                except TypeError as te: # Handle cases where module doesn't accept **kwargs
                    if "unexpected keyword argument" in str(te) and not module_options_wf:
                         result_data_wf = action_func(target_arg)
                    elif "required positional argument" in str(te) and not module_options_wf: # e.g. port_scanner.scan needs ports
                         click.echo(f"  Module {module_name_wf} seems to require options that were not provided in workflow: {te}")
                         continue
                    else:
                        raise te # Re-raise if it's a different TypeError

                _display_result(result_data_wf)

                if effective_wf_output_dir and config.DEFAULT_CONFIG.get("save_results", True):
                    safe_target_name_wf_file = re.sub(r'[^\w\-_\.]', '_', target_arg)
                    output_file_path = os.path.join(effective_wf_output_dir, f"{safe_target_name_wf_file}_{module_name_wf}.json")
                    try:
                        with open(output_file_path, 'w') as f:
                            json.dump(result_data_wf, f, indent=2, default=str)
                        click.echo(f"  Results saved to: {output_file_path}")
                    except IOError as e:
                        click.echo(f"  Error saving {module_name_wf} results to {output_file_path}: {e}")
            except ImportError:
                click.echo(f"  Error importing module {module_name_wf} (path: {full_module_path}). Ensure it exists.")
            except Exception as e:
                click.echo(f"  Error running module {module_name_wf}: {str(e)}")
                if config.DEFAULT_CONFIG["verbosity"] >= config.VerbosityLevel.DEBUG:
                    logger.exception(f"Full error in module {module_name_wf}:")

        click.echo("\nWorkflow execution completed.")

    except json.JSONDecodeError:
        click.echo(f"Error: Workflow file '{workflow_file}' is not valid JSON.")
    except Exception as e:
        click.echo(f"Error loading or running workflow: {str(e)}")
        if config.DEFAULT_CONFIG["verbosity"] >= config.VerbosityLevel.DEBUG:
            logger.exception("Full error during workflow execution:")

# Utility to display results based on output format
def _display_result(result_data): # Renamed
    """Display results in the configured format"""
    output_format_disp = config.DEFAULT_CONFIG["output_format"] # Renamed

    from .utils.formatters import format_output
    formatted_output = format_output(result_data, output_format_disp) # Renamed

    click.echo(formatted_output)

# Main entry point
def main_entry():
    try:
        # The cli object is already initialized with verbosity by Click when options are parsed.
        # The setup_logger is now called within the cli() function itself.
        cli(standalone_mode=False) # standalone_mode=False to prevent Click from exiting prematurely
    except Exception as e:
        # Logger might not be fully configured if error is very early, so also print
        print(f"Critical Error: {str(e)}", file=sys.stderr)
        if logger.handlers: # Check if logger has handlers
            if config.DEFAULT_CONFIG.get("verbosity", config.VerbosityLevel.NORMAL) >= config.VerbosityLevel.DEBUG:
                logger.exception("An unhandled error occurred:")
            else:
                logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # This is for direct execution of main.py (e.g. python reconpy/main.py)
    # The `run_recon.py` or `setup.py` entry point is preferred.
    main_entry()