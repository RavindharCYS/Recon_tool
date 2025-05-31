#!/usr/bin/env python3
"""
ReconPy: A cross-platform Python CLI reconnaissance tool
Main entry point for the application
"""
import sys
import click
from typing import Optional, Tuple, Dict, List, Any
import importlib
import os
import json
import datetime
from tabulate import tabulate
from urllib.parse import urlparse
import re

# Import configuration
from . import config # config.py will now have the updated RESULTS_DIR

# Import utilities
from .utils.logger import setup_logger, get_logger
from .utils.validators import is_valid_ip, is_valid_domain, is_valid_url, is_valid_email

# Initialize logger
logger = get_logger(__name__)

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
@click.option('--verbose', '-v', count=True, help='Increase verbosity (e.g., -v, -vv)')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-error output')
@click.option('--output', '-o', type=click.Choice(['text', 'json', 'csv', 'html']),
              default=config.DEFAULT_CONFIG["output_format"], help='Output format')
@click.option('--no-color', is_flag=True, help='Disable colored output')
def cli(verbose: int, quiet: bool, output: str, no_color: bool):
    """
    ReconPy: A cross-platform reconnaissance toolkit for security professionals
    """
    if quiet: verbosity = config.VerbosityLevel.QUIET
    elif verbose == 1: verbosity = config.VerbosityLevel.VERBOSE
    elif verbose >= 2: verbosity = config.VerbosityLevel.DEBUG
    else: verbosity = config.VerbosityLevel.NORMAL

    config.DEFAULT_CONFIG["verbosity"] = verbosity
    config.DEFAULT_CONFIG["output_format"] = output
    config.DEFAULT_CONFIG["use_color"] = not no_color
    setup_logger(verbosity)

    if not quiet:
        click.echo(click.style(BANNER, fg='blue', bold=True) if config.DEFAULT_CONFIG["use_color"] else BANNER)
        click.echo(f"Version: {config.VERSION}\n")

@cli.command('recon')
@click.argument('target')
@click.option('--passive-only', is_flag=True, help='Only perform passive reconnaissance')
@click.option('--active-only', is_flag=True, help='Only perform active reconnaissance')
@click.option('--output-dir', '-d', type=click.Path(file_okay=False, dir_okay=True, writable=True, resolve_path=True), help='Directory to save results (overrides default local project results folder)')
@click.option('--report', '-r', is_flag=True, help='Generate individual module HTMLs and a single consolidated HTML report, plus individual JSON files')
@click.option('--ports', '-p', default='1-1000', help='Port range for scanning')
@click.option('--threads', '-t', type=int, default=config.DEFAULT_CONFIG["max_threads"], help='Number of threads')
def all_in_one_recon(target: str, passive_only: bool, active_only: bool, output_dir: Optional[str], report: bool, ports: str, threads: int):
    """
    Perform comprehensive reconnaissance on a target.
    """
    current_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_type: Optional[str] = None
    domain: Optional[str] = None

    if is_valid_ip(target): target_type = "ip"
    elif is_valid_url(target):
        target_type = "url"
        try:
            parsed_url = urlparse(target)
            domain = parsed_url.netloc.split(':')[0]
        except Exception as e:
            logger.error(f"Could not parse domain from URL {target}: {e}")
            domain = target # Fallback
    elif is_valid_domain(target):
        target_type = "domain"
        domain = target
    else:
        click.echo(f"[!] Unable to determine target type for {target}")
        if not click.confirm("Continue anyway?"): sys.exit(1)
        domain = target # Fallback

    # Determine output directory
    # Priority: --output-dir > config.RESULTS_DIR (now local)
    effective_output_dir: Optional[str] = None
    safe_target_for_dir = re.sub(r'[^\w\-_\.]', '_', target)
    # If --output-dir is given, use it directly
    if output_dir:
        effective_output_dir = os.path.join(output_dir, f"{safe_target_for_dir}_{current_timestamp}")
    # Else, if report is true OR general saving is enabled, use default config.RESULTS_DIR
    elif report or config.DEFAULT_CONFIG.get("save_results", False):
        effective_output_dir = os.path.join(config.RESULTS_DIR, f"{safe_target_for_dir}_{current_timestamp}")
    
    if effective_output_dir:
        click.echo(f"[+] Output will be saved in: {effective_output_dir}")
        try:
            os.makedirs(effective_output_dir, exist_ok=True)
        except OSError as e:
            click.echo(f"[!] Error creating output directory {effective_output_dir}: {e}. File saving disabled.")
            effective_output_dir = None # Disable saving if dir creation fails
            if report: # If report was requested but dir fails, inform user
                 click.echo("[!] Reporting disabled due to output directory creation failure.")


    report_data: Dict[str, Any] = {
        "target": target, "target_type": target_type, "timestamp": current_timestamp,
        "scan_parameters": {"passive_only": passive_only, "active_only": active_only, "ports": ports, "threads": threads},
        "modules_run": [], "results": {}
    }

    def save_module_result(module_name: str, result_data: Dict[str, Any]):
        report_data["results"][module_name] = result_data
        if module_name not in report_data["modules_run"]:
            report_data["modules_run"].append(module_name)

        # Save individual JSON and HTML if an output directory is effectively set
        if effective_output_dir: # No need to check config.DEFAULT_CONFIG["save_results"] here, dir presence implies intent
            safe_target_name = re.sub(r'[^\w\-_\.]', '_', target)
            base_filename = os.path.join(effective_output_dir, f"{safe_target_name}_{module_name}_{current_timestamp}")
            
            # Save individual JSON
            try:
                with open(f"{base_filename}.json", 'w', encoding='utf-8') as f_json:
                    json.dump(result_data, f_json, indent=2, default=str)
                click.echo(f"[+] {module_name.capitalize()} JSON results saved to: {base_filename}.json")
            except IOError as e:
                 click.echo(f"[!] Error saving {module_name} JSON results: {e}")

            # Save individual HTML (if report flag is true or if global output is html)
            # For `all_in_one_recon`, we only save individual HTMLs if --report is on.
            if report:
                try:
                    from .utils.formatters import format_output
                    # Pass the module name to format_output so it can make a specific title
                    html_content_module = format_output(result_data, output_format="html")
                    with open(f"{base_filename}.html", 'w', encoding='utf-8') as f_html:
                        f_html.write(html_content_module)
                    click.echo(f"[+] {module_name.capitalize()} HTML results saved to: {base_filename}.html")
                except Exception as e_fmt:
                     click.echo(f"[!] Error formatting/saving HTML for {module_name}: {e_fmt}")
                     logger.error(f"Error formatting/saving HTML for {module_name}: {e_fmt}", exc_info=True)

    # --- Passive Reconnaissance Modules ---
    if not active_only:
        click.echo("\n" + click.style("=== PASSIVE RECONNAISSANCE ===", fg="green" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))
        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running WHOIS lookup...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.whois_lookup import lookup
                whois_result = lookup(domain)
                _display_result(whois_result)
                save_module_result("whois", whois_result)
            except Exception as e: click.echo(f"[!] WHOIS lookup failed: {str(e)}"); logger.error(f"WHOIS lookup failed: {e}", exc_info=True)

        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running DNS enumeration...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.dns_enum import lookup
                dns_result = lookup(domain, record_types=['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'])
                _display_result(dns_result)
                save_module_result("dns", dns_result)
                if dns_result and 'records' in dns_result and isinstance(dns_result['records'],dict) and 'A' in dns_result['records']:
                    a_records_list = dns_result['records']['A']
                    if isinstance(a_records_list, list) and a_records_list and isinstance(a_records_list[0],dict):
                        ip_address_from_dns = a_records_list[0].get('value')
                        if ip_address_from_dns: click.echo(f"[+] Primary IP address from DNS: {ip_address_from_dns}")
            except Exception as e: click.echo(f"[!] DNS enumeration failed: {str(e)}"); logger.error(f"DNS enumeration failed: {e}", exc_info=True)

        if target_type == "url":
            click.echo("\n" + click.style("Running web scraping...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.web_scraper import scrape
                web_result = scrape(target, depth=0)
                _display_result(web_result)
                save_module_result("web_scrape", web_result)
            except Exception as e: click.echo(f"[!] Web scraping failed: {str(e)}"); logger.error(f"Web scraping failed: {e}", exc_info=True)

        click.echo("\n" + click.style("Running Shodan search...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        api_check_shodan = config.check_api_requirements("reconpy.modules.passive.shodan_search")
        if api_check_shodan["all_configured"]:
            try:
                from .modules.passive.shodan_search import search_ip, search_query
                shodan_result: Dict[str, Any] = {}
                if target_type == "ip": shodan_result = search_ip(target)
                elif domain: shodan_result = search_query(f"hostname:{domain}")
                else: shodan_result = {"info": "Domain not available for Shodan query."}
                _display_result(shodan_result); save_module_result("shodan", shodan_result)
            except Exception as e: click.echo(f"[!] Shodan search failed: {str(e)}"); logger.error(f"Shodan search failed: {e}", exc_info=True)
        else: _handle_missing_api_key_prompt("shodan", "Shodan")

        click.echo("\n" + click.style("Running Censys search...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
        api_check_censys = config.check_api_requirements("reconpy.modules.passive.censys_search")
        if api_check_censys["all_configured"]:
            try:
                from .modules.passive.censys_search import search_ip, search_certificates
                censys_result: Dict[str, Any] = {}
                if target_type == "ip": censys_result = search_ip(target)
                elif domain: censys_result = search_certificates(domain)
                else: censys_result = {"info": "Domain not available for Censys search."}
                _display_result(censys_result); save_module_result("censys", censys_result)
            except Exception as e: click.echo(f"[!] Censys search failed: {str(e)}"); logger.error(f"Censys search failed: {e}", exc_info=True)
        else: _handle_missing_api_key_prompt("censys", "Censys")

        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running Wayback Machine search...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.passive.wayback_machine import get_snapshots
                wayback_result = get_snapshots(domain, limit=10)
                _display_result(wayback_result); save_module_result("wayback", wayback_result)
            except Exception as e: click.echo(f"[!] Wayback Machine search failed: {str(e)}"); logger.error(f"Wayback Machine search failed: {e}", exc_info=True)

        if domain and target_type in ["domain", "url"]:
            click.echo("\n" + click.style("Running repository search (GitHub)...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            api_check_github = config.check_api_requirements("reconpy.modules.passive.public_repos")
            if api_check_github["all_configured"]:
                try:
                    from .modules.passive.public_repos import search_repositories_for_domain
                    repo_result = search_repositories_for_domain(domain)
                    _display_result(repo_result); save_module_result("repos", repo_result)
                except Exception as e: click.echo(f"[!] Repository search failed: {str(e)}"); logger.error(f"Repository search failed: {e}", exc_info=True)
            else: _handle_missing_api_key_prompt("github", "GitHub", "Repository search may be limited.")


    # --- Active Reconnaissance Modules ---
    if not passive_only:
        click.echo("\n" + click.style("=== ACTIVE RECONNAISSANCE ===", fg="yellow" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))
        target_for_active_scan = target
        if target_type == "url" and domain: target_for_active_scan = domain
        elif target_type == "domain":
            if domain and not is_valid_ip(domain):
                try:
                    resolved_ip_for_active = get_ip_from_domain(domain)
                    click.echo(f"[+] Resolved {domain} to {resolved_ip_for_active} for active scans.")
                    target_for_active_scan = resolved_ip_for_active
                except Exception:
                    click.echo(f"[!] Could not resolve {domain} to IP. Active scans might use the domain name directly.")
                    target_for_active_scan = domain
            else: target_for_active_scan = domain
        
        if not target_for_active_scan: click.echo("[!] No valid target for active scans. Skipping active phase.")
        else:
            click.echo("\n" + click.style("Running ping test...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.active.ping_traceroute import ping as ping_func
                ping_result = ping_func(target_for_active_scan, count=4)
                _display_result(ping_result); save_module_result("ping", ping_result)
            except Exception as e: click.echo(f"[!] Ping test failed: {str(e)}"); logger.error(f"Ping test failed: {e}", exc_info=True)

            click.echo("\n" + click.style("Running traceroute...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.active.ping_traceroute import traceroute as traceroute_func
                traceroute_result = traceroute_func(target_for_active_scan, max_hops=20)
                _display_result(traceroute_result); save_module_result("traceroute", traceroute_result)
            except Exception as e: click.echo(f"[!] Traceroute failed: {str(e)}"); logger.error(f"Traceroute failed: {e}", exc_info=True)

            click.echo("\n" + click.style("Running port scan...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.active.port_scanner import scan as port_scan_func
                port_scan_result = port_scan_func(target_for_active_scan, ports=ports, method='tcp', threads=threads)
                _display_result(port_scan_result); save_module_result("port_scan", port_scan_result)

                if port_scan_result and "open_ports" in port_scan_result and \
                   isinstance(port_scan_result.get("open_ports"), dict) and \
                   isinstance(port_scan_result["open_ports"].get("tcp"), list) and \
                   port_scan_result["open_ports"]["tcp"]:
                    
                    open_tcp_ports_info = port_scan_result["open_ports"]["tcp"]
                    open_tcp_ports_numbers = [p_info["port"] for p_info in open_tcp_ports_info if isinstance(p_info, dict) and "port" in p_info]

                    if open_tcp_ports_numbers:
                        click.echo("\n" + click.style("Running banner grabbing on open TCP ports...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
                        banner_results_coll: Dict[str, Any] = {"target": target_for_active_scan, "banners": {}}
                        from .modules.active.banner_grabber import grab_banner
                        for port_num_banner in open_tcp_ports_numbers[:5]: # Limit banners for recon
                            click.echo(f"  Grabbing banner from port {port_num_banner}...")
                            try:
                                single_banner_result = grab_banner(target_for_active_scan, port=port_num_banner, protocol='tcp')
                                banner_results_coll["banners"][str(port_num_banner)] = single_banner_result
                            except Exception as e_banner:
                                banner_results_coll["banners"][str(port_num_banner)] = {"error": f"Banner grab error: {str(e_banner)}"}
                                logger.error(f"Banner grab for port {port_num_banner} failed: {e_banner}", exc_info=True)
                        _display_result(banner_results_coll); save_module_result("banners", banner_results_coll)
            except Exception as e: click.echo(f"[!] Port scanning or banner grabbing failed: {str(e)}"); logger.error(f"Port scan/banner failed: {e}", exc_info=True)

            click.echo("\n" + click.style("Running Nmap scan...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
            try:
                from .modules.active.nmap_scanner import scan as nmap_scan_func, is_nmap_installed
                if is_nmap_installed():
                    nmap_result = nmap_scan_func(target_for_active_scan, ports=ports, scan_type='sT')
                    _display_result(nmap_result); save_module_result("nmap", nmap_result)
                else: click.echo("[!] Nmap binary not found. Skipping Nmap scan.")
            except ImportError: click.echo("[!] Nmap scanning skipped (python-nmap library not available).")
            except Exception as e: click.echo(f"[!] Nmap scanning failed: {str(e)}"); logger.error(f"Nmap scan failed: {e}", exc_info=True)

            if target_type == "url":
                click.echo("\n" + click.style("Detecting Web Application Firewall...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
                try:
                    from .modules.active.waf_detector import detect as waf_detect_func
                    waf_result = waf_detect_func(target)
                    _display_result(waf_result); save_module_result("waf", waf_result)
                except Exception as e: click.echo(f"[!] WAF detection failed: {str(e)}"); logger.error(f"WAF detection failed: {e}", exc_info=True)

                click.echo("\n" + click.style("Running web vulnerability scan...", fg="cyan" if config.DEFAULT_CONFIG["use_color"] else None))
                api_check_vt = config.check_api_requirements("reconpy.modules.active.web_vulnerabilities")
                if not api_check_vt["all_configured"]: _handle_missing_api_key_prompt("virustotal", "VirusTotal", "Some web vulnerability checks might be limited.")
                try:
                    from .modules.active.web_vulnerabilities import scan as web_vuln_scan_func
                    web_vuln_result = web_vuln_scan_func(target, full_scan=False)
                    _display_result(web_vuln_result); save_module_result("web_vulns", web_vuln_result)
                except Exception as e: click.echo(f"[!] Web vulnerability scan failed: {str(e)}"); logger.error(f"Web vulnerability scan failed: {e}", exc_info=True)

    # --- Reporting ---
    if report and effective_output_dir:
        click.echo("\n" + click.style("=== GENERATING CONSOLIDATED REPORTS ===", fg="blue" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))
        safe_target_name_report = re.sub(r'[^\w\-_\.]', '_', target)
        
        # Consolidated JSON Report (contains all module data)
        report_file_path_json = os.path.join(effective_output_dir, f"{safe_target_name_report}_consolidated_report_{current_timestamp}.json")
        try:
            with open(report_file_path_json, 'w', encoding='utf-8') as f_json_report:
                json.dump(report_data, f_json_report, indent=2, default=str)
            click.echo(f"[+] Consolidated JSON report saved to: {report_file_path_json}")
        except IOError as e:
            click.echo(f"[!] Error saving consolidated JSON report: {e}")

        # SINGLE Consolidated HTML Report (contains all module data)
        report_file_path_html = os.path.join(effective_output_dir, f"{safe_target_name_report}_consolidated_report_{current_timestamp}.html")
        try:
            from .utils.formatters import format_output
            html_full_content = format_output(report_data, output_format="html")
            with open(report_file_path_html, 'w', encoding='utf-8') as f_html_report:
                f_html_report.write(html_full_content)
            click.echo(f"[+] Consolidated HTML report saved to: {report_file_path_html}")
        except Exception as e:
            click.echo(f"[!] Error saving consolidated HTML report: {e}")
            logger.error(f"Consolidated HTML report generation/saving failed: {e}", exc_info=True)
        
        # Text Summary for Console
        click.echo("\n" + click.style("=== KEY FINDINGS (CONSOLE SUMMARY) ===", fg="green" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))
        summary_for_display: Dict[str, Any] = {
            "Target": target, "Target Type": target_type, "Scan Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Modules Run": ", ".join(report_data["modules_run"])
        }
        if "dns" in report_data["results"] and isinstance(report_data["results"]["dns"], dict) and "records" in report_data["results"]["dns"]:
            dns_recs = report_data["results"]["dns"]["records"]
            if isinstance(dns_recs, dict) and "A" in dns_recs and isinstance(dns_recs["A"], list) and dns_recs["A"]:
                primary_ip_val = dns_recs["A"][0].get("value", "N/A") if isinstance(dns_recs["A"][0], dict) else "N/A"
                summary_for_display["Primary IP"] = primary_ip_val
        
        if "port_scan" in report_data["results"] and isinstance(report_data["results"]["port_scan"], dict):
            ps_data = report_data["results"]["port_scan"]
            if isinstance(ps_data.get("open_ports"), dict) and isinstance(ps_data["open_ports"].get("tcp"), list):
                 open_ports_tcp_list = [str(p["port"]) for p in ps_data["open_ports"]["tcp"] if isinstance(p, dict) and "port" in p]
                 if open_ports_tcp_list:
                     summary_for_display["Open TCP Ports (first 5)"] = ", ".join(open_ports_tcp_list[:5]) + ("..." if len(open_ports_tcp_list) > 5 else "")

        if "waf" in report_data["results"] and isinstance(report_data["results"]["waf"], dict):
             waf_info = report_data["results"]["waf"]
             summary_for_display["WAF Detected"] = waf_info.get("waf_detected", False)
             if waf_info.get("waf_detected"): summary_for_display["WAF Name"] = waf_info.get("identified_waf_name", "Unknown")

        if "web_vulns" in report_data["results"] and isinstance(report_data["results"]["web_vulns"], dict):
            wv_info = report_data["results"]["web_vulns"]
            if isinstance(wv_info.get("summary"), dict): summary_for_display["Web Vuln Summary"] = wv_info["summary"]
        _display_result(summary_for_display)

    elif report and not effective_output_dir:
        click.echo("[!] Reporting disabled as output directory could not be created or was not specified.")

    click.echo("\n" + click.style("=== RECONNAISSANCE COMPLETE ===", fg="green" if config.DEFAULT_CONFIG["use_color"] else None, bold=True))

# --- API Key Management Commands (Keep as is) ---
@cli.group('api')
def api_group():
    """Manage API keys for various services"""
    pass

@api_group.command('list')
@click.option('--show-keys', is_flag=True, help='Show masked API key values')
def list_apis(show_keys: bool):
    """List all supported API services and their configuration status"""
    services = config.list_api_services()
    if not services: click.echo("No API services defined."); return
    if config.DEFAULT_CONFIG["output_format"] == "json": click.echo(json.dumps(services, indent=2)); return
    
    table_data, headers = [], ["Service", "Description", "Status"]
    if show_keys: headers.append("Keys")
    for s_item in services:
        status = "✓ Configured" if s_item["fully_configured"] else "✗ Not Configured"
        style = click.style(status, fg='green' if s_item["fully_configured"] else 'red') if config.DEFAULT_CONFIG["use_color"] else status
        row = [f"{s_item['name']} ({s_item['id']})", s_item['description'], style]
        if show_keys:
            keys_parts = []
            for k_stat in s_item["keys"]:
                val = k_stat["value_preview"] if k_stat["configured"] else "✗"
                disp = f"{k_stat['name']}: {val}"
                if config.DEFAULT_CONFIG["use_color"]: disp = click.style(disp, fg='green' if k_stat["configured"] else 'red')
                keys_parts.append(disp)
            row.append('\n'.join(keys_parts))
        table_data.append(row)
    click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))

@api_group.command('configure')
@click.argument('service_id_arg', metavar='SERVICE_ID', required=False)
def configure_api(service_id_arg: Optional[str]):
    """Configure API keys for a service"""
    if service_id_arg:
        if service_id_arg not in config.API_DEFINITIONS:
            click.echo(f"Unknown service: {service_id_arg}\nAvailable: {', '.join(config.API_DEFINITIONS.keys())}"); return
        config.prompt_for_api_key(service_id_arg)
    else:
        services = config.list_api_services()
        if not services: click.echo("No API services available."); return
        click.echo("Available API services:")
        for i, s_item in enumerate(services, 1):
            status = "Configured" if s_item["fully_configured"] else "Not Configured"
            style = click.style(status, fg='green' if s_item["fully_configured"] else 'red') if config.DEFAULT_CONFIG["use_color"] else status
            click.echo(f"{i}. {s_item['name']} ({s_item['id']}) - {style}")
        try:
            choice = click.prompt("Select a service to configure (number or 0 to cancel)", type=int, default=0)
            if 0 < choice <= len(services): config.prompt_for_api_key(services[choice-1]["id"])
            elif choice == 0: click.echo("Configuration cancelled.")
            else: click.echo("Invalid selection.")
        except click.exceptions.Abort: click.echo("\nConfiguration aborted.")
        except Exception as e: click.echo(f"Error: {str(e)}")

@api_group.command('check')
@click.argument('module_name_arg', metavar='MODULE_NAME', required=False)
def check_api_requirements_cmd(module_name_arg: Optional[str]):
    """Check API requirements for a module or all modules."""
    if module_name_arg:
        res = config.check_api_requirements(module_name_arg)
        if not res["required_services"]: click.echo(f"Module '{module_name_arg}' requires no API keys."); return
        click.echo(f"API requirements for module '{module_name_arg}':")
        for sid in res["required_services"]:
            s_info = config.API_DEFINITIONS.get(sid, {})
            s_name = s_info.get("name", sid)
            status = "Configured" if sid not in res["missing_services"] else "Not Configured"
            style = click.style(status, fg='green' if sid not in res["missing_services"] else 'red') if config.DEFAULT_CONFIG["use_color"] else status
            click.echo(f"- {s_name} ({sid}): {style}")
        if res["all_configured"]: click.echo(click.style("\nAll required API keys are configured.", fg="green" if config.DEFAULT_CONFIG["use_color"] else None))
        else:
            missing = [config.API_DEFINITIONS.get(s, {}).get("name", s) for s in res["missing_services"]]
            click.echo(click.style(f"\nMissing API keys for: {', '.join(missing)}", fg="red" if config.DEFAULT_CONFIG["use_color"] else None))
            click.echo("Configure with: reconpy api configure <service_id>")
    else:
        modules_api = []
        for sid, info in config.API_DEFINITIONS.items():
            for mn in info.get("required_for", []):
                if not any(m["module"] == mn for m in modules_api):
                    chk_res = config.check_api_requirements(mn)
                    if chk_res["required_services"]: modules_api.append(chk_res)
        if not modules_api: click.echo("No modules found with API requirements."); return
        if config.DEFAULT_CONFIG["output_format"] == "json": click.echo(json.dumps(modules_api, indent=2)); return
        
        table_data, headers = [], ["Module", "Required APIs", "Status"]
        for mod_info in modules_api:
            s_mod_name = mod_info["module"].split(".")[-1]
            apis_disp = []
            for sid in mod_info["required_services"]:
                s_name = config.API_DEFINITIONS.get(sid, {}).get("name", sid)
                color = 'red' if sid in mod_info["missing_services"] else 'green'
                disp = click.style(s_name, fg=color) if config.DEFAULT_CONFIG["use_color"] else f"{s_name} ({'missing' if sid in mod_info['missing_services'] else 'ok'})"
                apis_disp.append(disp)
            status = "Ready" if mod_info["all_configured"] else "Missing Keys"
            style = click.style(status, fg='green' if mod_info["all_configured"] else 'red') if config.DEFAULT_CONFIG["use_color"] else status
            table_data.append([s_mod_name, ", ".join(apis_disp), style])
        if table_data: click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))
        else: click.echo("No modules with API requirements found.")

@api_group.command('clear')
@click.argument('service_id_arg', metavar='SERVICE_ID')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def clear_api_keys(service_id_arg: str, confirm: bool):
    """Clear API keys for a specific service"""
    if service_id_arg not in config.API_DEFINITIONS:
        click.echo(f"Unknown service: {service_id_arg}\nAvailable: {', '.join(config.API_DEFINITIONS.keys())}"); return
    s_name = config.API_DEFINITIONS[service_id_arg]["name"]
    if not confirm and not click.confirm(f"Clear API keys for {s_name}?"): click.echo("Cancelled."); return
    
    keys = config.load_api_keys()
    if service_id_arg in keys:
        for k_name in config.API_DEFINITIONS[service_id_arg]["keys"]:
            if k_name in keys[service_id_arg]: keys[service_id_arg][k_name] = ""
        if config.save_api_keys(keys): click.echo(f"API keys for {s_name} cleared.")
        else: click.echo(f"Error clearing API keys for {s_name}.")
    else: click.echo(f"No API keys configured for {s_name}.")


# --- Passive reconnaissance commands (Keep as is, they call _display_result) ---
# ... (whois_lookup, dns_lookup, web_scrape, shodan_search_cmd, etc. remain structurally the same) ...
@cli.group('passive')
def passive_group():
    """Passive reconnaissance commands that don't interact with the target"""
    pass

@passive_group.command('whois')
@click.argument('domain_arg', metavar='DOMAIN')
def whois_lookup(domain_arg: str):
    from .modules.passive.whois_lookup import lookup
    _display_result(lookup(domain_arg))

@passive_group.command('dns')
@click.argument('domain_arg', metavar='DOMAIN')
@click.option('--type', '-t', 'record_types_arg', multiple=True,
              type=click.Choice(['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'ALL'], case_sensitive=False),
              default=('A',), help='DNS record type to query (default: A)')
def dns_lookup(domain_arg: str, record_types_arg: Tuple[str, ...]):
    from .modules.passive.dns_enum import lookup
    final_types = list(record_types_arg)
    if 'ALL' in final_types: final_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    _display_result(lookup(domain_arg, record_types=final_types))

@passive_group.command('web')
@click.argument('url_arg', metavar='URL')
@click.option('--depth', '-d', type=int, default=0, help='Crawling depth (0 for single page)')
def web_scrape(url_arg: str, depth: int):
    from .modules.passive.web_scraper import scrape
    _display_result(scrape(url_arg, depth=depth))

@passive_group.command('shodan')
@click.argument('target_arg', metavar='TARGET')
@click.option('--query', '-q', 'is_query_mode_shodan', is_flag=True, help='Perform a custom Shodan query')
def shodan_search_cmd(target_arg: str, is_query_mode_shodan: bool):
    api_check = config.check_api_requirements("reconpy.modules.passive.shodan_search")
    if not api_check["all_configured"]:
        if not _handle_missing_api_key_prompt("shodan", "Shodan"): return
    from .modules.passive.shodan_search import search_ip, search_query
    _display_result(search_query(target_arg) if is_query_mode_shodan else search_ip(target_arg))

@passive_group.command('censys')
@click.argument('target_arg', metavar='TARGET')
@click.option('--certificates', '-c', 'search_certs_mode_censys', is_flag=True, help='Search for certificates')
def censys_search_cmd(target_arg: str, search_certs_mode_censys: bool):
    api_check = config.check_api_requirements("reconpy.modules.passive.censys_search")
    if not api_check["all_configured"]:
        if not _handle_missing_api_key_prompt("censys", "Censys"): return
    from .modules.passive.censys_search import search_ip, search_certificates
    _display_result(search_certificates(target_arg) if search_certs_mode_censys else search_ip(target_arg))

@passive_group.command('social')
@click.argument('query_arg', metavar='USERNAME_OR_EMAIL')
@click.option('--email', '-e', 'is_email_search_social', is_flag=True, help='Search by email')
def social_media_search(query_arg: str, is_email_search_social: bool):
    from .modules.passive.social_media import search_profiles, find_profiles_by_email
    if is_email_search_social:
        if not is_valid_email(query_arg): click.echo(click.style(f"Invalid email: {query_arg}", fg="red")); return
        _display_result(find_profiles_by_email(query_arg))
    else:
        if not query_arg.strip(): click.echo(click.style("Username empty.", fg="red")); return
        _display_result(search_profiles(query_arg))

@passive_group.command('wayback')
@click.argument('domain_arg', metavar='DOMAIN')
@click.option('--from-date', '-f', help='Start date (YYYYMMDD)')
@click.option('--to-date', '-t', help='End date (YYYYMMDD)')
@click.option('--limit', '-l', type=int, default=10, help='Max snapshots')
def wayback_search(domain_arg: str, from_date: Optional[str], to_date: Optional[str], limit: int):
    from .modules.passive.wayback_machine import get_snapshots
    _display_result(get_snapshots(domain_arg, from_date=from_date, to_date=to_date, limit=limit))

@passive_group.command('repos')
@click.argument('target_arg', metavar='DOMAIN_OR_KEYWORD')
@click.option('--check-leaks', '-c', 'check_leaks_mode_repos', is_flag=True, help='Check for credential leaks')
def repo_search(target_arg: str, check_leaks_mode_repos: bool):
    api_check = config.check_api_requirements("reconpy.modules.passive.public_repos")
    if not api_check["all_configured"]: _handle_missing_api_key_prompt("github", "GitHub", "Limited functionality.")
    from .modules.passive.public_repos import search_repositories_for_domain, search_for_leaked_credentials
    if check_leaks_mode_repos: _display_result(search_for_leaked_credentials(target_arg))
    else:
        if not is_valid_domain(target_arg): click.echo(click.style(f"Invalid domain: {target_arg}", fg="red")); return
        _display_result(search_repositories_for_domain(target_arg))

@passive_group.command('exif')
@click.argument('target_arg', metavar='IMAGE_URL_OR_FILE')
@click.option('--analyze', '-a', 'analyze_mode_exif', is_flag=True, help='Perform security analysis')
def exif_extraction(target_arg: str, analyze_mode_exif: bool):
    from .modules.passive.exif_metadata import extract_from_url, extract_from_file, analyze_image_security
    res: Optional[Dict[str, Any]] = None
    if os.path.isfile(target_arg): res = analyze_image_security(target_arg) if analyze_mode_exif else extract_from_file(target_arg)
    elif is_valid_url(target_arg): res = analyze_image_security(target_arg) if analyze_mode_exif else extract_from_url(target_arg)
    else: click.echo(click.style(f"Invalid target: '{target_arg}'. Must be file or URL.", fg="red")); return
    if res: _display_result(res)

# --- Active reconnaissance commands (Keep as is, they call _display_result) ---
@cli.group('active')
def active_group():
    """Active reconnaissance commands that interact with the target"""
    pass

@active_group.command('scan')
@click.argument('target_arg', metavar='TARGET')
@click.option('--ports', '-p', default='1-1000', help='Port range (e.g., 1-1000, 22,80,443)')
@click.option('--method', type=click.Choice(['tcp', 'udp', 'both'], case_sensitive=False), default='tcp', help='Scan method')
@click.option('--threads', '-t', type=int, default=config.DEFAULT_CONFIG["max_threads"], help='Threads')
def port_scan_cmd(target_arg: str, ports: str, method: str, threads: int):
    try:
        from .modules.active.port_scanner import scan as ps_func
        _display_result(ps_func(target_arg, ports=ports, method=method, threads=threads))
    except ImportError as e: logger.error(f"Port scanner import error: {e}"); click.echo(click.style(f"Module not available: {e}", fg="red"))
    except Exception as e_ps: logger.error(f"Port scan failed: {e_ps}", exc_info=True); click.echo(click.style(f"Port scan failed: {e_ps}", fg="red"))

@active_group.command('nmap')
@click.argument('target_arg', metavar='TARGET')
@click.option('--ports', '-p', default='1-1000', help='Port range')
@click.option('--scan-type', '-s', type=click.Choice(['sT', 'sS', 'sU', 'sV', 'O'], case_sensitive=False), default='sT', help='Nmap scan type')
@click.option('--args', 'nmap_args_opt', help='Additional Nmap arguments')
def nmap_scan_cmd(target_arg: str, ports: str, scan_type: str, nmap_args_opt: Optional[str]):
    try:
        from .modules.active.nmap_scanner import scan as nmap_func, is_nmap_installed
        if not is_nmap_installed(): click.echo(click.style("Nmap not installed.", fg="red")); return
        final_args, final_ports = nmap_args_opt, ports
        if scan_type.upper() == 'O' and not nmap_args_opt: final_args, final_ports = "-O", ""
        _display_result(nmap_func(target_arg, ports=final_ports, scan_type=scan_type, arguments=final_args))
    except ImportError as e: logger.error(f"Nmap import error: {e}"); click.echo(click.style(f"python-nmap not installed: {e}", fg="red"))
    except Exception as e_nmap: logger.error(f"Nmap scan failed: {e_nmap}", exc_info=True); click.echo(click.style(f"Nmap scan failed: {e_nmap}", fg="red"))

@active_group.command('ping')
@click.argument('target_arg', metavar='TARGET')
@click.option('--count', '-c', type=int, default=4, help='Packets to send')
def ping_cmd(target_arg: str, count: int):
    from .modules.active.ping_traceroute import ping as ping_func
    _display_result(ping_func(target_arg, count=count))

@active_group.command('traceroute')
@click.argument('target_arg', metavar='TARGET')
@click.option('--max-hops', type=int, default=30, help='Max hops')
def traceroute_cmd(target_arg: str, max_hops: int):
    from .modules.active.ping_traceroute import traceroute as trace_func
    _display_result(trace_func(target_arg, max_hops=max_hops))

@active_group.command('banner')
@click.argument('target_arg', metavar='TARGET')
@click.option('--port', '-p', type=int, required=True, help='Port')
@click.option('--protocol', type=click.Choice(['tcp', 'udp'], case_sensitive=False), default='tcp', help='Protocol')
def grab_banner_cmd(target_arg: str, port: int, protocol: str):
    from .modules.active.banner_grabber import grab_banner as gb_func
    _display_result(gb_func(target_arg, port=port, protocol=protocol))

@active_group.command('waf')
@click.argument('url_arg', metavar='URL')
def detect_waf_cmd(url_arg: str):
    from .modules.active.waf_detector import detect as dw_func
    _display_result(dw_func(url_arg))

@active_group.command('webscan')
@click.argument('url_arg', metavar='URL')
@click.option('--full', '-f', 'full_scan_web', is_flag=True, help='Perform full scan')
def scan_web_vulnerabilities_cmd(url_arg: str, full_scan_web: bool):
    from .modules.active.web_vulnerabilities import scan as wvs_func
    _display_result(wvs_func(url_arg, full_scan=full_scan_web))

# --- Utility commands (Keep as is, they call _display_result) ---
@cli.group('util')
def util_group():
    """Utility commands for various tasks"""
    pass

@util_group.command('validate')
@click.argument('target_arg', metavar='TARGET_TO_VALIDATE')
@click.option('--type', '-t', 'type_to_validate_arg',
              type=click.Choice(['ip', 'domain', 'url', 'email'], case_sensitive=False),
              help='Type of target to validate')
def validate_target_cmd(target_arg: str, type_to_validate_arg: Optional[str]):
    res: Dict[str, Any] = {"target": target_arg, "type_validated_as": None, "is_valid": False}
    if type_to_validate_arg:
        res["type_validated_as"] = type_to_validate_arg
        if type_to_validate_arg == 'ip': res["is_valid"] = is_valid_ip(target_arg)
        elif type_to_validate_arg == 'domain': res["is_valid"] = is_valid_domain(target_arg)
        elif type_to_validate_arg == 'url': res["is_valid"] = is_valid_url(target_arg)
        elif type_to_validate_arg == 'email': res["is_valid"] = is_valid_email(target_arg)
    else:
        if is_valid_ip(target_arg): res.update({"is_valid": True, "type_validated_as": "ip"})
        elif is_valid_url(target_arg): res.update({"is_valid": True, "type_validated_as": "url"})
        elif is_valid_domain(target_arg): res.update({"is_valid": True, "type_validated_as": "domain"})
        elif is_valid_email(target_arg): res.update({"is_valid": True, "type_validated_as": "email"})
        else: res.update({"is_valid": False, "type_validated_as": "unknown"})
    _display_result(res)

@util_group.command('format')
@click.argument('input_file', type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option('--output-format', '-of', 'output_format_util',
              type=click.Choice(['json', 'csv', 'text', 'html'], case_sensitive=False), default='json',
              help='Output format')
@click.option('--output-file', '-f', 'output_file_util', type=click.Path(dir_okay=False, writable=True),
              help='Output file (stdout if not specified)')
def format_conversion(input_file: str, output_format_util: str, output_file_util: Optional[str]):
    from .utils.formatters import convert_file_format
    res = convert_file_format(input_file, output_format=output_format_util, output_file=output_file_util)
    if "error" in res: click.echo(click.style(f"Error: {res['error']}", fg="red"))
    elif res.get("message"):
        click.echo(click.style(res["message"], fg="green"))
        if res.get("output_content") and not output_file_util: click.echo(res["output_content"])

# --- Workflow commands ---
@cli.group('workflow')
def workflow_group():
    """Manage and run reconnaissance workflows"""
    pass

@workflow_group.command('list')
def list_workflows():
    """List available reconnaissance workflows"""
    base_path = os.path.dirname(os.path.abspath(__file__))
    workflows_dir = os.path.join(base_path, 'workflows')
    if not os.path.isdir(workflows_dir):
        click.echo(f"Workflows directory not found: {workflows_dir}"); return
    
    wf_list_data = []
    for fname in os.listdir(workflows_dir):
        if fname.endswith('.json'):
            try:
                with open(os.path.join(workflows_dir, fname), 'r', encoding='utf-8') as f:
                    content = json.load(f)
                    wf_list_data.append({
                        "name": content.get("name", os.path.splitext(fname)[0]),
                        "description": content.get("description", "N/A"),
                        "modules_count": len(content.get("modules", [])),
                        "filename": fname
                    })
            except Exception as e: logger.warning(f"Error loading workflow {fname}: {e}")
    
    if not wf_list_data: click.echo("No valid workflows found."); return
    if config.DEFAULT_CONFIG["output_format"] == "json": click.echo(json.dumps(wf_list_data, indent=2)); return
    
    table = [[wf["name"], wf["description"], wf["modules_count"], wf["filename"]] for wf in wf_list_data]
    click.echo(tabulate(table, headers=["Name", "Description", "Modules", "Filename"], tablefmt="simple"))


@workflow_group.command('run')
@click.argument('workflow_name_or_path_run', metavar='WORKFLOW_NAME_OR_PATH')
@click.argument('target_arg_run', metavar='TARGET')
@click.option('--output-dir', '-d', 'output_dir_wf_run', type=click.Path(file_okay=False, dir_okay=True, writable=True, resolve_path=True), help='Directory to save results')
def run_workflow(workflow_name_or_path_run: str, target_arg_run: str, output_dir_wf_run: Optional[str]):
    """Run a predefined reconnaissance workflow on a target"""
    base_path_wf = os.path.dirname(os.path.abspath(__file__))
    workflows_dir_wf = os.path.join(base_path_wf, 'workflows')
    workflow_file: Optional[str] = None

    if os.path.exists(workflow_name_or_path_run) and workflow_name_or_path_run.endswith('.json'):
        workflow_file = workflow_name_or_path_run
    else:
        potential_file = os.path.join(workflows_dir_wf, f"{workflow_name_or_path_run}.json" if not workflow_name_or_path_run.endswith(".json") else workflow_name_or_path_run)
        if os.path.exists(potential_file): workflow_file = potential_file

    if not workflow_file:
        click.echo(f"Workflow '{workflow_name_or_path_run}' not found."); return

    try:
        with open(workflow_file, 'r', encoding='utf-8') as f: workflow_content = json.load(f)
    except Exception as e: click.echo(f"Error loading workflow file {workflow_file}: {e}"); return

    click.echo(f"Running workflow: {workflow_content.get('name', os.path.basename(workflow_file))}")
    click.echo(f"Description: {workflow_content.get('description', 'N/A')}")

    target_type_wf: Optional[str] = None
    if is_valid_ip(target_arg_run): target_type_wf = "ip"
    elif is_valid_url(target_arg_run): target_type_wf = "url"
    elif is_valid_domain(target_arg_run): target_type_wf = "domain"
    if not target_type_wf: click.echo(f"Invalid target for workflow: {target_arg_run}"); return

    effective_output_dir_wf: Optional[str] = None
    workflow_run_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target_name_wf = re.sub(r'[^\w\-_\.]', '_', target_arg_run)
    wf_name_for_dir = os.path.splitext(os.path.basename(workflow_file))[0]

    if output_dir_wf_run:
        effective_output_dir_wf = os.path.join(output_dir_wf_run, f"{safe_target_name_wf}_workflow_{wf_name_for_dir}_{workflow_run_timestamp}")
    elif config.DEFAULT_CONFIG.get("save_results", False): # Use default if saving is on
        effective_output_dir_wf = os.path.join(config.RESULTS_DIR, f"{safe_target_name_wf}_workflow_{wf_name_for_dir}_{workflow_run_timestamp}")
    
    if effective_output_dir_wf:
        click.echo(f"[+] Workflow output will be in: {effective_output_dir_wf}")
        try:
            os.makedirs(effective_output_dir_wf, exist_ok=True)
        except OSError as e:
            click.echo(f"[!] Error creating workflow output directory {effective_output_dir_wf}: {e}. File saving disabled.")
            effective_output_dir_wf = None
    
    consolidated_wf_results: Dict[str, Any] = {
        "workflow_name": workflow_content.get('name', os.path.basename(workflow_file)),
        "target": target_arg_run, "target_type": target_type_wf, "timestamp": workflow_run_timestamp,
        "modules_data": {}
    }

    for mod_spec in workflow_content.get("modules", []):
        mod_name, mod_type, mod_opts = mod_spec.get("name"), mod_spec.get("type", "passive").lower(), mod_spec.get("options", {})
        if not mod_name: click.echo("  Skipping module with no name."); continue
        click.echo(f"\nRunning {mod_type} module: {mod_name}")

        try:
            full_mod_path = f"reconpy.modules.{mod_type}.{mod_name}"
            api_check = config.check_api_requirements(full_mod_path)
            if not api_check["all_configured"]:
                missing = ", ".join([config.API_DEFINITIONS.get(s,{}).get("name",s) for s in api_check.get("missing_services",[])])
                click.echo(click.style(f"  Skipping {mod_name} due to missing API keys for: {missing}", fg="yellow"))
                if not _handle_missing_api_key_prompt(api_check["missing_services"][0] if api_check["missing_services"] else "unknown", 
                                                      config.API_DEFINITIONS.get(api_check["missing_services"][0],{}).get("name","?") if api_check["missing_services"] else "?",
                                                      "Module cannot run."):
                    consolidated_wf_results["modules_data"][mod_name] = {"error": f"Skipped: Missing API keys for {missing}"}; continue
            
            mod_obj = importlib.import_module(f".modules.{mod_type}.{mod_name}", package=__package__)
            action_fn = next((getattr(mod_obj, fn) for fn in ["scan","lookup","search","detect","get_snapshots","scrape","ping","traceroute","grab_banner"] if hasattr(mod_obj, fn)), None)
            if not action_fn:
                click.echo(f"  Module {mod_name} has no compatible interface."); consolidated_wf_results["modules_data"][mod_name] = {"error":"No compatible interface."}; continue
            
            mod_result_data: Dict[str, Any]
            try: mod_result_data = action_fn(target_arg_run, **mod_opts)
            except TypeError as te:
                if ("unexpected keyword argument" in str(te) or "got multiple values for argument" in str(te)) and not mod_opts:
                    try: mod_result_data = action_fn(target_arg_run)
                    except TypeError as te2: click.echo(f"  Module {mod_name} call failed: {te2}"); consolidated_wf_results["modules_data"][mod_name] = {"error":f"Call failed: {te2}"}; continue
                elif "required positional argument" in str(te):
                    click.echo(f"  Module {mod_name} missing required args: {te}"); consolidated_wf_results["modules_data"][mod_name] = {"error":f"Missing args: {te}"}; continue
                else: raise te
            
            _display_result(mod_result_data)
            consolidated_wf_results["modules_data"][mod_name] = mod_result_data

            if effective_output_dir_wf:
                mod_json_path = os.path.join(effective_output_dir_wf, f"{safe_target_name_wf}_workflow_module_{mod_name}_{workflow_run_timestamp}.json")
                mod_html_path = os.path.join(effective_output_dir_wf, f"{safe_target_name_wf}_workflow_module_{mod_name}_{workflow_run_timestamp}.html")
                try:
                    with open(mod_json_path, 'w', encoding='utf-8') as f: json.dump(mod_result_data, f, indent=2, default=str)
                    click.echo(f"  Workflow module JSON results saved: {mod_json_path}")
                    from .utils.formatters import format_output
                    mod_html_content = format_output(mod_result_data, output_format="html")
                    with open(mod_html_path, 'w', encoding='utf-8') as f: f.write(mod_html_content)
                    click.echo(f"  Workflow module HTML results saved: {mod_html_path}")
                except Exception as e: click.echo(f"  Error saving/formatting module {mod_name} results: {e}")

        except ImportError as e: click.echo(f"  Error importing module {mod_name} ({full_mod_path}): {e}"); consolidated_wf_results["modules_data"][mod_name]={"error":f"Import error: {e}"}
        except Exception as e: click.echo(f"  Error running module {mod_name}: {e}"); consolidated_wf_results["modules_data"][mod_name]={"error":f"Runtime error: {e}"}; logger.exception(f"Full error in module {mod_name}:")
    
    if effective_output_dir_wf:
        consolidated_json_path = os.path.join(effective_output_dir_wf, f"{safe_target_name_wf}_workflow_{wf_name_for_dir}_consolidated_{workflow_run_timestamp}.json")
        consolidated_html_path = os.path.join(effective_output_dir_wf, f"{safe_target_name_wf}_workflow_{wf_name_for_dir}_consolidated_{workflow_run_timestamp}.html")
        try:
            with open(consolidated_json_path, 'w', encoding='utf-8') as f: json.dump(consolidated_wf_results, f, indent=2, default=str)
            click.echo(f"\n[+] Consolidated workflow JSON report saved: {consolidated_json_path}")
            from .utils.formatters import format_output
            html_content = format_output(consolidated_wf_results, output_format="html")
            with open(consolidated_html_path, 'w', encoding='utf-8') as f: f.write(html_content)
            click.echo(f"[+] Consolidated workflow HTML report saved: {consolidated_html_path}")
        except Exception as e: click.echo(f"[!] Error saving consolidated workflow reports: {e}"); logger.error(f"Consolidated workflow report error: {e}", exc_info=True)
    
    click.echo("\nWorkflow execution completed.")


def _display_result(result_data_display: Optional[Dict[str, Any]]):
    if result_data_display is None: click.echo("No results to display."); return
    from .utils.formatters import format_output
    click.echo(format_output(result_data_display, config.DEFAULT_CONFIG["output_format"]))

def _handle_missing_api_key_prompt(service_id: str, service_name: str, extra_message: str = "") -> bool:
    """Helper for API key prompts. Returns True if OK to proceed."""
    click.echo(click.style(f"{service_name} API key not configured. {extra_message}", fg="yellow"))
    if click.confirm(f"Configure {service_name} API key now?"):
        if not config.prompt_for_api_key(service_id):
            click.echo(click.style(f"{service_name} API key config failed/cancelled.", fg="red")); return False
        
        mod_path_check = next((mod for sid, info in config.API_DEFINITIONS.items() for mod in info.get("required_for",[]) if sid == service_id), "")
        if not mod_path_check: # Fallback if not found via API_DEFINITIONS structure
            if service_id == "github": mod_path_check = "reconpy.modules.passive.public_repos"
            elif service_id == "virustotal": mod_path_check = "reconpy.modules.active.web_vulnerabilities"
            elif service_id in ["shodan", "censys"]: mod_path_check = f"reconpy.modules.passive.{service_id}_search"
        
        if mod_path_check:
            api_check_post_prompt = config.check_api_requirements(mod_path_check)
            if not api_check_post_prompt["all_configured"]:
                click.echo(click.style(f"{service_name} API key still not configured properly.", fg="red")); return False
        click.echo(click.style(f"{service_name} API key configured.", fg="green")); return True
    else:
        click.echo(click.style(f"{service_name} operation cannot proceed without API key.", fg="red")); return False

def main_entry():
    try: cli(standalone_mode=False)
    except Exception as e:
        print(f"Critical Error: {str(e)}", file=sys.stderr)
        if logger.handlers:
            if config.DEFAULT_CONFIG.get("verbosity", config.VerbosityLevel.NORMAL) >= config.VerbosityLevel.DEBUG:
                logger.exception("Unhandled error:")
            else: logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main_entry()