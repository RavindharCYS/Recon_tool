"""
Formatters module - format output in various ways
"""
import json
import csv
import logging
import io
import os
from typing import Dict, List, Any, Optional, Union
from tabulate import tabulate
import yaml

logger = logging.getLogger(__name__)

def format_output(data: Any, output_format: str = "text") -> str:
    """
    Format data for output.
    
    Args:
        data: Data to format
        output_format: Format to use (text, json, csv)
        
    Returns:
        Formatted string
    """
    if output_format == "json":
        return format_json(data)
    elif output_format == "csv":
        return format_csv(data)
    else:  # Default to text
        return format_text(data)

def format_json(data: Any) -> str:
    """
    Format data as JSON.
    
    Args:
        data: Data to format
        
    Returns:
        JSON string
    """
    try:
        return json.dumps(data, indent=2, sort_keys=True, default=str)
    except Exception as e:
        logger.error(f"Error formatting JSON: {str(e)}")
        return f"Error formatting JSON: {str(e)}"

def format_csv(data: Any) -> str:
    """
    Format data as CSV.
    
    Args:
        data: Data to format
        
    Returns:
        CSV string
    """
    try:
        # Handle different data types
        if isinstance(data, dict):
            # Try to convert dict to list of dicts
            if all(isinstance(v, dict) for v in data.values()):
                # Dict of dicts, convert to list of dicts with ID field
                rows = []
                for k, v in data.items():
                    row = {"id": k}
                    row.update(v)
                    rows.append(row)
                data = rows
            elif any(isinstance(v, (list, dict)) for v in data.values()):
                # Complex dict, flatten to single level
                data = [{"key": k, "value": str(v)} for k, v in data.items()]
            else:
                # Simple dict
                data = [{"key": k, "value": v} for k, v in data.items()]
        
        if isinstance(data, list):
            # Ensure all elements are dictionaries
            if all(isinstance(item, dict) for item in data):
                # Get all possible field names from all dictionaries
                fieldnames = set()
                for item in data:
                    fieldnames.update(item.keys())
                
                # Create CSV
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
                return output.getvalue()
            else:
                # List of non-dicts, convert to simple CSV
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["value"])
                for item in data:
                    writer.writerow([item])
                return output.getvalue()
        
        # Fallback for other data types
        return f"Cannot format as CSV: {type(data)}"
    
    except Exception as e:
        logger.error(f"Error formatting CSV: {str(e)}")
        return f"Error formatting CSV: {str(e)}"

def format_text(data: Any) -> str:
    """
    Format data as human-readable text.
    
    Args:
        data: Data to format
        
    Returns:
        Formatted text string
    """
    try:
        # Handle different data types
        if isinstance(data, dict):
            # Check for specific dictionary structures we know how to handle
            if "vulnerabilities" in data and "information" in data:
                # This is a web vulnerability scan result
                return format_web_scan_result(data)
            elif "open_ports" in data and "target" in data:
                # This is a port scan result
                return format_port_scan_result(data)
            elif "hops" in data and "target" in data:
                # This is a traceroute result
                return format_traceroute_result(data)
            else:
                # Generic dictionary formatter
                return format_dict(data)
        
        elif isinstance(data, list):
            # Check if it's a list of dictionaries with common keys
            if all(isinstance(item, dict) for item in data) and len(data) > 0:
                # If all dictionaries have similar structure, format as table
                common_keys = set.intersection(*[set(item.keys()) for item in data])
                if common_keys:
                    return tabulate([{k: item[k] for k in common_keys} for item in data], 
                                   headers="keys", tablefmt="simple")
            
            # Simple list formatter
            return "\n".join([f"{i+1}. {str(item)}" for i, item in enumerate(data)])
        
        else:
            # Convert other types to string
            return str(data)
    
    except Exception as e:
        logger.error(f"Error formatting text: {str(e)}")
        return f"Error formatting text: {str(e)}"

def format_dict(data: Dict[str, Any], indent: int = 0) -> str:
    """
    Format a dictionary as indented text.
    
    Args:
        data: Dictionary to format
        indent: Current indentation level
        
    Returns:
        Formatted text string
    """
    result = []
    prefix = " " * indent
    
    for key, value in data.items():
        if isinstance(value, dict):
            result.append(f"{prefix}{key}:")
            result.append(format_dict(value, indent + 2))
        elif isinstance(value, list):
            if not value:
                result.append(f"{prefix}{key}: []")
            elif all(isinstance(item, dict) for item in value):
                result.append(f"{prefix}{key}:")
                for item in value:
                    result.append(f"{prefix}  - {format_dict(item, indent + 4)}")
            else:
                result.append(f"{prefix}{key}:")
                for item in value:
                    result.append(f"{prefix}  - {str(item)}")
        else:
            result.append(f"{prefix}{key}: {value}")
    
    return "\n".join(result)

def format_web_scan_result(data: Dict[str, Any]) -> str:
    """
    Format a web vulnerability scan result.
    
    Args:
        data: Scan result to format
        
    Returns:
        Formatted text string
    """
    result = []
    
    # Add header
    result.append("=" * 60)
    result.append(f"Web Vulnerability Scan for {data['url']}")
    result.append(f"Scan Type: {data['scan_type']}")
    if 'duration_seconds' in data:
        result.append(f"Duration: {data['duration_seconds']} seconds")
    result.append("=" * 60)
    
    # Add summary
    result.append("\n[Summary]")
    summary = data.get("summary", {})
    result.append(f"High Risk Vulnerabilities: {summary.get('high_risk', 0)}")
    result.append(f"Medium Risk Vulnerabilities: {summary.get('medium_risk', 0)}")
    result.append(f"Low Risk Vulnerabilities: {summary.get('low_risk', 0)}")
    result.append(f"Informational Items: {summary.get('info', 0)}")
    
    # Add vulnerabilities
    if data.get("vulnerabilities"):
        result.append("\n[Vulnerabilities]")
        for i, vuln in enumerate(data["vulnerabilities"], 1):
            result.append(f"\n{i}. {vuln.get('name', 'Unknown')} ({vuln.get('risk', 'unknown').upper()})")
            result.append(f"   Description: {vuln.get('description', 'No description')}")
            if 'evidence' in vuln:
                result.append(f"   Evidence: {vuln['evidence']}")
            if 'recommendation' in vuln:
                result.append(f"   Recommendation: {vuln['recommendation']}")
    
    # Add information items
    if data.get("information"):
        result.append("\n[Information]")
        for i, info in enumerate(data["information"], 1):
            result.append(f"\n{i}. {info.get('name', 'Unknown')}")
            result.append(f"   Description: {info.get('description', 'No description')}")
            if 'evidence' in info:
                result.append(f"   Evidence: {info['evidence']}")
    
    # Add security headers
    if data.get("security_headers"):
        result.append("\n[Security Headers]")
        headers = data["security_headers"]
        for header, info in headers.items():
            status = "✓ Present" if info.get("present") else "✗ Missing"
            result.append(f"{header}: {status}")
            if info.get("value"):
                result.append(f"  Value: {info['value']}")
    
    return "\n".join(result)

def format_port_scan_result(data: Dict[str, Any]) -> str:
    """
    Format a port scan result.
    
    Args:
        data: Scan result to format
        
    Returns:
        Formatted text string
    """
    result = []
    
    # Add header
    result.append("=" * 60)
    result.append(f"Port Scan for {data['target']} ({data.get('target_ip', 'Unknown IP')})")
    result.append(f"Scan Method: {data.get('scan_method', 'Unknown')}")
    if 'duration_seconds' in data:
        result.append(f"Duration: {data['duration_seconds']} seconds")
    result.append("=" * 60)
    
    # Add summary
    result.append("\n[Summary]")
    if 'summary' in data:
        summary = data["summary"]
        result.append(f"Total Ports Scanned: {summary.get('total_ports_scanned', 0)}")
        result.append(f"Open Ports: {summary.get('total_open_ports', 0)}")
        result.append(f"TCP Open: {summary.get('tcp_open_count', 0)}")
        result.append(f"UDP Open: {summary.get('udp_open_count', 0)}")
    
    # Add open TCP ports
    if data.get("open_ports", {}).get("tcp"):
        result.append("\n[Open TCP Ports]")
        tcp_ports = data["open_ports"]["tcp"]
        if tcp_ports:
            # Format as table
            table_data = []
            for port_info in tcp_ports:
                row = [
                    port_info.get("port"),
                    port_info.get("service", "unknown"),
                    port_info.get("state", "open"),
                    port_info.get("banner", "")[:50] + ("..." if port_info.get("banner", "") and len(port_info.get("banner", "")) > 50 else "")
                ]
                table_data.append(row)
            
            result.append(tabulate(table_data, headers=["Port", "Service", "State", "Banner"], tablefmt="simple"))
        else:
            result.append("No open TCP ports found.")
    
    # Add open UDP ports
    if data.get("open_ports", {}).get("udp"):
        result.append("\n[Open UDP Ports]")
        udp_ports = data["open_ports"]["udp"]
        if udp_ports:
            # Format as table
            table_data = []
            for port_info in udp_ports:
                row = [
                    port_info.get("port"),
                    port_info.get("service", "unknown"),
                    port_info.get("state", "open|filtered")
                ]
                table_data.append(row)
            
            result.append(tabulate(table_data, headers=["Port", "Service", "State"], tablefmt="simple"))
        else:
            result.append("No open UDP ports found.")
    
    return "\n".join(result)

def format_traceroute_result(data: Dict[str, Any]) -> str:
    """
    Format a traceroute result.
    
    Args:
        data: Traceroute result to format
        
    Returns:
        Formatted text string
    """
    result = []
    
    # Add header
    result.append("=" * 60)
    result.append(f"Traceroute to {data['target']} ({data.get('target_ip', 'Unknown IP')})")
    result.append("=" * 60)
    
    # Add hops
    if data.get("hops"):
        result.append("\n[Route]")
        
        # Format as table
        table_data = []
        for hop in data["hops"]:
            if hop.get("timeout", False):
                row = [hop.get("hop"), "* * *", "", "Request timed out"]
            else:
                ip = hop.get("ip", "")
                hostname = hop.get("hostname", "")
                rtt = f"{hop.get('rtt_ms', 0):.1f} ms" if hop.get('rtt_ms') is not None else ""
                
                row = [hop.get("hop"), ip, hostname, rtt]
            
            table_data.append(row)
        
        result.append(tabulate(table_data, headers=["Hop", "IP Address", "Hostname", "RTT"], tablefmt="simple"))
        
        # Add completion status
        if "reached_target" in data:
            if data["reached_target"]:
                result.append("\nTrace complete. Target reached.")
            else:
                result.append("\nTrace incomplete. Target not reached.")
    else:
        result.append("\nNo route information available.")
    
    return "\n".join(result)

def convert_file_format(input_file: str, output_format: str = "json", output_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert a file between different formats.
    
    Args:
        input_file: Path to input file
        output_format: Desired output format (json, csv, text)
        output_file: Path to output file (stdout if None)
        
    Returns:
        Dictionary with conversion result
    """
    result = {
        "input_file": input_file,
        "output_format": output_format,
        "output_file": output_file,
        "success": False
    }
    
    try:
        # Read input file
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Determine input format
        input_format = os.path.splitext(input_file)[1].lower()
        
        # Parse input data
        if input_format == '.json':
            data = json.loads(content)
        elif input_format == '.yaml' or input_format == '.yml':
            data = yaml.safe_load(content)
        elif input_format == '.csv':
            # Parse CSV
            reader = csv.DictReader(io.StringIO(content))
            data = list(reader)
        else:
            # Assume text or unknown
            data = {"content": content}
        
        # Format output
        if output_format == 'json':
            output_content = format_json(data)
        elif output_format == 'csv':
            output_content = format_csv(data)
        else:  # text
            output_content = format_text(data)
        
        # Write output
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_content)
            result["message"] = f"Converted {input_file} to {output_file} in {output_format} format"
        else:
            result["output_content"] = output_content
            result["message"] = f"Converted {input_file} to {output_format} format"
        
        result["success"] = True
        return result
    
    except json.JSONDecodeError:
        result["error"] = "Invalid JSON in input file"
        return result
    
    except yaml.YAMLError:
        result["error"] = "Invalid YAML in input file"
        return result
    
    except Exception as e:
        result["error"] = f"Error converting file: {str(e)}"
        return result