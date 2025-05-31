# recon_tool/utils/formatters.py

import json
import csv
import io
import os
from typing import Dict, List, Any, Optional, Tuple
from tabulate import tabulate
import html

# --- Enhanced HTML Formatting Logic ---

CSS_STYLES = """
<style>
    /* Reset and Base Styles */
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        line-height: 1.7; /* Slightly increased line height */
        color: #374151; /* Softer black */
        background-color: #f9fafb; /* Very light grey, almost white */
        font-size: 15px; /* Slightly smaller base font for more content */
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
    }
    .container {
        max-width: 1400px; /* Wider for more complex data */
        margin: 25px auto;
        background-color: #ffffff;
        padding: 25px 35px;
        border-radius: 12px; /* Softer radius */
        box-shadow: 0 6px 25px rgba(0, 0, 0, 0.07);
        border: 1px solid #e5e7eb; /* Lighter border */
    }

    /* Headings */
    h1, h2, h3, h4 {
        font-weight: 600; /* Semi-bold */
        color: #1f2937; /* Darker grey for headings */
        margin-bottom: 0.7em;
        line-height: 1.3;
    }
    h1 {
        font-size: 2.4em;
        text-align: center;
        border-bottom: 3px solid #3b82f6; /* Tailwind Blue 500 */
        padding-bottom: 18px;
        margin-bottom: 28px;
        color: #3b82f6;
    }
    h2 { /* Module Titles */
        font-size: 1.9em;
        color: #1d4ed8; /* Tailwind Blue 700 */
        padding-bottom: 12px;
        border-bottom: 2px solid #eff6ff; /* Tailwind Blue 50 */
        margin-top: 45px;
        margin-bottom: 22px;
    }
    h3 { /* Sub-sections within modules or main target display */
        font-size: 1.5em;
        color: #2563eb; /* Tailwind Blue 600 */
        margin-top: 30px;
        margin-bottom: 12px;
    }
    h4 { /* Finding Titles / Further sub-sections */
        font-size: 1.25em;
        color: #10b981; /* Tailwind Emerald 500 */
        margin-top: 22px;
        margin-bottom: 8px;
    }

    /* Paragraphs and Links */
    p {
        margin-bottom: 0.8em;
    }
    a {
        color: #3b82f6;
        text-decoration: none;
        font-weight: 500;
        transition: color 0.2s ease-in-out;
    }
    a:hover, a:focus {
        text-decoration: underline;
        color: #1d4ed8;
    }

    /* Lists */
    ul, ol {
        margin-left: 22px;
        margin-bottom: 0.8em;
        padding-left: 5px; /* Add some padding inside the list marker */
    }
    li {
        margin-bottom: 0.6em;
    }
    ul ul, ol ol { margin-top: 0.4em; margin-bottom: 0.4em;} /* Spacing for nested lists */


    /* Tables */
    table {
        width: 100%;
        border-collapse: separate; /* Allows for border-spacing and rounded corners on cells */
        border-spacing: 0;
        margin-bottom: 22px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
        border-radius: 8px;
        border: 1px solid #d1d5db; /* Tailwind Gray 300 */
        overflow: auto; /* Add scroll for very wide tables on small screens */
        display: block; /* Needed for overflow: auto to work well on tables */
        max-width: 100%;
    }
    thead tr th:first-child { border-top-left-radius: 7px; }
    thead tr th:last-child { border-top-right-radius: 7px; }
    tbody tr:last-child td:first-child { border-bottom-left-radius: 7px; }
    tbody tr:last-child td:last-child { border-bottom-right-radius: 7px; }

    th, td {
        padding: 10px 15px; /* Slightly less padding */
        text-align: left;
        vertical-align: top;
        border-bottom: 1px solid #e5e7eb; /* Tailwind Gray 200 */
        /* ADDED FOR WRAPPING */
        word-wrap: break-word; /* Standard property */
        overflow-wrap: break-word; /* Newer standard, more robust */
        /* max-width: 300px; /* Optional: Set a max-width for cells to force wrapping */
                           /* Adjust as needed, or remove if automatic wrapping is sufficient */
    }
    td { background-color: #fff; }
    th {
        background-color: #60a5fa; /* Tailwind Blue 400 - Lighter, more modern */
        color: white;
        font-weight: 500; /* Slightly less bold */
        text-transform: capitalize;
        position: sticky; /* Make headers sticky for scrollable tables */
        top: 0;
        z-index: 10;
    }
    tr:nth-child(even) td {
        background-color: #f9fafb;
    }
    tr:hover td {
        background-color: #f3f4f6; /* Tailwind Gray 100 on hover */
    }
    td ul, td ol, td dl { /* Reduce margins for lists/dls inside table cells */
        margin-top: 0.3em;
        margin-bottom: 0.3em;
        font-size: 0.95em;
    }
    td pre { /* Code blocks in tables */
        font-size: 0.85em;
        padding: 8px;
        margin-top: 5px;
        max-height: 150px; /* Limit height of code blocks in cells */
        overflow-y: auto;
    }


    /* Definition Lists (Key-Value pairs) */
    dl {
        margin-bottom: 0.8em;
        padding-left: 5px;
    }
    dt {
        font-weight: 500;
        color: #4b5563; /* Tailwind Gray 600 */
        margin-top: 0.7em;
    }
    dd {
        margin-left: 15px;
        margin-bottom: 0.7em;
        padding-left: 8px;
        border-left: 2px solid #e5e7eb;
        color: #6b7280; /* Tailwind Gray 500 for dd content */
    }
    dd > dl { margin-left: 0; padding-left: 3px; }


    /* Code and Preformatted Text */
    pre, code, .evidence {
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
        font-size: 0.9em; /* Slightly smaller for code */
        border-radius: 6px; /* Softer radius */
    }
    pre {
        background-color: #1f2937; /* Tailwind Gray 800 */
        color: #d1d5db;      /* Tailwind Gray 300 */
        padding: 16px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        border: 1px solid #374151; /* Tailwind Gray 700 */
        margin-bottom: 0.8em;
    }
    code:not(.evidence) {
        background-color: #e5e7eb; /* Tailwind Gray 200 */
        color: #1e293b; /* Tailwind Slate 800 */
        padding: 0.2em 0.5em;
        border-radius: 4px;
    }
    .evidence {
        display: block;
        background-color: #f3f4f6; /* Tailwind Gray 100 */
        color: #374151;
        padding: 10px 12px;
        border: 1px solid #e5e7eb;
        margin-top: 0.4em;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 200px; /* Prevent extremely long evidence blocks */
        overflow-y: auto;
    }

    /* Module Sections */
    .module-section {
        margin-bottom: 35px;
        padding: 22px 28px;
        background-color: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 10px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.05);
    }
    .module-content {
        margin-top: 12px;
    }

    /* Findings Styling */
    .finding {
        margin-bottom: 18px;
        padding: 18px 22px;
        border-radius: 8px;
        border-width: 1px 1px 1px 6px;
        border-style: solid;
        box-shadow: 0 3px 8px rgba(0,0,0,0.04);
    }
    .finding h4 { margin-top: 0; margin-bottom: 8px; font-size: 1.2em; }
    .finding p { margin-bottom: 6px; font-size: 0.95em; }
    .finding strong.key-label { color: #374151; }

    .finding-risk-critical { border-color: #dc2626 #e5e7eb #e5e7eb #dc2626; background-color: #fee2e2; } /* Tailwind Red 600, Red 50 */
    .finding-risk-critical h4 { color: #b91c1c; } /* Tailwind Red 700 */
    .finding-risk-high { border-color: #ef4444 #e5e7eb #e5e7eb #ef4444; background-color: #fee2e2; } /* Tailwind Red 500, Red 50 */
    .finding-risk-high h4 { color: #dc2626; } /* Tailwind Red 600 */
    .finding-risk-medium { border-color: #f59e0b #e5e7eb #e5e7eb #f59e0b; background-color: #fffbeb; } /* Tailwind Amber 500, Amber 50 */
    .finding-risk-medium h4 { color: #d97706; } /* Tailwind Amber 600 */
    .finding-risk-low { border-color: #10b981 #e5e7eb #e5e7eb #10b981; background-color: #ecfdf5; } /* Tailwind Emerald 500, Emerald 50 */
    .finding-risk-low h4 { color: #059669; } /* Tailwind Emerald 600 */
    .finding-risk-informational { border-color: #3b82f6 #e5e7eb #e5e7eb #3b82f6; background-color: #eff6ff; } /* Tailwind Blue 500, Blue 50 */
    .finding-risk-informational h4 { color: #2563eb; } /* Tailwind Blue 600 */


    /* Utility Classes */
    .error-message {
        color: #991b1b; /* Tailwind Red 800 */
        font-weight: 500;
        background-color: #fee2e2; /* Tailwind Red 50 */
        padding: 12px 15px;
        border: 1px solid #fecaca; /* Tailwind Red 200 */
        border-left-width: 5px;
        border-left-color: #ef4444; /* Tailwind Red 500 */
        border-radius: 6px;
        margin-bottom: 1.2em;
    }
    .info-message {
        color: #1e40af; /* Tailwind Blue 800 */
        background-color: #eff6ff; /* Tailwind Blue 50 */
        padding: 12px 15px;
        border: 1px solid #bfdbfe; /* Tailwind Blue 200 */
        border-left-width: 5px;
        border-left-color: #3b82f6; /* Tailwind Blue 500 */
        border-radius: 6px;
        margin-bottom: 1.2em;
    }
    .timestamp {
        font-size: 0.9em;
        color: #6b7280; /* Tailwind Gray 500 */
        text-align: right;
        margin-bottom: 18px;
    }
    .empty-value {
        font-style: italic;
        color: #9ca3af; /* Tailwind Gray 400 */
    }
    .key-label {
        font-weight: 500;
        color: #4b5563; /* Tailwind Gray 600 */
    }

    /* Footer */
    .footer {
        text-align: center;
        margin-top: 35px;
        padding-top: 25px;
        border-top: 1px solid #e5e7eb;
        font-size: 0.88em;
        color: #6b7280;
    }
    
    /* Responsive adjustments */
    @media (max-width: 992px) { /* Wider breakpoint for responsiveness */
        .container { margin: 20px; padding: 20px 25px; }
        h1 { font-size: 2.1em; }
        h2 { font-size: 1.7em; }
        table { font-size: 0.95em; } /* Slightly smaller table font on medium screens */
    }
    @media (max-width: 768px) {
        body { font-size: 14px; }
        .container { margin: 15px; padding: 15px 20px; }
        h1 { font-size: 1.9em; }
        h2 { font-size: 1.5em; }
        h3 { font-size: 1.3em; }
        th, td { padding: 8px 10px; }
        pre { padding: 10px; font-size: 0.88em; }
        dd { margin-left: 10px; padding-left: 6px;}
        .finding { padding: 15px; }
    }
    @media (max-width: 480px) {
        table { display: block; /* Force table to not be wider than its container */ width: 100%; }
        thead, tbody, th, td, tr { display: block; } /* Stack table cells */
        thead tr { position: absolute; top: -9999px; left: -9999px; } /* Hide headers visually but keep for accessibility */
        tr { border: 1px solid #d1d5db; margin-bottom: 10px; border-radius: 6px; }
        td {
            border: none;
            border-bottom: 1px solid #e5e7eb;
            position: relative;
            padding-left: 50%; /* Make space for the label */
            white-space: normal; /* Allow wrapping in stacked cells */
            text-align: right; /* Align data to the right */
        }
        td:before {
            position: absolute;
            top: 8px;
            left: 10px;
            width: 45%;
            padding-right: 10px;
            white-space: nowrap;
            text-align: left;
            font-weight: 600;
            color: #4b5563;
            content: attr(data-label); /* Use data-label for cell headers */
        }
    }
</style>
"""

# _is_finding_like and _render_finding_html remain the same as the previous good version.
# The main changes will be in _render_html_value for how lists/dicts are handled within tables
# and in _format_to_html for the table generation part (adding data-label).

def _is_finding_like(data_dict: Dict[str, Any]) -> bool:
    """Heuristically identifies dictionaries that represent vulnerability findings."""
    if not isinstance(data_dict, dict):
        return False
    keys = data_dict.keys()
    return all(k in keys for k in ['name', 'risk', 'description']) or \
           all(k in keys for k in ['type', 'details', 'severity'])

def _render_finding_html(finding_data: Dict[str, Any]) -> str:
    """Formats a 'finding' dictionary into a styled HTML block."""
    risk = finding_data.get('risk', finding_data.get('severity', 'informational')).lower()
    name = finding_data.get('name', finding_data.get('type', 'N/A'))
    description = finding_data.get('description', finding_data.get('details', 'N/A'))
    
    html_parts = [f'<div class="finding finding-risk-{html.escape(risk)}">']
    html_parts.append(f'<h4>{html.escape(name)} (Risk: {html.escape(risk.capitalize())})</h4>')
    
    if description and description != 'N/A':
        html_parts.append(f'<p>{_render_html_value(description)}</p>') # Render description to handle links etc.
    
    preferred_order = ['evidence', 'recommendation', 'cwe', 'url_tested', 'confidence', 'reason', 'payload', 'status_code', 'details']
    main_display_keys = {'name', 'risk', 'description', 'type', 'severity', 'timestamp'}
    
    details_dl = ["<dl>"]
    has_details = False

    all_keys = list(finding_data.keys())
    # Prioritize preferred_order, then alphabetical for the rest
    sorted_keys = [pk for pk in preferred_order if pk in all_keys] + \
                  sorted([k for k in all_keys if k not in preferred_order and k not in main_display_keys])

    for key in sorted_keys:
        if key in main_display_keys : continue # Already handled or part of main display
        value = finding_data[key]
        if value or isinstance(value, (bool, int, float)): 
            value_html = _render_html_value(value, is_evidence=(key == 'evidence' or key.endswith("_hex")), level=1)
            details_dl.append(f"<dt>{html.escape(key.replace('_', ' ').capitalize())}</dt><dd>{value_html}</dd>")
            has_details = True
            
    details_dl.append("</dl>")
    if has_details:
        html_parts.extend(details_dl)
        
    html_parts.append('</div>')
    return "".join(html_parts)

def _render_html_value(value: Any, is_evidence: bool = False, level: int = 0, in_table_cell: bool = False) -> str:
    """Recursively renders a Python data structure to an HTML string."""
    MAX_LIST_ITEMS_IN_CELL = 5 # Max list items to show directly in a table cell before truncating

    if isinstance(value, dict):
        if not value: return "<em class='empty-value'>(empty dictionary)</em>"
        if _is_finding_like(value) and level > 0 : 
            return _render_finding_html(value)

        parts = ["<dl class='nested-dl'>"]
        for k_item, v_item in value.items():
            treat_as_evidence = is_evidence or str(k_item).lower() in ['evidence', 'banner', 'banner_text', 'raw_output', 'content_preview', 'content'] or \
                                str(k_item).lower().endswith('_hex')
            v_html = _render_html_value(v_item, is_evidence=treat_as_evidence, level=level + 1, in_table_cell=in_table_cell)
            parts.append(f"<dt>{html.escape(str(k_item).replace('_', ' ').capitalize())}</dt><dd>{v_html}</dd>")
        parts.append("</dl>")
        return "".join(parts)

    elif isinstance(value, list):
        if not value: return "<em class='empty-value'>(empty list)</em>"
        
        if value and all(isinstance(item, dict) and _is_finding_like(item) for item in value):
            return "".join([_render_finding_html(item) for item in value])
        
        # If in a table cell, show a summary for long lists or complex lists
        if in_table_cell and (len(value) > MAX_LIST_ITEMS_IN_CELL or not all(isinstance(i, (str, int, float, bool, type(None))) for i in value)):
            if value and isinstance(value[0], dict) and _is_finding_like(value[0]): # List of findings
                 return f"<em class='empty-value'>({len(value)} findings, see details)</em>"
            return f"<em class='empty-value'>({len(value)} items, see details if available)</em>"


        # Table rendering for list of dicts (outside of table cells or for simple lists in cells)
        if value and all(isinstance(item, dict) for item in value):
            # Collect all unique keys to handle varying dict structures in the list
            all_keys_set = set()
            for item_dict_keys in value:
                all_keys_set.update(item_dict_keys.keys())
            
            if all_keys_set: # Ensure there are keys to form headers
                # Maintain a somewhat consistent order for headers if possible
                first_item_keys_order = list(value[0].keys()) if value[0] else []
                ordered_headers_list = sorted(list(all_keys_set), key=lambda k: (first_item_keys_order.index(k) if k in first_item_keys_order else float('inf'), k))

                headers_html = [html.escape(str(k).replace('_', ' ').capitalize()) for k in ordered_headers_list]
                rows_html = ""
                for item_dict_row in value: # Renamed item_dict
                    cells_html = ""
                    for k_header in ordered_headers_list: # Renamed k_val
                        cell_value = item_dict_row.get(k_header) # Use .get() for safety
                        # Add data-label for responsive tables
                        cells_html += f"<td data-label='{html.escape(str(k_header).replace('_', ' ').capitalize())}'>{_render_html_value(cell_value, level=level+1, in_table_cell=True)}</td>"
                    rows_html += f"<tr>{cells_html}</tr>"
                return f"<table><thead><tr><th>{'</th><th>'.join(headers_html)}</th></tr></thead><tbody>{rows_html}</tbody></table>"

        # Default list rendering (e.g., list of strings)
        parts = ["<ul>"]
        for i, item_val in enumerate(value):
            if in_table_cell and i >= MAX_LIST_ITEMS_IN_CELL:
                parts.append(f"<li><em class='empty-value'>... and {len(value) - MAX_LIST_ITEMS_IN_CELL} more</em></li>")
                break
            parts.append(f"<li>{_render_html_value(item_val, level=level+1, in_table_cell=in_table_cell)}</li>")
        parts.append("</ul>")
        return "".join(parts)

    elif isinstance(value, bool):
        return "<strong>True</strong>" if value else "<strong>False</strong>"
    
    elif isinstance(value, (int, float)):
        return html.escape(str(value))
        
    elif isinstance(value, str):
        if not value: return "<em class='empty-value'>(empty string)</em>"
        escaped_value = html.escape(value)
        if is_evidence:
            return f'<code class="evidence">{escaped_value}</code>'
        
        # Make URLs clickable only if they are standalone and simple
        is_simple_url = (value.startswith("http://") or value.startswith("https://")) and \
                        (' ' not in value and '\n' not in value and '\r' not in value) and \
                        len(value) < 200 # Avoid making overly long strings into links

        if is_simple_url:
            return f'<a href="{escaped_value}" target="_blank" rel="noopener noreferrer">{escaped_value}</a>'
        
        # Use <pre> for long multi-line strings, or strings with many special chars that might imply code/log
        if ('\n' in value and len(value) > 80) or (len(value) > 150 and any(c in value for c in ['{', '}', '[', ']', '<', '>'])):
             return f"<pre>{escaped_value}</pre>"
        
        # For table cells, truncate very long strings
        if in_table_cell and len(escaped_value) > 150: # Max length for string in a cell before truncation
            return f"{escaped_value[:150]}<em class='empty-value'>... (truncated)</em>"
            
        return escaped_value
        
    elif value is None:
        return "<em class='empty-value'>N/A</em>"
        
    return html.escape(str(value))


def _format_to_html(data: Dict[str, Any], report_title_prefix: str = "ReconPy Report") -> str:
    """Constructs the full HTML page for the given data."""
    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
    ]

    main_title_val = html.escape(report_title_prefix)
    page_target_info = ""
    target_display_value = "" 
    if isinstance(data, dict):
        target_keys = ['target_url', 'target_input', 'target', 'domain', 'domain_input', 'query', 'url_analyzed', 'username_searched', 'email_searched', 'input_source', 'workflow_name']
        for tk in target_keys:
            target_value = data.get(tk)
            if target_value and isinstance(target_value, str):
                main_title_val_base = "ReconPy Report"
                if tk == "workflow_name": # Special handling for workflow reports
                    main_title_val_base = f"Workflow Report: {html.escape(target_value)}"
                    target_from_data = data.get('target', data.get('target_arg_run', '')) # Get actual target for workflow
                    if target_from_data:
                         target_display_value = html.escape(target_from_data)
                         page_target_info = f"<h3>For Target: {target_display_value}</h3>"
                else:
                    target_display_value = html.escape(target_value)
                    page_target_info = f"<h3>Target: {target_display_value}</h3>"
                main_title_val = main_title_val_base
                break
    
    final_page_title = main_title_val
    if target_display_value and "Target:" not in main_title_val and "Workflow Report:" not in main_title_val : # Add target to browser title if not already part of main title
        final_page_title += f" - {target_display_value}"

    html_parts.append(f"<title>{final_page_title}</title>")
    html_parts.append(CSS_STYLES)
    html_parts.append("</head><body><div class='container'>")
    html_parts.append(f"<h1>{main_title_val}</h1>")
    if page_target_info:
        html_parts.append(page_target_info)

    # Consolidated report from all_in_one_recon
    if isinstance(data, dict) and "results" in data and "modules_run" in data:
        report_data = data
        timestamp_val = report_data.get('timestamp', 'N/A')
        target_type_val = report_data.get('target_type', 'N/A')
        scan_params = report_data.get('scan_parameters', {})
        
        html_parts.append(f"<p class='timestamp'>Report Generated: {html.escape(str(timestamp_val))}</p>")
        if target_type_val and target_type_val != 'N/A':
            html_parts.append(f"<p><strong class='key-label'>Target Type:</strong> {html.escape(str(target_type_val))}</p>")
        if scan_params:
            params_str = ", ".join(f"<strong class='key-label'>{k.replace('_',' ').capitalize()}:</strong> {v}" for k,v in scan_params.items())
            html_parts.append(f"<p>Scan Parameters: {params_str}</p>")
        
        summary_section = []
        if "web_vulns" in report_data["results"] and \
           isinstance(report_data["results"]["web_vulns"], dict) and \
           "summary" in report_data["results"]["web_vulns"]:
            vuln_summary = report_data["results"]["web_vulns"]["summary"]
            if isinstance(vuln_summary, dict):
                summary_parts = [f"<strong class='key-label'>{k.capitalize()}:</strong> {v}" for k,v in vuln_summary.items() if isinstance(v, int) and v >= 0] # Show even if 0
                if summary_parts:
                    summary_section.append(f"<strong>Vulnerability Scan:</strong> {'; '.join(summary_parts)}")
        
        if "port_scan" in report_data["results"] and isinstance(report_data["results"]["port_scan"],dict) and "summary" in report_data["results"]["port_scan"]:
            ps_summary = report_data["results"]["port_scan"]["summary"]
            if isinstance(ps_summary, dict) and ps_summary.get("total_open_ports_found", 0) > 0:
                summary_section.append(f"<strong>Open Ports Found:</strong> TCP: {ps_summary.get('open_tcp_ports_count',0)}, UDP: {ps_summary.get('open_udp_ports_count',0)}")


        if summary_section:
            html_parts.append("<div class='info-message'><h3>Overall Summary</h3><ul>")
            for item in summary_section: html_parts.append(f"<li>{item}</li>")
            html_parts.append("</ul></div>")

        for module_name_val in report_data.get("modules_run", []):
            module_data_val = report_data["results"].get(module_name_val, {})
            html_parts.append("<div class='module-section'>")
            html_parts.append(f"<h2>{html.escape(module_name_val.replace('_', ' ').capitalize())}</h2>")
            # ... (rest of the module data rendering logic from previous version) ...
            if isinstance(module_data_val, dict) and "error" in module_data_val:
                html_parts.append(f"<p class='error-message'>Error: {html.escape(str(module_data_val['error']))}</p>")
            elif module_data_val or isinstance(module_data_val, (bool, int, float)):
                html_parts.append("<div class='module-content'>")
                html_parts.append(_render_html_value(module_data_val))
                html_parts.append("</div>")
            else:
                html_parts.append("<p><em class='empty-value'>No data or error reported for this module.</em></p>")
            html_parts.append("</div>") # Close module-section
    
    # Consolidated workflow report
    elif isinstance(data, dict) and "modules_data" in data and "workflow_name" in data:
        workflow_data = data
        timestamp_val = workflow_data.get('timestamp', 'N/A')
        target_type_val = workflow_data.get('target_type', 'N/A')
        html_parts.append(f"<p class='timestamp'>Report Generated: {html.escape(str(timestamp_val))}</p>")
        if target_type_val and target_type_val != 'N/A':
            html_parts.append(f"<p><strong class='key-label'>Target Type:</strong> {html.escape(str(target_type_val))}</p>")

        for module_name_wf, module_data_wf in workflow_data.get("modules_data", {}).items():
            html_parts.append("<div class='module-section'>")
            html_parts.append(f"<h2>{html.escape(module_name_wf.replace('_', ' ').capitalize())}</h2>")
            if isinstance(module_data_wf, dict) and "error" in module_data_wf:
                html_parts.append(f"<p class='error-message'>Error: {html.escape(str(module_data_wf['error']))}</p>")
            elif module_data_wf or isinstance(module_data_wf, (bool, int, float)):
                html_parts.append("<div class='module-content'>")
                html_parts.append(_render_html_value(module_data_wf))
                html_parts.append("</div>")
            else:
                html_parts.append("<p><em class='empty-value'>No data or error reported for this module.</em></p>")
            html_parts.append("</div>") # Close module-section
    
    else: # Single module output
        if isinstance(data, dict) and "error" in data:
            html_parts.append(f"<p class='error-message'>Error: {html.escape(str(data['error']))}</p>")
        elif data or isinstance(data, (bool, int, float)):
             html_parts.append("<div class='module-section'><div class='module-content'>")
             html_parts.append(_render_html_value(data))
             html_parts.append("</div></div>")
        else:
            html_parts.append("<p><em class='empty-value'>No data available to display.</em></p>")

    html_parts.append("<div class='footer'><p>ReconPy Report © 2024. Use responsibly.</p></div>")
    html_parts.append("</div></body></html>")
    return "\n".join(html_parts)


# --- Main Formatting Functions (format_output, _format_to_text, _format_to_json, _format_to_csv, convert_file_format) ---
# These remain largely the same as the previous "good" version, ensuring they call the updated _format_to_html.
# I'll re-paste them here for completeness, assuming minor adjustments for consistency if needed.

def _format_to_text(data: Dict[str, Any], indent_level: int = 0) -> str:
    """Formats a dictionary into a human-readable text string with indentation."""
    if not isinstance(data, dict):
        return str(data) 

    text_parts = []
    indent = "  " * indent_level 

    for key, value in data.items():
        key_str = str(key).replace('_', ' ').capitalize()
        
        if key == "findings" and isinstance(value, list) and value and all(isinstance(item, dict) and _is_finding_like(item) for item in value):
            text_parts.append(f"{indent}{key_str}:")
            for i, finding in enumerate(value):
                text_parts.append(f"{indent}  Finding {i+1}:")
                text_parts.append(f"{indent}    Name: {finding.get('name', finding.get('type', 'N/A'))}")
                text_parts.append(f"{indent}    Risk: {finding.get('risk', finding.get('severity', 'N/A')).capitalize()}")
                text_parts.append(f"{indent}    Description: {html.unescape(finding.get('description', finding.get('details', 'N/A')))}") # Unescape for text
                for f_key, f_val in finding.items():
                    if f_key not in ['name', 'risk', 'description', 'type', 'details', 'severity']:
                        f_val_str_lines = str(f_val).splitlines()
                        text_parts.append(f"{indent}    {str(f_key).replace('_', ' ').capitalize()}: {f_val_str_lines[0] if f_val_str_lines else ''}")
                        for line in f_val_str_lines[1:]:
                            text_parts.append(f"{indent}      {line}")
            continue

        text_parts.append(f"{indent}{key_str}:")

        if isinstance(value, dict):
            if not value: text_parts.append(f"{indent}  (empty dictionary)")
            else: text_parts.append(_format_to_text(value, indent_level + 1))
        elif isinstance(value, list):
            if not value: text_parts.append(f"{indent}  (empty list)")
            else:
                if all(isinstance(item, (str, int, float, bool)) or item is None for item in value):
                    for item in value: text_parts.append(f"{indent}  - {str(item)}")
                elif all(isinstance(item, dict) for item in value): 
                     text_parts.append(f"{indent}  (List of dictionaries - best viewed in HTML/JSON or as table)")
                     # Attempt to tabulate if simple enough
                     try:
                         simple_list_data = []
                         temp_headers = set()
                         for item_dict_in_list in value[:10]: # Limit preview for text
                             row = {}
                             for k_list, v_list in item_dict_in_list.items():
                                 temp_headers.add(k_list)
                                 if isinstance(v_list, (str, int, float, bool)) or v_list is None: row[k_list] = v_list
                                 else: row[k_list] = "(...)" 
                             simple_list_data.append(row)
                         
                         ordered_temp_headers = sorted(list(temp_headers))
                         final_simple_list_data = [[item.get(h,"(...)") for h in ordered_temp_headers] for item in simple_list_data]

                         if final_simple_list_data and ordered_temp_headers:
                             table_output = tabulate(final_simple_list_data, headers=ordered_temp_headers, tablefmt="grid",maxcolwidths=[None, 50])
                             for line in table_output.splitlines(): text_parts.append(f"{indent}  {line}")
                         if len(value) > 10: text_parts.append(f"{indent}  ... and {len(value) - 10} more items.")
                     except Exception: # Fallback if tabulation fails
                        for i, item in enumerate(value[:3]): 
                            text_parts.append(f"{indent}  - Item {i+1} (preview):")
                            if isinstance(item, dict): text_parts.append(_format_to_text(item, indent_level + 2))
                            else: text_parts.append(f"{indent}    {str(item)[:100]}{'...' if len(str(item)) > 100 else ''}")
                        if len(value) > 3 : text_parts.append(f"{indent}    ...and {len(value)-3} more items.")
                else: 
                    for item in value: text_parts.append(f"{indent}  - {str(item)}")
        else:
            value_str_lines = str(value).splitlines()
            for line_idx, line in enumerate(value_str_lines): text_parts.append(f"{indent}  {line}")
    return "\n".join(text_parts)


def _format_to_json(data: Dict[str, Any]) -> str:
    try:
        return json.dumps(data, indent=2, default=str)
    except TypeError as e:
        return json.dumps({"error": f"JSON serialization error: {str(e)}", 
                           "original_data_type": str(type(data))}, indent=2)

def _flatten_dict_for_csv(data_dict: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
    items: List[Tuple[str, Any]] = []
    for k, v in data_dict.items():
        new_key = f"{prefix}{k}" if prefix else k
        if isinstance(v, dict): items.extend(_flatten_dict_for_csv(v, f"{new_key}_").items())
        elif isinstance(v, list):
            if all(isinstance(i, (str, int, float, bool, type(None))) for i in v):
                items.append((new_key, "; ".join(map(str, filter(lambda x: x is not None, v)))))
            else: items.append((new_key, json.dumps(v, default=str)))
        else: items.append((new_key, str(v) if v is not None else "")) 
    return dict(items)

def _format_to_csv(data: Dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator='\n')

    if isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
        flattened_data = [_flatten_dict_for_csv(item) for item in data]
        all_headers_set = set()
        ordered_headers = [] # To maintain order of first appearance
        for item in flattened_data:
            for key in item.keys():
                if key not in all_headers_set:
                    all_headers_set.add(key)
                    ordered_headers.append(key)
        if not ordered_headers: return "No data with headers to write to CSV."
        writer.writerow(ordered_headers)
        for row_dict in flattened_data:
            writer.writerow([row_dict.get(h, "") for h in ordered_headers])
    elif isinstance(data, dict):
        list_keys = ["matches", "services_data", "findings", "items", "records", "snapshots", 
                     "direct_platform_checks", "search_engine_mentions", "pages_data", "hops",
                     "services", "open_ports", "ports", "repositories", "logs", "urls", "emails", "phones", "links", "banners"]
        
        primary_list_data = None
        for lk in list_keys:
            list_candidate = data.get(lk)
            if lk == "open_ports" and isinstance(list_candidate, dict): # Special handling for port_scan open_ports
                combined_ports = []
                for proto_ports_val in list_candidate.values():
                    if isinstance(proto_ports_val, list): combined_ports.extend(proto_ports_val)
                if combined_ports: primary_list_data = combined_ports; break 
            elif lk == "banners" and isinstance(list_candidate, dict): # Special handling for banner results
                 banner_list = []
                 for port_str, banner_info in list_candidate.items():
                     if isinstance(banner_info, dict):
                         banner_list.append({"port":port_str, **banner_info})
                     else: # e.g. if banner_info is just an error string
                         banner_list.append({"port":port_str, "banner_text":str(banner_info)})
                 if banner_list: primary_list_data = banner_list; break

            elif isinstance(list_candidate, list) and list_candidate and all(isinstance(item, dict) for item in list_candidate):
                primary_list_data = list_candidate; break
        
        if primary_list_data is not None: return _format_to_csv(primary_list_data)
        else:
            flattened_dict = _flatten_dict_for_csv(data)
            if not flattened_dict: return "No data to write to CSV."
            headers = sorted(flattened_dict.keys())
            writer.writerow(headers)
            writer.writerow([flattened_dict.get(h, "") for h in headers])
    else: return "CSV conversion not supported for this data structure."
    return output.getvalue()


def format_output(data: Optional[Dict[str, Any]], output_format: str = "text") -> str:
    if data is None:
        if output_format.lower() == 'html': return _format_to_html({}, report_title_prefix="ReconPy Report - No Data")
        return "No data to format."

    output_format_lower = output_format.lower()

    if output_format_lower == "json": return _format_to_json(data)
    elif output_format_lower == "csv": return _format_to_csv(data)
    elif output_format_lower == "html":
        title_prefix_html = "ReconPy Output"
        target_keys_html = ['target_url', 'target_input', 'target', 'domain', 'domain_input', 'query', 'url_analyzed', 'username_searched', 'email_searched', 'input_source', 'workflow_name']
        if isinstance(data, dict):
            for tk_html in target_keys_html:
                target_val_html = data.get(tk_html)
                if target_val_html and isinstance(target_val_html, str):
                    title_prefix_html = f"Report for {target_val_html}"
                    if tk_html == "workflow_name": # Prepend if it's a workflow report
                        title_prefix_html = f"Workflow: {target_val_html} - Target: {data.get('target', data.get('target_arg_run', 'N/A'))}"
                    break
        return _format_to_html(data, report_title_prefix=title_prefix_html)
    elif output_format_lower == "text":
        if isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
            # Simplified tabulate for lists of dicts
            try:
                return tabulate(data, headers="keys", tablefmt="grid",maxcolwidths=[None, 60])
            except Exception: # Fallback if tabulate fails with complex data
                return _format_to_text({"list_data": data}) # Wrap list in a dict for _format_to_text
        elif isinstance(data, dict): return _format_to_text(data)
        else: return str(data)
    else:
        unsupported_msg = f"Unsupported output format: {output_format}. Using text.\n"
        return unsupported_msg + _format_to_text(data if isinstance(data, dict) else {"data": data})

def convert_file_format(input_file: str, output_format: str, output_file: Optional[str] = None) -> Dict[str, Any]:
    try:
        with open(input_file, 'r', encoding='utf-8') as f_in: data_to_convert = json.load(f_in)
    except FileNotFoundError: return {"error": f"Input file not found: {input_file}"}
    except json.JSONDecodeError: return {"error": f"Invalid JSON: {input_file}"}
    except Exception as e: return {"error": f"Error reading {input_file}: {str(e)}"}

    output_format_lower = output_format.lower()
    formatted_content = ""; file_extension = f".{output_format_lower}"
    report_title = f"Converted Report: {os.path.basename(input_file)}"

    if output_format_lower == "json": formatted_content = _format_to_json(data_to_convert)
    elif output_format_lower == "csv": formatted_content = _format_to_csv(data_to_convert)
    elif output_format_lower == "html":
        formatted_content = _format_to_html(data_to_convert, report_title_prefix=report_title)
        file_extension = ".html"
    elif output_format_lower == "text":
        formatted_content = _format_to_text(data_to_convert)
        file_extension = ".txt"
    else: return {"error": f"Unsupported output format: {output_format}"}

    if output_file:
        if not output_file.lower().endswith(file_extension):
            output_file_name, current_ext = os.path.splitext(output_file)
            if current_ext.lower() != file_extension: output_file = output_file_name + file_extension
        try:
            with open(output_file, 'w', encoding='utf-8') as f_out: f_out.write(formatted_content)
            return {"message": f"File converted to {output_format} and saved to {output_file}"}
        except Exception as e: return {"error": f"Error writing to {output_file}: {str(e)}"}
    else:
        return {"message": "File converted successfully (output to stdout).", "output_content": formatted_content}