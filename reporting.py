# reporting.py - Delivery System for IOC Analysis Reports
# Phase 4: The Delivery System (Output & Reporting)

import csv
import json
import os
from datetime import datetime
from utils import defang_ioc

class ReportGenerator:
    """
    Generates various report formats from IOC analysis results.
    
    Supports CSV, Markdown, HTML, and JSON outputs with quick links
    for analyst-friendly consumption.
    """
    
    def __init__(self, output_dir='reports'):
        """
        Initialize the report generator.
        
        Args:
            output_dir (str): Base directory to save generated reports
        """
        # Create timestamped subdirectory for this run
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.output_dir = os.path.join(output_dir, timestamp)
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_all_reports(self, analysis_data):
        """
        Generate all report formats from analysis data.
        
        Args:
            analysis_data (dict): Complete analysis results
            
        Returns:
            dict: Paths to generated report files
        """
        reports = {}
        
        # Generate CSV reports
        reports['csv_summary'] = self._generate_csv_summary(analysis_data)
        reports['csv_detailed'] = self._generate_csv_detailed(analysis_data)
        
        # Generate Markdown report
        reports['markdown'] = self._generate_markdown_report(analysis_data)
        
        # Generate HTML dashboard
        reports['html'] = self._generate_html_dashboard(analysis_data)
        
        # Enhanced JSON (already exists, but add metadata)
        reports['enhanced_json'] = self._enhance_json_report(analysis_data)
        
        return reports
    
    def _generate_csv_summary(self, data):
        """
        Generate a summary CSV with one row per IOC.
        
        Args:
            data (dict): Analysis data
            
        Returns:
            str: Path to generated CSV file
        """
        filename = f"{self.output_dir}/ioc_summary.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['IOC', 'Category', 'Risk_Level', 'Risk_Score', 
                         'VT_Malicious', 'VT_Total_Engines', 'VT_Detection_Rate', 'VT_Reputation',
                         'AbuseIPDB_Score', 'AbuseIPDB_Reports', 'Is_Tor', 'Country',
                         'VT_Link', 'AbuseIPDB_Link', 'Recommendations']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for category, iocs in data.get('risk_analysis', {}).items():
                for ioc, analysis in iocs.items():
                    row = {
                        'IOC': defang_ioc(ioc),  # Use defanged IOC for safety
                        'Category': category.upper(),
                        'Risk_Level': analysis.get('risk_level', 'UNKNOWN'),
                        'Risk_Score': analysis.get('risk_score', 0),
                        'VT_Link': self._generate_vt_link(ioc, category),
                        'AbuseIPDB_Link': self._generate_abuseipdb_link(ioc, category),
                        'Recommendations': '; '.join(analysis.get('recommendations', []))
                    }
                    
                    # Add VT data
                    vt_data = analysis.get('analysis', {}).get('virustotal', {})
                    row.update({
                        'VT_Malicious': vt_data.get('malicious_detections', 0),
                        'VT_Total_Engines': vt_data.get('total_engines', 0),
                        'VT_Detection_Rate': f"{vt_data.get('detection_rate', 0):.1%}",
                        'VT_Reputation': vt_data.get('reputation', 0)
                    })
                    
                    # Add AbuseIPDB data
                    abuse_data = analysis.get('analysis', {}).get('abuseipdb', {})
                    row.update({
                        'AbuseIPDB_Score': abuse_data.get('abuse_confidence_score', 0),
                        'AbuseIPDB_Reports': abuse_data.get('total_reports', 0),
                        'Is_Tor': abuse_data.get('is_tor', False),
                        'Country': abuse_data.get('country_code', '')
                    })
                    
                    writer.writerow(row)
        
        return filename
    
    def _generate_csv_detailed(self, data):
        """
        Generate a detailed CSV with threat categories and full analysis.
        
        Args:
            data (dict): Analysis data
            
        Returns:
            str: Path to generated CSV file
        """
        filename = f"{self.output_dir}/ioc_detailed.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['IOC', 'Category', 'Risk_Level', 'Risk_Score', 
                         'VT_Last_Analysis', 'VT_Threat_Categories', 'VT_Popular_Threats',
                         'AbuseIPDB_Last_Reported', 'AbuseIPDB_Usage_Type', 'AbuseIPDB_ISP',
                         'Quick_Actions']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for category, iocs in data.get('risk_analysis', {}).items():
                for ioc, analysis in iocs.items():
                    vt_data = analysis.get('analysis', {}).get('virustotal', {})
                    abuse_data = analysis.get('analysis', {}).get('abuseipdb', {})
                    
                    # Format dates
                    vt_date = vt_data.get('last_analysis_date')
                    if vt_date:
                        try:
                            vt_date = datetime.fromtimestamp(vt_date).strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            vt_date = str(vt_date)
                    
                    abuse_date = abuse_data.get('last_reported')
                    if abuse_date:
                        try:
                            abuse_date = abuse_date.split('T')[0]  # Just date part
                        except:
                            abuse_date = str(abuse_date)
                    
                    row = {
                        'IOC': defang_ioc(ioc),  # Use defanged IOC for safety
                        'Category': category.upper(),
                        'Risk_Level': analysis.get('risk_level', 'UNKNOWN'),
                        'Risk_Score': analysis.get('risk_score', 0),
                        'VT_Last_Analysis': vt_date or '',
                        'VT_Threat_Categories': ', '.join(vt_data.get('categories', [])),
                        'VT_Popular_Threats': '',  # Could be expanded
                        'AbuseIPDB_Last_Reported': abuse_date or '',
                        'AbuseIPDB_Usage_Type': abuse_data.get('usage_type', ''),
                        'AbuseIPDB_ISP': abuse_data.get('isp', ''),
                        'Quick_Actions': self._generate_quick_actions(ioc, category, analysis.get('risk_level', 'UNKNOWN'))
                    }
                    
                    writer.writerow(row)
        
        return filename
    
    def _generate_markdown_report(self, data):
        """
        Generate a human-readable Markdown report.
        
        Args:
            data (dict): Analysis data
            
        Returns:
            str: Path to generated Markdown file
        """
        filename = f"{self.output_dir}/ioc_report.md"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("# IOC Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Source File:** {data.get('metadata', {}).get('source_file', 'Unknown')}\n\n")
            f.write(f"**Total IOCs Analyzed:** {data.get('metadata', {}).get('total_iocs', 0)}\n\n")
            
            # Risk Summary
            f.write("## Risk Summary\n\n")
            risk_counts = self._calculate_risk_summary(data)
            for level, count in risk_counts.items():
                if count > 0:
                    icon = self._get_risk_icon(level)
                    f.write(f"- {icon} **{level}**: {count} IOCs\n")
            f.write("\n")
            
            # Detailed Analysis by Category
            for category in ['ips', 'domains', 'hashes', 'urls']:
                iocs = data.get('risk_analysis', {}).get(category, {})
                if iocs:
                    f.write(f"## {category.upper()}\n\n")
                    
                    # Sort by risk level (Critical first)
                    sorted_iocs = sorted(iocs.items(), 
                                       key=lambda x: self._risk_sort_key(x[1].get('risk_level', 'UNKNOWN')),
                                       reverse=True)
                    
                    for ioc, analysis in sorted_iocs:
                        risk_level = analysis.get('risk_level', 'UNKNOWN')
                        risk_score = analysis.get('risk_score', 0)
                        icon = self._get_risk_icon(risk_level)
                        
                        # Use defanged IOC for display
                        display_ioc = defang_ioc(ioc)
                        
                        f.write(f"### {icon} {display_ioc}\n\n")
                        f.write(f"**Risk Level:** {risk_level} (Score: {risk_score})\n\n")
                        
                        # Quick Links (use original IOC for links)
                        f.write("**Quick Links:**\n")
                        f.write(f"- [VirusTotal]({self._generate_vt_link(ioc, category)})\n")
                        f.write(f"- [AbuseIPDB]({self._generate_abuseipdb_link(ioc, category)})\n\n")
                        
                        # Key Findings
                        f.write("**Key Findings:**\n")
                        vt_data = analysis.get('analysis', {}).get('virustotal', {})
                        abuse_data = analysis.get('analysis', {}).get('abuseipdb', {})
                        
                        if not vt_data.get('error'):
                            malicious = vt_data.get('malicious_detections', 0)
                            total = vt_data.get('total_engines', 0)
                            reputation = vt_data.get('reputation', 0)
                            f.write(f"- VirusTotal: {malicious}/{total} malicious detections, Reputation: {reputation}\n")
                        
                        if not abuse_data.get('error'):
                            score = abuse_data.get('abuse_confidence_score', 0)
                            reports = abuse_data.get('total_reports', 0)
                            is_tor = abuse_data.get('is_tor', False)
                            country = abuse_data.get('country_code', '')
                            f.write(f"- AbuseIPDB: Confidence score {score}%, {reports} reports")
                            if is_tor:
                                f.write(" (Tor node)")
                            if country:
                                f.write(f", Country: {country}")
                            f.write("\n")
                        
                        f.write("\n**Recommendations:**\n")
                        for rec in analysis.get('recommendations', []):
                            f.write(f"- {rec}\n")
                        f.write("\n")
            
            f.write("---\n*Report generated by IOC Analysis Pipeline v1.0*\n")
        
        return filename
    
    def _generate_html_dashboard(self, data):
        """
        Generate a professional HTML dashboard without emojis.
        
        Args:
            data (dict): Analysis data
            
        Returns:
            str: Path to generated HTML file
        """
        filename = f"{self.output_dir}/ioc_dashboard.html"
        
        # Calculate summary statistics
        risk_counts = self._calculate_risk_summary(data)
        total_iocs = sum(risk_counts.values())
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOC Threat Intelligence Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #2c3e50;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            text-align: center;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
            text-align: center;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }}
        
        .stat-card.critical {{ border-top: 4px solid #e74c3c; }}
        .stat-card.high {{ border-top: 4px solid #f39c12; }}
        .stat-card.medium {{ border-top: 4px solid #f1c40f; }}
        .stat-card.low {{ border-top: 4px solid #27ae60; }}
        .stat-card.safe {{ border-top: 4px solid #16a085; }}
        .stat-card.unknown {{ border-top: 4px solid #95a5a6; }}
        
        .stat-number {{
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 1.1em;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .section {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
        }}
        
        .section h2 {{
            font-size: 1.8em;
            font-weight: 600;
            margin-bottom: 20px;
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }}
        
        .ioc-grid {{
            display: grid;
            gap: 20px;
        }}
        
        .ioc-card {{
            border: 1px solid #ecf0f1;
            border-radius: 8px;
            padding: 20px;
            transition: all 0.2s ease;
        }}
        
        .ioc-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            border-color: #bdc3c7;
        }}
        
        .ioc-card.critical {{ border-left: 4px solid #e74c3c; background: linear-gradient(90deg, rgba(231, 76, 60, 0.05) 0%, transparent 100%); }}
        .ioc-card.high {{ border-left: 4px solid #f39c12; background: linear-gradient(90deg, rgba(243, 156, 18, 0.05) 0%, transparent 100%); }}
        .ioc-card.medium {{ border-left: 4px solid #f1c40f; background: linear-gradient(90deg, rgba(241, 196, 15, 0.05) 0%, transparent 100%); }}
        .ioc-card.low {{ border-left: 4px solid #27ae60; background: linear-gradient(90deg, rgba(39, 174, 96, 0.05) 0%, transparent 100%); }}
        .ioc-card.safe {{ border-left: 4px solid #16a085; background: linear-gradient(90deg, rgba(22, 160, 133, 0.05) 0%, transparent 100%); }}
        .ioc-card.unknown {{ border-left: 4px solid #95a5a6; background: linear-gradient(90deg, rgba(149, 165, 166, 0.05) 0%, transparent 100%); }}
        
        .ioc-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .ioc-title {{
            font-size: 1.3em;
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .risk-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .risk-badge.critical {{ background: #e74c3c; color: white; }}
        .risk-badge.high {{ background: #f39c12; color: white; }}
        .risk-badge.medium {{ background: #f1c40f; color: #2c3e50; }}
        .risk-badge.low {{ background: #27ae60; color: white; }}
        .risk-badge.safe {{ background: #16a085; color: white; }}
        .risk-badge.unknown {{ background: #95a5a6; color: white; }}
        
        .ioc-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #7f8c8d;
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .links {{
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
        }}
        
        .link-btn {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
            transition: background 0.2s ease;
        }}
        
        .link-btn:hover {{
            background: #2980b9;
        }}
        
        .link-btn.secondary {{
            background: #95a5a6;
        }}
        
        .link-btn.secondary:hover {{
            background: #7f8c8d;
        }}
        
        .recommendations {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #3498db;
        }}
        
        .recommendations h4 {{
            font-size: 1em;
            font-weight: 600;
            margin-bottom: 8px;
            color: #2c3e50;
        }}
        
        .recommendations ul {{
            list-style: none;
            padding: 0;
        }}
        
        .recommendations li {{
            padding: 3px 0;
            font-size: 0.9em;
            color: #34495e;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header {{
                padding: 20px 0;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }}
            
            .ioc-meta {{
                flex-direction: column;
                gap: 5px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IOC Threat Intelligence Dashboard</h1>
            <p>Analysis Report - {data.get('metadata', {}).get('source_file', 'Unknown Source')}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats-grid">
"""
        
        # Add summary cards
        risk_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'UNKNOWN']
        for level in risk_levels:
            count = risk_counts.get(level, 0)
            if count > 0:
                css_class = f"stat-card {level.lower()}"
                color = self._get_risk_color(level)
                percentage = (count / total_iocs) * 100 if total_iocs > 0 else 0
                html_content += f"""
            <div class="{css_class}">
                <div class="stat-number" style="color: {color}">{count}</div>
                <div class="stat-label">{level}</div>
                <div style="font-size: 0.8em; color: #7f8c8d; margin-top: 5px;">{percentage:.1f}% of total</div>
            </div>"""
        
        html_content += """
        </div>
"""
        
        # Add IOC sections
        for category in ['ips', 'domains', 'hashes', 'urls']:
            iocs = data.get('risk_analysis', {}).get(category, {})
            if iocs:
                category_title = category.upper()
                if category == 'ips':
                    category_title = 'IP Addresses'
                elif category == 'domains':
                    category_title = 'Domains'
                elif category == 'hashes':
                    category_title = 'File Hashes'
                elif category == 'urls':
                    category_title = 'URLs'
                
                html_content += f"""
        <div class="section">
            <h2>{category_title}</h2>
            <div class="ioc-grid">
"""
                
                # Sort by risk level
                sorted_iocs = sorted(iocs.items(), 
                                   key=lambda x: self._risk_sort_key(x[1].get('risk_level', 'UNKNOWN')),
                                   reverse=True)
                
                for ioc, analysis in sorted_iocs:
                    risk_level = analysis.get('risk_level', 'UNKNOWN')
                    risk_score = analysis.get('risk_score', 0)
                    css_class = f"ioc-card {risk_level.lower()}"
                    
                    # Build metadata
                    vt_data = analysis.get('analysis', {}).get('virustotal', {})
                    abuse_data = analysis.get('analysis', {}).get('abuseipdb', {})
                    
                    meta_items = []
                    if not vt_data.get('error'):
                        malicious = vt_data.get('malicious_detections', 0)
                        total = vt_data.get('total_engines', 0)
                        meta_items.append(f"VT: {malicious}/{total} detections")
                    
                    if not abuse_data.get('error'):
                        score = abuse_data.get('abuse_confidence_score', 0)
                        meta_items.append(f"AbuseIPDB: {score}% confidence")
                    
                    meta_html = ""
                    if meta_items:
                        meta_html = '<div class="ioc-meta">'
                        for item in meta_items:
                            meta_html += f'<div class="meta-item">{item}</div>'
                        meta_html += '</div>'
                    
                    # Build links
                    links_html = '<div class="links">'
                    vt_link = self._generate_vt_link(ioc, category)
                    abuse_link = self._generate_abuseipdb_link(ioc, category)
                    
                    if vt_link != "#":
                        links_html += f'<a href="{vt_link}" target="_blank" class="link-btn">View on VirusTotal</a>'
                    if abuse_link != "#":
                        links_html += f'<a href="{abuse_link}" target="_blank" class="link-btn secondary">View on AbuseIPDB</a>'
                    links_html += '</div>'
                    
                    # Build recommendations
                    recommendations = analysis.get('recommendations', [])
                    rec_html = ""
                    if recommendations:
                        rec_html = '<div class="recommendations"><h4>Recommended Actions</h4><ul>'
                        for rec in recommendations:
                            rec_html += f'<li>{rec}</li>'
                        rec_html += '</ul></div>'
                    
                    html_content += f"""
                <div class="{css_class}">
                    <div class="ioc-header">
                        <div class="ioc-title">{defang_ioc(ioc)}</div>
                        <div class="risk-badge {risk_level.lower()}">{risk_level} ({risk_score})</div>
                    </div>
                    {meta_html}
                    {links_html}
                    {rec_html}
                </div>"""
                
                html_content += """
            </div>
        </div>
"""
        
        html_content += f"""
        <div class="footer">
            <p>Report generated by IOC Analysis Pipeline v1.0 | Total IOCs Analyzed: {total_iocs}</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename
    
    def _enhance_json_report(self, data):
        """
        Enhance the existing JSON report with additional metadata.
        
        Args:
            data (dict): Analysis data
            
        Returns:
            str: Path to enhanced JSON file
        """
        filename = f"{self.output_dir}/ioc_analysis_enhanced.json"
        
        # Add report metadata
        enhanced_data = data.copy()
        enhanced_data['report_metadata'] = {
            'generated_at': datetime.now().isoformat(),
            'generator': 'IOC Analysis Pipeline v1.0',
            'formats_available': ['json', 'csv_summary', 'csv_detailed', 'markdown', 'html'],
            'api_sources': ['VirusTotal', 'AbuseIPDB'],
            'risk_levels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'UNKNOWN']
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(enhanced_data, f, indent=2, default=str)
        
        return filename
    
    def _generate_vt_link(self, ioc, category):
        """Generate VirusTotal quick link."""
        if category in ['ips', 'domains']:
            return f"https://www.virustotal.com/gui/{category[:-1]}/{ioc}"
        elif category == 'hashes':
            return f"https://www.virustotal.com/gui/file/{ioc}"
        elif category == 'urls':
            return f"https://www.virustotal.com/gui/url/{ioc.replace('://', '%3A%2F%2F')}"
        return "#"
    
    def _generate_abuseipdb_link(self, ioc, category):
        """Generate AbuseIPDB quick link."""
        if category == 'ips':
            return f"https://www.abuseipdb.com/check/{ioc}"
        return "#"
    
    def _generate_quick_actions(self, ioc, category, risk_level):
        """Generate quick action suggestions."""
        actions = []
        if risk_level in ['CRITICAL', 'HIGH']:
            actions.append("BLOCK")
        if risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
            actions.append("INVESTIGATE")
        if category == 'ips':
            actions.append("CHECK_FIREWALL")
        return ', '.join(actions)
    
    def _calculate_risk_summary(self, data):
        """Calculate risk level counts."""
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'SAFE': 0, 'UNKNOWN': 0}
        for category_iocs in data.get('risk_analysis', {}).values():
            for analysis in category_iocs.values():
                level = analysis.get('risk_level', 'UNKNOWN')
                risk_counts[level] += 1
        return risk_counts
    
    def _get_risk_icon(self, level):
        """Get emoji icon for risk level."""
        icons = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': '👀',
            'SAFE': '✅',
            'UNKNOWN': '❓'
        }
        return icons.get(level, '❓')
    
    def _get_risk_color(self, level):
        """Get color for risk level."""
        colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
            'SAFE': '#20c997',
            'UNKNOWN': '#6c757d'
        }
        return colors.get(level, '#6c757d')
    
    def _risk_sort_key(self, risk_level):
        """Sort key for risk levels (Critical first)."""
        order = {'CRITICAL': 6, 'HIGH': 5, 'MEDIUM': 4, 'LOW': 3, 'SAFE': 2, 'UNKNOWN': 1}
        return order.get(risk_level, 0)