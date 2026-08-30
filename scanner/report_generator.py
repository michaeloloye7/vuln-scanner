from datetime import datetime

def generate_html_report(findings, output_path="reports/scan_report.html"):
    """
    Generate and HTML vuln. report from scan findings.

    Args: findings(dict): combined scan + CVE data from run_vulnerability_scan()
    """