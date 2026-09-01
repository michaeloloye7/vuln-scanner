from datetime import datetime

def generate_html_report(findings, output_path="reports/scan_report.html"):
    """
    Generates an HTML vulnerability report from scan findings.

    Args:
        findings (dict): Combined scan + CVE data from run_vulnerability_scan().
        output_path (str): File path to save the HTML report.

    Returns:
        str: The path the report was saved to.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_parts = [f"""
    <html>
    <head>
        <title>Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }}
            h1 {{ color: #222; }}
            .host {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; }}
            .port {{ border-left: 4px solid #ccc; padding: 10px; margin: 10px 0; }}
            .critical {{ border-left-color: #d32f2f; background: #fdecea; }}
            .clean {{ border-left-color: #388e3c; }}
            .skipped {{ border-left-color: #999; color: #777; }}
            .cve {{ margin: 5px 0 5px 15px; font-size: 0.9em; }}
            .severity {{ font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>Vulnerability Scan Report</h1>
        <p>Generated: {timestamp}</p>
    """]

    for host, data in findings.items():
        html_parts.append(f'<div class="host"><h2>Host: {host} ({data["state"]})</h2>')

        for port in data["ports"]:
            if port["cves"]:
                css_class = "port critical"
            elif port["searched"]:
                css_class = "port clean"
            else:
                css_class = "port skipped"

            html_parts.append(f'<div class="{css_class}">')
            html_parts.append(
                f'<strong>Port {port["port"]}</strong> - {port["name"]} '
                f'({port["product"]} {port["version"]})'
            )

            if port["cves"]:
                for cve in port["cves"]:
                    html_parts.append(
                        f'<div class="cve">-> <a href="https://nvd.nist.gov/vuln/detail/{cve["cve_id"]}" '
                        f'target="_blank">{cve["cve_id"]}</a> '
                        f'| <span class="severity">Severity: {cve["severity"]}</span> '
                        f'| {cve["description"]}</div>'
                    )
            elif port["searched"]:
                html_parts.append('<div class="cve">No known CVEs found</div>')
            else:
                html_parts.append('<div class="cve">Skipped (no version detected)</div>')

            html_parts.append('</div>')

        html_parts.append('</div>')

    html_parts.append('</body></html>')

    full_html = "".join(html_parts)

    with open(output_path, "w") as f:
        f.write(full_html)

    print(f"[*] Report saved to {output_path}")
    return output_path