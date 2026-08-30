import argparse
from scanner.nmap_wrapper import scan_target
from scanner.cve_lookup import lookup_cve

def run_vulnerability_scan(target_ip, ports="1-1024"):
    """ 
    Runs a vulnerability scan: port/service scan + CVE lookup for each each service.

    Args: 
        target_ip(str): IP address to scan
        ports(str): Port range to scan

    Returns: 
        dict: Combined scan + vulnerability findings
    """

    scan_results = scan_target(target_ip, ports)

    findings = {}

    for host, host_data in scan_results.items():
        findings[host] = {
            "state": host_data["state"],
            "ports": []
        }

        for port_entry in host_data["ports"]:
            product = port_entry.get("product", "")
            version = port_entry.get("version", "")

            cves = []
            if product and version: 
                cves = lookup_cve(product, version)

            findings[host]["ports"].append({
                "port": port_entry["port"],
                "name": port_entry["name"],
                "product": product,
                "version": version,
                "cves": cves,
                "searched": bool(product and version)
            })

    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability scanner: Nmap + CVE lookup")
    parser.add_argument("target", help="The target IP address to scan.")
    parser.add_argument("--ports", default="1-1024", help="The range of ports to scan (default: 1-1024).")

    args = parser.parse_args()

results = run_vulnerability_scan(args.target, args.ports)

for host, data in results.items():
    print(f"\nHost: {host}, ({data['state']})")
    for port in data["ports"]:
        print(f"  Port: {port['port']} - {port['name']} ({port['product']}, {port['version']})")
        if port["cves"]:
            print("    CVEs:")
            for cve in port["cves"]:
                print(f"      -> {cve['cve_id']} | severity: {cve['severity']} | {cve['description'][:80]}")
        elif port["searched"]:
            print("    ->No CVEs found.")
        else:
            print("    -> Skipped (no version detected)")
                                     