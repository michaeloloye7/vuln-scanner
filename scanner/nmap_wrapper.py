import nmap

def scan_target(target_ip, ports="1-1024"):
    """
    Scans the specified target IP address for open ports using nmap.

    Args:
        target_ip (str): IP address to scan.
        ports (str): The range of ports to scan (default is "1-1024").

    Returns:
        dict: structured scan results.
    """
    scanner = nmap.PortScanner()

    print(f"[*] Scanning {target_ip_} on ports {ports}...")
    scanner.scan(target_ip, ports, arguments="-sV")

    results = {}

    for host in scanner.all_hosts():
        results[host] = {
            "state": scanner[host].state(),
            "ports": []
        }

        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                port_info = scanner[host][proto][port]
                results[host]["ports"].append({
                    "port": port,
                    "state": port_info["state"],
                    "name": port_info["name"],
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", "")
                })
    return results

if __name__ == "__main__":
    #QUICK MANUAL TEST - only runs if you execute this file directly
    test_results = scan_target("192.168.56.101")
    print(test_results)