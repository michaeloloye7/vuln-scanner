## vuln-scanner
Python tool that wraps Nmap scans and cross-references discovered services against known CVEs.
Built as a hands-on project to apply concepts from CompTIA Security+. More specifically, vulnerability management, risk scoring (CVSS), and vulnerability assessment reporting. 

# What it does
1. Scans a target IP with Nmap.
2. Cross references each deteced service & version against the NVD API for known CVEs.
3. Scores findings using real CVSS severity data.
4. Generates an HTML report page of its findings and why they may be dangerous.

