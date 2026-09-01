# vuln-scanner
Python tool that wraps Nmap scans and cross-references discovered services against known CVEs.
Built as a hands-on project to apply concepts from CompTIA Security+. More specifically, vulnerability management, risk scoring (CVSS), and vulnerability assessment reporting. 

## What it does
1. Scans a target IP with Nmap.
2. Cross references each deteced service & version against the NVD API for known CVEs.
3. Scores findings using real CVSS severity data.
4. Generates an HTML report page of its findings and why they may be dangerous.

## Example Output
Port 21 - ftp (vsftpd 2.3.4)
-> CVE-2011-2523 | Severity: 9.8 | vsftpd 2.3.4 ...

<img width="1897" height="911" alt="image" src="https://github.com/user-attachments/assets/65b19efd-3063-4da2-b4c7-7844644e955a" />

## Tech Stack 
- Python
- python.nmap 
- NVD API 2.0 - CVE data source
- requests - HTTP calls to the NVD API
- argparse - command-line interface

## Setup
### Prerequisites: Python 3.8+, Nmap installed and on your system PATH
git clone https://github.com/michaeloloye7/vuln-scanner.git

cd vuln-scanner

pip install -r requirements.txt

### Usage
python main.py (insert your target ip here)

## What I learned
- Wrapping and parsing output from a real security tool in a program
- Working with a live, REST API
- Applying CVSS severity scoring to real scan findings
- Structuring a python project into reusable, independently-testable modules

