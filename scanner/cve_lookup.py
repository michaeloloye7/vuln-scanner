import requests
import time

NVD_API_URL= "https://services.nvd.nist.gov/rest/json/cves/2.0"

def lookup_cve(product, version):
    """
    Searches teh NVD for known CVEs matching a given product and version
    
    Args: 
        product (str): The name of the product to search for.
        version (str): The version of the product to search for.
        
    Returns: 
        list: A list of dicts, each containing cve_id, description, and severity
    """
    if not product or not version:
        return [] # nothing to search for

    query = f"{product} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 5 # limit the number of results to avoid overwhelming the user
    }

    print(f"     [*] Looking up CVEs for: {query}")

    response = requests.get(NVD_API_URL, params=params)

    if response.status_code != 200:
        print(f"     [!] Error querying NVD API: {response.status_code} for {query}")
        return []

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    results = []
    for vuln in vulnerabilities:
        cve = vuln["cve"]
        cve_id = cve["id"]

        # Get the English description 
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get the severity score if available
        severity = "Unknown"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            severity = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        results.append({
            "cve_id": cve_id,
            "description": description,
            "severity": severity
        })
    
    time.sleep(6) 
    return results


if __name__ == "__main__":
    #quick manual test
    test_results = lookup_cve("vsftpd", "2.3.4")
    for r in test_results:
        print(r)