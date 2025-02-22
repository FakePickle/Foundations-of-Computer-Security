import json
import socket
import ipaddress
import requests
import os

"""
Cert.sh details
"""
# Function to check if an IP address is private
def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False  # Invalid IPs (e.g., unresolved domains)

# Load subdomains from the JSON file
def load_subdomains(json_file):
    with open(json_file, "r") as file:
        data = json.load(file)
    return list(set(entry["name_value"] for entry in data))

# Resolve IP addresses and filter private ones
def get_private_ips(subdomains):
    private_ips = {}
    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            if is_private_ip(ip):
                private_ips[subdomain] = ip
        except socket.gaierror:
            pass  # Ignore subdomains that cannot be resolved
    return private_ips

# Main function
def cert_sh():
    json_file = "crt.sh.json"  # Replace with your actual file
    subdomains = load_subdomains(json_file)
    private_ips = get_private_ips(subdomains)

    # Print results
    for subdomain, ip in private_ips.items():
        print(f"{subdomain}: [{ip}]")

"""
dnsdumpster details
"""
def dnsdumpster():
    # API Key and Endpoint
    api_key = "a6878277f8988893421e173fc221aa508f90fe1ef7fdb4e683b4ad4faeb63a58"
    url = "https://api.dnsdumpster.com/domain/iiitd.edu.in"

    # Headers
    headers = {
        "X-API-Key": api_key
    }

    # Make the API request
    response = requests.get(url, headers=headers)

    # Check response status
    if response.status_code == 200:
        data = response.json()  # Parse JSON response
        # Save it in json file
        with open("dnsdumpster.json", "w") as file:
            json.dump(data, file, indent=4)
    else:
        print(f"Error: {response.status_code}, {response.text}")  # Print error message if request fails

def load_dnsdumpster_subdomains(json_file):
    with open(json_file, "r") as file:
        data = json.load(file)
    
    subdomains = {}
    for entry in data.get("a", []):
        host = entry.get("host")
        ips = [ip_info.get("ip") for ip_info in entry.get("ips", [])]
        subdomains[host] = ips
    
    return subdomains

# Example usage
if __name__ == "__main__":
    cert_sh()
    
    # If there already exists a json file for dnsdumpster, then we can directly use it
    if not os.path.exists("dnsdumpster.json"):
        dnsdumpster()
    else:
        print("\nUsing existing dnsdumpster.json file.")
    
    dns_subdomains = load_dnsdumpster_subdomains("dnsdumpster.json")
    print("Subdomains and their IPs:")
    for subdomain, ips in dns_subdomains.items():
        print(f"{subdomain}: {ips}")
        
