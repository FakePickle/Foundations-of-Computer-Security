import json
import socket
import ipaddress

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
def main():
    json_file = "crt.sh.json"  # Replace with your actual file
    subdomains = load_subdomains(json_file)
    private_ips = get_private_ips(subdomains)

    # Print results
    for subdomain, ip in private_ips.items():
        print(f"{subdomain}: [{ip}]")

if __name__ == "__main__":
    main()
