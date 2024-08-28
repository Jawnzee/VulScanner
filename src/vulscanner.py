"""
VulScanner - A Vulnerability Scanning Tool
Author: Jawnzee
Date: August 28, 2024
Version: 1.0

Description:
VulScanner is designed to identify active hosts, open ports, and associated vulnerabilities 
within a specified IP range. This tool integrates with the CVE database to provide detailed 
vulnerability information based on the services detected on open ports.

Dependencies:
- Python 3.x
- Scapy
- Requests
- nvdlib
"""

from scapy.all import sr1, IP, TCP  # Import necessary modules from Scapy
import requests  # Import the requests module for HTTP requests
import argparse  # Import argparse for command-line interface handling
import nvdlib  # Import nvdlib for querying the National Vulnerability Database
import json  # Import json for handling JSON data
import socket  # Import socket for banner grabbing
import re  # Import regular expressions for parsing

"""
Scans a range of IP addresses to identify active hosts.

Args:        
ip_range (list): List of IP addresses to scan.

Returns:
list: List of active IP addresses.
"""
def scan_ip(ip_range):
    active_ips = []
    for ip in ip_range:  # Loop through each IP address in the provided range
        print(f"Scanning IP: {ip}")
        response = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=1, verbose=0)
        if response:  # If a response is received, the IP is active
            print(f"{ip} is up and responding")
            active_ips.append(ip)
    return active_ips

"""
Scans specific ports on a given IP address to identify open ports.

Args:
ip (str): The IP address to scan.
ports (list): List of ports to scan on the target IP.

Returns:
list: List of open ports on the target IP.
"""
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:  # Loop through each port in the provided list
        port = int(port)
        response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if response:  # If a response is received, the port is open
            print(f"Port {port} on {ip} is open")
            open_ports.append(port)
    return open_ports

"""
Attempts to grab the service banner from an open port.

Args:
ip (str): The IP address of the target.
port (int): The open port to connect to.

Returns:
tuple: A tuple containing the service name and version, 
or ("Unknown Service", "Unknown Version") if it can't be determined.
"""
def get_service_banner(ip, port):
    try:
        # Create a socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            
            # Send a dummy request to prompt a response (optional for some services)
            s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            
            # Receive the banner
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Debug: Print the received banner for inspection
            print(f"[DEBUG] Banner Received from {ip}:{port} -> {banner}")

            # Use regular expressions to extract service name and version
            patterns = [
                (r"Apache/?([^\s]*)", "Apache"),
                (r"nginx/?([^\s]*)", "Nginx"),
                (r"Microsoft-IIS/?([^\s]*)", "Microsoft-IIS"),
                (r"OpenSSH_([^\s]*)", "OpenSSH"),
                (r"lighttpd/?([^\s]*)", "lighttpd"),  # Added lighttpd detection
                (r"FTP server \(.*\) version ([^\s]*)", "FTP Server"),
                # Add more patterns as needed
            ]
            
            for pattern, service_name in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service_version = match.group(1) if match.group(1) else "Unknown Version"
                    return (service_name, service_version)
            
            return ("Unknown Service", "Unknown Version")
    except Exception as e:
        print(f"[ERROR] Failed to retrieve banner from {ip}:{port} -> {e}")
        return ("Unknown Service", "Unknown Version")

"""
Queries the CVE database for known vulnerabilities associated with a given service.

Args:
service_name (str): The name of the service (e.g., "Apache", "OpenSSH").
service_version (str): The version of the service.

Returns:
list: A list of CVEs related to the service and version.
"""
def lookup_vulnerabilities(service_name, service_version):
    try:
        # Modify the query to match the correct parameters for nvdlib.searchCVE
        cpe_name = f"cpe:2.3:a:{service_name}:{service_name}:{service_version}"
        cve_results = nvdlib.searchCVE(cpeName=cpe_name)
        cve_list = []

        for cve in cve_results:
            # Safely access the description and other attributes
            description = getattr(cve, 'description', 'No description available')
            severity = getattr(cve, 'v3severity', 'N/A')

            cve_list.append({
                'id': cve.id,
                'description': description,
                'severity': severity
            })

        return cve_list
    except Exception as e:
        print(f"Error querying CVE database for {service_name} {service_version}: {str(e)}")
        return []

"""
Generates a JSON report of the scan results.

Args:
ip (str): The IP address that was scanned.
open_ports (list): List of open ports found on the IP.
vulnerabilities (list): List of vulnerabilities associated with the open ports.

Returns:
None
"""
def generate_report(ip, open_ports, vulnerabilities):
    report = {
        'ip': ip,
        'open_ports': open_ports,
        'vulnerabilities': vulnerabilities
    }

    filename = f"vulscan_report_{ip}.json"
    with open(filename, 'w') as report_file:
        json.dump(report, report_file, indent=4)
    print(f"Report saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulScanner: A Vulnerability Scanning Tool")
    parser.add_argument("ip_range", nargs='+', help="IP range to scan")
    parser.add_argument("--ports", nargs='+', default=[22, 80, 443], help="Ports to scan (default: 22, 80, 443)")
    args = parser.parse_args()

    # Scan the provided IP range for active hosts
    active_ips = scan_ip(args.ip_range)

    # Scan each active IP for open ports and look up vulnerabilities
    for ip in active_ips:
        open_ports = scan_ports(ip, args.ports)

        # For each open port, lookup vulnerabilities
        vulnerabilities = []
        for port in open_ports:
            service_name, service_version = get_service_banner(ip, port)
            print(f"Detected service: {service_name} version: {service_version} on port {port}")
            
            if service_name != "Unknown Service":
                vulns = lookup_vulnerabilities(service_name, service_version)
                vulnerabilities.extend(vulns)

        # Generate a report for each scanned IP
        generate_report(ip, open_ports, vulnerabilities)
