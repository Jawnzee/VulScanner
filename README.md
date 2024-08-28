# Vulnerability Scanner

## Objective

The primary objective of VulScanner is to provide cybersecurity professionals and network administrators with a tool to identify active hosts, open ports, and associated vulnerabilities within a specified IP range. This tool integrates with the National Vulnerability Database (NVD) to provide detailed vulnerability information, including CVE details, based on the detected services running on open ports.

### Skills Learned

- **Python Programming:** Enhanced proficiency in Python, focusing on network interactions, automation, and vulnerability assessment.
- **Networking Fundamentals:** Gained a deeper understanding of IP addressing, TCP/UDP protocols, service detection, and vulnerability assessment.
- **Vulnerability Scanning:** Learned techniques for querying the NVD to identify known vulnerabilities associated with detected services.
- **Scapy Library:** Practiced using the Scapy library for crafting and sending packets, as well as analyzing responses.
- **Problem Solving:** Applied logical reasoning to handle edge cases, such as empty banners, connection refusals, and service identification.

### Tools Used

- **Python:** The primary programming language used to develop the vulnerability scanning tool.
- **Scapy:** A powerful Python library used for packet manipulation, network scanning, and service detection.
- **nvdlib:** A Python library used to query the National Vulnerability Database for CVE information.
- **Linux/Unix Environment:** The script is designed to be executed in a Linux or Unix-based operating system.

## Steps
1. **Clone the Repository:**
   - Navigate to your desired directory and run:
     ```bash
     git clone https://github.com/YourUsername/VulScanner.git
     cd VulScanner
     ```

2. **Set Up the Python Environment:**
   - Optionally, create a virtual environment:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
     
   - Install required dependencies:
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Script:**
   - Execute the main script to start scanning. The script can be run with the following arguments:
     ```bash
     python vulscanner.py [arguments]
     ```

   - Required Arguments:
      - -t, --target: (Required) Specify the target IP address or domain to scan.
        ```bash
        python vulscanner.py -t 192.168.1.1
        ```

   - Optional Arguments:
      - -p, --ports: (Optional) Specify the ports to scan (e.g., 80,443). If not provided, the script will scan common ports.
        ```bash
        python vulscanner.py -t 192.168.1.1 -p 80,443
        ```

      - -o, --output: (Optional) Specify the output file to save the scan results. If not provided, results will be displayed in the terminal.
        ```bash
        python vulscanner.py -t 192.168.1.1 -o results.txt
        ```

      - -v, --verbose: (Optional) Increase the verbosity of the output for debugging purposes.
        ```bash
        python vulscanner.py -t 192.168.1.1 -v
        ```

   - Example Usage:
      - To run a scan on the target IP 192.168.1.1 on ports 80 and 443, with results saved to results.txt, you would use:
        ```bash
        python vulscanner.py -t 192.168.1.1 -p 80,443 -o results.txt
        ```

## Screenshots
_Include relevant screenshots here to illustrate how the tool works._
