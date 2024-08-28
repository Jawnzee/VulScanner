# VulScanner

## Objective

The primary objective of VulScanner is to provide cybersecurity professionals and network administrators with a tool to identify active hosts, open ports, and associated vulnerabilities within a specified IP range. This tool integrates with the National Vulnerability Database (NVD) to provide detailed vulnerability information based on the detected services running on open ports.

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
   - Execute the main script to start scanning:
     ```bash
     python vulscanner.py
     ```

## Screenshots
_Include relevant screenshots here to illustrate how the tool works._
