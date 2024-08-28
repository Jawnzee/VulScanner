import unittest
from unittest.mock import patch, MagicMock
from src.vulscanner import scan_ip, scan_ports, get_service_banner, lookup_vulnerabilities

class TestVulScanner(unittest.TestCase):

    # Tests the scan_ip function by mocking the response from sr1 to simulate active IPs.
    @patch('src.vulscanner.sr1')
    def test_scan_ip(self, mock_sr1):
        # Mock the response for an active IP
        mock_sr1.return_value = MagicMock()
        
        test_ip_range = ["192.168.1.1", "192.168.1.2"]
        active_ips = scan_ip(test_ip_range)
        
        self.assertIn("192.168.1.1", active_ips)
        self.assertIn("192.168.1.2", active_ips)

    # Tests the scan_ports function by mocking the sr1 response to simulate open ports.
    @patch('src.vulscanner.sr1')
    def test_scan_ports(self, mock_sr1):
        # Mock the response for an open port
        mock_sr1.return_value = MagicMock()
        
        test_ip = "192.168.1.1"
        test_ports = [22, 80, 443]
        open_ports = scan_ports(test_ip, test_ports)
        
        self.assertIn(22, open_ports)
        self.assertIn(80, open_ports)
        self.assertIn(443, open_ports)

    # Mocks the socket connection and banner reception to test if the service name and version are correctly parsed.
    @patch('src.vulscanner.socket.socket')
    def test_get_service_banner(self, mock_socket):
        # Mock the banner returned by a service
        mock_socket_instance = MagicMock()
        mock_socket_instance.recv.return_value = b"Apache/2.4.41 (Ubuntu)"
        mock_socket.return_value = mock_socket_instance
        
        service_name, service_version = get_service_banner("192.168.1.1", 80)
        self.assertEqual(service_name, "Apache")
        self.assertEqual(service_version, "2.4.41")

    # Mocks the nvdlib.searchCVE function to simulate CVE search results 
    # and ensure that the vulnerability lookup function works as expected.
    @patch('src.vulscanner.nvdlib.searchCVE')
    def test_lookup_vulnerabilities(self, mock_searchCVE):
        # Mock the CVE search result
        mock_cve = MagicMock()
        mock_cve.id = "CVE-2021-1234"
        mock_cve.description = "Sample vulnerability"
        mock_cve.v3severity = "High"
        mock_searchCVE.return_value = [mock_cve]
        
        vulns = lookup_vulnerabilities("Apache", "2.4.41")
        
        self.assertGreater(len(vulns), 0)
        self.assertEqual(vulns[0]['id'], "CVE-2021-1234")
        self.assertEqual(vulns[0]['severity'], "High")

if __name__ == "__main__":
    unittest.main()