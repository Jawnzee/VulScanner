import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from vulscanner import scan_ip, scan_ports, get_service_banner, lookup_vulnerabilities

class TestVulScanner(unittest.TestCase):

    # Tests the scan_ip function by mocking the response from sr1 to simulate active IPs.
    @patch('vulscanner.sr1')
    def test_scan_ip(self, mock_sr1):
        # Mock the response for an active IP
        mock_sr1.return_value = MagicMock()
        
        test_ip_range = ["192.168.1.1", "192.168.1.2"]
        active_ips = scan_ip(test_ip_range)
        
        self.assertIn("192.168.1.1", active_ips)
        self.assertIn("192.168.1.2", active_ips)

    # Tests the scan_ports function by mocking the sr1 response to simulate open ports.
    @patch('vulscanner.sr1')
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
    @patch('socket.socket')
    def test_get_service_banner(self, mock_socket_class):
        # Create a mock socket instance
        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance

        # Set up the __enter__ method to return the mock socket instance
        mock_socket_instance.__enter__.return_value = mock_socket_instance

        # Mock the connect and sendall methods (do nothing)
        mock_socket_instance.connect.return_value = None
        mock_socket_instance.sendall.return_value = None
    
        # Mock the recv method to return a sample Apache banner
        mock_socket_instance.recv.return_value = b"Apache/2.4.41 (Ubuntu)\r\n"

        # Test the banner grabbing
        service_name, service_version = get_service_banner("192.168.1.1", 80)

        # Check if the service and version were correctly identified
        self.assertEqual(service_name, "Apache")
        self.assertEqual(service_version, "2.4.41")

        # Ensure that socket methods were called as expected
        mock_socket_instance.connect.assert_called_with(("192.168.1.1", 80))
        mock_socket_instance.sendall.assert_called_with(b'HEAD / HTTP/1.0\r\n\r\n')
        mock_socket_instance.recv.assert_called_with(1024)

    # Mocks the nvdlib.searchCVE function to simulate CVE search results 
    # and ensure that the vulnerability lookup function works as expected.
    @patch('vulscanner.nvdlib.searchCVE')
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
