import unittest
from unittest.mock import patch, MagicMock
from security_scanner import SecurityScanner

class TestSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecurityScanner("example.com")

    @patch('security_scanner.dns.resolver.resolve')
    def test_dns_health_check(self, mock_resolve):
        # Mock DNS response
        mock_resolve.return_value = MagicMock()
        mock_resolve.return_value.__iter__.return_value = [MagicMock(to_text=lambda: "v=spf1 include:_spf.google.com ~all")]
        
        results = self.scanner.assess_dns_health()
        self.assertIn('spf', results)
        self.assertIn('dmarc', results)
        self.assertIn('dnssec', results)

    @patch('security_scanner.requests.get')
    def test_ssl_security_check(self, mock_get):
        # Mock SSL response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "endpoints": [{
                "grade": "A+",
                "server_name": "example.com"
            }]
        }
        mock_get.return_value = mock_response
        
        results = self.scanner.assess_ssl_security()
        self.assertIn('ssl_version', results)
        self.assertIn('certificate', results)
        self.assertIn('security_headers', results)

    @patch('security_scanner.requests.get')
    def test_ip_reputation_check(self, mock_get):
        # Mock VirusTotal response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 100
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        results = self.scanner.assess_ip_reputation()
        self.assertIn('reputation_score', results)
        self.assertIn('threats', results)
        self.assertIn('historical_data', results)

    def test_email_validation(self):
        # Test valid email
        self.assertTrue(self.scanner.validate_email("test@example.com"))
        # Test invalid email
        self.assertFalse(self.scanner.validate_email("invalid-email"))

if __name__ == '__main__':
    unittest.main() 