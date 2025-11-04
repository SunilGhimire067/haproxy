import unittest
from src.core.parser import Parser

class TestParser(unittest.TestCase):
    def setUp(self):
        self.parser = Parser()

    def test_parse_valid_config(self):
        config_content = """
        frontend http_front
            bind *:80
            default_backend http_back

        backend http_back
            server server1 192.168.1.1:80 check
            server server2 192.168.1.2:80 check
        """
        backends = self.parser.parse(config_content)
        self.assertIn('http_back', backends)
        self.assertEqual(len(backends['http_back']), 2)

    def test_parse_invalid_config(self):
        config_content = """
        frontend http_front
            bind *:80
            default_backend http_back

        backend http_back
            server server1 192.168.1.1:80 check
            server server2 invalid_ip:80 check
        """
        with self.assertRaises(ValueError):
            self.parser.parse(config_content)

    def test_extract_backend_info(self):
        config_content = """
        backend http_back
            server server1 192.168.1.1:80 check
        """
        backends = self.parser.parse(config_content)
        backend_info = self.parser.get_backend_info('http_back')
        self.assertEqual(backend_info['servers'][0]['name'], 'server1')
        self.assertEqual(backend_info['servers'][0]['address'], '192.168.1.1:80')

if __name__ == '__main__':
    unittest.main()