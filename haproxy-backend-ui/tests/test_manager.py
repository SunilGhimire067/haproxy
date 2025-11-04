import unittest
from src.core.manager import Manager

class TestManager(unittest.TestCase):

    def setUp(self):
        self.manager = Manager()

    def test_edit_backend(self):
        # Assuming the Manager class has a method to edit backends
        result = self.manager.edit_backend('backend_name', {'option': 'value'})
        self.assertTrue(result)

    def test_restart_backend(self):
        # Assuming the Manager class has a method to restart backends
        result = self.manager.restart_backend('backend_name')
        self.assertTrue(result)

    def test_invalid_backend_edit(self):
        # Test editing a non-existent backend
        with self.assertRaises(ValueError):
            self.manager.edit_backend('invalid_backend', {'option': 'value'})

    def test_restart_nonexistent_backend(self):
        # Test restarting a non-existent backend
        with self.assertRaises(ValueError):
            self.manager.restart_backend('invalid_backend')

if __name__ == '__main__':
    unittest.main()