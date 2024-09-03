import unittest
import subprocess

class TestUtils(unittest.TestCase):
    def testAllCategoriesInCmdlineOutput(self):
        out = subprocess.run(['python3', '-m', 'ghauri.scripts.ghauri'], stdout=subprocess.PIPE)\
            .stdout.decode('utf8')
        self.assertIn('Enumeration', out)
        self.assertIn('Example', out)
        self.assertIn('Techniques', out)
        self.assertIn('Detection', out)
        self.assertIn('Injection', out)
        self.assertIn('Optimization', out)
        self.assertIn('Request', out)
        self.assertIn('Target', out)
        self.assertIn('General', out)
 