import subprocess
import unittest
import os

class TestGhauri(unittest.TestCase):
    def testHelpDisplayedOnMissingBulkFile(self):
        out = subprocess.run(
                ['python3', '-m', 'ghauri.scripts.ghauri'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            ).stdout.decode('utf-8')
        self.assertIn('usage: ghauri.py -u URL [OPTIONS]', out)

    def testHelpNotDisplayedIfBulkFileProvided(self):
        out = subprocess.run(
            ['python3', '-m', 'ghauri.scripts.ghauri', '-m', 'foobar'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)\
            .stdout.decode('utf-8')
        self.assertNotIn('usage: ghauri.py -u URL [OPTIONS]', out)

    @unittest.skipIf(os.environ.get('ALL_TESTS',None) is None, 'skip to avoid remote calls')
    def testUpdateHappensIfFlagIsIncluded(self):
        proc = subprocess.run(
            ['python3', '-m', 'ghauri.scripts.ghauri', '--update'],
            stderr=subprocess.STDOUT, stdout=subprocess.PIPE
        )
        out = proc.stdout.decode()
        self.assertIn('updating ghauri to the latest development revision from the GitHub repository', out)
        self.assertIn('update in progress....', out)

    def testNoUpdatesIfFlagIsOmitted(self):
        out = subprocess.run(
            ['python3', '-m', 'ghauri.scripts.ghauri'],
            stderr=subprocess.STDOUT, stdout=subprocess.PIPE
        ).stdout.decode('utf-8')
        self.assertNotIn('updating ghauri to the latest development revision from the GitHub repository', out)
        self.assertNotIn('update in progress....', out)
