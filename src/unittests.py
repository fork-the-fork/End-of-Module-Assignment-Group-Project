"""
This file performs the unit tests on the client-server code.
"""

import sys
import os
import unittest


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))


class ClientServer(unittest.TestCase):
    """
    This class contains tests which assess the functionality of the imperative algorithm.
    It utilises predefined input-output pairs from test_samples module.
    """


if __name__=="__main__":
    unittest.main()
