import os
import unittest

# Workaround for python unittest not discovering tests in subdirectories
# https://stackoverflow.com/questions/44708204/run-all-tests-from-subdirectories-in-python

suite = unittest.TestSuite()

for path,subdirs,files in os.walk('tests'):
    if "pycache" not in path:
        loader = unittest.TestLoader()
        suite.addTests(loader.discover(path, "*_test.py"))

unittest.TextTestRunner().run(suite)