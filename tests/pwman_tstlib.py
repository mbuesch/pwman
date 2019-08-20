from unittest import TestCase

__all__ = [
	"TestCase",
	"initTest",
]

def initTest(testCaseFile):
	from os.path import basename
	print("(test case file: %s)" % basename(testCaseFile))
