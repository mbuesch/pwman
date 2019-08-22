from pwman_tstlib import *
initTest(__file__)

import pathlib
from libpwman.database import *

class Test_Database_v0(TestCase):
	"""Legacy version 0 database format.
	"""
	def test_v0(self):
		db = PWManDatabase(filename=pathlib.Path("tests", "test_database_v0.db"),
				   passphrase="test")

		self.assertEqual(db.getCategoryNames(),
				 sorted([ "testcategory", "testcategory2", "testcategory3" ]))

		self.assertEqual(db.getEntryTitles("testcategory"),
				 sorted([ "testtitle", "foo", "biz" ]))
		self.assertEqual(db.getEntryTitles("testcategory2"),
				 sorted([ "testtitle2" ]))
		self.assertEqual(db.getEntryTitles("testcategory3"),
				 sorted([ "testtitle3" ]))

		entry = db.getEntry("testcategory", "testtitle")
		self.assertEqual(entry.user, "testuser")
		self.assertEqual(entry.pw, "testpassword")
		entryBulk = db.getEntryBulk(entry)
		self.assertEqual(entryBulk.data, "testbulk")

		entry = db.getEntry("testcategory", "foo")
		self.assertEqual(entry.user, "bar")
		self.assertEqual(entry.pw, "")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("testcategory", "biz")
		self.assertEqual(entry.user, "baz")
		self.assertEqual(entry.pw, "")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("testcategory2", "testtitle2")
		self.assertEqual(entry.user, "testuser2")
		self.assertEqual(entry.pw, "testpassword2")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("testcategory3", "testtitle3")
		self.assertEqual(entry.user, "testuser3")
		self.assertEqual(entry.pw, "")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)
