from pwman_tstlib import *
initTest(__file__)

import pathlib
from libpwman.database import *

class Test_Database_v1(TestCase):
	"""Version 1 database format.
	"""
	def test_read_contents(self):
		db = PWManDatabase(filename=pathlib.Path("tests", "test_database_v1.db"),
				   passphrase="test")

		self.assertEqual(db.getCategoryNames(),
				 sorted([ "123",
					  "test2",
					  "testcat1" ]))

		self.assertEqual(db.getEntryTitles("123"),
				 sorted([ "4711",
					  "456" ]))
		self.assertEqual(db.getEntryTitles("test2"),
				 sorted([ "test2" ]))
		self.assertEqual(db.getEntryTitles("testcat1"),
				 sorted([ "testtitle1",
					  "testtitle2",
					  "test title3",
					  "test-title3",
					  "test title4",
					  "test title 5",
					  "test  title  6" ]))

		entry = db.getEntry("testcat1", "testtitle1")
		self.assertEqual(entry.user, "uuuuuuuuu")
		self.assertEqual(entry.pw, "pppppp")
		entryBulk = db.getEntryBulk(entry)
		self.assertEqual(entryBulk.data, "bbbbbbbb")
		entryAttr = db.getEntryAttr(entry, "AAAA")
		self.assertEqual(entryAttr.data, "BBBB")
		entryAttr = db.getEntryAttr(entry, "CCCC")
		self.assertEqual(entryAttr.data, "DDDDDDD")
		entryTotp = db.getEntryTotp(entry)
		self.assertEqual(entryTotp.key, "MZXW63YK")
		self.assertEqual(entryTotp.digits, 6)
		self.assertEqual(entryTotp.hmacHash, "SHA1")

		entry = db.getEntry("testcat1", "testtitle2")
		self.assertEqual(entry.user, "user")
		self.assertEqual(entry.pw, "pw")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)
		entryTotp = db.getEntryTotp(entry)
		self.assertEqual(entryTotp.key, "MJQXE4QK")
		self.assertEqual(entryTotp.digits, 8)
		self.assertEqual(entryTotp.hmacHash, "SHA256")

		entry = db.getEntry("testcat1", "test-title3")
		self.assertEqual(entry.user, "aa bb")
		self.assertEqual(entry.pw, "cc dd")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("testcat1", "test title3")
		self.assertEqual(entry.user, "xx yy")
		self.assertEqual(entry.pw, "oo pp")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("testcat1", "test title4")
		self.assertEqual(entry.user, "4")
		self.assertEqual(entry.pw, "44")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("testcat1", "test title 5")
		self.assertEqual(entry.user, "5")
		self.assertEqual(entry.pw, "55")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("testcat1", "test  title  6")
		self.assertEqual(entry.user, "6")
		self.assertEqual(entry.pw, "66")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("123", "4711")
		self.assertEqual(entry.user, "UUU")
		self.assertEqual(entry.pw, "password")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)
		entryAttr = db.getEntryAttr(entry, "git")
		self.assertEqual(entryAttr.data, "https://git.example.com")
		entryAttr = db.getEntryAttr(entry, "www")
		self.assertEqual(entryAttr.data, "https://www.example.com")

		entry = db.getEntry("123", "456")
		self.assertEqual(entry.user, "789")
		self.assertEqual(entry.pw, "")
		entryBulk = db.getEntryBulk(entry)
		self.assertIsNone(entryBulk)

		entry = db.getEntry("test2", "test2")
		self.assertEqual(entry.user, "TEST!")
		self.assertEqual(entry.pw, "TEST!!")
		entryBulk = db.getEntryBulk(entry)
		self.assertEqual(entryBulk.data, "TEST!!!")
