from pwman_tstlib import *
initTest(__file__)

import importlib
import os
import pathlib
import shutil
import tempfile

class Test_UI(TestCase):
	"""User interface.
	"""

	def __fakeClearScreen(self):
		print("CLEAR SCREEN")

	def __fakeReadPassphrase(self, prompt, verify=False):
		print("READ PASSPHRASE")
		return "test"

	def setUp(self):
		import libpwman.util
		self.__origClearScreen = libpwman.util.clearScreen
		self.__origReadPassphrase = libpwman.util.readPassphrase
		libpwman.util.clearScreen = self.__fakeClearScreen
		libpwman.util.readPassphrase = self.__fakeReadPassphrase

		import libpwman
		importlib.reload(libpwman.ui)
		self.dbFile = tempfile.NamedTemporaryFile(suffix="_" + self.id())
		self.dbFileSecondary = tempfile.NamedTemporaryFile(suffix="_secondary_" + self.id())
		print("DB file:", self.dbFile.name)
		print("Secondary DB file:", self.dbFileSecondary.name)
		shutil.copy(pathlib.Path("tests", "test_database_v1.db"),
			    self.dbFile.name)
		self.ui = libpwman.PWMan(filename=self.dbFile.name,
					 passphrase="test")

	def tearDown(self):
		try:
			self.dbFile.close()
		except FileNotFoundError as e:
			pass
		try:
			self.dbFileSecondary.close()
		except FileNotFoundError as e:
			pass

		self.dbFile = None
		self.dbFileSecondary = None

		import libpwman.util
		libpwman.util.clearScreen = self.__origClearScreen

	def test_base(self):
		import libpwman

		self.ui.do_help("")
		self.assertRaises(libpwman.PWMan.Quit,
				  lambda: self.ui.do_quit(""))
		self.ui.do_cls("")

		self.ui.do_database("") # No params: db listing.
		self.ui.do_database("main") # Re-select of main shall succeed.
		self.ui.do_commit("")
		self.ui.do_masterp("")
		self.ui.do_dbdump("")
		self.assertRaises(libpwman.PWMan.CommandError,
				  lambda: self.ui.do_dbimport("/does/not/exist"))
		self.ui.do_drop("")

		self.ui.do_list("")
		self.ui.do_list("testcat1 testtitle1 totpkey")
		self.ui.do_find("test")
		self.ui.do_totp("testcat1 testtitle1")
		self.ui.do_diff("")

		self.ui.do_new("a b c")
		self.ui.do_edit_user("a b c")
		self.ui.do_edit_pw("a b c")
		self.ui.do_edit_bulk("a b c")
		self.ui.do_edit_totp("a b GEZDGNAK 6 SHA1")
		self.ui.do_edit_attr("a b c d")
		self.ui.do_move("a b c d")
		self.ui.do_remove("c d")

	def test_multidb_closemain(self):
		import libpwman
		self.assertRaises(libpwman.PWMan.Quit,
				  lambda: self.ui.do_close(""))

	def test_multidb(self):
		import libpwman
		try:
			os.unlink(self.dbFileSecondary.name)
		except FileNotFoundError as e:
			pass

		# main db
		self.ui.do_database("main")
		self.ui.do_new("cat0 ent0 user0 pw0")
		self.ui.do_new("cat1 ent1 user1 pw1")
		self.ui.do_new("bigcat ent10 user10 pw10")
		self.ui.do_new("bigcat ent11 user11 pw11")
		self.ui.do_new("bigcat ent12 user12 pw12")
		self.ui.do_new("bigcat ent13 user13 pw13")
		self.ui.do_edit_bulk("cat0 ent0 bulk0")
		self.ui.do_edit_attr("cat0 ent0 attr0 attrdata0")
		self.ui.do_edit_totp("cat0 ent0 GEZDGNAK 6 SHA1")
		self.ui.do_edit_bulk("bigcat ent10 bulk10")
		self.ui.do_edit_attr("bigcat ent10 attr10 attrdata10")
		self.ui.do_edit_totp("bigcat ent10 GEZDGNAK 8 SHA256")
		# secondary db
		self.ui.do_database("-f %s secondary" % self.dbFileSecondary.name)
		self.ui.do_new("cat2 ent2 user2 pw2")

		# move

		self.ui.do_database("main")

		self.ui.do_move("-d secondary cat0 ent0 cat0")
		self.assertRaises(libpwman.PWMan.CommandError,
			lambda: self.ui.do_move("-d secondary cat0 ent0 cat0"))

		self.ui.do_move("-s secondary -d main cat2 ent2 cat2")
		self.assertRaises(libpwman.PWMan.CommandError,
			lambda: self.ui.do_move("-s secondary -d main cat2 ent2 cat2"))

		self.ui.do_move("-d secondary bigcat")
		self.assertRaises(libpwman.PWMan.CommandError,
			lambda: self.ui.do_move("-d secondary bigcat"))

		# copy

		self.ui.do_database("main")

		self.ui.do_copy("-s secondary -d main cat0 ent0 cat0copy ent0copy")
		self.ui.do_copy("-s secondary -d main bigcat bigcatcopy")

		# check data

		db = self.ui._getDb("main")
		# cat1/ent1
		entry = db.getEntry("cat1", "ent1")
		self.assertEqual(entry.user, "user1")
		self.assertEqual(entry.pw, "pw1")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr1")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)
		# cat2/ent2
		entry = db.getEntry("cat2", "ent2")
		self.assertEqual(entry.user, "user2")
		self.assertEqual(entry.pw, "pw2")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr2")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)
		# cat0copy/ent0copy
		entry = db.getEntry("cat0copy", "ent0copy")
		self.assertEqual(entry.user, "user0")
		self.assertEqual(entry.pw, "pw0")
		bulk = db.getEntryBulk(entry)
		self.assertEqual(bulk.data, "bulk0")
		attr = db.getEntryAttr(entry, "attr0")
		self.assertEqual(attr.name, "attr0")
		self.assertEqual(attr.data, "attrdata0")
		totp = db.getEntryTotp(entry)
		self.assertEqual(totp.key, "GEZDGNAK")
		self.assertEqual(totp.digits, 6)
		self.assertEqual(totp.hmacHash, "SHA1")
		# bigcatcopy/ent10
		entry = db.getEntry("bigcatcopy", "ent10")
		self.assertEqual(entry.user, "user10")
		self.assertEqual(entry.pw, "pw10")
		bulk = db.getEntryBulk(entry)
		self.assertEqual(bulk.data, "bulk10")
		attr = db.getEntryAttr(entry, "attr10")
		self.assertEqual(attr.name, "attr10")
		self.assertEqual(attr.data, "attrdata10")
		totp = db.getEntryTotp(entry)
		self.assertEqual(totp.key, "GEZDGNAK")
		self.assertEqual(totp.digits, 8)
		self.assertEqual(totp.hmacHash, "SHA256")
		# bigcatcopy/ent11
		entry = db.getEntry("bigcatcopy", "ent11")
		self.assertEqual(entry.user, "user11")
		self.assertEqual(entry.pw, "pw11")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr11")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)
		# bigcatcopy/ent12
		entry = db.getEntry("bigcatcopy", "ent12")
		self.assertEqual(entry.user, "user12")
		self.assertEqual(entry.pw, "pw12")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr12")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)
		# bigcatcopy/ent13
		entry = db.getEntry("bigcatcopy", "ent13")
		self.assertEqual(entry.user, "user13")
		self.assertEqual(entry.pw, "pw13")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr13")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)


		db = self.ui._getDb("secondary")
		# cat0/ent0
		entry = db.getEntry("cat0", "ent0")
		self.assertEqual(entry.user, "user0")
		self.assertEqual(entry.pw, "pw0")
		bulk = db.getEntryBulk(entry)
		self.assertEqual(bulk.data, "bulk0")
		attr = db.getEntryAttr(entry, "attr0")
		self.assertEqual(attr.name, "attr0")
		self.assertEqual(attr.data, "attrdata0")
		totp = db.getEntryTotp(entry)
		self.assertEqual(totp.key, "GEZDGNAK")
		self.assertEqual(totp.digits, 6)
		self.assertEqual(totp.hmacHash, "SHA1")
		# bigcat/ent10
		entry = db.getEntry("bigcat", "ent10")
		self.assertEqual(entry.user, "user10")
		self.assertEqual(entry.pw, "pw10")
		bulk = db.getEntryBulk(entry)
		self.assertEqual(bulk.data, "bulk10")
		attr = db.getEntryAttr(entry, "attr10")
		self.assertEqual(attr.name, "attr10")
		self.assertEqual(attr.data, "attrdata10")
		totp = db.getEntryTotp(entry)
		self.assertEqual(totp.key, "GEZDGNAK")
		self.assertEqual(totp.digits, 8)
		self.assertEqual(totp.hmacHash, "SHA256")
		# bigcat/ent11
		entry = db.getEntry("bigcat", "ent11")
		self.assertEqual(entry.user, "user11")
		self.assertEqual(entry.pw, "pw11")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr11")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)
		# bigcat/ent12
		entry = db.getEntry("bigcat", "ent12")
		self.assertEqual(entry.user, "user12")
		self.assertEqual(entry.pw, "pw12")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr12")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)
		# bigcat/ent13
		entry = db.getEntry("bigcat", "ent13")
		self.assertEqual(entry.user, "user13")
		self.assertEqual(entry.pw, "pw13")
		bulk = db.getEntryBulk(entry)
		self.assertIsNone(bulk)
		attr = db.getEntryAttr(entry, "attr13")
		self.assertIsNone(attr)
		totp = db.getEntryTotp(entry)
		self.assertIsNone(totp)


		self.ui.do_commit("-a")
