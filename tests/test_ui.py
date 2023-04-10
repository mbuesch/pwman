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
		# secondary db
		self.ui.do_database("-f %s secondary" % self.dbFileSecondary.name)
		self.ui.do_new("cat2 ent2 user2 pw2")

		self.ui.do_database("main")

		self.ui.do_move("-d secondary cat0 ent0 cat0")
		self.assertRaises(libpwman.PWMan.CommandError,
			lambda: self.ui.do_move("-d secondary cat0 ent0 cat0"))

		self.ui.do_move("-s secondary -d main cat0 ent0 cat0")
		self.assertRaises(libpwman.PWMan.CommandError,
			lambda: self.ui.do_move("-s secondary -d main cat0 ent0 cat0"))

		self.ui.do_move("-d secondary bigcat")
		self.assertRaises(libpwman.PWMan.CommandError,
			lambda: self.ui.do_move("-d secondary bigcat"))
		self.ui.do_move("-s secondary -d main bigcat bigcat2")
		self.assertRaises(libpwman.PWMan.CommandError,
			lambda: self.ui.do_move("-s secondary -d main bigcat bigcat2"))

		self.ui.do_commit("-a")
