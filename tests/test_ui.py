from pwman_tstlib import *
initTest(__file__)

import importlib
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
		print("DB file:", self.dbFile.name)
		shutil.copy(pathlib.Path("tests", "test_database_v1.db"),
			    self.dbFile.name)
		self.ui = libpwman.PWMan(filename=self.dbFile.name,
					 passphrase="test")

	def tearDown(self):
		self.dbFile.close()
		self.dbFile = None

		import libpwman.util
		libpwman.util.clearScreen = self.__origClearScreen

	def test_base(self):
		import libpwman

		self.ui.do_help("")
		self.assertRaises(libpwman.PWMan.Quit,
				  lambda: self.ui.do_quit(""))
		self.ui.do_cls("")

		self.ui.do_commit("")
		self.ui.do_masterp("")
		self.ui.do_dbdump("")
		self.assertRaises(libpwman.PWMan.CommandError,
				  lambda: self.ui.do_dbimport("/does/not/exist"))
		self.ui.do_drop("")

		self.ui.do_list("")
		self.ui.do_find("test")
		self.ui.do_totp("testcat1 testtitle1")
		self.ui.do_totp_key("testcat1 testtitle1")
		self.ui.do_diff("")

		self.ui.do_new("a b c")
		self.ui.do_edit_user("a b c")
		self.ui.do_edit_pw("a b c")
		self.ui.do_edit_bulk("a b c")
		self.ui.do_edit_totp("a b GEZDGNAK 6 SHA1")
		self.ui.do_edit_attr("a b c d")
		self.ui.do_move("a b c d")
		self.ui.do_remove("c d")

		self.ui.do_undo("")
		self.ui.do_redo("")
