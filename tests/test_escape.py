from pwman_tstlib import *
initTest(__file__)

from libpwman.ui import escapeCmd, unescapeCmd

class Test_Escape(TestCase):
	def test_escape(self):
		t0 = t1 = '1-2x-y-a\tb c\\\\_ \\\\ x_-y\r\n_\tz\v__\\\\__\\-'
		nrIter = 3
		print("ORIG :", t0)
		for i in range(nrIter):
			t1 = escapeCmd(t1)
			print("ESC%d : %s" % (i, t1))
		for i in range(nrIter):
			t1 = unescapeCmd(t1)
		print("UNESC:", t1)
		self.assertEqual(t1, t0)
