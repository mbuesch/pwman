from pwman_tstlib import *
initTest(__file__)

from libpwman.crypto_fallback.aesgcm import AESGCM

class Test_CryptoFallback(TestCase):
	def test_aesgcm(self):
		AESGCM.quickSelfTest()
