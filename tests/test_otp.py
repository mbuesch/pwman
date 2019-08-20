from pwman_tstlib import *
initTest(__file__)

from base64 import b32decode
from libpwman.otp import *

class Test_OTP(TestCase):
	def test_totp(self):
		tBase = 1566319890
		results = {
			"SHA1" : {
				1 : ("5", "2", "2"),
				2 : ("75", "82", "92"),
				3 : ("575", "982", "792"),
				4 : ("7575", "5982", "3792"),
				5 : ("67575", "95982", "93792"),
				6 : ("667575", "995982", "893792"),
				7 : ("2667575", "1995982", "1893792"),
				8 : ("02667575", "81995982", "71893792"),
			},
			"SHA256" : {
				1 : ("5", "5", "3"),
				2 : ("55", "35", "23"),
				3 : ("655", "735", "223"),
				4 : ("8655", "4735", "9223"),
				5 : ("08655", "34735", "89223"),
				6 : ("108655", "834735", "589223"),
				7 : ("5108655", "4834735", "0589223"),
				8 : ("25108655", "64834735", "00589223"),
			},
			"SHA512" : {
				1 : ("6", "7", "6"),
				2 : ("16", "07", "36"),
				3 : ("016", "907", "736"),
				4 : ("0016", "8907", "4736"),
				5 : ("70016", "38907", "54736"),
				6 : ("670016", "038907", "254736"),
				7 : ("0670016", "4038907", "6254736"),
				8 : ("00670016", "94038907", "66254736"),
			},
		}
		for hmacHash in ("SHA1", "SHA256", "SHA512"):
			for nrDigits in range(1, 8 + 1):
				for t in range(tBase - 1, tBase + 30 + 1):
					otp = totp(key="ORSXG5A=",
						   nrDigits=nrDigits,
						   hmacHash=hmacHash,
						   t=float(t))
					if t < tBase:
						self.assertEqual(otp, results[hmacHash][nrDigits][0])
					elif t < tBase + 30:
						self.assertEqual(otp, results[hmacHash][nrDigits][1])
					else:
						self.assertEqual(otp, results[hmacHash][nrDigits][2])
					self.assertEqual(otp,
							 totp(key="ORSXG5A=".lower(),
							      nrDigits=nrDigits,
							      hmacHash=hmacHash,
							      t=float(t)))
					self.assertEqual(otp,
							 totp(key=b32decode("ORSXG5A=".encode("UTF-8")),
							      nrDigits=nrDigits,
							      hmacHash=hmacHash,
							      t=float(t)))

	def test_totp_errors(self):
		self.assertRaises(OtpError, lambda: totp(key="ORSXG5A=", nrDigits=0))
		self.assertRaises(OtpError, lambda: totp(key="ORSXG5A=", nrDigits=9))
		self.assertRaises(OtpError, lambda: totp(key="ORSXG5A=", hmacHash="foobar"))
		self.assertRaises(OtpError, lambda: totp(key="ORSXG5A"))

	def test_hotp_errors(self):
		self.assertRaises(OtpError, lambda: hotp(key="ORSXG5A=", counter=-1))
		self.assertRaises(OtpError, lambda: hotp(key="ORSXG5A=", counter=2**64))
