from pwman_tstlib import *
initTest(__file__)

from base64 import b32decode
from libpwman.otp import *

class Test_OTP(TestCase):
	def test_totp(self):
		tBase = 1566319890
		results = {
			"SHA1" : ("71893792", "61002911"),
			"SHA256" : ("00589223", "95469059"),
			"SHA512" : ("66254736", "69059965"),
		}
		for hmacHash in ("SHA1", "SHA256", "SHA512"):
			for nrDigits in range(1, 8 + 1):
				for t in range(tBase - 2, tBase + 30 + 2):
					otp = totp(key="ORSXG5A=",
						   nrDigits=nrDigits,
						   hmacHash=hmacHash,
						   t=float(t))
					if t < tBase + 15:
						self.assertEqual(otp, results[hmacHash][0][8 - nrDigits :])
					else:
						self.assertEqual(otp, results[hmacHash][1][8 - nrDigits :])
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
