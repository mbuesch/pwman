from pwman_tstlib import *
initTest(__file__)

from libpwman.crypto_fallback.aesgcm import AESGCM
import libpwman.crypto_fallback.argon2purers as argon2purers

class Test_CryptoFallback(TestCase):
	def test_aesgcm(self):
		AESGCM.selfTest()

	def test_argon2(self):
		self.assertEqual(
			argon2purers.argon2(
				password=b"\x01" * 32,
				salt=b"\x02" * 16,
				time_cost=3,
				memory_cost=32,
				parallelism=4,
				tag_length=32,
				secret=b"\x03" * 8,
				associated_data=b"\x04" * 12,
				type_code=argon2purers.ARGON2D,
				version=0x13,
			).hex(),
			"512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
		)
		self.assertEqual(
			argon2purers.argon2(
				password=b"\x01" * 32,
				salt=b"\x02" * 16,
				time_cost=3,
				memory_cost=32,
				parallelism=4,
				tag_length=32,
				secret=b"\x03" * 8,
				associated_data=b"\x04" * 12,
				type_code=argon2purers.ARGON2I,
				version=0x13,
			).hex(),
			"c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
		)
		self.assertEqual(
			argon2purers.argon2(
				password=b"\x01" * 32,
				salt=b"\x02" * 16,
				time_cost=3,
				memory_cost=32,
				parallelism=4,
				tag_length=32,
				secret=b"\x03" * 8,
				associated_data=b"\x04" * 12,
				type_code=argon2purers.ARGON2ID,
				version=0x13,
			).hex(),
			"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
		)
		self.assertEqual(
			len(
				argon2purers.argon2(
					password=b"password",
					salt=b"saltysaltsaltysalt",
					time_cost=1,
					memory_cost=8,
					parallelism=1
				)
			),
			32
		)
		self.assertEqual(
			len(
				argon2purers.argon2(
					password=b"pw",
					salt=b"salt",
					time_cost=1,
					memory_cost=8,
					parallelism=1,
					tag_length=100
				)),
			100
		)
		with self.assertRaisesRegex(ValueError, "time_cost must be >0"):
			argon2purers.argon2(
				password=b"p",
				salt=b"s",
				time_cost=0, # invalid
				memory_cost=8,
				parallelism=1,
			)
		with self.assertRaisesRegex(ValueError, "parallelism too small or too large"):
			argon2purers.argon2(
				password=b"p",
				salt=b"s",
				time_cost=1,
				memory_cost=8,
				parallelism=0, # invalid
			)
		with self.assertRaisesRegex(ValueError, "memory_cost must be >=8 times #lanes"):
			argon2purers.argon2(
				password=b"p",
				salt=b"s",
				time_cost=1,
				memory_cost=4, # invalid
				parallelism=1,
			)
		with self.assertRaisesRegex(ValueError, "type_code not supported"):
			argon2purers.argon2(
				password=b"p",
				salt=b"s",
				time_cost=1,
				memory_cost=8,
				parallelism=1,
				tag_length=32,
				secret=b"",
				associated_data=b"",
				type_code=9, # invalid
				version=0x13,
			)
		with self.assertRaisesRegex(ValueError, "version not supported"):
			argon2purers.argon2(
				password=b"p",
				salt=b"s",
				time_cost=1,
				memory_cost=8,
				parallelism=1,
				tag_length=32,
				secret=b"",
				associated_data=b"",
				type_code=1,
				version=0x99, # invalid
			)
		with self.assertRaisesRegex(ValueError, "tag_length must be >0"):
			argon2purers.argon2(
				password=b"p",
				salt=b"s",
				time_cost=1,
				memory_cost=8,
				parallelism=1,
				tag_length=0, # invalid
				secret=b"",
				associated_data=b"",
				type_code=1,
				version=0x13,
			)
