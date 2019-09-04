# -*- coding: utf-8 -*-
"""
# HOTP/TOTP support
# Copyright (c) 2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import time
from base64 import b32decode
import binascii
import hmac
import hashlib

__all__ = [
	"OtpError",
	"hotp",
	"totp",
]

class OtpError(Exception):
	"""HOTP/TOTP exception.
	"""

def hotp(key, counter, nrDigits=6, hmacHash="SHA1"):
	"""HOTP - An HMAC-Based One-Time Password Algorithm.
	key: The HOTP key. Either raw bytes or a base32 encoded string.
	counter: The HOTP counter integer.
	nrDigits: The number of digits to return. Can be 1 to 8.
	hmacHash: The name string of the hashing algorithm.
	Returns the calculated HOTP token string.
	"""
	if isinstance(key, str):
		try:
			key = b32decode(key.encode("UTF-8"), casefold=True)
		except (binascii.Error, UnicodeError):
			raise OtpError("Invalid key.")
	if not (0 <= counter <= (2 ** 64) - 1):
		raise OtpError("Invalid counter.")
	if not (1 <= nrDigits <= 8):
		raise OtpError("Invalid number of digits.")

	try:
		hmacHash = hmacHash.replace("-", "")
		hmacHash = hmacHash.replace("_", "")
		hmacHash = hmacHash.replace(" ", "")
		hmacHash = hmacHash.upper().strip()
		hmacHash = {
			"SHA1"   : hashlib.sha1,
			"SHA256" : hashlib.sha256,
			"SHA512" : hashlib.sha512,
		}[hmacHash]
	except KeyError:
		raise OtpError("Invalid HMAC hash type.")

	counter = bytes(((counter >> 56) & 0xFF,
			 (counter >> 48) & 0xFF,
			 (counter >> 40) & 0xFF,
			 (counter >> 32) & 0xFF,
			 (counter >> 24) & 0xFF,
			 (counter >> 16) & 0xFF,
			 (counter >> 8) & 0xFF,
			 (counter >> 0) & 0xFF))
	h = hmac.new(key, counter, hmacHash).digest()
	offset = h[19] & 0xF
	hSlice = (((h[offset + 0] & 0x7F) << 24) |
		  ((h[offset + 1] & 0xFF) << 16) |
		  ((h[offset + 2] & 0xFF) << 8) |
		  ((h[offset + 3] & 0xFF) << 0))
	otp = hSlice % (10 ** nrDigits)
	fmt = "%0" + str(nrDigits) + "d"
	return fmt % otp

def totp(key, nrDigits=6, hmacHash="SHA1", t=None):
	"""TOTP - Time-Based One-Time Password Algorithm.
	nrDigits: The number of digits to return. Can be 1 to 8.
	hmacHash: The name string of the hashing algorithm.
	t: Optional; the time in seconds. Uses time.time(), if not given.
	Returns the calculated TOTP token string.
	"""
	if t is None:
		t = time.time()
	t = (int(round(t)) // 30) - 1
	return hotp(key, t, nrDigits, hmacHash)
