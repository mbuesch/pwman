# -*- coding: utf-8 -*-
"""
# AES wrapper
# Copyright (c) 2023-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.exception import PWManError

import os

__all__ = [
	"AES",
]

class AES:
	"""Abstraction layer for the AES implementation.
	"""

	BLOCK_SIZE = 128 // 8
	__singleton = None

	@classmethod
	def get(cls):
		"""Get the AES singleton.
		"""
		if cls.__singleton is None:
			cls.__singleton = cls()
		return cls.__singleton

	def __init__(self):
		self.__pyaes = None
		self.__cryptodome = None

		cryptolib = os.getenv("PWMAN_CRYPTOLIB", "").lower().strip()

		if cryptolib in ("", "cryptodome"):
			# Try to use Cryptodome
			try:
				import Cryptodome
				import Cryptodome.Cipher.AES
				import Cryptodome.Util.Padding
				self.__cryptodome = Cryptodome
				return
			except ImportError as e:
				pass

		if cryptolib in ("", "pyaes"):
			# Try to use pyaes
			try:
				import pyaes
				self.__pyaes = pyaes
				return
			except ImportError as e:
				pass

		msg = "Python module import error."
		if cryptolib == "":
			msg += "\nNeither 'Cryptodome' nor 'pyaes' is installed."
		else:
			msg += "\n'PWMAN_CRYPTOLIB=%s' is not supported or not installed." % cryptolib
		raise PWManError(msg)

	def encrypt(self, key, iv, data):
		"""Encrypt data.
		"""

		# Check parameters.
		if len(key) != 256 // 8:
			raise PWManError("AES: Invalid key length.")
		if len(iv) != self.BLOCK_SIZE:
			raise PWManError("AES: Invalid iv length.")
		if len(data) <= 0:
			raise PWManError("AES: Invalid data length.")

		try:
			if self.__cryptodome is not None:
				# Use Cryptodome
				padData = self.__cryptodome.Util.Padding.pad(
					data_to_pad=data,
					block_size=self.BLOCK_SIZE,
					style="pkcs7")
				cipher = self.__cryptodome.Cipher.AES.new(
					key=key,
					mode=self.__cryptodome.Cipher.AES.MODE_CBC,
					iv=iv)
				encData = cipher.encrypt(padData)
				return encData

			if self.__pyaes is not None:
				# Use pyaes
				mode = self.__pyaes.AESModeOfOperationCBC(key=key, iv=iv)
				padding = self.__pyaes.PADDING_DEFAULT
				enc = self.__pyaes.Encrypter(mode=mode, padding=padding)
				encData = enc.feed(data)
				encData += enc.feed()
				return encData

		except Exception as e:
			raise PWManError("AES error: %s: %s" % (type(e), str(e)))
		raise PWManError("AES not implemented.")

	def decrypt(self, key, iv, data, legacyPadding=False):
		"""Decrypt data.
		"""

		# Check parameters.
		if len(key) != 256 // 8:
			raise PWManError("AES: Invalid key length.")
		if len(iv) != self.BLOCK_SIZE:
			raise PWManError("AES: Invalid iv length.")
		if len(data) <= 0:
			raise PWManError("AES: Invalid data length.")

		try:
			if self.__cryptodome is not None:
				# Use Cryptodome
				cipher = self.__cryptodome.Cipher.AES.new(
					key=key,
					mode=self.__cryptodome.Cipher.AES.MODE_CBC,
					iv=iv)
				decData = cipher.decrypt(data)
				if legacyPadding:
					unpadData = self.__unpadLegacy(decData)
				else:
					unpadData = self.__cryptodome.Util.Padding.unpad(
						padded_data=decData,
						block_size=self.BLOCK_SIZE,
						style="pkcs7")
				return unpadData

			if self.__pyaes is not None:
				# Use pyaes
				mode = self.__pyaes.AESModeOfOperationCBC(key=key, iv=iv)
				if legacyPadding:
					padding = self.__pyaes.PADDING_NONE
				else:
					padding = self.__pyaes.PADDING_DEFAULT
				dec = self.__pyaes.Decrypter(mode=mode, padding=padding)
				decData = dec.feed(data)
				decData += dec.feed()
				if legacyPadding:
					unpadData = self.__unpadLegacy(decData)
				else:
					unpadData = decData
				return unpadData

		except Exception as e:
			raise PWManError("AES error: %s: %s" % (type(e), str(e)))
		raise PWManError("AES not implemented.")

	@staticmethod
	def __unpadLegacy(data):
		"""Strip legacy padding.
		"""
		index = data.rfind(b"\xFF")
		if index < 0 or index >= len(data):
			raise PWManError("Legacy padding: Did not find start.")
		return data[:index]

	@classmethod
	def quickSelfTest(cls):
		inst = cls.get()
		enc = inst.encrypt(key=(b"_keykey_" * 4), iv=(b"iv" * 8), data=b"pwman")
		if enc != bytes.fromhex("cf73a286509e1265d26490a76dcbb2fd"):
			raise PWManError("AES encrypt: Quick self test failed.")
		dec = inst.decrypt(key=(b"_keykey_" * 4), iv=(b"iv" * 8), data=enc)
		if dec != b"pwman":
			raise PWManError("AES decrypt: Quick self test failed.")
