# -*- coding: utf-8 -*-
"""
# AES wrapper
# Copyright (c) 2023 Michael Büsch <m@bues.ch>
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
		assert len(key) == 256 // 8
		assert len(iv) == self.BLOCK_SIZE

		if self.__cryptodome is not None:
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
			mode = self.__pyaes.AESModeOfOperationCBC(key=key, iv=iv)
			padding = self.__pyaes.PADDING_DEFAULT
			enc = self.__pyaes.Encrypter(mode=mode, padding=padding)
			encData = enc.feed(data)
			encData += enc.feed()
			return encData

		raise NotImplementedError

	def decrypt(self, key, iv, data, legacyPadding=False):
		"""Decrypt data.
		"""
		assert len(key) == 256 // 8
		assert len(iv) == self.BLOCK_SIZE

		if self.__cryptodome is not None:
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

		raise NotImplementedError

	@staticmethod
	def __unpadLegacy(data):
		"""Strip legacy padding.
		"""
		index = data.rfind(b"\xFF")
		if index < 0 or index >= len(data):
			raise CSQLError("unpad_PWMAN: error")
		return data[:index]
