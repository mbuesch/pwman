# -*- coding: utf-8 -*-
"""
# AES wrapper
# Copyright (c) 2023-2026 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.exception import PWManError
from libpwman.util import getenv
from libpwman.crypto_fallback.aesgcm import AESGCM

__all__ = [
	"AES",
]

class AES:
	"""Abstraction layer for the AES implementation.
	"""

	BLOCK_SIZE = 128 // 8
	GCM_NONCE_SIZE = 256 // 8
	GCM_TAG_SIZE = 128 // 8

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

		cryptolib = getenv("PWMAN_CRYPTOLIB", "").lower().strip()

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

	def encryptGCM(self, key, nonce, data, assocData):
		"""Encrypt data with AES-256-GCM.
		Returns a tuple (ciphertext, authTag).
		"""

		# Check parameters.
		if len(key) != 256 // 8:
			raise PWManError("AES-GCM: Invalid key length.")
		if len(nonce) != self.GCM_NONCE_SIZE:
			raise PWManError("AES-GCM: Invalid nonce length.")
		if len(data) <= 0:
			raise PWManError("AES-GCM: Invalid data length.")
		if len(assocData) <= 0:
			raise PWManError("AES-GCM: Invalid associated data length.")

		try:
			if self.__cryptodome is not None:
				# Use Cryptodome
				cipher = self.__cryptodome.Cipher.AES.new(
					key=key,
					mode=self.__cryptodome.Cipher.AES.MODE_GCM,
					nonce=nonce)
				cipher.update(assocData)
				encData = cipher.encrypt(data)
				tag = cipher.digest()
			elif self.__pyaes is not None:
				# Use pyaes and fallback-AESGCM
				aes = self.__pyaes.AES(key)
				aesgcm = AESGCM(lambda block: aes.encrypt(block))
				encData, tag = aesgcm.encrypt(
					nonce=nonce,
					plaintext=data,
					associated_data=assocData)
			else:
				raise PWManError("AES-GCM: No implementation available.")

			if len(encData) != len(data):
				raise PWManError("AES-GCM: Encrypted data length mismatch.")
			if len(tag) != self.GCM_TAG_SIZE:
				raise PWManError("AES-GCM: Invalid tag length.")
		except PWManError as e:
			raise e
		except Exception as e:
			raise PWManError("AES-GCM error: %s: %s" % (type(e), str(e)))
		return encData, tag

	def decryptGCM(self, key, nonce, data, tag, assocData):
		"""Decrypt data with AES-256-GCM.
		"""

		# Check parameters.
		if len(key) != 256 // 8:
			raise PWManError("AES-GCM: Invalid key length.")
		if len(nonce) != self.GCM_NONCE_SIZE:
			raise PWManError("AES-GCM: Invalid nonce length.")
		if len(data) <= 0:
			raise PWManError("AES-GCM: Invalid data length.")
		if len(assocData) <= 0:
			raise PWManError("AES-GCM: Invalid associated data length.")
		if len(tag) != self.GCM_TAG_SIZE:
			raise PWManError("AES-GCM: Invalid tag length.")

		try:
			if self.__cryptodome is not None:
				# Use Cryptodome
				cipher = self.__cryptodome.Cipher.AES.new(
					key=key,
					mode=self.__cryptodome.Cipher.AES.MODE_GCM,
					nonce=nonce)
				cipher.update(assocData)
				try:
					decData = cipher.decrypt_and_verify(data, tag)
				except ValueError as e:
					raise PWManError("AES-GCM: Authentication failed.")
			elif self.__pyaes is not None:
				# Use pyaes and fallback-AESGCM
				aes = self.__pyaes.AES(key)
				aesgcm = AESGCM(lambda block: aes.encrypt(block))
				try:
					decData = aesgcm.decrypt(
						nonce=nonce,
						ciphertext=data,
						authentication_tag=tag,
						associated_data=assocData)
				except ValueError as e:
					raise PWManError("AES-GCM: Authentication failed.")
			else:
				raise PWManError("AES-GCM: No implementation available.")

			if len(decData) != len(data):
				raise PWManError("AES-GCM: Decrypted data length mismatch.")
		except PWManError as e:
			raise e
		except Exception as e:
			raise PWManError("AES-GCM error: %s: %s" % (type(e), str(e)))
		return decData

	def decryptCBC(self, key, iv, data, legacyPadding=False):
		"""Decrypt data with AES-256-CBC.
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
			elif self.__pyaes is not None:
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
			else:
				raise PWManError("AES-CBC: No implementation available.")
		except PWManError as e:
			raise e
		except Exception as e:
			raise PWManError("AES error: %s: %s" % (type(e), str(e)))
		return unpadData

	@staticmethod
	def __unpadLegacy(data):
		"""Strip legacy padding.
		"""
		index = data.rfind(b"\xFF")
		if index < 0 or index >= len(data):
			raise PWManError("Legacy padding: Did not find start.")
		return data[:index]

	@classmethod
	def __quickTestCBC(cls):
		inst = cls.get()
		key = b"_keykey_" * 4
		iv = b"iv" * 8
		enc = bytes.fromhex("cf73a286509e1265d26490a76dcbb2fd")
		dec = inst.decryptCBC(key=key, iv=iv, data=enc)
		if dec != b"pwman":
			raise PWManError("AES-CBC decrypt: Quick self test failed.")

	@classmethod
	def __quickTestGCM(cls):
		inst = cls.get()
		key = b"_keykey_" * 4
		nonce = b"n" * inst.GCM_NONCE_SIZE
		assoc = b"_assoc_" * 4
		enc, tag = inst.encryptGCM(key=key, nonce=nonce, data=b"pwman", assocData=assoc)
		if enc != bytes.fromhex("c71c5f2f94") or tag != bytes.fromhex("72629905a2a0ac6be642c9ea62de0d52"):
			raise PWManError("AES-GCM encrypt: Quick self test failed.")
		dec = inst.decryptGCM(key=key, nonce=nonce, data=enc, tag=tag, assocData=assoc)
		if dec != b"pwman":
			raise PWManError("AES-GCM decrypt: Quick self test failed.")

	@classmethod
	def quickSelfTest(cls):
		cls.__quickTestCBC()
		cls.__quickTestGCM()
