# -*- coding: utf-8 -*-
"""
# Argon2 wrapper
# Copyright (c) 2023-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.exception import PWManError

import gc
import os

__all__ = [
	"Argon2"
]

class Argon2:
	"""Abstraction layer for the Argon2 implementation.
	"""

	__singleton = None
	DEBUG = False

	@classmethod
	def get(cls):
		"""Get the Argon2 singleton.
		"""
		if cls.__singleton is None:
			cls.__singleton = cls()
		return cls.__singleton

	def __init__(self):
		self.__argon2cffi = None
		self.__argon2pure = None

		argon2lib = os.getenv("PWMAN_ARGON2LIB", "").lower().strip()

		if argon2lib in ("", "argon2-cffi", "argon2cffi"):
			# Try to use argon2-cffi
			try:
				import argon2
				self.__argon2cffi = argon2
				return
			except ImportError as e:
				pass

		if argon2lib == "argon2pure":
			# Use argon2pure, but only if explicitly selected,
			# because it's really really slow.
			try:
				import argon2pure
				self.__argon2pure = argon2pure
				return
			except ImportError as e:
				pass

		msg = "Python module import error."
		if argon2lib == "":
			msg += "\n'argon2-cffi' is not installed."
		else:
			msg += "\n'PWMAN_ARGON2LIB=%s' is not supported or not installed." % argon2lib
		raise PWManError(msg)

	def argon2id_v1p3(self, passphrase, salt, timeCost, memCost, parallel, keyLen):
		"""Run Argon2id v1.3.
		passphrase: The passphrase bytes.
		salt: The salt bytes.
		timeCost: The time cost, in number of iterations.
		memCost: The memory cost, in number of kiB.
		parallel: The number of parallel threads.
		keyLen: The number of bytes to return.
		"""

		# Check parameters.
		if (not isinstance(passphrase, bytes) or
		    len(passphrase) < 1 or
		    len(passphrase) > ((1 << 32) - 1)):
			raise PWManError("Argon2id: Invalid passphrase.")
		if (not isinstance(salt, bytes) or
		    len(salt) < 1 or
		    len(salt) > ((1 << 32) - 1)):
			raise PWManError("Argon2id: Invalid salt.")
		if (not isinstance(timeCost, int) or
		    timeCost < 1 or
		    timeCost > ((1 << 32) - 1)):
			raise PWManError("Argon2id: Invalid time cost.")
		if (not isinstance(parallel, int) or
		    parallel < 1 or
		    parallel > ((1 << 24) - 1)):
			raise PWManError("Argon2id: Invalid parallelism.")
		if (not isinstance(memCost, int) or
		    memCost < 8 * parallel or
		    memCost > ((1 << 32) - 1)):
			raise PWManError("Argon2id: Invalid memory cost.")
		if (not isinstance(keyLen, int) or
		    keyLen < 1 or
		    keyLen > ((1 << 32) - 1)):
			raise PWManError("Argon2id: Invalid hash length.")

		# Memory is locked (for security reasons)
		# and we might not have much of it.
		# Try to free some unused memory to avoid OOM.
		gc.collect()

		if self.DEBUG:
			import time
			begin = time.time()

		key = None
		try:
			if self.__argon2cffi is not None:
				# Use argon2-cffi.
				low_level = self.__argon2cffi.low_level
				key = low_level.hash_secret_raw(
					secret=passphrase,
					salt=salt,
					time_cost=timeCost,
					memory_cost=memCost,
					parallelism=parallel,
					hash_len=keyLen,
					type=low_level.Type.ID,
					version=0x13,
				)
			elif self.__argon2pure is not None:
				# Use argon2pure.
				# Avoid subprocesses:
				# Do not use multiprocessing to keep all memory locked.
				# Subprocesses do not inherit mlockall().
				argon2pure = self.__argon2pure
				key = argon2pure.argon2(
					password=passphrase,
					salt=salt,
					time_cost=timeCost,
					memory_cost=memCost,
					parallelism=parallel,
					tag_length=keyLen,
					type_code=argon2pure.ARGON2ID,
					threads=1, # no threads
					use_threads=True, # no subprocesses
					version=0x13,
				)
		except Exception as e:
			raise PWManError("Argon2 error: %s: %s" % (type(e), str(e)))
		if key is None:
			raise PWManError("Argon2 not implemented.")

		if self.DEBUG:
			print("Argon2id took %.02f s." % (time.time() - begin))

		return key

	@classmethod
	def quickSelfTest(cls):
		"""Run a quick algorithm self test.
		"""
		inst = cls.get()
		h = inst.argon2id_v1p3(
			passphrase=b"namwp",
			salt=(b"pwman"*4),
			timeCost=4,
			memCost=16,
			parallel=2,
			keyLen=32,
		)
		if h != bytes.fromhex("6aa4b71bbf34cce1383577f2fcedecf1074fa7e1f5a664e00cf92f509fb54a35"):
			raise PWManError("Argon2id: Quick self test failed.")
