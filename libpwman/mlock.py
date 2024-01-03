# -*- coding: utf-8 -*-
"""
# mlock support
# Copyright (c) 2019-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import platform
import os
import sys

__all__ = [
	"MLockWrapper",
]

class MLockWrapper:
	"""OS mlock wrapper.
	"""

	__singleton = None

	@classmethod
	def get(cls):
		if cls.__singleton is None:
			cls.__singleton = cls()
		return cls.__singleton

	def __init__(self):
		self.__ffi = None
		self.__linux_libc = None

		isLinux = os.name == "posix" and "linux" in sys.platform.lower()
		isWindows = os.name == "nt" and "win32" in sys.platform.lower()

		if isLinux:
			try:
				from cffi import FFI
			except ImportError as e:
				print("Failed to import CFFI: %s\n"
				      "Cannot use mlock() via CFFI.\n"
				      "You might want to install CFFI by running: "
				      "pip3 install cffi" % (
				      str(e)), file=sys.stderr)
				return
			self.__ffi = FFI()
			# Use getattr to avoid Cython cdef compile error.
			getattr(self.__ffi, "cdef")("int mlockall(int flags);")
			self.__linux_libc = self.__ffi.dlopen(None)
		elif isWindows:
			pass # TODO
		else:
			pass # Unsupported OS.

	def mlockall(self):
		"""Lock all current and all future memory.
		"""
		error = "mlockall() is not supported on this operating system."
		if self.__linux_libc is not None and self.__ffi is not None:
			if platform.machine().lower() in (
					"alpha",
					"ppc", "ppc64", "ppcle", "ppc64le",
					"sparc", "sparc64" ):
				MCL_CURRENT	= 0x2000
				MCL_FUTURE	= 0x4000
			else:
				MCL_CURRENT	= 0x1
				MCL_FUTURE	= 0x2
			ret = self.__linux_libc.mlockall(MCL_CURRENT | MCL_FUTURE)
			error = os.strerror(self.__ffi.errno) if ret else ""
		return error
