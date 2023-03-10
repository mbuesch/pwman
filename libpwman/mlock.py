# -*- coding: utf-8 -*-
"""
# mlock support
# Copyright (c) 2019-2023 Michael Büsch <m@bues.ch>
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

	singleton = None

	if platform.machine().lower() in (
			"alpha",
			"ppc", "ppc64", "ppcle", "ppc64le",
			"sparc", "sparc64" ):
		MCL_CURRENT	= 0x2000
		MCL_FUTURE	= 0x4000
		MCL_ONFAULT	= 0x8000
	else:
		MCL_CURRENT	= 0x1
		MCL_FUTURE	= 0x2
		MCL_ONFAULT	= 0x4

	def __init__(self):
		self.__ffi = None
		self.__libc = None

		if os.name != "posix" or "linux" not in sys.platform.lower():
			return # "mlock() is only supported on Linux.

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
		getattr(self.__ffi, "cdef")("""
			int mlock(const void *addr, size_t len);
			int mlock2(const void *addr, size_t len, int flags);
			int munlock(const void *addr, size_t len);
			int mlockall(int flags);
			int munlockall(void);
		""")
		self.__libc = self.__ffi.dlopen(None)

	@classmethod
	def get(cls):
		s = cls.singleton
		if not s:
			s = cls.singleton = cls()
		return s

	@classmethod
	def mlockall(cls, flags):
		error = "mlockall() is not supported on this operating system."
		s = cls.get()
		if s.__libc:
			ret = s.__libc.mlockall(flags)
			error = os.strerror(s.__ffi.errno) if ret else ""
		return error

	@classmethod
	def munlockall(cls):
		error = "munlockall() is not supported on this operating system."
		s = cls.get()
		if s.__libc:
			ret = s.__libc.munlockall()
			error = os.strerror(s.__ffi.errno) if ret else ""
		return error
