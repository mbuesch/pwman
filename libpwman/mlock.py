# -*- coding: utf-8 -*-
"""
#
# mlock support
#
# Copyright 2019-2020 Michael Buesch <m@bues.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
"""

import platform
import os
import sys

__all__ = [
	"MLockWrapper",
]

class MLockWrapper(object):
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
			      "Cannot use mlock() via CFFI." % (
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
