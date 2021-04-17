# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

__all__ = [
	"VERSION_MAJOR",
	"VERSION_MINOR",
	"VERSION_EXTRA",
	"VERSION_STRING",
]

VERSION_MAJOR = 2
VERSION_MINOR = 4
VERSION_EXTRA = ""

VERSION_STRING = "%d.%d%s" % (VERSION_MAJOR, VERSION_MINOR, VERSION_EXTRA)
