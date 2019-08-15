#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from distutils.core import setup
from libpwman import VERSION

setup(
	name		= "pwman",
	version		= "%d" % VERSION,
	description	= "Lightweight password manager",
	author		= "Michael Buesch",
	author_email	= "m@bues.ch",
	url		= "git://git.bues.ch/pwman.git",
	py_modules	= [ "libpwman", "cryptsql", ],
	scripts		= [ "pwman", ]
)
