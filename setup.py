#!/usr/bin/env python

from distutils.core import setup
from libpwman import VERSION

setup(
	name		= "pwman",
	version		= "%d" % VERSION,
	description	= "Lightweight password manager",
	author		= "Michael Buesch",
	author_email	= "m@bues.ch",
	url		= "git://git.bu3sch.de/pwman.git",
	py_modules	= [ "libpwman", "cryptsql", ],
	scripts		= [ "pwman", "pwman-import-pwmanager", ]
)
