#!/usr/bin/env python

from distutils.core import setup

setup(
	name		= "pwman",
#	version		=
	description	= "Lightweight password manager",
	author		= "Michael Buesch",
	author_email	= "m@bues.ch",
	url		= "git://git.bu3sch.de/pwman.git",
	py_modules	= [ "libpwman", "cryptsql", ],
	scripts		= [ "pwman", "pwman-import-pwmanager", ]
)
