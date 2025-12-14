#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup
try:
	from cx_Freeze import setup, Executable
	cx_Freeze = True
except ImportError:
	cx_Freeze = False
import sys
from pathlib import Path
from libpwman import __version__

basedir = Path(__file__).parent.absolute()
sys.path.insert(0, basedir)

extraKeywords = {}
if cx_Freeze:
	extraKeywords["executables"] = [ Executable(script="pwman") ]
	extraKeywords["options"] = {
		"build_exe" : {
			"packages" : [ "readline",
				       "pyreadline3",
				       "curses",
				       "_curses",
				       "sqlite3",
				       "sqlite3.dump", ],
			"excludes" : [ "tkinter", ],
		}
	}

with open(basedir / "README.rst", "rb") as fd:
	readmeText = fd.read().decode("UTF-8")

setup(
	name		= "pwman-python",
	version		= __version__,
	description	= "Commandline password manager",
	author		= "Michael Büsch",
	author_email	= "m@bues.ch",
	license		= "GPL-2.0-or-later",
	url		= "https://bues.ch/h/pwman",
	python_requires = ">=3.7",
	install_requires = [
		"argon2-cffi",
		"cffi",
		"pycryptodomex",
	],
	packages	= [ "libpwman", ],
	scripts		= [ "pwman", ],
	keywords	= "password manager command line TOTP 2FA",
	classifiers	= [
		"Development Status :: 5 - Production/Stable",
		"Environment :: Console",
		"Intended Audience :: Developers",
		"Intended Audience :: Information Technology",
		"Intended Audience :: End Users/Desktop",
		"Intended Audience :: System Administrators",
		"Operating System :: OS Independent",
		"Programming Language :: Python :: 3",
	],
	long_description=readmeText,
	long_description_content_type="text/x-rst",
	**extraKeywords
)

# vim: ts=8 sw=8 noexpandtab
