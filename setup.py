#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from distutils.core import setup
try:
	from cx_Freeze import setup, Executable
	cx_Freeze = True
except ImportError:
	cx_Freeze = False
import warnings
import os
import sys

from libpwman import __version__

basedir = os.path.abspath(os.path.dirname(__file__))
for base in (os.getcwd(), basedir):
	sys.path.insert(0, base)

isWindows = os.name.lower() in {"nt", "ce"}
isPosix = os.name.lower() == "posix"

# Create freeze executable list.
extraKeywords = {}
if cx_Freeze:
	guiBase = "Win32GUI" if isWindows else None
	freezeExecutables = [
		("pwman", None, None),
	]
	executables = []
	for script, exe, base in freezeExecutables:
		if exe:
			if isWindows:
				exe += ".exe"
			executables.append(Executable(script=script,
						      targetName=exe,
						      base=base))
		else:
			executables.append(Executable(script=script,
						      base=base))
	extraKeywords["executables"] = executables
	extraKeywords["options"] = {
			"build_exe" : {
				"packages" : [ "readline",
					       "pyreadline",
					       "curses",
					       "_curses",
					       "sqlite3",
					       "sqlite3.dump", ],
				"excludes" : [ "tkinter", ],
			}
		}

warnings.filterwarnings("ignore", r".*'python_requires'.*")
warnings.filterwarnings("ignore", r".*'install_requires'.*")
warnings.filterwarnings("ignore", r".*'long_description_content_type'.*")

with open(os.path.join(basedir, "README.rst"), "rb") as fd:
	readmeText = fd.read().decode("UTF-8")

setup(
	name		= "pwman-python",
	version		= __version__,
	description	= "Commandline password manager",
	author		= "Michael Buesch",
	author_email	= "m@bues.ch",
	url		= "https://bues.ch/h/pwman",
	python_requires = ">=3.7",
	install_requires = [ "pyaes", ],
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
		"License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
		"Operating System :: OS Independent",
		"Programming Language :: Python :: 3",
	],
	long_description=readmeText,
	long_description_content_type="text/x-rst",
	**extraKeywords
)
