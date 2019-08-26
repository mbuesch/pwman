#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from distutils.core import setup
import warnings
import os
import sys

from libpwman import VERSION

basedir = os.path.abspath(os.path.dirname(__file__))
for base in (os.getcwd(), basedir):
	sys.path.insert(0, base)

warnings.filterwarnings("ignore", r".*'python_requires'.*")
warnings.filterwarnings("ignore", r".*'long_description_content_type'.*")

with open(os.path.join(basedir, "README.rst"), "rb") as fd:
	readmeText = fd.read().decode("UTF-8")

setup(
	name		= "pwman",
	version		= "%d" % VERSION,
	description	= "Commandline password manager",
	author		= "Michael Buesch",
	author_email	= "m@bues.ch",
	url		= "https://bues.ch/h/pwman",
	python_requires = ">=3.7",
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
)
