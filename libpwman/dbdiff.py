# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.database import *

import difflib

__all__ = [
	"PWManDatabaseDiff",
]

class PWManDatabaseDiff:
	def __init__(self, db, oldDb):
		self.__db = db
		self.__oldDb = oldDb

	def getUnifiedDiff(self, contextLines=3):
		diff = difflib.unified_diff(
			a=self.__oldDb.dumpEntries(totp="show").splitlines(),
			b=self.__db.dumpEntries(totp="show").splitlines(),
			fromfile=str(self.__oldDb.getFilename()),
			tofile=str(self.__db.getFilename()),
			n=contextLines,
			lineterm="")
		return "\n".join(diff)

	def getContextDiff(self, contextLines=3):
		diff = difflib.context_diff(
			a=self.__oldDb.dumpEntries(totp="show").splitlines(),
			b=self.__db.dumpEntries(totp="show").splitlines(),
			fromfile=str(self.__oldDb.getFilename()),
			tofile=str(self.__db.getFilename()),
			n=contextLines,
			lineterm="")
		return "\n".join(diff)

	def getNdiffDiff(self):
		diff = difflib.ndiff(
			a=self.__oldDb.dumpEntries(totp="show").splitlines(),
			b=self.__db.dumpEntries(totp="show").splitlines(),
			linejunk=None,
			charjunk=None)
		return "\n".join(diff)

	def getHtmlDiff(self, contextLines=3):
		htmldiff = difflib.HtmlDiff(
			linejunk=None,
			charjunk=None)
		diff = htmldiff.make_file(
			fromlines=self.__oldDb.dumpEntries(totp="show").splitlines(),
			tolines=self.__db.dumpEntries(totp="show").splitlines(),
			fromdesc=str(self.__oldDb.getFilename()),
			todesc=str(self.__db.getFilename()),
			context=True,
			numlines=contextLines)
		return "".join(diff)
