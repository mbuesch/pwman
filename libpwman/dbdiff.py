# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.database import *
from libpwman.ui import dumpEntry

import difflib

__all__ = [
	"PWManDatabaseDiff",
]

class PWManDatabaseDiff(object):
	def __init__(self, db, oldDb):
		self.__db = db
		self.__oldDb = oldDb

	def __dumpDb(self, db):
		ret = []
		for category in db.getCategoryNames():
			for title in db.getEntryTitles(category):
				entry = db.getEntry(category, title)
				dump = dumpEntry(db, entry, showTotpKey=True)
				ret.append(dump + "\n")
		return "".join(ret)

	def getUnifiedDiff(self, contextLines=3):
		diff = difflib.unified_diff(a=self.__dumpDb(self.__oldDb).splitlines(),
					    b=self.__dumpDb(self.__db).splitlines(),
					    fromfile=str(self.__oldDb.getFilename()),
					    tofile=str(self.__db.getFilename()),
					    n=contextLines,
					    lineterm="")
		return "\n".join(diff)

	def getContextDiff(self, contextLines=3):
		diff = difflib.context_diff(a=self.__dumpDb(self.__oldDb).splitlines(),
					    b=self.__dumpDb(self.__db).splitlines(),
					    fromfile=str(self.__oldDb.getFilename()),
					    tofile=str(self.__db.getFilename()),
					    n=contextLines,
					    lineterm="")
		return "\n".join(diff)

	def getNdiffDiff(self):
		diff = difflib.ndiff(a=self.__dumpDb(self.__oldDb).splitlines(),
				     b=self.__dumpDb(self.__db).splitlines(),
				     linejunk=None,
				     charjunk=None)
		return "\n".join(diff)

	def getHtmlDiff(self, contextLines=3):
		htmldiff = difflib.HtmlDiff(linejunk=None,
					    charjunk=None)
		diff = htmldiff.make_file(fromlines=self.__dumpDb(self.__oldDb).splitlines(),
					  tolines=self.__dumpDb(self.__db).splitlines(),
					  fromdesc=str(self.__oldDb.getFilename()),
					  todesc=str(self.__db.getFilename()),
					  context=True,
					  numlines=contextLines)
		return "".join(diff)
