# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.cryptsql import *
from libpwman.exception import *
from libpwman.util import *

import os

__all__ = [
	"CSQLError",
	"getDefaultDatabase",
	"PWManEntry",
	"PWManDatabase",
]

def getDefaultDatabase():
	db = os.getenv("PWMAN_DATABASE")
	if db:
		return db
	home = os.getenv("HOME")
	if home:
		return home + "/.pwman.db"
	return None

class PWManEntry(object):
	Undefined = None

	def __init__(self,
		     category,
		     title,
		     user=Undefined,
		     pw=Undefined,
		     bulk=Undefined):
		self.category = category
		self.title = title
		self.user = user
		self.pw = pw
		self.bulk = bulk

	def copyUndefined(self, fromEntry):
		assert(self.category is not self.Undefined)
		assert(self.title is not self.Undefined)
		if self.user is self.Undefined:
			self.user = fromEntry.user
		if self.pw is self.Undefined:
			self.pw = fromEntry.pw
		if self.bulk is self.Undefined:
			self.bulk = fromEntry.bulk

	def dump(self):
		res = []
		res.append("===  %s  ===" % self.category)
		res.append("\t---  %s  ---" % self.title)
		if self.user:
			res.append("\tUser:\t\t%s" % self.user)
		if self.pw:
			res.append("\tPassword:\t%s" % self.pw)
		if self.bulk:
			res.append("\tBulk data:\t%s" % self.bulk)
		return "\n".join(res) + "\n"

class PWManDatabase(CryptSQL):
	"""pwman database.
	"""

	DB_TYPE		= "PWMan database"
	DB_VER		= "0"

	def __init__(self, filename, passphrase):
		try:
			CryptSQL.__init__(self)
			self.__openFile(filename, passphrase)
		except (CSQLError) as e:
			raise PWManError(str(e))

	def __openFile(self, filename, passphrase):
		self.open(filename, passphrase)
		self.__passphrase = passphrase
		self.dirty = False
		initialize = False
		if self.sqlIsEmpty():
			initialize = True
		else:
			dbType = self.__getInfoField("db_type")
			dbVer = self.__getInfoField("db_version")
			if dbType != self.DB_TYPE or\
			   dbVer != self.DB_VER:
				raise PWManError("Unsupported database version '%s/%s'. "
					"Expected '%s/%s'" %\
					(str(dbType), str(dbVer), self.DB_TYPE, self.DB_VER))
		self.sqlExec("CREATE TABLE IF NOT EXISTS "
			"info(name TEXT, data TEXT);")
		self.sqlExec("CREATE TABLE IF NOT EXISTS "
			"pw(category TEXT, title TEXT, user TEXT, pw TEXT, bulk TEXT);")
		if initialize:
			self.__setInfoField("db_type", self.DB_TYPE)
			self.__setInfoField("db_version", self.DB_VER)

	def getPassphrase(self):
		return self.__passphrase

	def setPassphrase(self, passphrase):
		self.__passphrase = passphrase
		self.setDirty()

	def getCategoryNames(self):
		categories = self.sqlExec("SELECT category FROM pw;").fetchAll()
		if not categories:
			return []
		return uniq([c[0] for c in categories])

	def getEntryTitles(self, category):
		sql = "SELECT title FROM pw WHERE category=?;"
		titles = self.sqlExec(sql, (category,)).fetchAll()
		if not titles:
			return []
		titles = [t[0] for t in titles]
		titles.sort()
		return titles

	def getEntry(self, entry):
		sql = "SELECT category, title, user, pw, bulk FROM pw "\
			"WHERE category=? AND title=?;"
		data = self.sqlExec(sql, (entry.category, entry.title)).fetchOne()
		if not data:
			return None
		return PWManEntry(data[0], data[1], data[2], data[3], data[4])

	def findEntries(self, pattern, leftAnchor=False, rightAnchor=False,
			inCategory=None, matchTitle=False,
			matchUser=False, matchPw=False, matchBulk=False,
			doGlobMatch=False):
		if not leftAnchor:
			pattern = "*" + pattern
		if not rightAnchor:
			pattern = pattern + "*"
		conditions = []
		operator = "GLOB" if doGlobMatch else "="
		if matchTitle:
			conditions.append( ("title %s ?" % operator, pattern) )
		if matchUser:
			conditions.append( ("user %s ?" % operator, pattern) )
		if matchPw:
			conditions.append( ("pw %s ?" % operator, pattern) )
		if matchBulk:
			conditions.append( ("bulk %s ?" % operator, pattern) )
		if not conditions:
			return []
		condStr = " OR ".join([c[0] for c in conditions])
		params = [c[1] for c in conditions]
		sql = "SELECT category, title, user, pw, bulk FROM pw"
		if inCategory:
			sql += " WHERE category = ? AND ( " + condStr + " );"
			params.insert(0, inCategory)
		else:
			sql += " WHERE " + condStr + ";"
		dataSet = self.sqlExec(sql, params).fetchAll()
		if not dataSet:
			return []
		return [PWManEntry(data[0], data[1], data[2], data[3], data[4]) for data in dataSet]

	def __delEntry(self, entry):
		self.sqlExec("DELETE FROM pw WHERE category=? AND title=?;",
			     (entry.category, entry.title))

	def __editEntry(self, oldEntry, newEntry):
		if oldEntry:
			assert(oldEntry.category == newEntry.category)
			assert(oldEntry.title == newEntry.title)
			newEntry.copyUndefined(oldEntry)
			self.__delEntry(oldEntry)
		self.sqlExec("INSERT INTO pw(category, title, user, pw, bulk) "
			     "VALUES(?,?,?,?,?);",
			     (newEntry.category, newEntry.title, newEntry.user,
			      newEntry.pw, newEntry.bulk))

	def entryExists(self, entry):
		return bool(self.getEntry(entry))

	def addEntry(self, entry):
		if self.entryExists(entry):
			raise PWManError("Entry does already exist")
		self.__editEntry(None, entry)
		self.setDirty()

	def editEntry(self, entry):
		oldEntry = self.getEntry(entry)
		if not oldEntry:
			raise PWManError("Entry does not exist")
		self.__editEntry(oldEntry, entry)
		self.setDirty()

	def delEntry(self, entry):
		if not self.entryExists(entry):
			raise PWManError("Entry does not exist")
		self.__delEntry(entry)
		self.setDirty()

	def __getInfoField(self, name):
		try:
			d = self.sqlExec("SELECT data FROM info WHERE name=?;", (name,)).fetchOne()
			return d[0] if d else None
		except (sql.OperationalError) as e:
			return None

	def __setInfoField(self, name, data):
		self.sqlExec("DELETE FROM info WHERE name=?;", (name,))
		self.sqlExec("INSERT INTO info(name, data) VALUES(?,?);",
			     (name, data))

	def setDirty(self, d=True):
		self.dirty = d

	def isDirty(self):
		return self.dirty

	def flunkDirty(self):
		if self.isDirty():
			print("WARNING: Dropping uncommitted data")
			self.setDirty(False)

	def commit(self):
		CryptSQL.commit(self, self.__passphrase)
		self.setDirty(False)
