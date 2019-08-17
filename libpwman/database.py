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
from dataclasses import dataclass

__all__ = [
	"CSQLError",
	"getDefaultDatabase",
	"PWManEntryTOTP",
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

@dataclass
class PWManEntry(object):
	category	: str
	title		: str
	user		: str = None
	pw		: str = None
	bulk		: str = None
	entryId		: int = None

@dataclass
class PWManEntryTOTP(object):
	key		: str
	digits		: int = 6
	hmacHash	: str = "SHA1"
	entry		: PWManEntry = None
	totpId		: int = None

class PWManDatabase(CryptSQL):
	"""pwman database.
	"""

	DB_TYPE	= "PWMan database"
	DB_VER	= ("0", "1")

	def __init__(self, filename, passphrase):
		try:
			super().__init__()
			self.__openFile(filename, passphrase)
		except (CSQLError) as e:
			raise PWManError(str(e))

	def __openFile(self, filename, passphrase):
		self.open(filename, passphrase)
		self.__passphrase = passphrase
		self.__dirty = False
		initDBVer = False
		if self.sqlIsEmpty():
			initDBVer = True
		else:
			dbType = self.__getGlobalAttr("db_type")
			dbVer = self.__getGlobalAttr("db_version")
			if dbType is None and dbVer is None: # Compat v0
				dbType = self.DB_TYPE
				dbVer = self.DB_VER[0]
			if (dbType != self.DB_TYPE or
			    dbVer not in self.DB_VER):
				raise PWManError("Unsupported database version '%s / %s'. "
					"Expected '%s / %s'" % (
					str(dbType),
					str(dbVer),
					self.DB_TYPE,
					", ".join(self.DB_VER)))
			if dbVer != self.DB_VER[-1]:
				self.__migrateVersion(dbVer)
				initDBVer = True
		self.__initTables()
		if initDBVer:
			self.__setGlobalAttr("db_type", self.DB_TYPE)
			self.__setGlobalAttr("db_version", self.DB_VER[-1])

	def __migrateVersion(self, dbVer):
		if dbVer == self.DB_VER[0]:
			print("Migrating database from version %s to version %s..." % (
			      dbVer, self.DB_VER[-1]))

			self.__initTables()

			c = self.sqlExec("SELECT category FROM pw;")
			categories = c.fetchAll()
			categories = uniq(c[0] for c in categories)
			for category in categories:
				c = self.sqlExec("SELECT title FROM pw WHERE category=?;",
						 (category,))
				titles = c.fetchAll()
				titles = sorted(t[0] for t in titles)
				for title in titles:
					c = self.sqlExec("SELECT category, title, user, pw, bulk FROM pw "
							 "WHERE category=? AND title=?;",
							 (category, title))
					data = c.fetchOne()
					c = self.sqlExec("INSERT INTO entries(category, title, user, pw) "
							 "VALUES(?,?,?,?);",
							 (data[0], data[1], data[2], data[3]))
					entryId = c.lastRowID()
					if data[4]:
						c = self.sqlExec("INSERT INTO bulk(entry, data) "
								 "VALUES(?,?);",
								 (entryId, data[4]))
			c = self.sqlExec("SELECT name, data FROM info;")
			infos = c.fetchAll()
			for info in infos:
				c = self.sqlExec("INSERT INTO globalattr(name, data) VALUES(?,?);",
						 (info[0], info[1]))
			c = self.sqlExec("DROP TABLE IF EXISTS pw;")
			c = self.sqlExec("DROP TABLE IF EXISTS info;")
			c = self.sqlExec("VACUUM;")
		else:
			assert(0)

	def __initTables(self):
		c = self.sqlExec("CREATE TABLE IF NOT EXISTS "
				 "globalattr(id INTEGER PRIMARY KEY AUTOINCREMENT, "
					    "name TEXT, data TEXT);")
		c = self.sqlExec("CREATE TABLE IF NOT EXISTS "
				 "entries(id INTEGER PRIMARY KEY AUTOINCREMENT, "
					 "category TEXT, title TEXT, user TEXT, pw TEXT);")
		c = self.sqlExec("CREATE TABLE IF NOT EXISTS "
				 "bulk(id INTEGER PRIMARY KEY AUTOINCREMENT, "
				      "entry INTEGER, data TEXT);")
		c = self.sqlExec("CREATE TABLE IF NOT EXISTS "
				 "totp(id INTEGER PRIMARY KEY AUTOINCREMENT, "
				      "entry INTEGER, key TEXT, digits INTEGER, hash TEXT);")

	def getPassphrase(self):
		return self.__passphrase

	def setPassphrase(self, passphrase):
		self.__passphrase = passphrase
		self.setDirty()

	def getCategoryNames(self):
		c = self.sqlExec("SELECT category FROM entries;")
		categories = c.fetchAll()
		if not categories:
			return []
		return uniq(c[0] for c in categories)

	def getEntryTitles(self, category):
		c = self.sqlExec("SELECT title FROM entries WHERE category=?;",
				 (category,))
		titles = c.fetchAll()
		if not titles:
			return []
		titles = sorted(t[0] for t in titles)
		return titles

	def getEntry(self, entry):
		c = self.sqlExec("SELECT id, category, title, user, pw FROM entries "
				 "WHERE category=? AND title=?;",
				 (entry.category,
				  entry.title))
		data = c.fetchOne()
		if not data:
			return None
		entryId = data[0]
		c = self.sqlExec("SELECT id, data FROM bulk WHERE entry=?",
				 (entryId, ))
		bulk = c.fetchOne()
		bulk = bulk if bulk is None else bulk[1]
		return PWManEntry(category=data[1],
				  title=data[2],
				  user=data[3],
				  pw=data[4],
				  bulk=bulk,
				  entryId=entryId)

	def findEntries(self, pattern,
			leftAnchor=False, rightAnchor=False,
			inCategory=None,
			matchTitle=False, matchUser=False, matchPw=False, matchBulk=False,
			doGlobMatch=False):
		if not leftAnchor:
			pattern = "*" + pattern
		if not rightAnchor:
			pattern = pattern + "*"
		conditions = []
		operator = "GLOB" if doGlobMatch else "="
		if matchTitle:
			conditions.append( ("entries.title %s ?" % operator, pattern) )
		if matchUser:
			conditions.append( ("entries.user %s ?" % operator, pattern) )
		if matchPw:
			conditions.append( ("entries.pw %s ?" % operator, pattern) )
		if matchBulk:
			conditions.append( ("bulk.data %s ?" % operator, pattern) )
		if not conditions:
			return []
		condStr = " OR ".join([c[0] for c in conditions])
		params = [c[1] for c in conditions]
		sql = "SELECT entries.id, entries.category, entries.title, entries.user, entries.pw, bulk.data "\
		      "FROM entries, bulk "\
		      "WHERE bulk.entry = entries.id AND "
		if inCategory:
			sql += "category = ? AND "
			params.insert(0, inCategory)
		sql += "( " + condStr + " );"
		c = self.sqlExec(sql, params)
		dataSet = c.fetchAll()
		if not dataSet:
			return []
		return [ PWManEntry(category=data[1],
				    title=data[2],
				    user=data[3],
				    pw=data[4],
				    bulk=data[5],
				    entryId=data[0])
			 for data in dataSet ]

	def entryExists(self, entry):
		return bool(self.getEntry(entry))

	def addEntry(self, entry):
		if self.entryExists(entry):
			raise PWManError("Entry does already exist")
		c = self.sqlExec("INSERT INTO entries(category, title, user, pw) "
				 "VALUES(?,?,?,?);",
				 (entry.category,
				  entry.title,
				  entry.user,
				  entry.pw))
		entry.entryId = c.lastRowID()
		if entry.bulk is not None:
			c = self.sqlExec("INSERT INTO bulk(entry, data) "
					 "VALUES(?,?);",
					 (entry.entryId,
					  entry.bulk))
		self.setDirty()

	def editEntry(self, entry):
		oldEntry = self.getEntry(entry)
		if not oldEntry:
			raise PWManError("Entry does not exist")

		if entry.user is None:
			entry.user = oldEntry.user
		if entry.pw is None:
			entry.pw = oldEntry.pw
		if entry.bulk is None:
			entry.bulk = oldEntry.bulk
		entry.entryId = oldEntry.entryId

		c = self.sqlExec("UPDATE entries SET "
				 "category=?, title=?, user=?, pw=? "
				 "WHERE id=?;",
				 (entry.category,
				  entry.title,
				  entry.user,
				  entry.pw,
				  entry.entryId))
		if entry.bulk:
			c = self.sqlExec("SELECT id, data FROM bulk WHERE entry=?",
					 (entry.entryId, ))
			bulk = c.fetchOne()
			if bulk is None:
				c = self.sqlExec("INSERT INTO bulk(entry, data) "
						 "VALUES(?,?);",
						 (entry.entryId,
						  entry.bulk))
			else:
				c = self.sqlExec("UPDATE bulk "
						 "SET data=? "
						 "WHERE entry=?;",
						 (entry.bulk,
						  entry.entryId))
		else:
			c = self.sqlExec("DELETE FROM bulk WHERE entry=?;",
					 (entry.entryId,))
		self.setDirty()

	def delEntry(self, entry):
		c = self.sqlExec("SELECT id FROM entries WHERE category=? AND title=?;",
				 (entry.category,
				  entry.title))
		entryId = c.fetchOne()
		if entryId is None:
			raise PWManError("Entry does not exist")
		entryId = entryId[0]
		c = self.sqlExec("DELETE FROM entries WHERE id=?;",
				 (entryId,))
		c = self.sqlExec("DELETE FROM bulk WHERE entry=?;",
				 (entryId,))
		self.setDirty()

	def getEntryTotp(self, entry):
		c = self.sqlExec("SELECT totp.id, totp.key, totp.digits, totp.hash "
				 "FROM totp, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "totp.entry = entries.id;",
				 (entry.category,
				  entry.title))
		data = c.fetchOne()
		if not data:
			return None
		return PWManEntryTOTP(key=data[1],
				      digits=data[2],
				      hmacHash=data[3],
				      entry=entry,
				      totpId=data[0])

	def setEntryTotp(self, entryTotp):
		entry = entryTotp.entry
		if not entry or entry.entryId is None:
			raise PWManError("Entry does not exist")
		if entryTotp.key:
			c = self.sqlExec("SELECT id FROM totp WHERE entry=?",
					 (entry.entryId, ))
			totpId = c.fetchOne()
			if totpId is None:
				c = self.sqlExec("INSERT INTO totp(entry, key, digits, hash) "
						 "VALUES(?,?,?,?);",
						 (entry.entryId,
						  entryTotp.key,
						  entryTotp.digits,
						  entryTotp.hmacHash))
			else:
				totpId = totpId[0]
				c = self.sqlExec("UPDATE totp "
						 "SET entry=?, key=?, digits=?, hash=? "
						 "WHERE id=?;",
						 (entry.entryId,
						  entryTotp.key,
						  entryTotp.digits,
						  entryTotp.hmacHash,
						  totpId))
		else:
			c = self.sqlExec("DELETE FROM totp WHERE id=?;",
					 (entryTotp.totpId,))

	def __getGlobalAttr(self, name):
		try:
			c = self.sqlExec("SELECT id, data FROM globalattr WHERE name=?;",
					 (name,))
			data = c.fetchOne()
			return data[1] if data else None
		except (CSQLError) as e:
			return None

	def __setGlobalAttr(self, name, data):
		attr = self.__getGlobalAttr(name)
		if attr and attr == data:
			return
		c = self.sqlExec("DELETE FROM globalattr WHERE name=?;",
				 (name,))
		c = self.sqlExec("INSERT INTO globalattr(name, data) VALUES(?,?);",
				 (name, data))

	def setDirty(self, d=True):
		self.__dirty = d

	def isDirty(self):
		return self.__dirty

	def flunkDirty(self):
		if self.isDirty():
			print("WARNING: Dropping uncommitted data")
			self.setDirty(False)

	def commit(self):
		super().commit(self.__passphrase)
		self.setDirty(False)
