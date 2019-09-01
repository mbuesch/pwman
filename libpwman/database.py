# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.cryptsql import *
from libpwman.exception import *
from libpwman.util import *

import csv
import io
import os
import pathlib
import sys
from dataclasses import dataclass

__all__ = [
	"CSQLError",
	"PWManDatabase",
	"PWManEntry",
	"PWManEntryAttr",
	"PWManEntryBulk",
	"PWManEntryTOTP",
	"getDefaultDatabase",
]

def getDefaultDatabase():
	db = os.getenv("PWMAN_DATABASE")
	if db:
		return pathlib.Path(db)
	home = pathlib.Path.home()
	if home:
		return home / ".pwman.db"
	return pathlib.Path(".pwman.db")

@dataclass
class PWManEntry(object):
	category	: str
	title		: str
	user		: str = None
	pw		: str = None
	entryId		: int = None

@dataclass
class PWManEntryAttr(object):
	name		: str
	data		: str = None
	entry		: PWManEntry = None
	attrId		: int = None

@dataclass
class PWManEntryBulk(object):
	data		: str = None
	entry		: PWManEntry = None
	bulkId		: int = None

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

	def __init__(self, filename, passphrase, key=None, readOnly=True, silent=False):
		try:
			super().__init__(readOnly=readOnly)
			self.__silent = silent
			self.__dirty = False
			self.__openFile(filename, passphrase, key)
		except (CSQLError) as e:
			raise PWManError(str(e))

	def __openFile(self, filename, passphrase, key):
		super().setPassphrase(passphrase)
		self.setKey(key)
		self.open(filename)
		self.setDirty(False)
		initDBVer = False
		if self.sqlIsEmpty():
			initDBVer = True
		else:
			dbType = self.getGlobalAttr("db_type")
			dbVer = self.getGlobalAttr("db_version")
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
			self.setGlobalAttr("db_type", self.DB_TYPE, setDirty=False)
			self.setGlobalAttr("db_version", self.DB_VER[-1], setDirty=False)

	def __migrateVersion(self, dbVer):
		if dbVer == self.DB_VER[0]:
			if not self.__silent:
				print("Migrating database from version %s to version %s..." % (
				      dbVer, self.DB_VER[-1]),
				      file=sys.stderr)

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
			self.vacuum()
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
				 "entryattr(id INTEGER PRIMARY KEY AUTOINCREMENT, "
					   "entry INTEGER, name TEXT, data TEXT);")
		c = self.sqlExec("CREATE TABLE IF NOT EXISTS "
				 "totp(id INTEGER PRIMARY KEY AUTOINCREMENT, "
				      "entry INTEGER, key TEXT, digits INTEGER, hash TEXT);")

	def __garbageCollect(self):
		c = self.sqlExec("DELETE FROM bulk "
				 "WHERE entry NOT IN (SELECT id FROM entries);")
		c = self.sqlExec("DELETE FROM entryattr "
				 "WHERE entry NOT IN (SELECT id FROM entries);")
		c = self.sqlExec("DELETE FROM totp "
				 "WHERE entry NOT IN (SELECT id FROM entries);")

	def setPassphrase(self, passphrase):
		super().setPassphrase(passphrase)
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

	def renameCategory(self, category, toCategory):
		categories = self.getCategoryNames()
		if category not in categories:
			raise PWManError("Source category does not exist.")
		if toCategory in categories:
			raise PWManError("Target category does already exist.")
		c = self.sqlExec("UPDATE entries SET category=? "
				 "WHERE category=?;",
				 (toCategory,
				  category))
		self.setDirty()

	def getEntry(self, category, title):
		c = self.sqlExec("SELECT id, category, title, user, pw FROM entries "
				 "WHERE category=? AND title=?;",
				 (category,
				  title))
		data = c.fetchOne()
		if not data:
			return None
		return PWManEntry(category=data[1],
				  title=data[2],
				  user=data[3],
				  pw=data[4],
				  entryId=data[0])

	def findEntries(self, pattern,
			leftAnchor=False, rightAnchor=False,
			inCategory=None,
			matchTitle=False, matchUser=False, matchPw=False,
			matchBulk=False, matchAttrName=False, matchAttrData=False):
		if not leftAnchor:
			pattern = "%" + pattern
		if not rightAnchor:
			pattern = pattern + "%"

		def dump(sql, params):
			pass
#			print(sql, "\nparams =", params)

		IDs = set()

		if matchTitle or matchUser or matchPw:
			conditions = []
			if matchTitle:
				conditions.append( ("entries.title LIKE ?", pattern) )
			if matchUser:
				conditions.append( ("entries.user LIKE ?", pattern) )
			if matchPw:
				conditions.append( ("entries.pw LIKE ?", pattern) )
			sql = "SELECT id FROM entries WHERE "
			params = []
			if inCategory:
				sql += "category=? AND "
				params.append(inCategory)
			sql += "( " + (" OR ".join(c[0] for c in conditions)) + " );"
			params.extend(c[1] for c in conditions)
			dump(sql, params)
			c = self.sqlExec(sql, params)
			IDs.update(entryId[0] for entryId in (c.fetchAll() or []))

		if matchBulk:
			conditions = [ ("bulk.data LIKE ?", pattern) ]
			sql = "SELECT entries.id "\
			      "FROM entries, bulk "\
			      "WHERE bulk.entry = entries.id AND "
			params = []
			if inCategory:
				sql += "entries.category = ? AND "
				params.append(inCategory)
			sql += "bulk.data LIKE ?;"
			params.append(pattern)
			dump(sql, params)
			c = self.sqlExec(sql, params)
			IDs.update(entryId[0] for entryId in (c.fetchAll() or []))

		if matchAttrName or matchAttrData:
			conditions = []
			if matchAttrName:
				conditions.append( ("entryattr.name LIKE ?", pattern) )
			if matchAttrData:
				conditions.append( ("entryattr.data LIKE ?", pattern) )
			sql = "SELECT entries.id "\
			      "FROM entries, entryattr "\
			      "WHERE entryattr.entry = entries.id AND "
			params = []
			if inCategory:
				sql += "entries.category = ? AND "
				params.append(inCategory)
			sql += "( " + (" OR ".join(c[0] for c in conditions)) + " );"
			params.extend(c[1] for c in conditions)
			dump(sql, params)
			c = self.sqlExec(sql, params)
			IDs.update(entryId[0] for entryId in (c.fetchAll() or []))

		if not IDs:
			return []
		IDs = sorted(IDs) # stable sorting

		sql = "SELECT entries.id, entries.category, "\
		      "entries.title, entries.user, entries.pw "\
		      "FROM entries "\
		      "WHERE entries.id IN ( "
		sql += ", ".join("?" for ID in IDs)
		sql += " );"
		params = [ str(ID) for ID in IDs ]
		dump(sql, params)
		c = self.sqlExec(sql, params)
		dataSet = c.fetchAll()
		if not dataSet:
			return []
		return [ PWManEntry(category=data[1],
				    title=data[2],
				    user=data[3],
				    pw=data[4],
				    entryId=data[0])
			 for data in dataSet ]

	def entryExists(self, category, title):
		return bool(self.getEntry(category, title))

	def addEntry(self, entry):
		if self.entryExists(entry.category, entry.title):
			raise PWManError("Entry does already exist")
		c = self.sqlExec("INSERT INTO entries(category, title, user, pw) "
				 "VALUES(?,?,?,?);",
				 (entry.category,
				  entry.title,
				  entry.user,
				  entry.pw))
		entry.entryId = c.lastRowID()
		self.setDirty()

	def editEntry(self, entry):
		oldEntry = self.getEntry(entry.category, entry.title)
		if not oldEntry:
			raise PWManError("Entry does not exist")

		if entry.user is None:
			entry.user = oldEntry.user
		if entry.pw is None:
			entry.pw = oldEntry.pw
		entry.entryId = oldEntry.entryId

		c = self.sqlExec("UPDATE entries SET "
				 "category=?, title=?, user=?, pw=? "
				 "WHERE id=?;",
				 (entry.category,
				  entry.title,
				  entry.user,
				  entry.pw,
				  entry.entryId))
		self.setDirty()

	def moveEntry(self, entry, newCategory, newTitle):
		if self.entryExists(newCategory, newTitle):
			raise PWManError("Entry does already exist.")
		oldEntry = self.getEntry(entry.category, entry.title)
		if not oldEntry:
			raise PWManError("Entry does not exist.")
		entry.category = newCategory
		entry.title = newTitle
		c = self.sqlExec("UPDATE entries SET "
				 "category=?, title=? "
				 "WHERE id=?;",
				 (entry.category,
				  entry.title,
				  oldEntry.entryId))
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
		self.__garbageCollect()
		self.setDirty()

	def getEntryBulk(self, entry):
		c = self.sqlExec("SELECT bulk.id, bulk.data "
				 "FROM bulk, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "bulk.entry = entries.id;",
				 (entry.category,
				  entry.title))
		data = c.fetchOne()
		if not data:
			return None
		return PWManEntryBulk(data=data[1],
				      entry=entry,
				      bulkId=data[0])

	def setEntryBulk(self, entryBulk):
		entry = entryBulk.entry
		if not entry or entry.entryId is None:
			raise PWManError("Bulk: Entry does not exist.")
		if entryBulk.data:
			c = self.sqlExec("SELECT id FROM bulk WHERE entry=?;",
					 (entry.entryId, ))
			bulkId = c.fetchOne()
			if bulkId is None:
				c = self.sqlExec("INSERT INTO bulk(entry, data) "
						 "VALUES(?,?);",
						 (entry.entryId,
						  entryBulk.data))
			else:
				bulkId = bulkId[0]
				c = self.sqlExec("UPDATE bulk "
						 "SET entry=?, data=? "
						 "WHERE id=?;",
						 (entry.entryId,
						  entryBulk.data,
						  bulkId))
		else:
			c = self.sqlExec("DELETE FROM bulk WHERE id=?;",
					 (entryBulk.bulkId,))
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
			raise PWManError("TOTP: Entry does not exist.")
		if entryTotp.key:
			c = self.sqlExec("SELECT id FROM totp WHERE entry=?;",
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
		self.setDirty()

	def getEntryAttr(self, entry, attrName):
		c = self.sqlExec("SELECT entryattr.id, entryattr.name, entryattr.data "
				 "FROM entryattr, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "entryattr.entry = entries.id AND entryattr.name=?;",
				 (entry.category,
				  entry.title,
				  attrName))
		data = c.fetchOne()
		if not data:
			return None
		return PWManEntryAttr(name=data[1],
				      data=data[2],
				      entry=entry,
				      attrId=data[0])

	def getEntryAttrs(self, entry):
		c = self.sqlExec("SELECT entryattr.id, entryattr.name, entryattr.data "
				 "FROM entryattr, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "entryattr.entry = entries.id;",
				 (entry.category,
				  entry.title))
		dataSet = c.fetchAll()
		if not dataSet:
			return []
		return [ PWManEntryAttr(name=data[1],
				        data=data[2],
				        entry=entry,
				        attrId=data[0])
			 for data in dataSet ]

	def setEntryAttr(self, entryAttr):
		entry = entryAttr.entry
		if not entry or entry.entryId is None:
			raise PWManError("Attr: Entry does not exist.")
		if entryAttr.data:
			c = self.sqlExec("SELECT id FROM entryattr "
					 "WHERE entry=? AND name=?;",
					 (entry.entryId,
					  entryAttr.name))
			attrId = c.fetchOne()
			if attrId is None:
				c = self.sqlExec("INSERT INTO entryattr(entry, name, data) "
						 "VALUES(?,?,?);",
						 (entry.entryId,
						  entryAttr.name,
						  entryAttr.data))
			else:
				attrId = attrId[0]
				c = self.sqlExec("UPDATE entryattr "
						 "SET entry=?, name=?, data=? "
						 "WHERE id=?;",
						 (entry.entryId,
						  entryAttr.name,
						  entryAttr.data,
						  attrId))
		else:
			c = self.sqlExec("DELETE FROM entryattr WHERE id=?;",
					 (entryAttr.attrId,))
		self.setDirty()

	def getGlobalAttr(self, name):
		try:
			c = self.sqlExec("SELECT id, data FROM globalattr WHERE name=?;",
					 (name,))
			data = c.fetchOne()
			return data[1] if data else None
		except (CSQLError) as e:
			return None

	def setGlobalAttr(self, name, data, setDirty=True):
		if data:
			c = self.sqlExec("SELECT id FROM globalattr "
					 "WHERE name=?;",
					 (name,))
			attrId = c.fetchOne()
			if attrId is None:
				c = self.sqlExec("INSERT INTO globalattr(name, data) "
						 "VALUES(?,?);",
						 (name, data))
			else:
				attrId = attrId[0]
				c = self.sqlExec("UPDATE globalattr "
						 "SET data=? "
						 "WHERE name=?;",
						 (data, name))
		else:
			c = self.sqlExec("DELETE FROM globalattr WHERE name=?;",
					 (name,))
		if setDirty:
			self.setDirty()

	def setDirty(self, d=True):
		self.__dirty = d

	def isDirty(self):
		return self.__dirty

	def flunkDirty(self):
		if self.isDirty():
			print("WARNING: Dropping uncommitted data",
			      file=sys.stderr)
			self.setDirty(False)

	def dropUncommitted(self):
		super().dropUncommitted()
		self.setDirty(False)

	def commit(self):
		self.__garbageCollect()
		super().commit()
		self.setDirty(False)

	def importSqlScript(self, *args, **kwargs):
		self.setDirty()
		super().importSqlScript(*args, **kwargs)

	def getOnDiskDb(self):
		"""Get a read-only instance of PWManDatabase that contains
		the current on-disk data. The on-disk data is the data
		at the last commit.
		"""
		db = self.__class__(filename=self.getFilename(),
				    passphrase=self.getPassphrase(),
				    key=self.getKey(),
				    readOnly=True,
				    silent=True)
		return db

	def dumpEntry(self, entry, showTotpKey=False):
		"""Returns a human readable dump string of an entry.
		"""
		res = []
		res.append("===  %s  ===" % entry.category)
		res.append("\t---  %s  ---" % entry.title)
		if entry.user:
			res.append("\tUser:\t\t%s" % entry.user)
		if entry.pw:
			res.append("\tPassword:\t%s" % entry.pw)
		entryBulk = self.getEntryBulk(entry)
		if entryBulk:
			res.append("\tBulk data:\t%s" % entryBulk.data)
		entryTotp = self.getEntryTotp(entry)
		if entryTotp:
			if showTotpKey:
				res.append("\tTOTP key:\t%s" % entryTotp.key)
				res.append("\tTOTP digits:\t%d" % entryTotp.digits)
				res.append("\tTOTP hash:\t%s" % entryTotp.hmacHash)
			else:
				res.append("\tTOTP:\t\tavailable")
		entryAttrs = self.getEntryAttrs(entry)
		if entryAttrs:
			res.append("\tAttributes:")
			for entryAttr in entryAttrs:
				res.append("\t    %s:\t%s" % (entryAttr.name,
							      entryAttr.data))
		return "\n".join(res) + "\n"

	def dumpEntries(self, showTotpKey=False):
		"""Returns a human readable dump string of all entries.
		"""
		ret = []
		for category in self.getCategoryNames():
			for title in self.getEntryTitles(category):
				entry = self.getEntry(category, title)
				dump = self.dumpEntry(entry, showTotpKey)
				ret.append(dump)
		return "\n".join(ret)

	def dumpEntriesCsv(self, showTotpKey=False):
		"""Returns a CSV format dump string of all entries.
		"""
		csvHeads = [
			"Category",
			"Title",
			"User",
			"Password",
			"Bulk data",
			"TOTP key",
			"TOTP digits",
			"TOTP hash",
		]
		rows = []
		attrNames = set()
		for category in self.getCategoryNames():
			for title in self.getEntryTitles(category):
				entry = self.getEntry(category, title)
				row = {
					"Category"	: entry.category,
					"Title"		: entry.title,
					"User"		: entry.user,
					"Password"	: entry.pw,
				}
				entryBulk = self.getEntryBulk(entry)
				if entryBulk:
					row["Bulk data"] = entryBulk.data
				entryTotp = self.getEntryTotp(entry)
				if entryTotp:
					row["TOTP key"] = entryTotp.key
					row["TOTP digits"] = entryTotp.digits
					row["TOTP hash"] = entryTotp.hmacHash
				entryAttrs = self.getEntryAttrs(entry)
				if entryAttrs:
					for entryAttr in entryAttrs:
						attrNames.add(entryAttr.name)
						row[entryAttr.name] = entryAttr.data
				rows.append(row)
		csvHeads.extend(sorted(attrNames))

		f = io.StringIO()
		w = csv.DictWriter(f, fieldnames=csvHeads, dialect="excel")
		w.writeheader()
		for r in rows:
			w.writerow(r)
		return f.getvalue()
