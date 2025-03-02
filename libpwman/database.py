# -*- coding: utf-8 -*-
"""
#
# Simple password manager
# Encrypted database
#
# Copyright (c) 2011-2023 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
#
"""

from libpwman.cryptsql import *
from libpwman.exception import *
from libpwman.util import *
import libpwman.otp

import csv
import io
import os
import pathlib
import sys
from copy import deepcopy
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
	"""Get the default database path.
	Returns a pathlib.Path() instance.
	"""
	db = os.getenv("PWMAN_DATABASE")
	if db:
		return pathlib.Path(db)
	home = pathlib.Path.home()
	if home:
		return home / ".pwman.db"
	return pathlib.Path(".pwman.db")

@dataclass
class PWManEntry:
	"""Database entry data structure.
	"""
	category	: str
	title		: str
	user		: str = None
	pw		: str = None
	entryId		: int = None

@dataclass
class PWManEntryAttr:
	"""Entry attribute data structure.
	"""
	name		: str
	data		: str = None
	entry		: PWManEntry = None
	attrId		: int = None

@dataclass
class PWManEntryBulk:
	"""Entry bulk-data data structure.
	"""
	data		: str = None
	entry		: PWManEntry = None
	bulkId		: int = None

@dataclass
class PWManEntryTOTP:
	"""Entry TOTP-data data structure.
	"""
	key		: str
	digits		: int = 6
	hmacHash	: str = "SHA1"
	entry		: PWManEntry = None
	totpId		: int = None

	def generate(self):
		return libpwman.otp.totp(key=self.key,
					 nrDigits=self.digits,
					 hmacHash=self.hmacHash)

class PWManDatabase(CryptSQL):
	"""Encrypted pwman database.
	"""

	DB_TYPE	= "PWMan database"
	DB_VER	= ("0", "1")

	def __init__(self, filename, passphrase, key=None, readOnly=True, silent=False):
		"""filename: Path to the database file.
		             If it does not exist, a new file is created.
		passphrase: The passphrase string for the database file.
		key: An optional key to use instead of the passphrase. Don't use it.
		readOnly: Open the filename read-only. Commits will raise an exception.
		silent: Do not print information messages to the console.
		"""
		try:
			super().__init__(readOnly=readOnly)
			self.__silent = silent
			self.__dirty = False
			self.__openFile(filename, passphrase, key)
		except (CSQLError) as e:
			raise PWManError(str(e))

	def __openFile(self, filename, passphrase, key):
		"""Open the database file and parse the contents.
		"""
		super().setPassphrase(passphrase)
		self.setKey(key)
		self.open(filename)
		self.__setDirty(False)
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
		"""Migrate the database format to the latest version.
		"""
		if dbVer == self.DB_VER[0]:
			if not self.__silent:
				print("Migrating database from version %s to version %s..." % (
				      dbVer, self.DB_VER[-1]),
				      file=sys.stderr)

			self.__initTables()

			c = self.sqlExec("SELECT DISTINCT category FROM pw ORDER BY category;")
			categories = c.fetchAll()
			for (category, ) in categories:
				c = self.sqlExec("SELECT title FROM pw WHERE category=? ORDER BY title;",
						 (category,))
				titles = c.fetchAll()
				for (title, ) in titles:
					c = self.sqlExec("SELECT category, title, user, pw, bulk FROM pw "
							 "WHERE category=? AND title=? "
							 "LIMIT 1;",
							 (category, title))
					data = c.fetchOne()
					if not data:
						continue
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
			for name, data in infos:
				c = self.sqlExec("INSERT INTO globalattr(name, data) VALUES(?,?);",
						 (name, data))
			c = self.sqlExec("DROP TABLE IF EXISTS pw;")
			c = self.sqlExec("DROP TABLE IF EXISTS info;")
			self.sqlVacuum()
		else:
			assert(0)

	def __initTables(self):
		"""Create the SQL tables, if they don't exist.
		"""
		c = self.sqlExecScript("""
			CREATE TABLE IF NOT EXISTS
			globalattr(id INTEGER PRIMARY KEY AUTOINCREMENT,
				   name TEXT, data TEXT);

			CREATE TABLE IF NOT EXISTS
			entries(id INTEGER PRIMARY KEY AUTOINCREMENT,
				category TEXT, title TEXT, user TEXT, pw TEXT);

			CREATE TABLE IF NOT EXISTS
			bulk(id INTEGER PRIMARY KEY AUTOINCREMENT,
			     entry INTEGER, data TEXT);

			CREATE TABLE IF NOT EXISTS
			entryattr(id INTEGER PRIMARY KEY AUTOINCREMENT,
				  entry INTEGER, name TEXT, data TEXT);

			CREATE TABLE IF NOT EXISTS
			totp(id INTEGER PRIMARY KEY AUTOINCREMENT,
			     entry INTEGER, key TEXT, digits INTEGER, hash TEXT);
		""")

	def __garbageCollect(self):
		"""Remove rows from the SQL database that are not needed anymore.
		"""
		# Do not use sqlExecScript here, as that would commit transactions.
		c = self.sqlExec("DELETE FROM bulk WHERE entry NOT IN (SELECT id FROM entries);")
		c = self.sqlExec("DELETE FROM entryattr WHERE entry NOT IN (SELECT id FROM entries);")
		c = self.sqlExec("DELETE FROM totp WHERE entry NOT IN (SELECT id FROM entries);")

	def setPassphrase(self, passphrase):
		super().setPassphrase(passphrase)
		self.__setDirty()

	def categoryExists(self, category):
		"""Returns True, if a category exists in the database.
		category: The name string of the category.
		"""
		c = self.sqlExec("SELECT EXISTS(SELECT 1 FROM entries "
				 "WHERE category=? "
				 "LIMIT 1);",
				 (category,))
		data = c.fetchOne()
		return bool(data) and bool(data[0])

	def getCategoryNames(self):
		"""Get all category names in the database.
		Returns a sorted list of strings.
		"""
		c = self.sqlExec("SELECT DISTINCT category FROM entries "
				 "ORDER BY category;")
		return [ data[0] for data in c.fetchAll() ]

	def getEntryTitles(self, category):
		"""Get all titles from one category in the database.
		category: The category name string.
		Returns a sorted list of strings.
		"""
		c = self.sqlExec("SELECT title FROM entries "
				 "WHERE category=? "
				 "ORDER BY title;",
				 (category,))
		return [ data[0] for data in c.fetchAll() ]

	def getEntry(self, category, title):
		"""Get an entry from the database.
		category: The name string of the category to get an entry from.
		title: The title string of the entry to get.
		Returns a PWManEntry() instance.
		"""
		c = self.sqlExec("SELECT id, category, title, user, pw FROM entries "
				 "WHERE category=? AND title=? "
				 "LIMIT 1;",
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
			useRegexp=False,
			search=True,
			inCategory=None,
			matchCategory=False,
			matchTitle=False,
			matchUser=False,
			matchPw=False,
			matchBulk=False,
			matchAttrName=False,
			matchAttrData=False):
		"""Search the database for entries that match a pattern.
		useRegexp: If True, then the pattern is a regular expression string.
		           If False, then the pattern is a SQL LIKE pattern string.
		inCategory: If specified as non-zero length string, then only search
		            the category with this name.
		matchCategory: Match the pattern to the category name string of an entry.
		matchTitle: Match the pattern to the title string of an entry.
		matchUser: Match the pattern to the user string of an entry.
		matchPw: Match the pattern to the password string of an entry.
		matchBulk: Match the pattern to the bulk data string of an entry.
		matchAttrName: Match the pattern to all attribute name strings of an entry.
		matchAttrData: Match the pattern to all attribute data strings of an entry.
		Returns a list of PWManEntry() instances that match the pattern.
		"""
		if useRegexp:
			self.setRegexpFlags(search=search,
					    ignoreCase=True,
					    multiLine=True,
					    dotAll=True)
		else:
			if search:
				pattern = "%" + pattern + "%"

		def dump(sql, params):
			pass
#			print(sql, "\nparams =", params)

		def match(leftHand):
			if useRegexp:
				return "%s REGEXP ?" % leftHand
			return "%s LIKE ?" % leftHand

		IDs = set()

		if matchCategory or matchTitle or matchUser or matchPw:
			conditions = []
			if matchCategory:
				conditions.append( (match("entries.category"), pattern) )
			if matchTitle:
				conditions.append( (match("entries.title"), pattern) )
			if matchUser:
				conditions.append( (match("entries.user"), pattern) )
			if matchPw:
				conditions.append( (match("entries.pw"), pattern) )
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
			conditions = [ (match("bulk.data"), pattern) ]
			sql = "SELECT entries.id "\
			      "FROM entries, bulk "\
			      "WHERE bulk.entry = entries.id AND "
			params = []
			if inCategory:
				sql += "entries.category = ? AND "
				params.append(inCategory)
			sql += match("bulk.data") + ";"
			params.append(pattern)
			dump(sql, params)
			c = self.sqlExec(sql, params)
			IDs.update(entryId[0] for entryId in (c.fetchAll() or []))

		if matchAttrName or matchAttrData:
			conditions = []
			if matchAttrName:
				conditions.append( (match("entryattr.name"), pattern) )
			if matchAttrData:
				conditions.append( (match("entryattr.data"), pattern) )
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
		sql += " ) "
		sql += "ORDER BY entries.category, entries.title;"
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
		"""Returns True, if an entry exists in the database.
		category: The name string of the category.
		title: The title string of the entry.
		"""
		c = self.sqlExec("SELECT EXISTS(SELECT 1 FROM entries "
				 "WHERE category=? AND title=? "
				 "LIMIT 1);",
				 (category,
				  title))
		data = c.fetchOne()
		return bool(data) and bool(data[0])

	def addEntry(self, entry):
		"""Create a new entry in the database.
		entry: A PWManEntry() instance.
		"""
		if self.entryExists(entry.category, entry.title):
			raise PWManError("Entry does already exist")
		c = self.sqlExec("INSERT INTO entries(category, title, user, pw) "
				 "VALUES(?,?,?,?);",
				 (entry.category,
				  entry.title,
				  entry.user,
				  entry.pw))
		entry.entryId = c.lastRowID()
		self.__setDirty()

	def editEntry(self, entry):
		"""Update the contents of an existing entry.
		entry: A PWManEntry() containing the new data of the entry/
		"""
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
		self.__setDirty()

	def moveEntry(self, entry, newCategory, newTitle, toDb=None, copy=False):
		"""Move or copy an existing entry to a new category and/or set a new entry title.
		entry: The PWManEntry() instance to move/copy.
		newCategory: The target category name string.
		newTitle: The target title string.
		toDb: The target database. Defaults to self.
		copy: If False, then move. If True, then copy.
		"""
		toDb = toDb or self
		if toDb.entryExists(newCategory, newTitle):
			raise PWManError("Entry does already exist.")
		oldEntry = self.getEntry(entry.category, entry.title)
		if not oldEntry:
			raise PWManError("Entry does not exist.")
		if toDb is self and not copy:
			entry.category = newCategory
			entry.title = newTitle
			c = self.sqlExec("UPDATE entries SET "
					 "category=?, title=? "
					 "WHERE id=?;",
					 (entry.category,
					  entry.title,
					  oldEntry.entryId))
			self.__setDirty()
		else:
			newEntry = deepcopy(oldEntry)
			bulk = self.getEntryBulk(newEntry)
			attrs = self.getEntryAttrs(newEntry)
			totp = self.getEntryTotp(newEntry)
			newEntry.entryId = None
			newEntry.category = newCategory
			newEntry.title = newTitle
			toDb.addEntry(newEntry)
			if bulk:
				bulk.bulkId = None
				toDb.setEntryBulk(bulk)
			for attr in attrs:
				attr.attrId = None
				toDb.setEntryAttr(attr)
			if totp:
				totp.totpId = None
				toDb.setEntryTotp(totp)
			if not copy:
				entry.entryId = newEntry.entryId
				entry.category = newEntry.category
				entry.title = newEntry.title
				self.delEntry(oldEntry)

	def moveEntries(self, fromCategory, toCategory, toDb=None, copy=False):
		"""Move or copy all entries from one category to another category.
		fromCategory: The category to move all entries from.
		toCategory: The (new) category to move all entries to.
		toDb: The target database. Defaults to self.
		copy: If False, then move. If True, then copy.
		"""
		toDb = toDb or self
		if not self.categoryExists(fromCategory):
			raise PWManError("Source category does not exist.")
		if toDb is self and fromCategory == toCategory:
			return
		fromTitles = self.getEntryTitles(fromCategory)
		for fromTitle in fromTitles:
			if toDb.entryExists(toCategory, fromTitle):
				raise PWManError("Target entry %s/%s does already exist." % (
						 toCategory, fromTitle))
		if toDb is self and not copy:
			c = self.sqlExec("UPDATE entries SET category=? "
					 "WHERE category=?;",
					 (toCategory,
					  fromCategory))
			self.__setDirty()
		else:
			for fromTitle in fromTitles:
				entry = self.getEntry(fromCategory, fromTitle)
				bulk = self.getEntryBulk(entry)
				attrs = self.getEntryAttrs(entry)
				totp = self.getEntryTotp(entry)
				entry.entryId = None
				entry.category = toCategory
				toDb.addEntry(entry)
				if bulk:
					bulk.bulkId = None
					toDb.setEntryBulk(bulk)
				for attr in attrs:
					attr.attrId = None
					toDb.setEntryAttr(attr)
				if totp:
					totp.totpId = None
					toDb.setEntryTotp(totp)
			if not copy:
				for fromTitle in fromTitles:
					entry = self.getEntry(fromCategory, fromTitle)
					self.delEntry(entry)

	def delEntry(self, entry):
		"""Delete an existing entry from the database.
		entry: The PWManEntry() instance to delete from the database.
		"""
		c = self.sqlExec("SELECT id FROM entries "
				 "WHERE category=? AND title=? "
				 "LIMIT 1;",
				 (entry.category,
				  entry.title))
		entryId = c.fetchOne()
		if entryId is None:
			raise PWManError("Entry does not exist")
		entryId = entryId[0]
		c = self.sqlExec("DELETE FROM entries WHERE id=?;",
				 (entryId,))
		self.__garbageCollect()
		self.__setDirty()

	def getEntryBulk(self, entry):
		"""Get the bulk data associated with an entry.
		entry: The PWManEntry() to get the bulk data for.
		Returns a PWManEntryBulk() instance or None, if there is no bulk data.
		"""
		c = self.sqlExec("SELECT bulk.id, bulk.data "
				 "FROM bulk, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "bulk.entry = entries.id "
				 "LIMIT 1;",
				 (entry.category,
				  entry.title))
		data = c.fetchOne()
		if not data:
			return None
		return PWManEntryBulk(data=data[1],
				      entry=entry,
				      bulkId=data[0])

	def setEntryBulk(self, entryBulk):
		"""Set the bulk data associated with an entry.
		entryBulk: The new PWManEntryBulk() instance to write to the database.
		           If entryBulk.data is None, then the bulk data is deleted.
		"""
		entry = entryBulk.entry
		if not entry or entry.entryId is None:
			raise PWManError("Bulk: Entry does not exist.")
		if entryBulk.data:
			c = self.sqlExec("SELECT id FROM bulk WHERE entry=? LIMIT 1;",
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
		self.__setDirty()

	def getEntryTotp(self, entry):
		"""Get the TOTP parameters associated with an entry.
		entry: The PWManEntry() to get the TOTP parameters for.
		Returns a PWManEntryTOTP() instance, or None if there is no TOTP data.
		"""
		c = self.sqlExec("SELECT totp.id, totp.key, totp.digits, totp.hash "
				 "FROM totp, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "totp.entry = entries.id "
				 "LIMIT 1;",
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
		"""Set the TOTP data associated with an entry.
		entryTotp: The new PWManEntryTOTP() instance to write to the database.
		           If entryTotp.key is None, then the TOTP data is deleted.
		"""
		entry = entryTotp.entry
		if not entry or entry.entryId is None:
			raise PWManError("TOTP: Entry does not exist.")
		if entryTotp.key:
			c = self.sqlExec("SELECT id FROM totp WHERE entry=? LIMIT 1;",
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
		self.__setDirty()

	def getEntryAttr(self, entry, attrName):
		"""Get an attribute associated with an entry.
		entry: The PWManEntry() to get the attribute for.
		attrName: The name string of the attribute to get.
		Returns a PWManEntryAttr() instance, or None if there is such attribute.
		"""
		c = self.sqlExec("SELECT entryattr.id, entryattr.name, entryattr.data "
				 "FROM entryattr, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "entryattr.entry = entries.id AND entryattr.name=? "
				 "LIMIT 1;",
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
		"""Get all attributes associated with an entry.
		entry: The PWManEntry() to get the attributes for.
		Returns a list of PWManEntryAttr() instances,
		or an empty list if there are no attributes.
		"""
		c = self.sqlExec("SELECT entryattr.id, entryattr.name, entryattr.data "
				 "FROM entryattr, entries "
				 "WHERE entries.category=? AND entries.title=? AND "
				 "entryattr.entry = entries.id "
				 "ORDER BY entryattr.name;",
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
		"""Set an attribute associated with an entry.
		entryAttr: The new PWManEntryAttr() instance to write to the database.
		           If entryAttr.data is None, then the attribute is deleted.
		"""
		entry = entryAttr.entry
		if not entry or entry.entryId is None:
			raise PWManError("Attr: Entry does not exist.")
		if entryAttr.data:
			c = self.sqlExec("SELECT id FROM entryattr "
					 "WHERE entry=? AND name=? "
					 "LIMIT 1;",
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
		self.__setDirty()

	def getGlobalAttr(self, name):
		"""Get a global attribute.
		A global attribute is not associated with an entry.
		Returns None, if the attribute does not exist.
		"""
		try:
			c = self.sqlExec("SELECT id, data FROM globalattr "
					 "WHERE name=? "
					 "LIMIT 1;",
					 (name,))
			data = c.fetchOne()
			return data[1] if data else None
		except (CSQLError) as e:
			return None

	def setGlobalAttr(self, name, data, setDirty=True):
		"""Set a global attribute.
		A global attribute is not associated with an entry.
		If data is None or empty, the attribute is deleted from the database.
		"""
		if data:
			c = self.sqlExec("SELECT id FROM globalattr "
					 "WHERE name=? "
					 "LIMIT 1;",
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
			self.__setDirty()

	def __setDirty(self, d=True):
		"""Set the flag for uncommitted data.
		"""
		self.__dirty = d

	def isDirty(self):
		"""Returns True, if the database contains uncommitted data.
		"""
		return self.__dirty

	def flunkDirty(self):
		"""Print a warning, if the database contains uncommitted data.
		Then set the flag for uncommitted data to False.
		"""
		if self.isDirty():
			print("WARNING: Dropping uncommitted data",
			      file=sys.stderr)
			self.__setDirty(False)

	def dropUncommitted(self):
		super().dropUncommitted()
		self.__setDirty(False)

	def commit(self):
		self.__garbageCollect()
		super().commit()
		self.__setDirty(False)

	def importSqlScript(self, *args, **kwargs):
		self.__setDirty()
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

	def dumpEntry(self, entry, totp="gen"):
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
			if totp == "show":
				res.append("\tTOTP key:\t%s" % entryTotp.key)
				res.append("\tTOTP digits:\t%d" % entryTotp.digits)
				res.append("\tTOTP hash:\t%s" % entryTotp.hmacHash)
			elif totp == "gen":
				try:
					token = entryTotp.generate()
				except libpwman.otp.OtpError as e:
					raise PWManError("Failed to generate TOTP token: "
							 "%s" % str(e))
				res.append("\tTOTP:\t\t%s" % token)
			elif totp == "hide":
				res.append("\tTOTP:\t\tavailable")
			else:
				assert False
		entryAttrs = self.getEntryAttrs(entry)
		if entryAttrs:
			res.append("\tAttributes:")
			maxLen = max(len(a.name) for a in entryAttrs)
			for entryAttr in entryAttrs:
				align = maxLen - len(entryAttr.name)
				res.append("\t    %s:%s %s" % (
					entryAttr.name,
					align * " ",
					entryAttr.data))
		return "\n".join(res) + "\n"

	def dumpEntries(self, totp="hide"):
		"""Returns a human readable dump string of all entries.
		"""
		ret = []
		for category in self.getCategoryNames():
			for title in self.getEntryTitles(category):
				entry = self.getEntry(category, title)
				dump = self.dumpEntry(entry, totp)
				ret.append(dump)
		return "\n".join(ret)

	def dumpEntriesCsv(self, totp="hide"):
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
					if totp == "show":
						row["TOTP key"] = entryTotp.key
						row["TOTP digits"] = entryTotp.digits
						row["TOTP hash"] = entryTotp.hmacHash
					elif totp == "gen":
						try:
							token = entryTotp.generate()
						except libpwman.otp.OtpError as e:
							raise PWManError("Failed to generate TOTP token: "
									 "%s" % str(e))
						row["TOTP"] = token
					elif totp == "hide":
						row["TOTP key"] = "available"
					else:
						assert False
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
