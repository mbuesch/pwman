# -*- coding: utf-8 -*-
"""
# Crypto SQL
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import sys
import os
import zlib
import hashlib
import secrets
import sqlite3 as sql
import functools

from libpwman.fileobj import *

def missingMod(name, debpack=None):
	print("Python '%s' module is not installed." % name, file=sys.stderr)
	if debpack:
		print("On Debian do:  apt install %s" % debpack, file=sys.stderr)
	sys.exit(1)

try:
	import Crypto.Cipher.AES as AES
except (ImportError) as e:
	missingMod("Crypto", "python3-crypto")


__all__ = [
	"CSQLError",
	"CryptSQL",
]


CSQL_HEADER = b"CryptSQL v1"


class CSQLError(Exception): pass

class CompressDummy(object):
	def compress(self, payload, *args):
		return payload
	decompress = compress

class CryptSQLCursor(object):
	def __init__(self, db):
		self.__db = db
		self.__c = db.cursor()

	def sqlExec(self, code, params=[], dbCommit=True):
		try:
			self.__c.execute(code, params)
			if dbCommit:
				self.__db.commit()
			return self
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def sqlExecScript(self, code, dbCommit=True):
		try:
			self.__c.executescript(code)
			if dbCommit:
				self.__db.commit()
			return self
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def fetchOne(self):
		try:
			return self.__c.fetchone()
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def fetchAll(self):
		try:
			return self.__c.fetchall()
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def lastRowID(self):
		try:
			return self.__c.lastrowid
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

class CryptSQL(object):
	def __init__(self, readOnly=True):
		self.__readOnly = readOnly
		self.__reset()

	def __reset(self):
		self.__db = None
		self.__filename = None

	def getFilename(self):
		return self.__filename

	def __parseFile(self, filename, passphrase):
		assert isinstance(passphrase, str),\
		       "CryptSQL: Passphrase is not 'str'."
		try:
			fc = FileObjCollection.parseFile(filename)
			if fc is None:
				return

			try:
				passphrase = passphrase.encode("UTF-8")
			except UnicodeError as e:
				raise CSQLError("Cannot UTF-8-encode passphrase.")

			head = fc.getOne(b"HEAD", "Invalid file header object")
			if head.getData() != CSQL_HEADER:
				raise CSQLError("Invalid file header")
			cipher = fc.getOne(b"CIPHER", "Invalid CYPHER object").getData()
			cipherMode = fc.getOne(b"CIPHER_MODE", "Invalid CYPHER_MODE object").getData()
			cipherIV = fc.getOne(b"CIPHER_IV")
			if cipherIV:
				cipherIV = cipherIV.getData()
			keyLen = fc.getOne(b"KEY_LEN", "Invalid KEY_LEN object").getData()
			kdfMethod = fc.getOne(b"KDF_METHOD", "Invalid KDF_METHOD object").getData()
			kdfSalt = fc.getOne(b"KDF_SALT", "Invalid KDF_SALT object").getData()
			kdfIter = fc.getOne(b"KDF_ITER", "Invalid KDF_ITER object").getData()
			kdfHash = fc.getOne(b"KDF_HASH", "Invalid KDF_HASH object").getData()
			kdfMac = fc.getOne(b"KDF_MAC", "Invalid KDF_MAC object").getData()
			compress = fc.getOne(b"COMPRESS", "Invalid COMPRESS object").getData()
			payload = fc.getOne(b"PAYLOAD", "Invalid PAYLOAD object").getData()
			if cipher == b"AES":
				cipher = AES
			else:
				raise CSQLError("Unknown cipher: %s" % cipher.decode("UTF-8", "ignore"))
			if cipherMode == b"CBC":
				cipherMode = AES.MODE_CBC
			else:
				raise CSQLError("Unknown cipher mode: %s" % cipherMode.decode("UTF-8", "ignore"))
			if not cipherIV:
				cipherIV = b'\x00' * cipher.block_size
			if len(cipherIV) != cipher.block_size:
				raise CSQLError("Invalid IV len: %d" % len(cipherIV))
			if keyLen == b"256":
				keyLen = 256 // 8
			else:
				raise CSQLError("Unknown key len: %s" % keyLen.decode("UTF-8", "ignore"))
			if kdfHash in (b"SHA256", b"SHA512"):
				kdfHash = kdfHash.decode("UTF-8")
			else:
				raise CSQLError("Unknown kdf-hash: %s" % kdfHash.decode("UTF-8", "ignore"))
			if len(kdfSalt) < 32:
				raise CSQLError("Invalid salt len: %d" % len(kdfSalt))
			try:
				kdfIter = int(kdfIter.decode("UTF-8"), 10)
			except (ValueError, UnicodeError) as e:
				raise CSQLError("Unknown kdf-iter: %s" % kdfIter.decode("UTF-8", "ignore"))
			if kdfMethod == b"PBKDF2":
				if kdfMac != b"HMAC":
					raise CSQLError("Unknown kdf-mac: %s" % kdfMac)
				kdfMethod = lambda: hashlib.pbkdf2_hmac(hash_name=kdfHash,
									password=passphrase,
									salt=kdfSalt,
									iterations=kdfIter,
									dklen=keyLen)
			else:
				raise CSQLError("Unknown kdf method: %s" % kdfMethod)
			if compress == b"ZLIB":
				compress = zlib
			elif compress == b"NONE":
				compress = CompressDummy()
			else:
				raise CSQLError("Unknown compression: %s" % compress)
			try:
				# Decrypt payload
				key = kdfMethod()
				cipher = cipher.new(key,
						    mode=cipherMode,
						    IV=cipherIV)
				payload = cipher.decrypt(payload)
				payload = self.__unpadData(payload)

				# Decompress payload
				payload = compress.decompress(payload)

				# Import the SQL database
				self.__db.cursor().executescript(payload.decode("UTF-8"))
			except (CSQLError, zlib.error, sql.Error, sql.DatabaseError, UnicodeError) as e:
				raise CSQLError("Failed to decrypt database. "
						"Wrong passphrase?")
		except FileObjError as e:
			raise CSQLError("File error: %s" % str(e))

	def isOpen(self):
		return bool(self.__db)

	def open(self, filename, passphrase):
		if self.isOpen():
			raise CSQLError("A database is already open")
		self.__reset()
		self.__db = sql.connect(":memory:")
		self.__db.text_factory = str
		try:
			self.__parseFile(filename, passphrase)
		except (CSQLError) as e:
			self.__reset()
			raise
		self.__filename = filename

	def close(self):
		self.__reset()

	@staticmethod
	def __padData(data, align):
		data += b"\xFF"
		nrPad = (align - (len(data) % align))
		if nrPad != 0 and nrPad != align:
			data += b"\x00" * nrPad
		return data

	@staticmethod
	def __unpadData(data):
		index = data.rfind(b"\xFF")
		if index < 0 or index >= len(data):
			raise CSQLError("unpadData: error")
		return data[:index]

	def __random(self, nrBytes):
		if nrBytes <= 0:
			raise CSQLError("__random(): Invalid number of random bytes.")
		data = secrets.token_bytes(nrBytes)
		if len(data) != nrBytes:
			raise CSQLError("__random(): Sanity check failed (length).")
		if functools.reduce(lambda a, b: a | b, data) == 0:
			raise CSQLError("__random(): Sanity check failed (zero).")
		if functools.reduce(lambda a, b: a & b, data) == 0xFF:
			raise CSQLError("__random(): Sanity check failed (ones).")
		return data

	def __randomInt(self, belowVal):
		if belowVal <= 0:
			raise CSQLError("__randomInt(): Invalid range.")
		val = secrets.randbelow(belowVal)
		if not (0 <= val < belowVal):
			raise CSQLError("__randomInt(): Sanity check failed.")
		return val

	def commit(self, passphrase):
		if self.__readOnly:
			raise CSQLError("The database is read-only. "
					"Cannot commit changes.")
		assert isinstance(passphrase, str),\
		       "CryptSQL: Passphrase is not 'str'."
		try:
			passphrase = passphrase.encode("UTF-8")
		except UnicodeError as e:
			raise CSQLError("Cannot UTF-8-encode passphrase.")
		if not self.__db or not self.__filename:
			raise CSQLError("Database is not open")

		self.__db.commit()
		self.sqlExec("VACUUM;", dbCommit=True)

		# Dump the database
		payload = self.sqlPlainDump()

		# Encrypt payload
		kdfHash = "SHA512"
		kdfSalt = self.__random(34)
		kdfIter = self.__randomInt(10000) + 1000000
		keyLen = 256 // 8
		key = hashlib.pbkdf2_hmac(hash_name=kdfHash,
					  password=passphrase,
					  salt=kdfSalt,
					  iterations=kdfIter,
					  dklen=keyLen)
		cipherIV = self.__random(AES.block_size)
		aes = AES.new(key,
			      mode=AES.MODE_CBC,
			      IV=cipherIV)
		payload = aes.encrypt(self.__padData(payload, aes.block_size))

		try:
			# Assemble file objects
			fc = FileObjCollection(
				FileObj(b"HEAD", CSQL_HEADER),
				FileObj(b"CIPHER", b"AES"),
				FileObj(b"CIPHER_MODE", b"CBC"),
				FileObj(b"CIPHER_IV", cipherIV),
				FileObj(b"KEY_LEN", str(keyLen * 8).encode("UTF-8")),
				FileObj(b"KDF_METHOD", b"PBKDF2"),
				FileObj(b"KDF_SALT", kdfSalt),
				FileObj(b"KDF_ITER", str(kdfIter).encode("UTF-8")),
				FileObj(b"KDF_HASH", kdfHash.encode("UTF-8")),
				FileObj(b"KDF_MAC", b"HMAC"),
				FileObj(b"COMPRESS", b"NONE"),
				FileObj(b"PAYLOAD", payload),
			)

			# Write to the file
			fc.writeFile(self.__filename)

		except FileObjError as e:
			raise CSQLError("File error: %s" % str(e))

	def sqlExec(self, code, params=[], dbCommit=True):
		return CryptSQLCursor(self.__db).sqlExec(code, params, dbCommit)

	def sqlExecScript(self, code, dbCommit=True):
		return CryptSQLCursor(self.__db).sqlExecScript(code, dbCommit)

	def sqlCreateFunction(self, name, nrParams, func):
		self.__db.create_function(name, nrParams, func)

	def sqlIsEmpty(self):
		c = self.sqlExec("ANALYZE;")
		tbl = c.sqlExec("SELECT tbl FROM sqlite_stat1;").fetchOne()
		return not bool(tbl)

	def sqlPlainDump(self):
		return ("\n".join(self.__db.iterdump())).encode("UTF-8")

	def importSqlScript(self, script, clear=True):
		if clear:
			self.dropAllTables()
		self.sqlExecScript(script)

	def dropAllTables(self):
		c = self.sqlExec("SELECT name FROM sqlite_master "
				 "WHERE type='table';")
		for table in c.fetchAll():
			table = table[0]
			if table != "sqlite_sequence":
				self.sqlExec("DROP TABLE %s" % table)
