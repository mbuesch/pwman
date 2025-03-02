# -*- coding: utf-8 -*-
"""
# Crypto SQL
# Copyright (c) 2011-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import functools
import hashlib
import math
import os
import re
import secrets
import sqlite3 as sql
import zlib

from libpwman.aes import AES
from libpwman.argon2 import Argon2
from libpwman.fileobj import FileObj, FileObjCollection, FileObjError

__all__ = [
	"CSQLError",
	"CryptSQL",
]

def decodeInt(buf, error, minValue=None, maxValue=None):
	"""Decode bytes into a int as decimal representation.
	buf: Bytes buffer.
	error: Error message string, in case of conversion failure.
	minValue: The smallest allowed integer value.
	maxValue: The biggest allowed integer value.
	"""
	try:
		value = int(buf.decode("UTF-8"), 10)
		if minValue is not None and value < minValue:
			raise ValueError
		if maxValue is not None and value > maxValue:
			raise ValueError
		return value
	except (ValueError, UnicodeError) as e:
		raise CSQLError("%s: %s" % (error, buf.decode("UTF-8", "ignore")))

def decodeChoices(buf, error, choices):
	"""Decode bytes into one of the possible choices strings.
	buf: Bytes buffer.
	error: Error message string, in case of conversion failure.
	choices: An iterable of possible strings.
	"""
	try:
		string = buf.decode("UTF-8")
		if string not in choices:
			raise ValueError
		return string
	except (ValueError, UnicodeError) as e:
		raise CSQLError("%s: %s" % (error, buf.decode("UTF-8", "ignore")))

class CSQLError(Exception):
	"""CryptSQL exception.
	"""

class CryptSQLCursor:
	"""Encrypted SQL database cursor.
	"""

	def __init__(self, db):
		self.__db = db
		self.__c = db.cursor()

	def sqlExec(self, code, params=[]):
		"""Execute one SQL statement.
		"""
		try:
			self.__c.execute(code, params)
			return self
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def sqlExecScript(self, code):
		"""Execute multiple SQL statements.
		Warning: This implicitly commits pending transactions before executing.
		"""
		try:
			self.__c.executescript(code)
			return self
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def fetchOne(self):
		"""Fetches the next row of a query result set.
		Returns a list of query results or None.
		See sqlite3.Cursor.fetchone for more details.
		"""
		try:
			return self.__c.fetchone()
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def fetchAll(self):
		"""Fetches all rows of a query result.
		Returns a list of lists of query results or an empty list.
		See sqlite3.Cursor.fetchall for more details.
		"""
		try:
			return self.__c.fetchall()
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

	def lastRowID(self):
		"""Get the rowid of the last modified row.
		Returns an int or None.
		See sqlite3.Cursor.lastrowid for more details.
		"""
		try:
			return self.__c.lastrowid
		except (sql.Error, sql.DatabaseError) as e:
			raise CSQLError("Database error: " + str(e))

class CryptSQL:
	"""Encrypted SQL database.
	"""

	CSQL_HEADER = b"CryptSQL v1"

	# Argon2 KDF parameters.
	KDF_SALT_NBYTES		= 19
	KDF_THREADS		= 7
	KDF_MEM_BASE		= 1024 * 128
	KDF_MEM_CHUNK		= 4 * KDF_THREADS
	DEFAULT_KDF_MEM		= int(math.ceil(KDF_MEM_BASE / KDF_MEM_CHUNK)) * KDF_MEM_CHUNK
	DEFAULT_KDF_ITER	= lambda kdfMem: int(math.ceil(4000000 / kdfMem))
	KDF_MEMLIMIT		= 24584
	KDF_ITERLIMIT_A		= lambda kdfMem: int(math.ceil(2500000 / kdfMem))
	KDF_ITERLIMIT_B		= 2

	def __init__(self, readOnly=True):
		"""readOnly: If True, no commit is possible.
		"""
		self.__readOnly = readOnly
		self.__db = None
		self.__filename = None
		self.__passphrase = None
		self.__kdfMemFile = 0
		self.__key = None

	def getPassphrase(self):
		"""Get the current passphrase string for encryption and decryption.
		"""
		try:
			return self.__passphrase.decode("UTF-8")
		except UnicodeError as e:
			raise CSQLError("Cannot UTF-8-decode passphrase.")

	def setPassphrase(self, passphrase):
		"""Set a new passphrase string for encryption and decryption.
		"""
		assert isinstance(passphrase, str),\
		       "CryptSQL: Passphrase is not 'str'."
		try:
			self.__key = None
			self.__passphrase = passphrase.encode("UTF-8")
		except UnicodeError as e:
			raise CSQLError("Cannot UTF-8-encode passphrase.")

	def getKey(self):
		"""Get the raw key. May be None, if there is none, yet.
		Do not use this. getPassphrase probably is what you want.
		"""
		return self.__key

	def setKey(self, key):
		"""Set the raw key.
		Do not use this. setPassphrase probably is what you want.
		"""
		self.__key = key

	def getFilename(self):
		"""Get the file path of the currently open database.
		May return None, if no database file is opened.
		"""
		return self.__filename

	def __parseFile(self, filename):
		"""Read all data from 'filename' and decrypt it into memory.
		"""
		cls = self.__class__
		try:
			fc = FileObjCollection.parseFile(filename)
			if fc is None:
				return

			# Get the file fields.
			head = fc.get(
				name=b"HEAD",
				error="Missing file header object",
			)
			if head != cls.CSQL_HEADER:
				raise CSQLError("Invalid file header")
			cipher = fc.get(
				name=b"CIPHER",
				error="Missing CIPHER header object",
			)
			cipherMode = fc.get(
				name=b"CIPHER_MODE",
				error="Missing CIPHER_MODE header object",
			)
			cipherIV = fc.get(
				name=b"CIPHER_IV",
				error="Missing CIPHER_IV header object",
			)
			keyLen = fc.get(
				name=b"KEY_LEN",
				error="Missing KEY_LEN header object",
			)
			kdfMethod = fc.get(
				name=b"KDF_METHOD",
				error="Missing KDF_METHOD header object",
			)
			kdfSalt = fc.get(
				name=b"KDF_SALT",
				error="Missing KDF_SALT header object",
			)
			kdfIter = fc.get(
				name=b"KDF_ITER",
				error="Missing KDF_ITER header object",
			)
			if kdfMethod == b"PBKDF2":
				kdfHash = fc.get(
					name=b"KDF_HASH",
					error="Missing KDF_HASH header object",
				)
				kdfMac = fc.get(
					name=b"KDF_MAC",
					error="Missing KDF_MAC header object",
				)
			elif kdfMethod == b"ARGON2":
				kdfType = fc.get(
					name=b"KDF_TYPE",
					error="Missing KDF_TYPE header object",
				)
				kdfVer = fc.get(
					name=b"KDF_VER",
					error="Missing KDF_VER header object",
				)
				kdfPar = fc.get(
					name=b"KDF_PAR",
					error="Missing KDF_PAR header object",
				)
				kdfMem = fc.get(
					name=b"KDF_MEM",
					error="Missing KDF_MEM header object",
				)
			compress = fc.get(
				name=b"COMPRESS",
				default=b"NONE",
			)
			paddingMethod = fc.get(
				name=b"PADDING",
				default=b"PWMAN",
			)
			payload = fc.get(
				name=b"PAYLOAD",
				error="Missing PAYLOAD object",
			)

			# Check payload.
			if len(payload) < 1:
				raise CSQLError("Invalid PAYLOAD length: %d" % (
						len(payload)))

			# Check the padding method.
			paddingMethod = decodeChoices(
				buf=paddingMethod,
				choices=("PWMAN", "PKCS7"),
				error="Unknown padding method header",
			)

			# Check the cipher.
			cipher = decodeChoices(
				buf=cipher,
				choices=("AES",),
				error="Unknown CIPHER header value",
			)
			cipherMode = decodeChoices(
				buf=cipherMode,
				choices=("CBC",),
				error="Unknown CIPHER_MODE header value",
			)
			cipherBlockSize = AES.BLOCK_SIZE

			# Check the cipher IV.
			if len(cipherIV) != cipherBlockSize:
				raise CSQLError("Invalid CIPHER_IV header length: %d" % (
						len(cipherIV)))

			# Check the cipher key length.
			keyLen = decodeChoices(
				buf=keyLen,
				choices=("256",),
				error="Unknown KEY_LEN header value",
			)
			keyLen = int(keyLen) // 8

			# Check the key derivation function salt.
			if len(kdfSalt) < 16:
				raise CSQLError("Invalid KDF_SALT header length: %d" % (
						len(kdfSalt)))

			# Check the key derivation function iterations.
			kdfIter = decodeInt(
				buf=kdfIter,
				minValue=1,
				maxValue=((1 << 32) - 1),
				error="Invalid KDF_ITER header value",
			)

			# Check the key derivation function.
			kdfMethod = decodeChoices(
				buf=kdfMethod,
				choices=("PBKDF2", "ARGON2"),
				error="Unknown KDF_METHOD header value",
			)
			if kdfMethod == "PBKDF2":
				kdfHash = decodeChoices(
					buf=kdfHash,
					choices=("SHA256", "SHA512", "SHA3-512"),
					error="Unknown KDF_HASH header value",
				)
				kdfMac = decodeChoices(
					buf=kdfMac,
					choices=("HMAC",),
					error="Unknown KDF_MAC header value",
				)
				kdf = lambda: hashlib.pbkdf2_hmac(
					hash_name=kdfHash,
					password=self.__passphrase,
					salt=kdfSalt,
					iterations=kdfIter,
					dklen=keyLen,
				)
			elif kdfMethod == "ARGON2":
				kdfType = decodeChoices(
					buf=kdfType,
					choices=("ID",),
					error="Unknown KDF_TYPE header value",
				)
				kdfVer = decodeChoices(
					buf=kdfVer,
					choices=(str(0x13), ),
					error="Unknown KDF_VER header value",
				)
				kdfPar = decodeInt(
					buf=kdfPar,
					minValue=1,
					maxValue=((1 << 24) - 1),
					error="Invalid KDF_PAR header value",
				)
				kdfMem = decodeInt(
					buf=kdfMem,
					minValue=(8 * kdfPar),
					maxValue=((1 << 32) - 1),
					error="Invalid KDF_MEM header value",
				)
				kdf = lambda: Argon2.get().argon2id_v1p3(
					passphrase=self.__passphrase,
					salt=kdfSalt,
					timeCost=kdfIter,
					memCost=kdfMem,
					parallel=kdfPar,
					keyLen=keyLen,
				)
				self.__kdfMemFile = kdfMem
			else:
				assert False

			# Check the compression method.
			compress = decodeChoices(
				buf=compress,
				choices=("NONE", "ZLIB"),
				error="Unknown COMPRESS header value",
			)

			try:
				# Generate the key.
				key = kdf() if self.__key is None else self.__key
			except Exception as e:
				raise CSQLError("Failed to generate decryption key: %s: %s" % (
						type(e), str(e)))

			try:
				# Decrypt the payload.
				payload = AES.get().decrypt(
					key=key,
					iv=cipherIV,
					data=payload,
					legacyPadding=(paddingMethod == "PWMAN"))

				# Decompress the payload (legacy).
				if compress == "ZLIB":
					payload = zlib.decompress(payload)

				# Import the SQL database.
				self.importSqlScript(payload.decode("UTF-8"))

				# Store the raw key.
				self.__key = key
			except Exception as e:
				raise CSQLError("Failed to decrypt database. "
						"Wrong passphrase?")
		except FileObjError as e:
			raise CSQLError("Database file error: %s" % str(e))

	def isOpen(self):
		"""Returns True, if a database file is opened.
		"""
		return self.__db is not None

	def open(self, filename):
		"""Open a database file and decrypt its contents into memory.
		filename: The database file path.
		"""
		if self.isOpen():
			raise CSQLError("A database is already open")
		self.__db = sql.connect(":memory:")
		self.setRegexpFlags()
		self.sqlCreateFunction("regexp", 2, self._sqlRegexpMatch)
		try:
			self.__parseFile(filename)
		except CSQLError as e:
			self.close()
			raise e
		self.__filename = filename

	def close(self):
		"""Close the currently opened database.
		This does not commit. All uncommitted changes are lost.
		"""
		self.__db = None
		self.__filename = None
		self.__passphrase = None
		self.__kdfMemFile = 0

	def __random(self, nrBytes):
		"""Return cryptographically secure random bytes.
		nrBytes: The number of bytes to return.
		"""
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

	def dropUncommitted(self):
		"""Drop all changes that are not committed, yet.
		"""
		self.__db.rollback()

	def commit(self):
		"""Write all changes to the encrypted database file.
		"""
		cls = self.__class__
		if self.__readOnly:
			raise CSQLError("The database is read-only. "
					"Cannot commit changes.")
		if not self.__db or not self.__filename:
			raise CSQLError("Database is not open")

		# Cleanup the database.
		self.sqlVacuum()

		# Get the KDF parameters.
		kdfSalt = self.__random(cls.KDF_SALT_NBYTES)
		kdfMem = cls.DEFAULT_KDF_MEM
		kdfMemUser = os.getenv("PWMAN_ARGON2MEM", "").lower().strip()
		if kdfMemUser:
			# User override.
			try:
				kdfMem = int(kdfMemUser, 10)
			except ValueError:
				raise CSQLError("The value of the environment variable "
						"PWMAN_ARGON2MEM is invalid.")
		else:
			# By default never reduce the memory cost,
			# if the file already uses a higher cost.
			kdfMem = max(kdfMem, self.__kdfMemFile)
		kdfMem = max(kdfMem, cls.KDF_MEMLIMIT)
		kdfIter = cls.DEFAULT_KDF_ITER(kdfMem)
		kdfIterUser = os.getenv("PWMAN_ARGON2TIME", "").lower().strip()
		if kdfIterUser:
			# User override.
			try:
				kdfIter = int(kdfIterUser, 10)
			except ValueError:
				raise CSQLError("The value of the environment variable "
						"PWMAN_ARGON2TIME is invalid.")
		kdfIter = max(kdfIter, cls.KDF_ITERLIMIT_A(kdfMem))
		kdfIter = max(kdfIter, cls.KDF_ITERLIMIT_B)
		kdfPar = cls.KDF_THREADS
		keyLen = 256 // 8

		try:
			# Generate the key.
			key = Argon2.get().argon2id_v1p3(
				passphrase=self.__passphrase,
				salt=kdfSalt,
				timeCost=kdfIter,
				memCost=kdfMem,
				parallel=kdfPar,
				keyLen=keyLen,
			)
		except Exception as e:
			raise CSQLError("Failed to generate the encryption key: %s" % str(e))

		# Dump the database
		payload = self.sqlPlainDump()

		try:
			# Encrypt payload
			cipherIV = self.__random(AES.BLOCK_SIZE)
			payload = AES.get().encrypt(
				key=key,
				iv=cipherIV,
				data=payload,
			)
		except Exception as e:
			raise CSQLError("Failed to encrypt: %s" % str(e))

		try:
			# Assemble file objects
			fc = FileObjCollection((
				FileObj(b"HEAD", cls.CSQL_HEADER),
				FileObj(b"CIPHER", b"AES"),
				FileObj(b"CIPHER_MODE", b"CBC"),
				FileObj(b"CIPHER_IV", cipherIV),
				FileObj(b"KEY_LEN", str(keyLen * 8).encode("UTF-8")),
				FileObj(b"KDF_METHOD", b"ARGON2"),
				FileObj(b"KDF_TYPE", b"ID"),
				FileObj(b"KDF_VER", str(0x13).encode("UTF-8")),
				FileObj(b"KDF_SALT", kdfSalt),
				FileObj(b"KDF_ITER", str(kdfIter).encode("UTF-8")),
				FileObj(b"KDF_MEM", str(kdfMem).encode("UTF-8")),
				FileObj(b"KDF_PAR", str(kdfPar).encode("UTF-8")),
				FileObj(b"PADDING", b"PKCS7"),
				FileObj(b"PAYLOAD", payload),
			))

			# Write to the file
			self.__key = None
			fc.writeFile(self.__filename)
			self.__key = key
		except FileObjError as e:
			raise CSQLError("File error: %s" % str(e))

	def setRegexpFlags(self, search=True, ignoreCase=True, multiLine=True, dotAll=True):
		"""Change the behavior of the REGEXP operator.
		"""
		if search:
			self._regexpMatch = re.search
		else:
			self._regexpMatch = re.match
		self._regexpFlags = 0
		if ignoreCase:
			self._regexpFlags |= re.IGNORECASE
		if multiLine:
			self._regexpFlags |= re.MULTILINE
		if dotAll:
			self._regexpFlags |= re.DOTALL

	def _sqlRegexpMatch(self, pattern, string):
		"""Default implementation of the REGEXP operator.
		"""
		return 0 if self._regexpMatch(pattern,
					      string,
					      flags=self._regexpFlags) is None else 1

	def sqlVacuum(self):
		"""Run the SQL VACUUM statement.
		This also commits all changes to the SQL database,
		but not to the database file.
		"""
		self.__db.commit()
		self.sqlExec("VACUUM;")
		self.__db.commit()

	def sqlExec(self, code, params=[]):
		"""Execute one SQL statement.
		"""
		return CryptSQLCursor(self.__db).sqlExec(code, params)

	def sqlExecScript(self, code):
		"""Execute multiple SQL statements.
		Warning: This implicitly commits pending transactions before executing.
		"""
		return CryptSQLCursor(self.__db).sqlExecScript(code)

	def sqlCreateFunction(self, name, nrParams, func):
		"""Create an SQL function.
		See sqlite3.Connection.create_function for more details.
		"""
		self.__db.create_function(name, nrParams, func)

	def sqlIsEmpty(self):
		"""Returns True, if the database does not contain any tables.
		"""
		c = self.sqlExec("ANALYZE;")
		tbl = c.sqlExec("SELECT tbl FROM sqlite_stat1;").fetchOne()
		return not bool(tbl)

	def sqlPlainDump(self):
		"""Get a plain text dump of the database.
		Returns bytes.
		"""
		return ("\n".join(self.__db.iterdump())).encode("UTF-8")

	def importSqlScript(self, script, clear=True):
		"""Imports a plain text dump into the database.
		script: The script string to import.
		clear: If True, drop all tables from the database before importing.
		"""
		if clear:
			self.dropAllTables()
		self.sqlExecScript(script)

	def dropAllTables(self):
		"""Drop all tables from the database.
		"""
		c = self.sqlExec("SELECT name FROM sqlite_master "
				 "WHERE type='table';")
		for table in c.fetchAll():
			table = table[0]
			if table != "sqlite_sequence":
				self.sqlExec("DROP TABLE %s" % table)
