# -*- coding: utf-8 -*-
"""
# Crypto SQL
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import sys
import os
import errno
import zlib

def missingMod(name, debpack=None):
	print("Python '%s' module is not installed." % name)
	if debpack:
		print("On Debian do:  aptitude install %s" % debpack)
	sys.exit(1)

try:
	import Crypto.Hash.SHA256 as SHA256
	import Crypto.Hash.SHA512 as SHA512
	import Crypto.Hash.HMAC as HMAC
	from Crypto.Protocol.KDF import PBKDF2
	import Crypto.Random
	import Crypto.Cipher.AES as AES
except (ImportError) as e:
	missingMod("Crypto", "python3-crypto")
try:
	import sqlite3 as sql
except (ImportError) as e:
	missingMod("sqlite3")


CSQL_HEADER = b"CryptSQL v1"


class CSQLError(Exception): pass

class FileObj(object):
	# Raw object layout:
	#   [ 1 byte  ] => Name length
	#   [ x bytes ] => Name
	#   [ 4 bytes ] => Payload data length
	#   [ x bytes ] => Payload data

	def __init__(self, name, data):
		"""Construct FileObj().
		name: The object name. Must be bytes-like.
		data: The object payload. Must be bytes-like.
		"""
		assert isinstance(name, (bytes, bytearray)),\
		       "FileObj: Invalid 'name' type."
		assert isinstance(data, (bytes, bytearray)),\
		       "FileObj: Invalid 'data' type."
		if len(name) > 0xFF:
			raise CSQLError("FileObj: Name too long")
		self.__name = name
		if len(data) > 0xFFFFFFFF:
			raise CSQLError("FileObj: Data too long")
		self.__data = data

	def getName(self):
		return self.__name

	def getData(self):
		return self.__data

	def getRaw(self):
		r = bytearray()
		nameLen = len(self.__name)
		r += b"%c" % (nameLen & 0xFF)
		r += self.__name
		dataLen = len(self.__data)
		r += b"%c" % (dataLen & 0xFF)
		r += b"%c" % ((dataLen >> 8) & 0xFF)
		r += b"%c" % ((dataLen >> 16) & 0xFF)
		r += b"%c" % ((dataLen >> 24) & 0xFF)
		r += self.__data
		return r

	@staticmethod
	def parseRaw(raw):
		assert isinstance(raw, (bytes, bytearray)),\
		       "FileObj: Invalid 'raw' type."
		try:
			off = 0
			nameLen = raw[off]
			off += 1
			name = raw[off : off + nameLen]
			off += nameLen
			dataLen = (raw[off] |
				   (raw[off + 1] << 8) |
				   (raw[off + 2] << 16) |
				   (raw[off + 3] << 24))
			off += 4
			data = raw[off : off + dataLen]
			off += dataLen
		except (IndexError, KeyError) as e:
			raise CSQLError("Failed to parse file object")
		return (FileObj(name, data), off)

class FileObjCollection(object):
	def __init__(self, objects):
		self.objects = objects

	def getRaw(self):
		raw = bytearray()
		for obj in self.objects:
			raw += obj.getRaw()
		return raw

	def get(self, name):
		return [o for o in self.objects if o.getName() == name]

	def getOne(self, name, errorMsg=None):
		objs = self.get(name)
		if len(objs) != 1:
			if errorMsg:
				raise CSQLError(errorMsg)
			return None
		return objs[0]

	@staticmethod
	def parseRaw(raw):
		assert isinstance(raw, (bytes, bytearray)),\
		       "FileObjCollection: Invalid 'raw' type."
		offset = 0
		objects = []
		while offset < len(raw):
			(obj, objLen) = FileObj.parseRaw(raw[offset:])
			objects.append(obj)
			offset += objLen
		return FileObjCollection(objects)

class CryptSQLCursor(object):
	def __init__(self, c):
		self.c = c

	def sqlExec(self, code, params=[]):
		self.c.execute(code, params)
		return self

	def sqlExecScript(self, code):
		self.c.executescript(code)
		return self

	def fetchOne(self):
		return self.c.fetchone()

	def fetchAll(self):
		return self.c.fetchall()

class CryptSQL(object):
	def __init__(self):
		self.__reset()

	def __reset(self):
		self.__rng = Crypto.Random.new()
		self.db = None
		self.filename = None

	def __parseFileData(self, rawdata, passphrase):
		fc = FileObjCollection.parseRaw(rawdata)
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
			raise CSQLError("Unknown cipher: %s" % cipher)
		if cipherMode == b"CBC":
			cipherMode = AES.MODE_CBC
		else:
			raise CSQLError("Unknown cipher mode: %s" % cipherMode)
		if not cipherIV:
			cipherIV = b'\x00' * cipher.block_size
		if len(cipherIV) != cipher.block_size:
			raise CSQLError("Invalid IV len: %d" % len(cipherIV))
		if keyLen == b"256":
			keyLen = 256 // 8
		else:
			raise CSQLError("Unknown key len: %s" % keyLen)
		if kdfMethod == b"PBKDF2":
			kdfMethod = PBKDF2
		else:
			raise CSQLError("Unknown kdf method: %s" % kdfMethod)
		if len(kdfSalt) < 32:
			raise CSQLError("Invalid salt len: %d" % len(kdfSalt))
		try:
			kdfIter = int(kdfIter.decode("UTF-8"), 10)
		except (ValueError, UnicodeError) as e:
			raise CSQLError("Unknown kdf-iter: %s" % kdfIter)
		if kdfHash == b"SHA256":
			kdfHash = SHA256
		elif kdfHash == b"SHA512":
			kdfHash = SHA512
		else:
			raise CSQLError("Unknown kdf-hash: %s" % kdfHash)
		if kdfMac == b"HMAC":
			kdfMac = HMAC
		else:
			raise CSQLError("Unknown kdf-mac: %s" % kdfMac)
		if compress == b"ZLIB":
			compress = zlib
		else:
			raise CSQLError("Unknown compression: %s" % compress)
		try:
			# Decrypt payload
			prf = lambda p, s: kdfMac.new(p, s, kdfHash).digest()
			key = kdfMethod(passphrase, kdfSalt, keyLen,
					kdfIter, prf)
			cipher = cipher.new(key, mode = cipherMode,
					    IV = cipherIV)
			payload = cipher.decrypt(payload)
			payload = self.__unpadData(payload)
			# Decompress payload
			payload = compress.decompress(payload)
			# Import the SQL database
			self.db.cursor().executescript(payload.decode("UTF-8"))
		except (CSQLError, zlib.error, sql.Error, UnicodeError) as e:
			raise CSQLError("Failed to decrypt database. "
					"Wrong passphrase?")

	def isOpen(self):
		return bool(self.db)

	def open(self, filename, passphrase):
		if self.isOpen():
			raise CSQLError("A database is already open")
		self.__reset()
		self.db = sql.connect(":memory:")
		self.db.text_factory = str
		try:
			try:
				rawdata = open(filename, "rb").read()
			except (IOError) as e:
				if e.errno != errno.ENOENT:
					raise CSQLError("Failed to read file: %s" %\
						e.strerror)
			else:
				self.__parseFileData(rawdata, passphrase)
		except (CSQLError) as e:
			self.__reset()
			raise
		self.filename = filename

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
		return self.__rng.read(nrBytes)

	def commit(self, passphrase):
		if not self.db or not self.filename:
			raise CSQLError("Database is not open")
		self.db.commit()
		# Dump the database
		payload = self.sqlPlainDump()
		# Compress payload
		payload = zlib.compress(payload, 1)
		# Encrypt payload
		kdfSalt = self.__random(34)
		kdfIter = 40003
		prf = lambda p, s: HMAC.new(p, s, SHA512).digest()
		key = PBKDF2(passphrase, kdfSalt, 256 // 8,
			     kdfIter, prf)
		cipherIV = self.__random(16)
		aes = AES.new(key, mode = AES.MODE_CBC,
			      IV = cipherIV)
		payload = aes.encrypt(self.__padData(payload, aes.block_size))
		# Assemble file objects
		fc = FileObjCollection(
			(
				FileObj(b"HEAD", CSQL_HEADER),
				FileObj(b"CIPHER", b"AES"),
				FileObj(b"CIPHER_MODE", b"CBC"),
				FileObj(b"CIPHER_IV", cipherIV),
				FileObj(b"KEY_LEN", b"256"),
				FileObj(b"KDF_METHOD", b"PBKDF2"),
				FileObj(b"KDF_SALT", kdfSalt),
				FileObj(b"KDF_ITER", str(kdfIter).encode("UTF-8")),
				FileObj(b"KDF_HASH", b"SHA512"),
				FileObj(b"KDF_MAC", b"HMAC"),
				FileObj(b"COMPRESS", b"ZLIB"),
				FileObj(b"PAYLOAD", payload),
			)
		)
		# Write to the file
		rawdata = fc.getRaw()
		try:
			fd = open(self.filename, "wb")
			fd.write(rawdata)
			fd.flush()
			fd.close()
		except (IOError) as e:
			raise CSQLError("Failed to write file: %s" %\
				e.strerror)

	def sqlExec(self, code, params=[]):
		return CryptSQLCursor(self.db.cursor()).sqlExec(code, params)

	def sqlExecScript(self, code):
		return CryptSQLCursor(self.db.cursor()).sqlExecScript(code)

	def sqlCreateFunction(self, name, nrParams, func):
		self.db.create_function(name, nrParams, func)

	def sqlIsEmpty(self):
		c = self.sqlExec("ANALYZE;")
		tbl = c.sqlExec("SELECT tbl FROM sqlite_stat1;").fetchOne()
		return not bool(tbl)

	def sqlPlainDump(self):
		return ("\n".join(self.db.iterdump())).encode("UTF-8")

if __name__ == "__main__":
	databaseFile = sys.argv[1]
	passphrase = sys.argv[2]
	csql = CryptSQL()
	csql.open(databaseFile, passphrase)
	csql.commit(passphrase)
	csql.close()
