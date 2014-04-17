"""
# Crypto SQL
# Copyright (c) 2011 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import sys
import os
import errno
import zlib

def missingMod(name, debpack):
	print "Python '%s' module is not installed." % name
	if debpack:
		print "On Debian do:  aptitude install %s" % debpack
	sys.exit(1)

try:
	import Crypto.Hash.SHA256 as SHA256
	import Crypto.Hash.SHA512 as SHA512
	import Crypto.Hash.HMAC as HMAC
	import Crypto.Cipher.AES as AES
except (ImportError), e:
	missingMod("Crypto", "python-crypto")
try:
	from beaker.crypto.pbkdf2 import PBKDF2
except (ImportError), e:
	missingMod("beaker", "python-beaker")
try:
	import sqlite3 as sql
except (ImportError), e:
	missingMod("sqlite3", "python-sqlite")


CSQL_HEADER	= map(lambda c: ord(c), "CryptSQL v1")


class CSQLError(Exception): pass

class FileObj(object):
	# Raw object layout:
	#   [ 1 byte  ] => Name length
	#   [ x bytes ] => Name
	#   [ 4 bytes ] => Payload data length
	#   [ x bytes ] => Payload data

	def __init__(self, name, data):
		self.name = self.__2str(name)
		if len(self.name) > 0xFF:
			raise CSQLError("FileObj: Name too long")
		self.data = data
		if len(self.data) > 0xFFFFFFFF:
			raise CSQLError("FileObj: Data too long")

	@staticmethod
	def __2bytes(iterable):
		if type(iterable) == str or type(iterable) == unicode:
			iterable = map(lambda c: ord(c), iterable)
		return iterable

	@staticmethod
	def __2str(iterable):
		if type(iterable) != str:
			iterable = "".join(map(lambda c: chr(c), iterable))
		return iterable

	def getName(self):
		return self.name

	def getData(self):
		return self.data

	def getDataString(self):
		return self.__2str(self.data)

	def getRaw(self):
		name = self.__2bytes(self.name)
		nameLen = len(name)
		data = self.__2bytes(self.data)
		dataLen = len(data)
		r = [ nameLen & 0xFF, ]
		r.extend(name)
		r.extend( [
			dataLen & 0xFF,
			(dataLen >> 8) & 0xFF,
			(dataLen >> 16) & 0xFF,
			(dataLen >> 24) & 0xFF,
		] )
		r.extend(data)
		return r

	@staticmethod
	def parseRaw(r):
		try:
			off = 0
			nameLen = r[off]
			off += 1
			name = r[off : off + nameLen]
			off += nameLen
			dataLen = r[off] | (r[off + 1] << 8) |\
				  (r[off + 2] << 16) | (r[off + 3] << 24)
			off += 4
			data = r[off : off + dataLen]
			off += dataLen
		except (IndexError, KeyError), e:
			raise CSQLError("Failed to parse file object")
		return (FileObj(name, data), off)

class FileObjCollection(object):
	def __init__(self, objects):
		self.objects = objects

	def getRaw(self):
		r = []
		for obj in self.objects:
			r.extend(obj.getRaw())
		return r

	def get(self, name):
		return filter(lambda o: o.name == name, self.objects)

	def getOne(self, name, errorMsg=None):
		objs = self.get(name)
		if len(objs) != 1:
			if errorMsg:
				raise CSQLError(errorMsg)
			return None
		return objs[0]

	@staticmethod
	def parseRaw(r):
		offset = 0
		objects = []
		while offset < len(r):
			(obj, objLen) = FileObj.parseRaw(r[offset:])
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
		self.db = None
		self.filename = None

	def __parseFileData(self, rawdata, passphrase):
		fc = FileObjCollection.parseRaw(rawdata)
		head = fc.getOne("HEAD", "Invalid file header object")
		if head.getData() != CSQL_HEADER:
			raise CSQLError("Invalid file header")
		cipher = fc.getOne("CIPHER", "Invalid CYPHER object").getDataString()
		cipherMode = fc.getOne("CIPHER_MODE", "Invalid CYPHER_MODE object").getDataString()
		cipherIV = fc.getOne("CIPHER_IV")
		if cipherIV:
			cipherIV = cipherIV.getDataString()
		keyLen = fc.getOne("KEY_LEN", "Invalid KEY_LEN object").getDataString()
		kdfMethod = fc.getOne("KDF_METHOD", "Invalid KDF_METHOD object").getDataString()
		kdfSalt = fc.getOne("KDF_SALT", "Invalid KDF_SALT object").getDataString()
		kdfIter = fc.getOne("KDF_ITER", "Invalid KDF_ITER object").getDataString()
		kdfHash = fc.getOne("KDF_HASH", "Invalid KDF_HASH object").getDataString()
		kdfMac = fc.getOne("KDF_MAC", "Invalid KDF_MAC object").getDataString()
		compress = fc.getOne("COMPRESS", "Invalid COMPRESS object").getDataString()
		payload = fc.getOne("PAYLOAD", "Invalid PAYLOAD object").getDataString()
		if cipher == "AES":
			cipher = AES
		else:
			raise CSQLError("Unknown cipher: %s" % cipher)
		if cipherMode == "CBC":
			cipherMode = AES.MODE_CBC
		else:
			raise CSQLError("Unknown cipher mode: %s" % cipherMode)
		if not cipherIV:
			cipherIV = b'\x00' * cipher.block_size
		if len(cipherIV) != cipher.block_size:
			raise CSQLError("Invalid IV len: %d" % len(cipherIV))
		if keyLen == "256":
			keyLen = 256 // 8
		else:
			raise CSQLError("Unknown key len: %s" % keyLen)
		if kdfMethod == "PBKDF2":
			kdfMethod = PBKDF2
		else:
			raise CSQLError("Unknown kdf method: %s" % kdfMethod)
		if len(kdfSalt) < 32:
			raise CSQLError("Invalid salt len: %d" % len(kdfSalt))
		try:
			kdfIter = int(kdfIter, 10)
		except (ValueError), e:
			raise CSQLError("Unknown kdf-iter: %s" % kdfIter)
		if kdfHash == "SHA256":
			kdfHash = SHA256
		elif kdfHash == "SHA512":
			kdfHash = SHA512
		else:
			raise CSQLError("Unknown kdf-hash: %s" % kdfHash)
		if kdfMac == "HMAC":
			kdfMac = HMAC
		else:
			raise CSQLError("Unknown kdf-mac: %s" % kdfMac)
		if compress == "ZLIB":
			compress = zlib
		else:
			raise CSQLError("Unknown compression: %s" % compress)
		try:
			# Decrypt payload
			kdf = kdfMethod(passphrase, kdfSalt, kdfIter,
					kdfHash, kdfMac)
			key = kdf.read(keyLen)
			cipher = cipher.new(key, mode = cipherMode,
					    IV = cipherIV)
			payload = cipher.decrypt(payload)
			payload = self.__unpadData(payload)
			# Decompress payload
			payload = compress.decompress(payload)
			# Import the SQL database
			self.db.cursor().executescript(payload)
		except (CSQLError, zlib.error, sql.Error), e:
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
				rawdata = file(filename, "rb").read()
			except (IOError), e:
				if e.errno != errno.ENOENT:
					raise CSQLError("Failed to read file: %s" %\
						e.strerror)
			else:
				rawdata = map(lambda c: ord(c), rawdata)
				self.__parseFileData(rawdata, passphrase)
		except (CSQLError), e:
			self.__reset()
			raise
		self.filename = filename

	def close(self):
		self.__reset()

	@staticmethod
	def __padData(data, align):
		data += "\xFF"
		nrPad = (align - (len(data) % align))
		if nrPad != 0 and nrPad != align:
			data += "\x00" * nrPad
		return data

	@staticmethod
	def __unpadData(data):
		index = data.rfind("\xFF")
		if index < 0 or index >= len(data):
			raise CSQLError("unpadData: error")
		return data[:index]

	@staticmethod
	def __random(nrBytes):
		return os.urandom(nrBytes)

	def commit(self, passphrase):
		if not self.db or not self.filename:
			raise CSQLError("Database is not open")
		self.db.commit()
		# Dump the database
		payload = self.sqlPlainDump()
		# Compress payload
		payload = zlib.compress(payload, 9)
		# Encrypt payload
		kdfSalt = self.__random(34)
		kdfIter = 4003
		kdf = PBKDF2(passphrase, kdfSalt, kdfIter, SHA512, HMAC)
		key = kdf.read(256 // 8)
		cipherIV = self.__random(16)
		aes = AES.new(key, mode = AES.MODE_CBC,
			      IV = cipherIV)
		payload = aes.encrypt(self.__padData(payload, aes.block_size))
		# Assemble file objects
		fc = FileObjCollection(
			(
				FileObj("HEAD", CSQL_HEADER),
				FileObj("CIPHER", "AES"),
				FileObj("CIPHER_MODE", "CBC"),
				FileObj("CIPHER_IV", cipherIV),
				FileObj("KEY_LEN", "256"),
				FileObj("KDF_METHOD", "PBKDF2"),
				FileObj("KDF_SALT", kdfSalt),
				FileObj("KDF_ITER", str(kdfIter)),
				FileObj("KDF_HASH", "SHA512"),
				FileObj("KDF_MAC", "HMAC"),
				FileObj("COMPRESS", "ZLIB"),
				FileObj("PAYLOAD", payload),
			)
		)
		# Write to the file
		rawdata = fc.getRaw()
		try:
			fd = file(self.filename, "wb")
			fd.write("".join(map(lambda c: chr(c), rawdata)))
			fd.flush()
			fd.close()
		except (IOError), e:
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
		return "\n".join(self.db.iterdump())

if __name__ == "__main__":
	databaseFile = sys.argv[1]
	passphrase = sys.argv[2]
	csql = CryptSQL()
	csql.open(databaseFile, passphrase)
	csql.commit(passphrase)
	csql.close()
