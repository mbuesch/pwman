# -*- coding: utf-8 -*-
"""
# Simple object file format.
# Copyright (c) 2011-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import errno

__all__ = [
	"FileObjError",
	"FileObj",
	"FileObjCollection",
]

class FileObjError(Exception):
	pass

class FileObj:
	# Raw object layout:
	#   [ 1 byte  ] => Name length
	#   [ x bytes ] => Name
	#   [ 4 bytes ] => Payload data length
	#   [ x bytes ] => Payload data

	__slots__ = (
		"__name",
		"__data",
	)

	def __init__(self, name, data):
		"""Construct FileObj().
		name: The object name. Must be bytes-like.
		data: The object payload. Must be bytes-like.
		"""
		assert isinstance(name, (bytes, bytearray, memoryview)),\
		       "FileObj: Invalid 'name' type."
		assert isinstance(data, (bytes, bytearray, memoryview)),\
		       "FileObj: Invalid 'data' type."
		self.__name = memoryview(name)
		self.__data = memoryview(data)
		if len(self.__name) > 0x7F:
			raise FileObjError("FileObj: Name too long")
		if len(self.__data) > 0x7FFFFFFF:
			raise FileObjError("FileObj: Data too long")

	def getName(self):
		return self.__name

	def getData(self):
		return self.__data

	def getRaw(self, buffer):
		nameLen = len(self.__name)
		assert nameLen <= 0x7F
		buffer += b"%c" % (nameLen & 0xFF)
		buffer += self.__name
		dataLen = len(self.__data)
		assert dataLen <= 0x7FFFFFFF
		buffer += b"%c" % (dataLen & 0xFF)
		buffer += b"%c" % ((dataLen >> 8) & 0xFF)
		buffer += b"%c" % ((dataLen >> 16) & 0xFF)
		buffer += b"%c" % ((dataLen >> 24) & 0xFF)
		buffer += self.__data

	@classmethod
	def parseRaw(cls, raw):
		assert isinstance(raw, (bytes, bytearray, memoryview)),\
		       "FileObj: Invalid 'raw' type."
		raw = memoryview(raw)
		try:
			off = 0
			nameLen = raw[off]
			if nameLen & 0x80:
				raise FileObjError("FileObj: Name length extension bit is set, "
						   "but not supported by this pwman version.")
			off += 1
			name = raw[off : off + nameLen]
			off += nameLen
			dataLen = (raw[off] |
				   (raw[off + 1] << 8) |
				   (raw[off + 2] << 16) |
				   (raw[off + 3] << 24))
			if dataLen & 0x80000000:
				raise FileObjError("FileObj: Data length extension bit is set, "
						   "but not supported by this pwman version.")
			off += 4
			data = raw[off : off + dataLen]
			off += dataLen
		except (IndexError, KeyError) as e:
			raise FileObjError("Failed to parse file object")
		return (cls(name, data), off)

class FileObjCollection:
	__slots__ = (
		"__objects",
	)

	def __init__(self, objects):
		if isinstance(objects, dict):
			self.__objects = objects
		elif isinstance(objects, (list, tuple)):
			self.__objects = { obj.getName() : obj for obj in objects }
		else:
			assert False

	def writeFile(self, filepath):
		try:
			with open(filepath, "wb") as f:
				f.write(self.getRaw())
				f.flush()
		except IOError as e:
			raise FileObjError("Failed to write file: %s" % e.strerror)

	def getRaw(self):
		raw = bytearray()
		for obj in self.__objects.values():
			obj.getRaw(raw)
		return raw

	@property
	def objects(self):
		return self.__objects.values()

	def get(self, name, error=None, default=None):
		obj = self.__objects.get(name, None)
		if obj is None:
			if error:
				raise FileObjError(error)
			return default
		return bytes(obj.getData())

	@classmethod
	def parseRaw(cls, raw):
		assert isinstance(raw, (bytes, bytearray, memoryview)),\
		       "FileObjCollection: Invalid 'raw' type."
		raw = memoryview(raw)
		offset = 0
		objects = {}
		while offset < len(raw):
			obj, objLen = FileObj.parseRaw(raw[offset:])
			objects[obj.getName()] = obj
			offset += objLen
		return cls(objects)

	@classmethod
	def parseFile(cls, filepath):
		try:
			with open(filepath, "rb") as f:
				rawData = f.read()
		except IOError as e:
			if e.errno != errno.ENOENT:
				raise FileObjError("Failed to read file: %s" % e.strerror)
			return None
		return cls.parseRaw(rawData)
