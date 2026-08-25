# -*- coding: utf-8 -*-
"""
# Simple object file format.
# Copyright (c) 2011-2026 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import errno
from collections import OrderedDict

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

	NAMELEN_LEN = 1
	DATALEN_LEN = 4

	__slots__ = (
		"__name",
		"__data",
		"__index",
		"__rawOffset",
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
		self.__name = bytes(name)
		self.__data = memoryview(data)
		self.__index = None
		self.__rawOffset = None
		if len(self.__name) > 0x7F:
			raise FileObjError("FileObj: Name too long")
		if len(self.__data) > 0x7FFFFFFF:
			raise FileObjError("FileObj: Data too long")

	def getName(self):
		return bytes(self.__name)

	def getData(self):
		return self.__data

	def getIndex(self):
		return self.__index

	def setIndex(self, index):
		self.__index = index

	def getRawOffset(self):
		return self.__rawOffset

	def setRawOffset(self, rawOffset):
		self.__rawOffset = rawOffset

	def getRawPayloadOffset(self):
		return self.getRawOffset() + self.getHeaderLen()

	def getHeaderLen(self):
		return self.NAMELEN_LEN + len(self.__name) + self.DATALEN_LEN

	def __len__(self):
		return self.getHeaderLen() + len(self.__data)

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
			if len(raw) < off + 1:
				raise FileObjError("FileObj: Raw data too short (1)")
			nameLen = raw[off]
			if nameLen & 0x80:
				raise FileObjError("FileObj: Name length extension bit is set, "
						   "but not supported by this pwman version.")
			off += 1
			if len(raw) < off + nameLen:
				raise FileObjError("FileObj: Raw data too short (2)")
			name = raw[off : off + nameLen]
			off += nameLen
			if len(raw) < off + 4:
				raise FileObjError("FileObj: Raw data too short (3)")
			dataLen = (raw[off] |
				   (raw[off + 1] << 8) |
				   (raw[off + 2] << 16) |
				   (raw[off + 3] << 24))
			if dataLen & 0x80000000:
				raise FileObjError("FileObj: Data length extension bit is set, "
						   "but not supported by this pwman version.")
			off += 4
			if len(raw) < off + dataLen:
				raise FileObjError("FileObj: Raw data too short (4)")
			data = raw[off : off + dataLen]
			off += dataLen
		except (IndexError, KeyError) as e:
			raise FileObjError("Failed to parse file object")
		return (cls(name, data), off)

class FileObjCollection:
	__slots__ = (
		"__objects",
		"__rawOffset",
	)

	def __init__(self, objects):
		self.__objects = OrderedDict()
		self.__rawOffset = 0
		for obj in objects:
			self.setObj(obj)

	def getRaw(self):
		raw = bytearray()
		for obj in self.__objects.values():
			obj.getRaw(raw)
		return raw

	@property
	def objects(self):
		return self.__objects.values()

	def get(self, name, error=None, default=None):
		obj = self.getObj(name)
		if obj is None:
			if error:
				raise FileObjError(error)
			return default
		return bytes(obj.getData())

	def getObj(self, name):
		return self.__objects.get(name, None)

	def setObj(self, obj, override=False):
		if obj.getIndex() is not None or obj.getRawOffset() is not None:
			raise FileObjError("FileObjCollection.setObj: Object is already inserted.")
		name = obj.getName()
		oldObj = self.__objects.get(name, None)
		if oldObj is None:
			obj.setIndex(len(self))
			obj.setRawOffset(self.__rawOffset)
			self.__rawOffset += len(obj)
		else:
			if not override:
				raise FileObjError(f"Object '{name}' already exists.")
			if len(oldObj.getData()) != len(obj.getData()):
				raise FileObjError(f"Object '{name}' exists, but length differs.")
			obj.setIndex(oldObj.getIndex())
			obj.setRawOffset(oldObj.getRawOffset())
		self.__objects[name] = obj

	@classmethod
	def parseRaw(cls, raw):
		assert isinstance(raw, (bytes, bytearray, memoryview)),\
		       "FileObjCollection: Invalid 'raw' type."
		raw = memoryview(raw)
		offset = 0
		objects = []
		while offset < len(raw):
			obj, objLen = FileObj.parseRaw(raw[offset:])
			objects.append(obj)
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

	def __len__(self):
		return len(self.__objects)
