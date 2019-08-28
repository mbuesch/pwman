# -*- coding: utf-8 -*-
"""
# Simple object file format.
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
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
			raise FileObjError("FileObj: Name too long")
		self.__name = name
		if len(data) > 0xFFFFFFFF:
			raise FileObjError("FileObj: Data too long")
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

	@classmethod
	def parseRaw(cls, raw):
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
			raise FileObjError("Failed to parse file object")
		return (cls(name, data),
			off)

class FileObjCollection(object):
	def __init__(self, *objects):
		self.objects = objects

	def writeFile(self, filepath):
		try:
			with open(filepath, "wb") as f:
				f.write(self.getRaw())
				f.flush()
		except IOError as e:
			raise FileObjError("Failed to write file: %s" %
					   e.strerror)

	def getRaw(self):
		raw = bytearray()
		for obj in self.objects:
			raw += obj.getRaw()
		return raw

	def get(self, name):
		return [ o.getData()
			 for o in self.objects
			 if o.getName() == name ]

	def getOne(self, name, errorMsg=None, default=None):
		objs = self.get(name)
		if len(objs) != 1:
			if errorMsg:
				raise FileObjError(errorMsg)
			return default
		return objs[0]

	@classmethod
	def parseRaw(cls, raw):
		assert isinstance(raw, (bytes, bytearray)),\
		       "FileObjCollection: Invalid 'raw' type."
		offset = 0
		objects = []
		while offset < len(raw):
			(obj, objLen) = FileObj.parseRaw(raw[offset:])
			objects.append(obj)
			offset += objLen
		return cls(*objects)

	@classmethod
	def parseFile(cls, filepath):
		try:
			with open(filepath, "rb") as f:
				rawData = f.read()
		except (IOError) as e:
			if e.errno != errno.ENOENT:
				raise FileObjError("Failed to read file: %s" %\
						   e.strerror)
			return None
		return cls.parseRaw(rawData)
