# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import os

__all__ = [
	"getDefaultDatabase",
	"PWManEntry",
]

def getDefaultDatabase():
	db = os.getenv("PWMAN_DATABASE")
	if db:
		return db
	home = os.getenv("HOME")
	if home:
		return home + "/.pwman.db"
	return None

class PWManEntry(object):
	Undefined = None

	def __init__(self,
		     category,
		     title,
		     user=Undefined,
		     pw=Undefined,
		     bulk=Undefined):
		self.category = category
		self.title = title
		self.user = user
		self.pw = pw
		self.bulk = bulk

	def copyUndefined(self, fromEntry):
		assert(self.category is not self.Undefined)
		assert(self.title is not self.Undefined)
		if self.user is self.Undefined:
			self.user = fromEntry.user
		if self.pw is self.Undefined:
			self.pw = fromEntry.pw
		if self.bulk is self.Undefined:
			self.bulk = fromEntry.bulk

	def dump(self):
		res = []
		res.append("===  %s  ===" % self.category)
		res.append("\t---  %s  ---" % self.title)
		if self.user:
			res.append("\tUser:\t\t%s" % self.user)
		if self.pw:
			res.append("\tPassword:\t%s" % self.pw)
		if self.bulk:
			res.append("\tBulk data:\t%s" % self.bulk)
		return "\n".join(res) + "\n"
