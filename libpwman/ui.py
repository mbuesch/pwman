# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.database import *
from libpwman.exception import *
from libpwman.otp import *
from libpwman.undo import *
from libpwman.util import *

import sys
import time
import re
import readline
import signal
from copy import copy, deepcopy
from cmd import Cmd

__all__ = [
	"PWMan",
	"PWManTimeout",
]

class EscapeError(Exception):
	pass

def escapeCmd(s):
	# Commandline escape
	if s is None:
		return "\\-"
	if not s:
		return "\\~"
	subst = {
		'\t'	: '\\t',
		'\n'	: '\\n',
		'\\'	: '\\\\',
		' '	: '\\ ',
	}
	ret = []
	for c in s:
		try:
			c = subst[c]
		except (KeyError) as e:
			if c.isspace():
				c = '\\x%02X' % ord(c)
		ret.append(c)
	return "".join(ret)

def unescapeCmd(s):
	# Commandline unescape
	if s == '\\-':
		return None
	if s == '\\~':
		return ""
	slashSubst = {
		't'	: '\t',
		'n'	: '\n',
		'\\'	: '\\',
	}
	ret = []
	i = 0
	while i < len(s):
		if s[i] == '\\':
			try:
				if s[i + 1] == 'x':
					ret.append(chr(int(s[i + 2 : i + 4], 16)))
					i += 3
				elif s[i + 1] == ' ':
					ret.append(' ')
					i += 1
				else:
					ret.append(slashSubst[s[i + 1]])
					i += 1
			except (IndexError, ValueError, KeyError):
				raise EscapeError("Invalid backslash escape sequence "
					"at character %d" % i)
		else:
			ret.append(s[i])
		i += 1
	return "".join(ret)

class PWManTimeout(Exception):
	def __init__(self, seconds):
		self.seconds = seconds
		if seconds > 0:
			signal.signal(signal.SIGALRM, self.__timeout)
			self.poke()

	def poke(self):
		if self.seconds > 0:
			signal.alarm(self.seconds)

	def __timeout(self, signum, frame):
		raise self

class PWMan(Cmd):
	class CommandError(Exception): pass
	class Quit(Exception): pass

	def __init__(self, filename, passphrase,
		     commitClearsUndo=False, timeout=-1):
		super().__init__()

		self.__db = PWManDatabase(filename, passphrase)
		self.prompt = "pwman$ "

		self.__timeout = PWManTimeout(timeout)
		self.__commitClearsUndo = commitClearsUndo
		self.__undo = UndoStack()

	def __err(self, source, message):
		source = " " + source + ":" if source else ""
		raise self.CommandError("***%s %s" % (source, message))

	def __info(self, source, message):
		source = " " + source + ":" if source else ""
		print("+++%s %s\n" % (source, message))

	def precmd(self, line):
		self.__timeout.poke()
		first = self.__getParam(line, 0, unescape=False)
		if first.endswith('?'):
			return "help %s" % first[:-1]
		return line

	def postcmd(self, stop, line):
		self.__timeout.poke()

	def default(self, line):
		self.__err(None, "Unknown command: %s\nType 'help' for more help." % line)

	def emptyline(self):
		self.__timeout.poke()
		# Don't repeat the last command

	def __dumpEntry(self, entry):
		res = []
		res.append("===  %s  ===" % entry.category)
		res.append("\t---  %s  ---" % entry.title)
		if entry.user:
			res.append("\tUser:\t\t%s" % entry.user)
		if entry.pw:
			res.append("\tPassword:\t%s" % entry.pw)
		if entry.bulk:
			res.append("\tBulk data:\t%s" % entry.bulk)
		entryTotp = self.__db.getEntryTotp(entry)
		if entryTotp:
			res.append("\tTOTP:\t\tavailable")
		entryAttrs = self.__db.getEntryAttrs(entry)
		if entryAttrs:
			res.append("\tAttributes:")
			for entryAttr in entryAttrs:
				res.append("\t\t%s:\t%s" % (entryAttr.name,
							    entryAttr.data))
		return "\n".join(res) + "\n"

	def __complete_category_title(self, text, line, begidx, endidx):
		# Generic [category] [title] completion
		self.__timeout.poke()
		paramIdx = self.__calcParamIndex(line, endidx)
		text = self.__getParam(line, paramIdx, ignoreFirst=True)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, ignoreFirst=True),
							       text)
		return []

	cmdHelpMisc = (
		("help", ("h",), "Show help about commands"),
		("quit", ("q", "exit", "^D"), "Quit pwman"),
		("cls", (), "Clear screen and undo buffers"),
	)

	cmdHelpDatabase = (
		("commit", ("c", "w"), "Commit / write database file"),
		("masterp", (), "Change the master passphrase"),
	)

	cmdHelpShow = (
		("list", ("ls", "cat"), "List/print entry contents"),
		("find", ("f",), "Search the database for patterns"),
		("totp", ("t",), "Generate TOTP token"),
		("totp_key", ("tk",), "Show TOTP key and parameters"),
		("dbdump", (), "Dump the database"),
	)

	cmdHelpEdit = (
		("new", ("n", "add"), "Create new entry"),
		("edit_user", ("eu",), "Edit the 'user' field of an entry"),
		("edit_pw", ("ep",), "Edit the 'password' field of an entry"),
		("edit_bulk", ("eb",), "Edit the 'bulk' field of an entry"),
		("edit_totp", ("et",), "Edit the TOTP key and parameters"),
		("edit_attr", ("ea",), "Edit an entry attribute"),
		("move", ("mv", "rename"), "Move/rename and existing entry"),
		("remove", ("rm", "del"), "Remove and existing entry"),
	)

	cmdHelpHist = (
		("undo", (), "Undo the last command"),
		("redo", (), "Redo the last undone command"),
	)

	def do_help(self, params):
		"""--- Shows help text about a command ---\n
		Command: help\n
		Aliases: h"""
		if params:
			super().do_help(params)
			return
		def printCmdHelp(cmdHelp):
			for cmd, aliases, desc in cmdHelp:
				spc = " " * (10 - len(cmd))
				msg = "  %s%s%s" % (cmd, spc, desc)
				if aliases:
					msg += " " * (51 - len(msg))
					msg += " Alias%s: %s" %\
					("es" if len(aliases) > 1 else "",
					", ".join(aliases))
				print(msg)
		print("Misc commands:")
		printCmdHelp(self.cmdHelpMisc)
		print("\nDatabase commands:")
		printCmdHelp(self.cmdHelpDatabase)
		print("\nSearching/listing commands:")
		printCmdHelp(self.cmdHelpShow)
		print("\nEditing commands:")
		printCmdHelp(self.cmdHelpEdit)
		print("\nHistory commands:")
		printCmdHelp(self.cmdHelpHist)
		print("\nType 'command?' or 'help command' for more help on a command.")
	do_h = do_help

	def do_quit(self, params):
		"""--- Exit pwman ---
		Command: quit [!]\n
		Use the exclamation mark to force quit and discard changes.\n
		Aliases: q exit ^D"""
		if params == "!":
			self.__db.flunkDirty()
		raise self.Quit()
	do_q = do_quit
	do_exit = do_quit
	do_EOF = do_quit

	def do_cls(self, params):
		"""--- Clear console screen and undo/redo buffer ---
		Command: cls\n
		Clear the console screen and all undo/redo buffers.
		Note that this does not clear a possibly existing
		'screen' session buffer or other advanced console buffers.\n
		Aliases: None"""
		clearScreen()
		self.__undo.clear()

	def do_commit(self, params):
		"""--- Write changes to the database file ---\n
		Command: commit\n
		Aliases: c w"""
		self.__db.commit()
		if self.__commitClearsUndo:
			self.__undo.clear()
	do_c = do_commit
	do_w = do_commit

	def do_masterp(self, params):
		"""--- Change the master passphrase ---\n
		Command: masterp\n
		Aliases: None"""
		p = readPassphrase("Current master passphrase")
		if p != self.__db.getPassphrase():
			stdout("Passphrase mismatch! ")
			for i in range(3):
				stdout(".")
				time.sleep(0.5)
			print("")
			return
		p = readPassphrase("Master passphrase", verify=True)
		if p is None:
			print("Passphrase not changed.")
			return
		if p != self.__db.getPassphrase():
			self.__db.setPassphrase(p)
			self.__undo.clear()

	def do_list(self, params):
		"""--- Print a listing ---
		Command: list [category] [title]\n
		If a category is given as parameter, list the 
		contents of the category. If category and entry
		are given, list the contents of the entry.\n
		Aliases: ls cat"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category and not title:
			stdout("Categories:\n\t")
			stdout("\n\t".join(self.__db.getCategoryNames()) + "\n")
		elif category and not title:
			stdout("Entries in category '%s':\n\t" % category)
			stdout("\n\t".join(self.__db.getEntryTitles(category)) + "\n")
		elif category and title:
			entry = self.__db.getEntry(PWManEntry(category, title))
			if entry:
				stdout(self.__dumpEntry(entry))
			else:
				self.__err("list", "'%s/%s' not found" % (category, title))
		else:
			self.__err("list", "Invalid parameter")
	do_ls = do_list
	do_cat = do_list

	complete_list = __complete_category_title
	complete_ls = complete_list
	complete_cat = complete_list

	def do_new(self, params):
		"""--- Create a new entry ---
		Command: new [category] [title] [user] [password] [bulk-data]\n
		Create a new database entry. If no parameters are given,
		they are asked for interactively.\n
		Aliases: n add"""
		if params:
			category = self.__getParam(params, 0)
			title = self.__getParam(params, 1)
			user = self.__getParam(params, 2)
			pw = self.__getParam(params, 3)
			bulk = self.__getParam(params, 4)
		else:
			stdout("Create new entry:\n")
			category = input("\tCategory: ")
			title = input("\tEntry title: ")
			user = input("\tUsername: ")
			pw = input("\tPassword: ")
			bulk = input("\tBulk data: ")
		if not category or not title:
			self.__err("new", "Invalid parameters. "
				"Need to supply category and title.")
		entry = PWManEntry(category, title, user, pw, bulk)
		try:
			self.__db.addEntry(entry)
		except (PWManError) as e:
			self.__err("new", str(e))
		self.__undo.do("new %s" % params,
			       "remove %s %s" % (escapeCmd(category), escapeCmd(title)))
	do_n = do_new
	do_add = do_new

	complete_new = __complete_category_title
	complete_n = complete_new
	complete_add = complete_new

	def __do_edit_generic(self, params, commandName,
			      entry2data, data2entry):
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category or not title:
			self.__err(commandName, "Invalid parameters. "
				"Need to supply category and title.")
		oldEntry = self.__db.getEntry(PWManEntry(category, title))
		if not oldEntry:
			self.__err(commandName, "Entry does not exist")
		newData = self.__skipParams(params, 2).strip()
		try:
			self.__db.editEntry(data2entry(category, title, newData))
		except (PWManError) as e:
			self.__err(commandName, str(e))
		self.__undo.do("%s %s" % (commandName, params),
			       "%s %s %s %s" %\
			       (commandName, escapeCmd(oldEntry.category),
				escapeCmd(oldEntry.title),
				escapeCmd(entry2data(oldEntry))))

	def do_edit_user(self, params):
		"""--- Edit the 'user' field of an existing entry ---
		Command: edit_user category title NEWDATA...\n
		Change the 'user' field of an existing database entry.
		NEWDATA is the new data to write into the 'user' field.
		The NEWDATA must _not_ be escaped (however, category and
		title must be escaped).\n
		Aliases: eu"""
		self.__do_edit_generic(params, "edit_user",
			lambda entry: entry.user,
			lambda cat, tit, data: PWManEntry(cat, tit, user=data))
	do_eu = do_edit_user

	def complete_edit_user(self, text, line, begidx, endidx):
		self.__timeout.poke()
		paramIdx = self.__calcParamIndex(line, endidx)
		text = self.__getParam(line, paramIdx, ignoreFirst=True)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, ignoreFirst=True),
							       text)
		elif paramIdx == 2:
			# User data
			entry = self.__db.getEntry(PWManEntry(self.__getParam(line, 0, ignoreFirst=True),
							      self.__getParam(line, 1, ignoreFirst=True)))
			return [ escapeCmd(entry.user) ]
		return []
	complete_eu = complete_edit_user

	def do_edit_pw(self, params):
		"""--- Edit the 'password' field of an existing entry ---
		Command: edit_pw category title NEWDATA...\n
		Change the 'password' field of an existing database entry.
		NEWDATA is the new data to write into the 'password' field.
		The NEWDATA must _not_ be escaped (however, category and
		title must be escaped).\n
		Aliases: ep"""
		self.__do_edit_generic(params, "edit_pw",
			lambda entry: entry.pw,
			lambda cat, tit, data: PWManEntry(cat, tit, pw=data))
	do_ep = do_edit_pw

	def complete_edit_pw(self, text, line, begidx, endidx):
		self.__timeout.poke()
		paramIdx = self.__calcParamIndex(line, endidx)
		text = self.__getParam(line, paramIdx, ignoreFirst=True)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, ignoreFirst=True),
							       text)
		elif paramIdx == 2:
			# Password data
			entry = self.__db.getEntry(PWManEntry(self.__getParam(line, 0, ignoreFirst=True),
							      self.__getParam(line, 1, ignoreFirst=True)))
			return [ escapeCmd(entry.pw) ]
		return []
	complete_ep = complete_edit_pw

	def do_edit_bulk(self, params):
		"""--- Edit the 'bulk' field of an existing entry ---
		Command: edit_bulk category title NEWDATA...\n
		Change the 'bulk' field of an existing database entry.
		NEWDATA is the new data to write into the 'bulk' field.
		The NEWDATA must _not_ be escaped (however, category and
		title must be escaped).\n
		Aliases: eb"""
		self.__do_edit_generic(params, "edit_bulk",
			lambda entry: entry.bulk,
			lambda cat, tit, data: PWManEntry(cat, tit, bulk=data))
	do_eb = do_edit_bulk

	def complete_edit_bulk(self, text, line, begidx, endidx):
		self.__timeout.poke()
		paramIdx = self.__calcParamIndex(line, endidx)
		text = self.__getParam(line, paramIdx, ignoreFirst=True)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, ignoreFirst=True),
							       text)
		elif paramIdx == 2:
			# Bulk data
			entry = self.__db.getEntry(PWManEntry(self.__getParam(line, 0, ignoreFirst=True),
							      self.__getParam(line, 1, ignoreFirst=True)))
			return [ escapeCmd(entry.bulk) ]
		return []
	complete_eb = complete_edit_bulk

	def do_remove(self, params):
		"""--- Remove an existing entry ---
		Command: remove category title\n
		Remove an existing database entry.\n
		Aliases: rm del"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category or not title:
			self.__err("remove", "Invalid parameters. "
				"Need to supply category and title.")
		oldEntry = self.__db.getEntry(PWManEntry(category, title))
		if not oldEntry:
			self.__err("remove", "Entry does not exist")
		try:
			self.__db.delEntry(PWManEntry(category, title))
		except (PWManError) as e:
			self.__err("remove", str(e))
		self.__undo.do("remove %s" % params,
			       "new %s %s %s %s %s" %\
			       (escapeCmd(oldEntry.category), escapeCmd(oldEntry.title),
				escapeCmd(oldEntry.user), escapeCmd(oldEntry.pw),
				escapeCmd(oldEntry.bulk)))
	do_rm = do_remove
	do_del = do_remove

	complete_remove = __complete_category_title
	complete_rm = complete_remove
	complete_del = complete_remove

	def do_move(self, params):
		"""--- Move/rename an existing entry ---
		Command: move category title newCategory [newTitle]\n
		Move/rename an existing database entry.\n
		Aliases: mv rename"""
		fromCategory = self.__getParam(params, 0)
		fromTitle = self.__getParam(params, 1)
		toCategory = self.__getParam(params, 2)
		toTitle = self.__getParam(params, 3)
		if not fromCategory or not fromTitle or not toCategory:
			self.__err("remove", "Invalid parameters. "
				"Need to supply category, title and newCategory.")
		if not toTitle:
			toTitle = fromTitle
		if fromCategory == toCategory and fromTitle == toTitle:
			self.__info("move", "Nothing changed. Not moving anything.")
			return
		oldEntry = self.__db.getEntry(PWManEntry(fromCategory, fromTitle))
		if not oldEntry:
			self.__err("move", "Source entry does not exist.")
		newEntry = deepcopy(oldEntry)
		newEntry.category = toCategory
		newEntry.title = toTitle
		try:
			self.__db.addEntry(newEntry)
		except (PWManError) as e:
			self.__err("move", str(e))
		try:
			self.__db.delEntry(oldEntry)
		except (PWManError) as e:
			self.__info("move", str(e))
		self.__undo.do("move %s" % params,
			       "move %s %s %s %s" % (
			       escapeCmd(newEntry.category), escapeCmd(newEntry.title),
			       escapeCmd(oldEntry.category), escapeCmd(oldEntry.title)))
	do_mv = do_move
	do_rename = do_move

	complete_move = __complete_category_title
	complete_mv = complete_move
	complete_rename = complete_move

	def do_dbdump(self, params):
		"""--- Dump the SQL database as SQL script ---
		Command: dbdump [filepath]\n
		If filepath is given, the database is dumped
		unencrypted to the file.
		If filepath is omitted, the database is dumped
		unencrypted to stdout.\n
		Aliases: None"""
		try:
			dump = self.__db.sqlPlainDump() + b"\n"
			if params:
				with open(params, "wb") as f:
					f.write(dump)
			else:
				stdout(dump)
		except (IOError) as e:
			self.__err("dbdump", "Failed to write dump: %s" % e.strerror)

	def do_find(self, params):
		"""--- Search the database ---
		Command: find [OPTS] [category] PATTERN\n
		Searches the database for patterns. If 'category' is given, only search
		in the specified category. PATTERN may use unix globbing wildcards.\n
		OPTS may be one or multiple of:
		  -t   Only match 'title'
		  -u   Only match 'user'
		  -p   Only match 'password'
		  -b   Only match 'bulk'\n
		Aliases: f"""
		(p, i) = ([], 0)
		(mTitle, mUser, mPw, mBulk) = (False,) * 4
		while True:
			param = self.__getParam(params, i)
			if not param:
				break
			if param == "-t":
				mTitle = True
			elif param == "-u":
				mUser = True
			elif param == "-p":
				mPw = True
			elif param == "-b":
				mBulk = True
			else:
				p.append(param)
			i += 1
		if len(p) <= 0 or len(p) > 2:
			self.__err("find", "Invalid parameters.")
		category = p[0] if len(p) > 1 else None
		pattern = p[1] if len(p) > 1 else p[0]
		if not any( (mTitle, mUser, mPw, mBulk) ):
			(mTitle, mUser, mPw, mBulk) = (True,) * 4
		entries = self.__db.findEntries(pattern, inCategory=category,
						matchTitle=mTitle, matchUser=mUser,
						matchPw=mPw, matchBulk=mBulk,
						doGlobMatch=True)
		if not entries:
			self.__err("find", "'%s' not found" % pattern)
		for entry in entries:
			stdout(self.__dumpEntry(entry) + "\n\n")
	do_f = do_find

	def complete_find(self, text, line, begidx, endidx):
		self.__timeout.poke()
		paramIdx = self.__calcParamIndex(line, endidx)
		text = self.__getParam(line, paramIdx, ignoreFirst=True)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		return []
	complete_f = complete_find

	def do_totp(self, params):
		"""--- Generate a TOTP token ---
		Command: totp category title\n
		Generates a token using the Time-Based One-Time Password Algorithm.\n
		Aliases: t"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category:
			self.__err("totp", "Category parameter is required.")
		if not title:
			self.__err("totp", "Title parameter is required.")
		entry = self.__db.getEntry(PWManEntry(category, title))
		if not entry:
			self.__err("totp", "'%s/%s' not found" % (category, title))
		entryTotp = self.__db.getEntryTotp(entry)
		if not entryTotp:
			self.__err("totp", "'%s/%s' does not have "
				   "TOTP key information" % (category, title))
		try:
			token = totp(key=entryTotp.key,
				     nrDigits=entryTotp.digits,
				     hmacHash=entryTotp.hmacHash)
		except OtpError as e:
			self.__err("totp", "Failed to generate TOTP: %s" % str(e))
		stdout("%s\n" % token)
	do_t = do_totp

	complete_totp = __complete_category_title
	complete_t = complete_totp

	def do_totp_key(self, params):
		"""--- Show TOTP key and parameters ---
		Command: totp_key category title\n
		Show Time-Based One-Time Password Algorithm key and parameters.\n
		Aliases: tk"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category:
			self.__err("totp_key", "Category parameter is required.")
		if not title:
			self.__err("totp_key", "Title parameter is required.")
		entry = self.__db.getEntry(PWManEntry(category, title))
		if not entry:
			self.__err("totp_key", "'%s/%s' not found" % (category, title))
		entryTotp = self.__db.getEntryTotp(entry)
		enc = "  (base32 encoding)"
		if not entryTotp:
			entryTotp = PWManEntryTOTP(key="--- none ---",
						   digits=6,
						   hmacHash="SHA1")
			enc = ""
		stdout("TOTP key:     %s%s\n" % (entryTotp.key, enc))
		stdout("TOTP digits:  %d\n" % entryTotp.digits)
		stdout("TOTP hash:    %s\n" % entryTotp.hmacHash)
	do_tk = do_totp_key

	complete_totp_key = __complete_category_title
	complete_tk = complete_totp_key

	def do_edit_totp(self, params):
		"""--- Edit TOTP key and parameters ---
		Command: edit_totp category title [KEY] [DIGITS] [HASH]\n
		Set Time-Based One-Time Password Algorithm key and parameters.\n
		Aliases: et"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		key = self.__getParam(params, 2)
		digits = self.__getParam(params, 3)
		_hash = self.__getParam(params, 4)
		if not category:
			self.__err("edit_totp", "Category parameter is required.")
		if not title:
			self.__err("edit_totp", "Title parameter is required.")
		entry = self.__db.getEntry(PWManEntry(category, title))
		if not entry:
			self.__err("edit_totp", "'%s/%s' not found" % (category, title))
		entryTotp = self.__db.getEntryTotp(entry)
		if not entryTotp:
			entryTotp = PWManEntryTOTP(key=None, entry=entry)
		origEntryTotp = deepcopy(entryTotp)
		entryTotp.key = key
		if digits:
			try:
				entryTotp.digits = int(digits)
			except ValueError:
				self.__err("edit_totp", "Invalid digits parameter.")
		if _hash:
			entryTotp.hmacHash = _hash
		self.__db.setEntryTotp(entryTotp)
		self.__undo.do("edit_totp %s" % params,
			       "edit_totp %s %s %s %s %s" % (
			       escapeCmd(category),
			       escapeCmd(title),
			       escapeCmd(origEntryTotp.key or ""),
			       escapeCmd(("%d" % origEntryTotp.digits) if origEntryTotp.digits else ""),
			       escapeCmd(origEntryTotp.hmacHash or "")))
	do_et = do_edit_totp

	def complete_edit_totp(self, text, line, begidx, endidx):
		self.__timeout.poke()
		paramIdx = self.__calcParamIndex(line, endidx)
		if paramIdx in (0, 1):
			return self.__complete_category_title(text, line, begidx, endidx)
		category = self.__getParam(line, 0, ignoreFirst=True)
		title = self.__getParam(line, 1, ignoreFirst=True)
		if category and title:
			entry = self.__db.getEntry(PWManEntry(category, title))
			if entry:
				entryTotp = self.__db.getEntryTotp(entry)
				if entryTotp:
					if paramIdx == 2: # key
						return [ escapeCmd(entryTotp.key) + " " ]
					elif paramIdx == 3: # digits
						return [ escapeCmd(str(entryTotp.digits)) + " " ]
					elif paramIdx == 4: # hash
						return [ escapeCmd(entryTotp.hmacHash) + " " ]
		return []
	complete_et = complete_edit_totp

	def do_edit_attr(self, params):
		"""--- Edit an entry attribute ---
		Command: edit_attr category title NAME [DATA]\n
		Edit or delete an entry attribute.\n
		Aliases: ea"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		name = self.__getParam(params, 2)
		data = self.__getParam(params, 3)
		if not category:
			self.__err("edit_attr", "Category parameter is required.")
		if not title:
			self.__err("edit_attr", "Title parameter is required.")
		entry = self.__db.getEntry(PWManEntry(category, title))
		if not entry:
			self.__err("edit_attr", "'%s/%s' not found" % (category, title))
		entryAttr = self.__db.getEntryAttr(entry, name)
		if not entryAttr:
			entryAttr = PWManEntryAttr(name=name, entry=entry)
		origEntryAttr = deepcopy(entryAttr)
		entryAttr.data = data
		self.__db.setEntryAttr(entryAttr)
		self.__undo.do("edit_attr %s" % params,
			       "edit_attr %s %s %s %s" % (
			       escapeCmd(category),
			       escapeCmd(title),
			       escapeCmd(origEntryAttr.name or ""),
			       escapeCmd(origEntryAttr.data or "")))
	do_ea = do_edit_attr

	def complete_edit_attr(self, text, line, begidx, endidx):
		self.__timeout.poke()
		paramIdx = self.__calcParamIndex(line, endidx)
		if paramIdx in (0, 1):
			return self.__complete_category_title(text, line, begidx, endidx)
		category = self.__getParam(line, 0, ignoreFirst=True)
		title = self.__getParam(line, 1, ignoreFirst=True)
		name = self.__getParam(line, 2, ignoreFirst=True)
		if category and title:
			entry = self.__db.getEntry(PWManEntry(category, title))
			if entry:
				if paramIdx == 2: # name
					entryAttrs = self.__db.getEntryAttrs(entry)
					if entryAttrs:
						return [ escapeCmd(entryAttr.name) + " "
							 for entryAttr in entryAttrs ]
				elif paramIdx == 3: # data
					entryAttr = self.__db.getEntryAttr(entry, name)
					if entryAttr:
						return [ escapeCmd(entryAttr.data) + " " ]
		return []
	complete_ea = complete_edit_attr

	def do_undo(self, params):
		"""--- Undo the last command ---
		Command: undo\n
		Rewinds the last command that changed the database.\n
		Aliases: None"""
		cmd = self.__undo.undo()
		if not cmd:
			self.__err("undo", "There is no command to be undone.")
		self.__undo.freeze()
		try:
			for undoCommand in cmd.undoCommands:
				self.onecmd(undoCommand)
		finally:
			self.__undo.thaw()
		self.__info("undo",
			    "; ".join(cmd.doCommands) + "\nsuccessfully undone with\n" +\
			    "; ".join(cmd.undoCommands))

	def do_redo(self, params):
		"""--- Redo the last undone command ---
		Command: redo\n
		Redoes the last undone command.
		Also see 'undo' help.\n
		Aliases: None"""
		cmd = self.__undo.redo()
		if not cmd:
			self.__err("redo", "There is no undone command to be redone.")
		self.__undo.freeze()
		try:
			for doCommand in cmd.doCommands:
				self.onecmd(doCommand)
		finally:
			self.__undo.thaw()
		self.__info("redo",
			    "; ".join(cmd.undoCommands) + "\nsuccessfully redone with\n" +\
			    "; ".join(cmd.doCommands))

	def __skipParams(self, line, count,
			 lineIncludesCommand=False, unescape=True):
		# Return a parameter string with the first 'count'
		# parameters skipped.
		sline = self.__sanitizeCmdline(line)
		if lineIncludesCommand:
			count += 1
		i = 0
		while i < len(sline) and count > 0:
			while i < len(sline) and not sline[i].isspace():
				i += 1
			while i < len(sline) and sline[i].isspace():
				i += 1
			count -= 1
		if i >= len(sline):
			return ""
		s = line[i:]
		if unescape:
			s = unescapeCmd(s)
		return s

	def __calcParamIndex(self, line, endidx):
		# Returns the parameter index into the commandline
		# given the character end-index. This honors space-escape.
		line = self.__sanitizeCmdline(line)
		startidx = endidx - 1
		while startidx > 0 and not line[startidx].isspace():
			startidx -= 1
		return len([l for l in line[:startidx].split() if l]) - 1

	def __sanitizeCmdline(self, line):
		# Sanitize a commandline for simple whitespace based splitting.
		# We just replace the space escape sequence by a random
		# non-whitespace string. The line remains the same size.
		return line.replace('\\ ', '_S')

	def __getParam(self, line, paramIndex,
		       ignoreFirst=False, unescape=True):
		# Returns the full parameter from the commandline
		sline = self.__sanitizeCmdline(line)
		if ignoreFirst:
			paramIndex += 1
		inParam = False
		idx = 0
		for startIndex, c in enumerate(sline):
			if c.isspace():
				if inParam:
					idx += 1
				inParam = False
			else:
				inParam = True
				if idx == paramIndex:
					break
		else:
			return ""
		endIndex = startIndex
		while endIndex < len(sline) and not sline[endIndex].isspace():
			endIndex += 1
		p = line[startIndex : endIndex]
		if unescape:
			p = unescapeCmd(p)
		return p

	def __getCategoryCompletions(self, text):
		catNames = [n for n in self.__db.getCategoryNames() if n.lower().startswith(text.lower())]
		return [escapeCmd(n) + " " for n in catNames]

	def __getEntryTitleCompletions(self, category, text):
		titles = [t for t in self.__db.getEntryTitles(category) if t.lower().startswith(text.lower())]
		return [escapeCmd(t) + " " for t in titles]

	def __mayQuit(self):
		if self.__db.isDirty():
			print("Warning: Uncommitted changes. " \
				"Operation not performed. Use command 'commit' " \
				"to write the changes to the database. Use " \
				"command 'quit!' to quit without saving.")
			return False
		return True

	def flunkDirty(self):
		self.__db.flunkDirty()

	def interactive(self):
		while True:
			try:
				self.cmdloop()
				break
			except (self.Quit) as e:
				if self.__mayQuit():
					self.do_cls("")
					break
			except (EscapeError, self.CommandError) as e:
				stdout(str(e) + "\n")
			except (KeyboardInterrupt, EOFError) as e:
				stdout("\n")
			except (CSQLError) as e:
				stdout("SQL error: %s\n" % str(e))

	def runOneCommand(self, command):
		try:
			self.onecmd(command)
		except (EscapeError, self.CommandError) as e:
			raise PWManError(str(e))
		except (KeyboardInterrupt, EOFError) as e:
			raise PWManError("Interrupted")
		except (CSQLError) as e:
			raise PWManError("SQL error: %s" % str(e))
