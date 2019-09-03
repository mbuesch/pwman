# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

from libpwman.database import *
from libpwman.dbdiff import *
from libpwman.exception import *
from libpwman.otp import *
from libpwman.undo import *
from libpwman.util import *

import functools
import os
import pathlib
import re
import readline
import sys
import time
import traceback
from copy import copy, deepcopy
from cmd import Cmd
from dataclasses import dataclass, field

if osIsPosix:
	import signal

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
		if seconds is not None and seconds >= 0:
			self.seconds = seconds
			if osIsPosix:
				signal.signal(signal.SIGALRM, self.__timeout)
				self.poke()
			else:
				raise PWManError("Timeout is not supported on this OS.")
		else:
			self.seconds = None

	def poke(self):
		if self.seconds is not None:
			signal.alarm(self.seconds)

	def __timeout(self, signum, frame):
		raise self

# PWMan completion decorator that does common things and workarounds.
def completion(func):
	@functools.wraps(func)
	def wrapper(self, text, line, begidx, endidx):
		try:
			self._timeout.poke()

			# Find the real begidx that takes space escapes into account.
			sline = self._patchSpaceEscapes(line)
			realBegidx = endidx
			while realBegidx > 0:
				if sline[realBegidx - 1] == " ":
					break
				realBegidx -= 1

			if begidx == realBegidx:
				textPrefix = ""
			else:
				# Workaround: Patch the begidx to fully
				# honor all escapes. Remember the text
				# between the real begidx and the orig begidx.
				# It must be removed from the results.
				textPrefix = line[realBegidx : begidx]
				begidx = realBegidx

			# Fixup text.
			# By fetching the parameter again it is ensured that
			# it is properly unescaped.
			paramIdx = self._calcParamIndex(line, endidx)
			text = self._getComplParam(line, paramIdx)

			# Call the PWMan completion handler.
			completions = func(self, text, line, begidx, endidx)

			# If we fixed begidx in the workaround above,
			# we need to remove the additional prefix from the results,
			# because Cmd/readline won't expect it.
			if textPrefix:
				for i, comp in enumerate(copy(completions)):
					if comp.startswith(textPrefix):
						completions[i] = comp[len(textPrefix) : ]
			return completions
		except (EscapeError, CSQLError, PWManError, PWManTimeout) as e:
			return []
		except Exception as e:
			print("\nException in completion handler:\n\n%s" % (
			      traceback.format_exc()),
			      file=sys.stderr)
			return []
	return wrapper

class PWManMeta(type):
	def __new__(cls, name, bases, dct):
		for name, attr in dct.items():
			# Fixup command docstrings.
			if (name.startswith("do_") and
			    not getattr(attr, "_pwman_fixed", False) and
			    attr.__doc__):
				# Remove leading double-tabs.
				attr.__doc__, n = re.subn("^\t\t", "\t", attr.__doc__,
							  0, re.MULTILINE)
				# Tabs to spaces.
				attr.__doc__, n = re.subn("\t", " " * 8, attr.__doc__,
							  0, re.MULTILINE)
				attr._pwman_fixed = True
		return super().__new__(cls, name, bases, dct)

class PWMan(Cmd, metaclass=PWManMeta):
	class CommandError(Exception): pass
	class Quit(Exception): pass

	def __init__(self, filename, passphrase,
		     commitClearsUndo=False, timeout=None):
		super().__init__()

		if sys.flags.optimize >= 2:
			# We need docstrings.
			raise PWManError("pwman does not support "
					 "Python optimization level 2 (-OO). "
					 "Please call with python3 -O or less.")

		# argument delimiter shall be space.
		readline.set_completer_delims(" ")

		self.__db = PWManDatabase(filename, passphrase, readOnly=False)
		self.__updatePrompt()

		self._timeout = PWManTimeout(timeout)
		self.__commitClearsUndo = commitClearsUndo
		self.__undo = UndoStack()

	def __updatePrompt(self):
		if self.__db.isDirty():
			self.prompt = "*pwman$ "
		else:
			self.prompt = "pwman$ "

	def __err(self, source, message):
		source = (" " + source + ":") if source else ""
		raise self.CommandError("***%s %s" % (source, message))

	def __warn(self, source, message):
		source = (" " + source + ":") if source else ""
		print("***%s %s" % (source, message))

	def __info(self, source, message):
		source = ("+++ " + source + ": ") if source else ""
		print("%s%s" % (source, message))

	def precmd(self, line):
		self._timeout.poke()
		first = self._getParam(line, 0, unescape=False)
		if first.endswith('?'):
			return "help %s" % first[:-1]
		return line

	def postcmd(self, stop, line):
		self.__updatePrompt()
		self._timeout.poke()

	def default(self, line):
		self.__err(None,
			   "Unknown command: %s\n"
			   "Type 'help' for more help." % line)

	def emptyline(self):
		self._timeout.poke()
		# Don't repeat the last command

	@completion
	def __complete_category_title(self, text, line, begidx, endidx):
		# Generic [category] [title] completion
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self._getComplParam(line, 0),
							       text)
		return []

	def __getCategoryCompletions(self, text):
		return [ escapeCmd(n) + " "
			 for n in self.__db.getCategoryNames()
			 if n.lower().startswith(text.lower()) ]

	def __getEntryTitleCompletions(self, category, text):
		return [ escapeCmd(t) + " "
			 for t in self.__db.getEntryTitles(category)
			 if t.lower().startswith(text.lower()) ]

	def __getPathCompletions(self, text):
		"""Return an escaped file system path completion.
		'text' is the unescaped partial path string.
		"""
		try:
			path = pathlib.Path(text)
			trailingChar = text[-1] if text else ""
			sep = os.path.sep
			base = path.parts[-1] if path.parts else ""
			dirPath = pathlib.Path(*path.parts[:-1])
			dirPathListing = [ f for f in dirPath.iterdir()
					   if f.parts[-1].startswith(base) ]
			if (path.is_dir() and
			    (trailingChar in (sep, "/", "\\") or
			     len(dirPathListing) <= 1)):
				# path is an unambiguous directory.
				# Show its contents.
				useListing = path.iterdir()
			else:
				# path is a file or an ambiguous directory.
				# Show the alternatives.
				useListing = dirPathListing
			return [ escapeCmd(str(f)) + (escapeCmd(sep) if f.is_dir() else " ")
				 for f in useListing ]
		except OSError:
			pass
		return []

	cmdHelpShow = (
		("list", ("ls", "cat"), "List/print entry contents"),
		("find", ("f",), "Search the database for patterns"),
		("totp", ("t",), "Generate TOTP token"),
		("totp_key", ("tk",), "Show TOTP key and parameters"),
		("diff", (), "Show the database differences"),
	)

	cmdHelpEdit = (
		("new", ("n", "add"), "Create new entry"),
		("edit_user", ("eu",), "Edit the 'user' field of an entry"),
		("edit_pw", ("ep",), "Edit the 'password' field of an entry"),
		("edit_bulk", ("eb",), "Edit the 'bulk' field of an entry"),
		("edit_totp", ("et",), "Edit the TOTP key and parameters"),
		("edit_attr", ("ea",), "Edit an entry attribute"),
		("move", ("mv", "rename"), "Move/rename an existing entry"),
		("remove", ("rm", "del"), "Remove an existing entry"),
		("undo", (), "Undo the last command"),
		("redo", (), "Redo the last undone command"),
	)

	cmdHelpDatabase = (
		("commit", ("c", "w"), "Commit/write database file"),
		("masterp", (), "Change the master passphrase"),
		("dbdump", (), "Dump the database"),
		("dbimport", (), "Import a database dump file"),
		("drop", (), "Drop all uncommitted changes"),
	)

	cmdHelpMisc = (
		("help", ("h",), "Show help about commands"),
		("quit", ("q", "exit", "^D"), "Quit pwman"),
		("cls", (), "Clear screen and undo buffers"),
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
				self.__info(None, msg)
		self.__info(None, "\nSearching/listing commands:")
		printCmdHelp(self.cmdHelpShow)
		self.__info(None, "\nEditing commands:")
		printCmdHelp(self.cmdHelpEdit)
		self.__info(None, "\nDatabase commands:")
		printCmdHelp(self.cmdHelpDatabase)
		self.__info(None, "\nMisc commands:")
		printCmdHelp(self.cmdHelpMisc)
		self.__info(None, "\nType 'command?' or 'help command' for more help on a command.")
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
			time.sleep(1)
			self.__warn(None, "Passphrase mismatch! ")
			return
		p = readPassphrase("Master passphrase", verify=True)
		if p is None:
			self.__info(None, "Passphrase not changed.")
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
		category, title = self._getParams(params, 0, 2)
		if not category and not title:
			self.__info(None, "Categories:")
			self.__info(None, "\t" + "\n\t".join(self.__db.getCategoryNames()))
		elif category and not title:
			self.__info(None, "Entries in category '%s':" % category)
			self.__info(None, "\t" + "\n\t".join(self.__db.getEntryTitles(category)))
		elif category and title:
			entry = self.__db.getEntry(category, title)
			if entry:
				self.__info(None, self.__db.dumpEntry(entry))
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
		Command: new [category] [title] [user] [password]\n
		Create a new database entry. If no parameters are given,
		they are asked for interactively.\n
		Aliases: n add"""
		if params:
			category, title, user, pw = self._getParams(params, 0, 4)
		else:
			self.__info("new", "Create new entry:")
			category = input("\tCategory: ")
			title = input("\tEntry title: ")
			user = input("\tUsername: ")
			pw = input("\tPassword: ")
		if not category or not title:
			self.__err("new", "Invalid parameters. "
				"Need to supply category and title.")
		entry = PWManEntry(category=category, title=title, user=user, pw=pw)
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

	def __do_edit_entry(self, params, commandName,
			    entry2data, data2entry):
		category, title = self._getParams(params, 0, 2)
		if not category or not title:
			self.__err(commandName, "Invalid parameters. "
				"Need to supply category and title.")
		oldEntry = self.__db.getEntry(category, title)
		if not oldEntry:
			self.__err(commandName, "Entry does not exist")
		newData = self._skipParams(params, 2).strip()
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
		self.__do_edit_entry(params, "edit_user",
			lambda entry: entry.user,
			lambda cat, tit, data: PWManEntry(cat, tit, user=data))
	do_eu = do_edit_user

	@completion
	def complete_edit_user(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self._getComplParam(line, 0),
							       text)
		elif paramIdx == 2:
			# User data
			entry = self.__db.getEntry(self._getComplParam(line, 0),
						   self._getComplParam(line, 1))
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
		self.__do_edit_entry(params, "edit_pw",
			lambda entry: entry.pw,
			lambda cat, tit, data: PWManEntry(cat, tit, pw=data))
	do_ep = do_edit_pw

	@completion
	def complete_edit_pw(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self._getComplParam(line, 0),
							       text)
		elif paramIdx == 2:
			# Password data
			entry = self.__db.getEntry(self._getComplParam(line, 0),
						   self._getComplParam(line, 1))
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
		category, title = self._getParams(params, 0, 2)
		data = self._skipParams(params, 2).strip()
		if not category:
			self.__err("edit_bulk", "Category parameter is required.")
		if not title:
			self.__err("edit_bulk", "Title parameter is required.")
		entry = self.__db.getEntry(category, title)
		if not entry:
			self.__err("edit_bulk", "'%s/%s' not found" % (category, title))
		entryBulk = self.__db.getEntryBulk(entry)
		if not entryBulk:
			entryBulk = PWManEntryBulk(entry=entry)
		origEntryBulk = deepcopy(entryBulk)
		entryBulk.data = data
		self.__db.setEntryBulk(entryBulk)
		self.__undo.do("edit_bulk %s" % params,
			       "edit_bulk %s %s %s" % (
			       escapeCmd(category),
			       escapeCmd(title),
			       escapeCmd(origEntryBulk.data or "")))
	do_eb = do_edit_bulk

	@completion
	def complete_edit_bulk(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self._getComplParam(line, 0),
							       text)
		elif paramIdx == 2:
			# Bulk data
			entry = self.__db.getEntry(self._getComplParam(line, 0),
						   self._getComplParam(line, 1))
			if entry:
				entryBulk = self.__db.getEntryBulk(entry)
				if entryBulk:
					return [ escapeCmd(entryBulk.data) ]
		return []
	complete_eb = complete_edit_bulk

	def do_remove(self, params):
		"""--- Remove an existing entry ---
		Command: remove category [title]\n
		Remove an existing database entry.\n
		Aliases: rm del"""
		category, title = self._getParams(params, 0, 2)
		if not category:
			self.__err("remove", "Category parameter is required.")
		if not title:
			# Remove whole category
			for title in self.__db.getEntryTitles(category):
				p = "%s %s" % (escapeCmd(category),
					       escapeCmd(title))
				self.__info("remove", "running: remove %s" % p)
				self.do_remove(p)
			return
		oldEntry = self.__db.getEntry(category, title)
		if not oldEntry:
			self.__err("remove", "Entry does not exist")
		oldEntryBulk = self.__db.getEntryBulk(oldEntry)
		oldEntryAttrs = self.__db.getEntryAttrs(oldEntry)
		oldEntryTotp = self.__db.getEntryTotp(oldEntry)
		try:
			self.__db.delEntry(PWManEntry(category, title))
		except (PWManError) as e:
			self.__err("remove", str(e))
		undoCmds = [ "new %s %s %s %s" % (
			     escapeCmd(oldEntry.category),
			     escapeCmd(oldEntry.title),
			     escapeCmd(oldEntry.user),
			     escapeCmd(oldEntry.pw)) ]
		if oldEntryBulk:
			undoCmds.append("edit_bulk %s %s %s" % (
					escapeCmd(oldEntry.category),
					escapeCmd(oldEntry.title),
					escapeCmd(oldEntryBulk.data or "")))
		for oldEntryAttr in (oldEntryAttrs or []):
			undoCmds.append("edit_attr %s %s %s %s" % (
					escapeCmd(oldEntry.category),
					escapeCmd(oldEntry.title),
					escapeCmd(oldEntryAttr.name),
					escapeCmd(oldEntryAttr.data or "")))
		if oldEntryTotp:
			undoCmds.append("edit_totp %s %s %s %s %s" % (
					escapeCmd(oldEntry.category),
					escapeCmd(oldEntry.title),
					escapeCmd(oldEntryTotp.key or ""),
					escapeCmd(("%d" % oldEntryTotp.digits) if oldEntryTotp.digits else ""),
					escapeCmd(oldEntryTotp.hmacHash or "")))
		self.__undo.do("remove %s" % params, undoCmds)
	do_rm = do_remove
	do_del = do_remove

	complete_remove = __complete_category_title
	complete_rm = complete_remove
	complete_del = complete_remove

	def do_move(self, params):
		"""--- Move/rename an existing entry or a category ---\n
		Move/rename an existing entry:
		Command: move category title newCategory [newTitle]\n
		Rename an existing category:
		Command: move category newCategory\n
		Aliases: mv rename"""
		p0, p1, p2, p3 = self._getParams(params, 0, 4)
		if p0 and p1 and p2:
			# Entry move
			fromCategory, fromTitle, toCategory, toTitle = p0, p1, p2, p3
			if not toTitle:
				toTitle = fromTitle
			if fromCategory == toCategory and fromTitle == toTitle:
				self.__info("move", "Nothing changed. Not moving anything.")
				return
			entry = self.__db.getEntry(fromCategory, fromTitle)
			if not entry:
				self.__err("move", "Source entry does not exist.")
			oldEntry = deepcopy(entry)
			try:
				self.__db.moveEntry(entry, toCategory, toTitle)
			except (PWManError) as e:
				self.__err("move", str(e))
			self.__undo.do("move %s" % params,
				       "move %s %s %s %s" % (
				       escapeCmd(entry.category), escapeCmd(entry.title),
				       escapeCmd(oldEntry.category), escapeCmd(oldEntry.title)))
		elif p0 and p1:
			# Category rename
			fromCategory, toCategory = p0, p1
			try:
				self.__db.renameCategory(fromCategory, toCategory)
			except (PWManError) as e:
				self.__err("move", str(e))
			self.__undo.do("move %s" % params,
				       "move %s %s" % (
				       escapeCmd(toCategory), escapeCmd(fromCategory)))
		else:
			self.__err("move", "Invalid parameters.")
	do_mv = do_move
	do_rename = do_move

	@completion
	def complete_move(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx in (0, 2):
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx in (1, 3):
			# Entry title completion
			category = self._getComplParam(line, 0 if paramIdx == 1 else 2)
			return self.__getEntryTitleCompletions(category, text)
		return []
	complete_mv = complete_move
	complete_rename = complete_move

	__dbdump_opts = ("-s", "-h", "-c")
	def do_dbdump(self, params):
		"""--- Dump the pwman SQL database ---
		Command: dbdump [OPTS] [FILEPATH]\n
		If FILEPATH is given, the database is dumped
		unencrypted to the file.
		If FILEPATH is omitted, the database is dumped
		unencrypted to stdout.\n
		OPTS may be one of:
		  -s   Dump format SQL. (default)
		  -h   Dump format human readable text.
		  -c   Dump format CSV.\n
		WARNING: The database dump is not encrypted.\n
		Aliases: None"""
		opts = self._getOpts(params, self.__dbdump_opts)
		if opts.nrParams > 1:
			self.__err("dbdump", "Too many arguments.")
		optFmtSqlDump = "-s" in opts
		optFmtHumanReadable = "-h" in opts
		optFmtCsv = "-c" in opts
		numFmtOpts = int(optFmtSqlDump) + int(optFmtHumanReadable) + int(optFmtCsv)
		if not 0 <= numFmtOpts <= 1:
			self.__err("dbdump", "Multiple format OPTions. "
					     "Only one is allowed.")
		if numFmtOpts == 0:
			optFmtSqlDump = True
		dumpFile = opts.getParam(0) if opts.nrParams > 0 else None
		try:
			if optFmtSqlDump:
				dump = self.__db.sqlPlainDump() + b"\n"
			elif optFmtHumanReadable:
				dump = self.__db.dumpEntries(showTotpKey=True)
				dump = dump.encode("UTF-8") + b"\n"
			elif optFmtCsv:
				dump = self.__db.dumpEntriesCsv(showTotpKey=True)
				dump = dump.encode("UTF-8")
			else:
				assert(0)
			if dumpFile:
				with open(dumpFile, "wb") as f:
					f.write(dump)
			else:
				stdout(dump)
		except UnicodeError as e:
			self.__err("dbdump", "Unicode error.")
		except IOError as e:
			self.__err("dbdump", "Failed to write dump: %s" % e.strerror)

	@completion
	def complete_dbdump(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if text == "-":
			return self.__dbdump_opts
		opts = self._getOpts(line, self.__dbdump_opts, ignoreFirst=True)
		optName, value = opts.atCmdIndex(paramIdx)
		if optName: # -... option
			return [ text + " " ]
		if (opts.nrParams == 0 and not text) or (opts.nrParams == 1 and text): # trailing param
			return self.__getPathCompletions(text)
		return []

	def do_dbimport(self, params):
		"""--- Import an SQL database dump ---
		Command: dbimport FILEPATH\n
		Import the FILEPATH into the current database.
		The database is cleared before importing the file!\n
		Aliases: None"""
		try:
			if not params.strip():
				raise IOError("FILEPATH is empty.")
			with open(params, "rb") as f:
				data = f.read().decode("UTF-8")
			self.__db.importSqlScript(data)
			self.__info("dbimport", "success.")
		except (CSQLError, IOError, UnicodeError) as e:
			self.__err("dbimport", "Failed to import dump: %s" % str(e))

	@completion
	def complete_dbimport(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx == 0:
			return self.__getPathCompletions(text)
		return []

	def do_drop(self, params):
		"""--- Drop all uncommitted changes ---
		Command: drop\n
		Aliases: None"""
		self.__db.dropUncommitted()

	__find_opts = ("-c", "-t", "-u", "-p", "-b", "-a", "-A", "-r")
	def do_find(self, params):
		"""--- Search the database ---
		Command: find [OPTS] [IN_CATEGORY] PATTERN\n
		Searches the database for patterns. If 'IN_CATEGORY' is given, only search
		in the specified category.
		PATTERN may either use SQL LIKE wildcards (without -r)
		or Python Regular Expression special characters (with -r).\n
		OPTS may be one or multiple of:
		  -c   Match 'category'       (only if no IN_CATEGORY parameter)
		  -t   Match 'title'          (*)
		  -u   Match 'user'           (*)
		  -p   Match 'password'       (*)
		  -b   Match 'bulk'           (*)
		  -a   Match 'attribute data' (*)
		  -A   Match 'attribute name'
		  -r   Use Python Regular Expression matching\n
		(*) = These OPTS are enabled by default, if and only if
		      none of them are specified by the user.\n
		Aliases: f"""
		opts = self._getOpts(params, self.__find_opts)
		mCategory = "-c" in opts
		mTitle = "-t" in opts
		mUser = "-u" in opts
		mPw = "-p" in opts
		mBulk = "-b" in opts
		mAttrData = "-a" in opts
		mAttrName = "-A" in opts
		regexp = "-r" in opts
		if not any( (mTitle, mUser, mPw, mBulk, mAttrData) ):
			mTitle, mUser, mPw, mBulk, mAttrData = (True,) * 5
		if opts.nrParams < 1 or opts.nrParams > 2:
			self.__err("find", "Invalid parameters.")
		inCategory = opts.getParam(0) if opts.nrParams > 1 else None
		pattern = opts.getParam(1) if opts.nrParams > 1 else opts.getParam(0)
		if inCategory and mCategory:
			self.__err("find", "-c and [IN_CATEGORY] cannot be used at the same time.")
		entries = self.__db.findEntries(pattern=pattern,
						useRegexp=regexp,
						inCategory=inCategory,
						matchCategory=mCategory,
						matchTitle=mTitle,
						matchUser=mUser,
						matchPw=mPw,
						matchBulk=mBulk,
						matchAttrName=mAttrName,
						matchAttrData=mAttrData)
		if not entries:
			self.__err("find", "'%s' not found" % pattern)
		for entry in entries:
			self.__info(None, self.__db.dumpEntry(entry))
	do_f = do_find

	@completion
	def complete_find(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if text == "-":
			return self.__find_opts
		opts = self._getOpts(line, self.__find_opts, ignoreFirst=True)
		optName, value = opts.atCmdIndex(paramIdx)
		if optName: # -... option
			return [ text + " " ]
		if (opts.nrParams == 0 and not text) or (opts.nrParams == 1 and text): # category
			return self.__getCategoryCompletions(text)
		return []
	complete_f = complete_find

	def do_totp(self, params):
		"""--- Generate a TOTP token ---
		Command: totp [CATEGORY TITLE] OR [TITLE]\n
		Generates a token using the Time-Based One-Time Password Algorithm.\n
		Aliases: t"""
		first, second = self._getParams(params, 0, 2)
		if not first:
			self.__err("totp", "First parameter is required.")
		if second:
			category, title = first, second
		else:
			entries = self.__db.findEntries(first, matchTitle=True)
			if not entries:
				self.__err("totp", "Entry title not found.")
				return
			elif len(entries) == 1:
				category = entries[0].category
				title = entries[0].title
			else:
				self.__err("totp", "Entry title ambiguous.")
				return
		entry = self.__db.getEntry(category, title)
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
		self.__info(None, "%s" % token)
	do_t = do_totp

	complete_totp = __complete_category_title
	complete_t = complete_totp

	def do_totp_key(self, params):
		"""--- Show TOTP key and parameters ---
		Command: totp_key category title\n
		Show Time-Based One-Time Password Algorithm key and parameters.\n
		Aliases: tk"""
		category, title = self._getParams(params, 0, 2)
		if not category:
			self.__err("totp_key", "Category parameter is required.")
		if not title:
			self.__err("totp_key", "Title parameter is required.")
		entry = self.__db.getEntry(category, title)
		if not entry:
			self.__err("totp_key", "'%s/%s' not found" % (category, title))
		entryTotp = self.__db.getEntryTotp(entry)
		enc = "  (base32 encoding)"
		if not entryTotp:
			entryTotp = PWManEntryTOTP(key="--- none ---",
						   digits=6,
						   hmacHash="SHA1")
			enc = ""
		self.__info(None, "TOTP key:     %s%s" % (entryTotp.key, enc))
		self.__info(None, "TOTP digits:  %d" % entryTotp.digits)
		self.__info(None, "TOTP hash:    %s" % entryTotp.hmacHash)
	do_tk = do_totp_key

	complete_totp_key = __complete_category_title
	complete_tk = complete_totp_key

	def do_edit_totp(self, params):
		"""--- Edit TOTP key and parameters ---
		Command: edit_totp category title [KEY] [DIGITS] [HASH]\n
		Set Time-Based One-Time Password Algorithm key and parameters.
		If KEY is not provided, the TOTP parameters for this entry are deleted.
		DIGITS default to 6, if not provided.
		HASH defaults to SHA1, if not provided.\n
		Aliases: et"""
		category, title, key, digits, _hash = self._getParams(params, 0, 5)
		if not category:
			self.__err("edit_totp", "Category parameter is required.")
		if not title:
			self.__err("edit_totp", "Title parameter is required.")
		entry = self.__db.getEntry(category, title)
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

	@completion
	def complete_edit_totp(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx in (0, 1):
			return self.__complete_category_title(text, line, begidx, endidx)
		category, title = self._getComplParams(line, 0, 2)
		if category and title:
			entry = self.__db.getEntry(category, title)
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
		category, title, name, data = self._getParams(params, 0, 4)
		if not category:
			self.__err("edit_attr", "Category parameter is required.")
		if not title:
			self.__err("edit_attr", "Title parameter is required.")
		entry = self.__db.getEntry(category, title)
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

	@completion
	def complete_edit_attr(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if paramIdx in (0, 1):
			return self.__complete_category_title(text, line, begidx, endidx)
		category, title, name = self._getComplParams(line, 0, 3)
		if category and title:
			entry = self.__db.getEntry(category, title)
			if entry:
				if paramIdx == 2: # name
					entryAttrs = self.__db.getEntryAttrs(entry)
					if entryAttrs:
						return [ escapeCmd(entryAttr.name) + " "
							 for entryAttr in entryAttrs
							 if entryAttr.name.lower().startswith(name.lower()) ]
				elif paramIdx == 3: # data
					entryAttr = self.__db.getEntryAttr(entry, name)
					if entryAttr:
						return [ escapeCmd(entryAttr.data) + " " ]
		return []
	complete_ea = complete_edit_attr

	__diff_opts = ("-u", "-c", "-n")
	def do_diff(self, params):
		"""--- Diff the current database to another database ---
		Command: diff [OPTS] [DATABASE_FILE]\n
		If no DATABASE_FILE is provided: Diffs the latest changes in the
		currently open database to the committed changes in the current database.
		This can be used to review changes before commit.\n
		If DATABASE_FILE is provided: Diffs the latest changes in the
		currently opened database to the contents of DATABASE_FILE.\n
		OPTS may be one of:
		-u  Generate a unified diff (default if no OPT is given).
		-c  Generate a context diff
		-n  Generate an ndiff\n
		Aliases: None"""
		opts = self._getOpts(params, self.__diff_opts)
		if opts.nrParams > 1:
			self.__err("diff", "Too many arguments.")
		optUnified = "-u" in opts
		optContext = "-c" in opts
		optNdiff = "-n" in opts
		numFmtOpts = int(optUnified) + int(optContext) + int(optNdiff)
		if not 0 <= numFmtOpts <= 1:
			self.__err("diff", "Multiple format OPTions. "
					   "Only one is allowed.")
		if numFmtOpts == 0:
			optUnified = True
		dbFile = opts.getParam(0) if opts.nrParams > 0 else None
		try:
			if dbFile:
				path = pathlib.Path(dbFile)
				if not path.exists():
					self.__err("diff", "'%s' does not exist." % dbFile)
				passphrase = readPassphrase(
						"Master passphrase of '%s'" % dbFile,
						verify=False)
				if passphrase is None:
					self.__err("diff", "Could not get passphrase.")
				oldDb = PWManDatabase(filename=path,
						      passphrase=passphrase,
						      readOnly=True)
			else:
				oldDb = self.__db.getOnDiskDb()
			diff = PWManDatabaseDiff(db=self.__db, oldDb=oldDb)
			if optUnified:
				diffText = diff.getUnifiedDiff()
			elif optContext:
				diffText = diff.getContextDiff()
			elif optNdiff:
				diffText = diff.getNdiffDiff()
			else:
				assert(0)
			self.__info(None, diffText)
		except PWManError as e:
			self.__err("diff", "Failed: %s" % str(e))

	@completion
	def complete_diff(self, text, line, begidx, endidx):
		paramIdx = self._calcParamIndex(line, endidx)
		if text == "-":
			return self.__diff_opts
		opts = self._getOpts(line, self.__diff_opts, ignoreFirst=True)
		optName, value = opts.atCmdIndex(paramIdx)
		if optName: # -... option
			return [ text + " " ]
		if (opts.nrParams == 0 and not text) or (opts.nrParams == 1 and text): # trailing param
			return self.__getPathCompletions(text)
		return []

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
			    "\n    " + "\n    ".join(cmd.doCommands) +
			    "\nsuccessfully undone with:\n" +
			    "    " + "\n    ".join(cmd.undoCommands))

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
			    "\n    " + "\n    ".join(cmd.undoCommands) +
			    "\nsuccessfully redone with:\n" +
			    "    " + "\n    ".join(cmd.doCommands))

	def _skipParams(self, line, count,
			 lineIncludesCommand=False, unescape=True):
		# Return a parameter string with the first 'count'
		# parameters skipped.
		sline = self._patchSpaceEscapes(line)
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

	def _calcParamIndex(self, line, endidx):
		# Returns the parameter index into the commandline
		# given the character end-index. This honors space-escape.
		line = self._patchSpaceEscapes(line)
		startidx = endidx - 1
		while startidx > 0 and not line[startidx].isspace():
			startidx -= 1
		return len([l for l in line[:startidx].split() if l]) - 1

	def _patchSpaceEscapes(self, line):
		# Patch a commandline for simple whitespace based splitting.
		# We just replace the space escape sequence by a random
		# non-whitespace string. The line remains the same size.
		return line.replace('\\ ', '_S')

	def _getParam(self, line, paramIndex,
		       ignoreFirst=False, unescape=True):
		"""Returns the full parameter from the commandline.
		"""
		sline = self._patchSpaceEscapes(line)
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

	def _getComplParam(self, line, paramIndex, unescape=True):
		return self._getParam(line, paramIndex,
				      ignoreFirst=True, unescape=unescape)

	def _getParams(self, line, paramIndex, count,
		       ignoreFirst=False, unescape=True):
		"""Returns a generator of the specified parameters from the commandline.
		paramIndex: start index.
		count: Number of paramerts to fetch.
		"""
		return ( self._getParam(line, i, ignoreFirst, unescape)
			 for i in range(paramIndex, paramIndex + count) )

	def _getComplParams(self, line, paramIndex, count, unescape=True):
		return self._getParams(line, paramIndex, count,
				       ignoreFirst=True, unescape=unescape)

	@dataclass
	class Opts(object):
		__opts : list = field(default_factory=list)
		__params : list = field(default_factory=list)
		__atCmdIndex : dict = field(default_factory=dict)

		def _appendOpt(self, cmdIndex, optName, optValue=None):
			self.__opts.append( (optName, optValue) )
			self.__atCmdIndex[cmdIndex] = (optName, optValue)

		def _appendParam(self, cmdIndex, param):
			self.__params.append(param)
			self.__atCmdIndex[cmdIndex] = (None, param)

		def __contains__(self, optName):
			"""Check if we have a specific "-X" style option.
			"""
			return optName in (o[0] for o in self.__opts)

		@property
		def hasOpts(self):
			"""Do we have -X style options?
			"""
			return bool(self.__opts)

		def getOpt(self, optName):
			"""Get an option value by "-X" style name.
			"""
			if optName in self:
				return [ o[1] for o in self.__opts if o[0] == optName ][-1]
			return None

		@property
		def nrParams(self):
			"""The number of trailing parameters.
			"""
			return len(self.__params)

		def getParam(self, index):
			"""Get a trailing parameter at index.
			"""
			return self.__params[index]

		def atCmdIndex(self, cmdIndex):
			"""Get an item (option or parameter) at command line index cmdIndex.
			Returns (optName, optValue) if it is an option.
			Returns (None, parameter) if it is a parameter.
			Returns (None, None) if it does not exist.
			"""
			return self.__atCmdIndex.get(cmdIndex, (None, None))

	def _getOpts(self, line, possibleOpts,
		     ignoreFirst=False, unescape=True):
		"""Parses the command options in 'line' and returns an Opts instance.
		possibleOpts is a tuple of the possible options.
		"""
		possibleOptsPlain = [ o.replace(":", "") for o in possibleOpts ]
		opts = self.Opts()
		i = 0
		while True:
			p = self._getParam(line, i,
					   ignoreFirst=ignoreFirst,
					   unescape=unescape)
			if not p:
				break
			if opts.nrParams:
				opts._appendParam(i, p)
			else:
				try:
					optIdx = possibleOptsPlain.index(p)
				except ValueError:
					opts._appendParam(i, p)
					i += 1
					continue
				if possibleOpts[optIdx].endswith(":"):
					i += 1
					arg = self._getParam(line, i,
							     ignoreFirst=ignoreFirst,
							     unescape=unescape)
					if not arg:
						self.__err(None, "Option '%s' "
							   "requires an argument." % p)
					opts._appendOpt(i, p, arg)
				else:
					opts._appendOpt(i, p)
			i += 1
		return opts

	def __mayQuit(self):
		if self.__db.isDirty():
			self.__warn(None,
				    "Warning: Uncommitted changes. Operation not performed.\n"
				    "Use command 'commit' to write the changes to the database.\n"
				    "Use command 'quit!' to quit without saving.")
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
			except EscapeError as e:
				self.__warn(None, str(e))
			except self.CommandError as e:
				print(str(e), file=sys.stderr)
			except (KeyboardInterrupt, EOFError) as e:
				print("")
			except (CSQLError) as e:
				self.__warn(None, "SQL error: %s" % str(e))

	def runOneCommand(self, command):
		try:
			self.onecmd(command)
		except (EscapeError, self.CommandError) as e:
			raise PWManError(str(e))
		except (KeyboardInterrupt, EOFError) as e:
			raise PWManError("Interrupted")
		except (CSQLError) as e:
			raise PWManError("SQL error: %s" % str(e))
