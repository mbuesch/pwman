"""
# Simple password manager
# Copyright (c) 2011 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import sys
import os
import errno
import getpass
import time
import re
import readline
from cmd import Cmd
from cryptsql import *


def getDefaultDatabase():
	db = os.getenv("PWMAN_DATABASE")
	if db:
		return db
	home = os.getenv("HOME")
	if home:
		return home + "/.pwman.db"
	return None

def uniq(l, sort=True):
	l = list(set(l))
	if sort:
		l.sort()
	return l

class EscapeError(Exception): pass

def escapeCmd(s):
	# Commandline escape
	subst = {
		'\t'	: '\\t',
		'\n'	: '\\n',
		'\\'	: '\\\\',
		' '	: '-',
		'-'	: '\\-',
	}
	ret = []
	for c in s:
		try:
			c = subst[c]
		except (KeyError), e:
			if c.isspace():
				c = '\\x%02X' % ord(c)
		ret.append(c)
	return "".join(ret)

def unescapeCmd(s):
	# Commandline unescape
	slashSubst = {
		't'	: '\t',
		'n'	: '\n',
		'\\'	: '\\',
		'-'	: '-',
	}
	ret = []
	i = 0
	while i < len(s):
		if s[i] == '\\':
			try:
				if s[i + 1] == 'x':
					ret.append(chr(int(s[i + 2 : i + 4], 16)))
					i += 3
				else:
					ret.append(slashSubst[s[i + 1]])
					i += 1
			except (IndexError, ValueError, KeyError):
				raise EscapeError("Invalid backslash escape sequence "
					"at character %d" % i)
		elif s[i] == '-':
			ret.append(' ')
		else:
			ret.append(s[i])
		i += 1
	return "".join(ret)

def stdout(text, flush=True):
	sys.stdout.write(text)
	if flush:
		sys.stdout.flush()

def clearScreen():
	stdout("\x1B[2J\x1B[0;0f")

def readPassphrase(prompt, verify=False):
	if verify:
		prompt = "[New] " + prompt
	try:
		while True:
			p0 = getpass.getpass(prompt + ": ")
			if not p0:
				continue
			if not verify:
				return p0
			p1 = getpass.getpass(prompt + " (verify): ")
			if p0 == p1:
				return p0
			print "Passwords don't match. Try again..."
	except (EOFError), e:
		print ""
		return None
	except (getpass.GetPassWarning), e:
		print str(e)
		return None

def fileExists(path):
	try:
		os.stat(path)
	except (OSError), e:
		if e.errno == errno.ENOENT:
			return False
		raise CSQLError("fileExists(): " + str(e))
	return True

class PWManEntry(object):
	Undefined = None

	def __init__(self, category, title,
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

	def dump(self, prefix=""):
		res = [ ]
		res.append("Category:\t" + self.category)
		res.append("Title:\t\t" + self.title)
		if self.user:
			res.append("User:\t\t" + self.user)
		if self.pw:
			res.append("Password:\t" + self.pw)
		if self.bulk:
			res.append("Bulk data:\t" + self.bulk)
		return prefix + ("\n" + prefix).join(res)

class PWMan(CryptSQL, Cmd):
	class Error(Exception): pass
	class Quit(Exception): pass

	def __init__(self, filename, passphrase):
		try:
			CryptSQL.__init__(self)

			Cmd.__init__(self)
			self.prompt = "pwman$ "

			self.__openFile(filename, passphrase)
		except (CSQLError), e:
			raise PWMan.Error(str(e))

	def __openFile(self, filename, passphrase):
		self.open(filename, passphrase)
		self.passphrase = passphrase
		self.dirty = False
		self.sqlExec("CREATE TABLE IF NOT EXISTS "
			"pw(category TEXT, title TEXT, user TEXT, pw TEXT, bulk TEXT);")

	def __err(self, source, message):
		source = " " + source + ":" if source else ""
		print "***%s %s\n" % (source, message)

	def precmd(self, line):
		first = self.__getParam(line, 0, False, False)
		if first.endswith('?'):
			return "help %s" % first[:-1]
		return line

	def default(self, line):
		self.__err(None, "Unknown command: %s" % line)

	def emptyline(self):
		self.do_help([])

	def __complete_category_title(self, text, line, begidx, endidx):
		# Generic [category] [title] completion
		paramIdx = self.__calcParamIndex(line, begidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, True),
							       text)
		return []

	cmdHelpMisc = (
		("help", ("h",), "Show help about commands"),
		("quit", ("q", "exit", "^D"), "Quit pwman"),
		("cls", (), "Clear screen"),
	)

	cmdHelpDatabase = (
		("commit", ("c", "w"), "Commit / write database file"),
		("masterp", (), "Change the master passphrase"),
	)

	cmdHelpEdit = (
		("list", ("ls",), "Print entry contents"),
		("new", ("n", "add"), "Create new entry"),
		("edit_user", ("eu",), "Edit the 'user' field of an entry"),
		("edit_pw", ("ep",), "Edit the 'password' field of an entry"),
		("edit_bulk", ("eb",), "Edit the 'bulk' field of an entry"),
		("remove", ("rm", "del"), "Remove and existing entry"),
	)

	def do_help(self, params):
		"""--- Shows help text about a command ---\n
		Command: help\n
		Aliases: h"""
		if params:
			Cmd.do_help(self, params)
			return
		def printCmdHelp(cmdHelp):
			for (cmd, aliases, desc) in cmdHelp:
				spc = " " * (10 - len(cmd))
				msg = "  %s%s%s" % (cmd, spc, desc)
				if aliases:
					msg += " " * (51 - len(msg))
					msg += " Alias%s: %s" %\
					("es" if len(aliases) > 1 else "",
					", ".join(aliases))
				print msg
		print "Misc commands:"
		printCmdHelp(self.cmdHelpMisc)
		print "\nDatabase commands:"
		printCmdHelp(self.cmdHelpDatabase)
		print "\nEditing/listing commands:"
		printCmdHelp(self.cmdHelpEdit)
		print "\nType 'command?' or 'help command' for more help on a command."
	do_h = do_help

	def do_quit(self, params):
		"""--- Exit pwman ---
		Command: quit [!]\n
		Use the exclamation mark to force quit and discard changes.\n
		Aliases: q exit ^D"""
		if params == "!":
			self.flunkDirty()
		raise self.Quit()
	do_q = do_quit
	do_exit = do_quit
	do_EOF = do_quit

	def do_cls(self, params):
		"""--- Clear console screen ---
		Command: cls\n
		Clear the console screen. Note that this does not clear
		advanced buffers like the screen session buffer.\n
		Aliases: None"""
		clearScreen()

	def do_commit(self, params):
		"""--- Write changes to the database file ---\n
		Command: commit\n
		Aliases: c w"""
		self.commit()
	do_c = do_commit
	do_w = do_commit

	def do_masterp(self, params):
		"""--- Change the master passphrase ---\n
		Command: masterp\n
		Aliases: None"""
		p = readPassphrase("Current master passphrase")
		if p != self.passphrase:
			stdout("Passphrase mismatch! ")
			for i in range(0, 3):
				stdout(".")
				time.sleep(0.5)
			print ""
			return
		p = readPassphrase("Master passphrase", verify=True)
		if p is None:
			print "Passphrase not changed."
			return
		if p != self.passphrase:
			self.passphrase = p
			self.setDirty()

	def do_list(self, params):
		"""--- Print a listing ---
		Command: list [category] [title]\n
		If a category is given as parameter, list the 
		contents of the category. If category and entry
		are given, list the contents of the entry.\n
		Aliases: ls"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category and not title:
			stdout("Categories:\n\t")
			stdout("\n\t".join(self.getCategoryNames()) + "\n")
		elif category and not title:
			stdout("Entries in category '%s'\n\t" % category)
			stdout("\n\t".join(self.getEntryTitles(category)) + "\n")
		elif category and title:
			entry = self.getEntry(PWManEntry(category, title))
			if entry:
				stdout(entry.dump(prefix="\t") + "\n")
			else:
				self.__err("list", "'%s/%s' not found" % (category, title))
		else:
			self.__err("list", "Invalid parameter")
	do_ls = do_list

	complete_list = __complete_category_title
	complete_ls = complete_list

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
			category = raw_input("\tCategory: ")
			title = raw_input("\tEntry title: ")
			user = raw_input("\tUsername: ")
			pw = raw_input("\tPassword: ")
			bulk = raw_input("\tBulk data: ")
		if not category or not title:
			self.__err("new", "Invalid parameters. "
				"Need to supply category and title.")
			return
		entry = PWManEntry(category, title, user, pw, bulk)
		try:
			self.addEntry(entry)
		except (self.Error), e:
			self.__err("new", str(e))
			return
	do_n = do_new
	do_add = do_new

	complete_new = __complete_category_title
	complete_n = complete_new
	complete_add = complete_new

	def do_edit_user(self, params):
		"""--- Edit the 'user' field of an existing entry ---
		Command: edit_user category title NEWDATA...\n
		Change the 'user' field of an existing database entry.
		NEWDATA is the new data to write into the 'user' field.
		The NEWDATA must _not_ be escaped (however, category and
		title must be escaped).\n
		Aliases: eu"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category or not title:
			self.__err("edit_user", "Invalid parameters. "
				"Need to supply category and title.")
			return
		newUser = self.__skipParams(params, 2).strip()
		entry = PWManEntry(category, title, user=newUser)
		try:
			self.editEntry(entry)
		except (self.Error), e:
			self.__err("edit_user", str(e))
			return
	do_eu = do_edit_user

	def complete_edit_user(self, text, line, begidx, endidx):
		paramIdx = self.__calcParamIndex(line, begidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, True),
							       text)
		elif paramIdx == 2:
			# User data
			entry = self.getEntry(PWManEntry(self.__getParam(line, 0, True),
							 self.__getParam(line, 1, True)))
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
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category or not title:
			self.__err("edit_pw", "Invalid parameters. "
				"Need to supply category and title.")
			return
		newPw = self.__skipParams(params, 2).strip()
		entry = PWManEntry(category, title, pw=newPw)
		try:
			self.editEntry(entry)
		except (self.Error), e:
			self.__err("edit_pw", str(e))
			return
	do_ep = do_edit_pw

	def complete_edit_pw(self, text, line, begidx, endidx):
		paramIdx = self.__calcParamIndex(line, begidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, True),
							       text)
		elif paramIdx == 2:
			# Password data
			entry = self.getEntry(PWManEntry(self.__getParam(line, 0, True),
							 self.__getParam(line, 1, True)))
			return [ escapeCmd(entry.pw) ]
		return []
	complete_ep = complete_edit_pw

	def do_edit_bulk(self, params):
		"""--- Edit the 'bulk' field of an existing entry ---
		Command: edit_com category title NEWDATA...\n
		Change the 'bulk' field of an existing database entry.
		NEWDATA is the new data to write into the 'bulk' field.
		The NEWDATA must _not_ be escaped (however, category and
		title must be escaped).\n
		Aliases: ec"""
		category = self.__getParam(params, 0)
		title = self.__getParam(params, 1)
		if not category or not title:
			self.__err("edit_com", "Invalid parameters. "
				"Need to supply category and title.")
			return
		newBulk = self.__skipParams(params, 2).strip()
		entry = PWManEntry(category, title, bulk=newBulk)
		try:
			self.editEntry(entry)
		except (self.Error), e:
			self.__err("edit_com", str(e))
			return
	do_eb = do_edit_bulk

	def complete_edit_bulk(self, text, line, begidx, endidx):
		paramIdx = self.__calcParamIndex(line, begidx)
		if paramIdx == 0:
			# Category completion
			return self.__getCategoryCompletions(text)
		elif paramIdx == 1:
			# Entry title completion
			return self.__getEntryTitleCompletions(self.__getParam(line, 0, True),
							       text)
		elif paramIdx == 2:
			# Bulk data
			entry = self.getEntry(PWManEntry(self.__getParam(line, 0, True),
							 self.__getParam(line, 1, True)))
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
			return
		entry = PWManEntry(category, title)
		try:
			self.delEntry(entry)
		except (self.Error), e:
			self.__err("remove", str(e))
			return
	do_rm = do_remove
	do_del = do_remove

	complete_remove = __complete_category_title
	complete_rm = complete_remove
	complete_del = complete_remove

	def __skipParams(self, line, count, lineIncludesCommand=False):
		# Return a parameter string with the first 'count'
		# parameters skipped.
		if lineIncludesCommand:
			count += 1
		i = 0
		while i < len(line) and count > 0:
			while i < len(line) and not line[i].isspace():
				i += 1
			while i < len(line) and line[i].isspace():
				i += 1
			count -= 1
		if i >= len(line):
			return ""
		return line[i:]

	def __calcParamIndex(self, line, charIndex):
		# Returns the parameter index in a complete commandline
		# given the character index into the line.
		return len(filter(None, line[:charIndex].split())) - 1

	def __getParam(self, line, paramIndex,
		       ignoreFirst=False, unescape=True):
		# Returns the full parameter from the commandline
		if ignoreFirst:
			paramIndex += 1
		try:
			p = line.split()[paramIndex]
			if unescape:
				p = unescapeCmd(p)
			return p
		except (IndexError), e:
			return ""

	def getCategoryNames(self):
		categories = self.sqlExec("SELECT category FROM pw;").fetchAll()
		if not categories:
			return []
		return uniq(map(lambda c: c[0], categories))

	def __getCategoryCompletions(self, text):
		catNames = filter(lambda n: n.lower().startswith(text.lower()),
			      self.getCategoryNames())
		return map(lambda n: escapeCmd(n) + " ", catNames)

	def getEntryTitles(self, category):
		sql = "SELECT title FROM pw WHERE category=?;"
		titles = self.sqlExec(sql, (category,)).fetchAll()
		if not titles:
			return None
		titles = map(lambda t: t[0], titles)
		titles.sort()
		return titles

	def __getEntryTitleCompletions(self, category, text):
		titles = filter(lambda t: t.lower().startswith(text.lower()),
			      self.getEntryTitles(category))
		return map(lambda t: escapeCmd(t) + " ", titles)

	def getEntry(self, entry):
		sql = "SELECT category, title, user, pw, bulk FROM pw "\
			"WHERE category=? AND title=?;"
		data = self.sqlExec(sql, (entry.category, entry.title)).fetchOne()
		if not data:
			return None
		return PWManEntry(data[0], data[1], data[2], data[3], data[4])

	def __delEntry(self, entry):
		self.sqlExec("DELETE FROM pw WHERE category=? AND title=?;",
			     (entry.category, entry.title))

	def __editEntry(self, oldEntry, newEntry):
		if oldEntry:
			assert(oldEntry.category == newEntry.category)
			assert(oldEntry.title == newEntry.title)
			newEntry.copyUndefined(oldEntry)
			self.__delEntry(oldEntry)
		self.sqlExec("INSERT INTO pw(category, title, user, pw, bulk) "
			     "VALUES(?,?,?,?,?);",
			     (newEntry.category, newEntry.title, newEntry.user,
			      newEntry.pw, newEntry.bulk))

	def entryExists(self, entry):
		return bool(self.getEntry(entry))

	def addEntry(self, entry):
		if self.entryExists(entry):
			raise self.Error("Entry does already exist")
		self.__editEntry(None, entry)
		self.setDirty()

	def editEntry(self, entry):
		oldEntry = self.getEntry(entry)
		if not oldEntry:
			raise self.Error("Entry does not exist")
		self.__editEntry(oldEntry, entry)
		self.setDirty()

	def delEntry(self, entry):
		if not self.entryExists(entry):
			raise self.Error("Entry does not exist")
		self.__delEntry(entry)
		self.setDirty()

	def setDirty(self, d=True):
		self.dirty = d

	def isDirty(self):
		return self.dirty

	def flunkDirty(self):
		if self.isDirty():
			print "Warning: Dropping uncommitted data"
			self.setDirty(False)

	def commit(self):
		CryptSQL.commit(self, self.passphrase)
		self.setDirty(False)

	def __mayQuit(self):
		if self.isDirty():
			print "Warning: Uncommitted changes. " \
				"Operation not performed. Use command 'commit' " \
				"to write the changes to the database. Use " \
				"command 'quit!' to quit without saving."
			return False
		return True

	def interactive(self):
		while True:
			try:
				self.cmdloop()
				break
			except (self.Quit), e:
				if self.__mayQuit():
					clearScreen()
					break
			except (EscapeError), e:
				stdout(str(e) + "\n")
			except (KeyboardInterrupt, EOFError), e:
				stdout("\n")
			except (CSQLError), e:
				stdout("SQL error: %s\n" % str(e))
