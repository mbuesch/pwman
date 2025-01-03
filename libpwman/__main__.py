# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import argparse
import importlib
import libpwman
import pathlib
import sys
import traceback

__all__ = [
	"main",
]

def getPassphrase(dbPath, verbose=True, infoFile=sys.stdout):
	dbExists = dbPath.exists()
	if verbose:
		if dbExists:
			print("Opening database '%s'..." % dbPath,
			      file=infoFile)
		else:
			print("Creating NEW database '%s'..." % dbPath,
			      file=infoFile)
		promptSuffix = ""
	else:
		promptSuffix = " (%s)" % dbPath
	passphrase = libpwman.util.readPassphrase("Master passphrase%s" % promptSuffix,
						  verify=not dbExists)
	return passphrase

def run_infodump(dbPath):
	try:
		fc = libpwman.fileobj.FileObjCollection.parseFile(dbPath)
		print("pwman database: %s" % dbPath)
		head = fc.get(b"HEAD")
		if head != libpwman.cryptsql.CryptSQL.CSQL_HEADER:
			head = str(head)
			if len(head) > 16:
				head = head[:16] + "..."
			raise libpwman.PWManError("Invalid HEAD: %s" % head)
		for obj in fc.objects:
			name = bytes(obj.getName())
			data = bytes(obj.getData())
			trunc = False
			if name == b"PAYLOAD" and len(data) > 8:
				data = data[:8]
				trunc = True
			try:
				name = name.decode("UTF-8")
			except UnicodeError as e:
				raise libpwman.PWManError(
					"Failed to decode file header name.")
			try:
				data = data.decode("UTF-8")
			except UnicodeError as e:
				data = data.hex()
			if trunc:
				data += "..."
			pad = " " * (12 - len(name))
			print("  %s%s: %s" % (name, pad, data))
	except libpwman.fileobj.FileObjError as e:
		raise libpwman.PWManError(str(e))
	return 0

def run_diff(dbPath, oldDbPath, diffFormat):
	for p in (dbPath, oldDbPath):
		if not p.exists():
			print("Database '%s' does not exist." % p,
			      file=sys.stderr)
			return 1

	# Open the new database
	dbPassphrase = getPassphrase(dbPath, verbose=True,
				     infoFile=sys.stderr)
	if dbPassphrase is None:
		return 1
	db = libpwman.database.PWManDatabase(filename=dbPath,
					     passphrase=dbPassphrase,
					     readOnly=True)

	try:
		# Try to open the old database with the passphrase
		# of the new database.
		oldDb = libpwman.database.PWManDatabase(filename=oldDbPath,
							passphrase=dbPassphrase,
							readOnly=True)
	except libpwman.PWManError:
		# The attempt failed. Ask the user for the proper passphrase.
		dbPassphrase = getPassphrase(oldDbPath, verbose=True,
					     infoFile=sys.stderr)
		if dbPassphrase is None:
			return 1
		oldDb = libpwman.database.PWManDatabase(filename=oldDbPath,
							passphrase=dbPassphrase,
							readOnly=True)

	diff = libpwman.dbdiff.PWManDatabaseDiff(db=db, oldDb=oldDb)
	if diffFormat == "unified":
		print(diff.getUnifiedDiff())
	elif diffFormat == "context":
		print(diff.getContextDiff())
	elif diffFormat == "ndiff":
		print(diff.getNdiffDiff())
	elif diffFormat == "html":
		print(diff.getHtmlDiff())
	else:
		assert 0, "Invalid diffFormat"
		return 1
	return 0

def run_script(dbPath, pyModName):
	try:
		if pyModName.lower().endswith(".py"):
			pyModName = pyModName[:-3]
		pyMod = importlib.import_module(pyModName)
	except ImportError as e:
		print("Failed to import --call-pymod "
		      "Python module '%s':\n%s" % (
		      pyModName, str(e)),
		      file=sys.stderr)
		return 1
	run = getattr(pyMod, "run", None)
	if not callable(run):
		print("%s.run is not a callable." % (
		      pyModName),
		      file=sys.stderr)
		return 1

	passphrase = getPassphrase(dbPath, verbose=False)
	if passphrase is None:
		return 1
	db = libpwman.database.PWManDatabase(filename=dbPath,
					     passphrase=passphrase,
					     readOnly=False)
	try:
		run(db)
	except Exception as e:
		print("%s.run(database) raised an exception:\n\n%s" % (
		      pyModName, traceback.format_exc()),
		      file=sys.stderr)
		return 1
	db.flunkDirty()
	return 0

def run_ui(dbPath, timeout, commands):
	passphrase = getPassphrase(dbPath, verbose=not commands)
	if passphrase is None:
		return 1
	try:
		p = libpwman.PWMan(filename=dbPath,
				   passphrase=passphrase,
				   timeout=timeout)
		if commands:
			for command in commands:
				p.runOneCommand(command)
		else:
			p.interactive()
		p.flunkDirty()
	except libpwman.PWManTimeout as e:
		libpwman.util.clearScreen()
		print("pwman session timeout after %d seconds of inactivity." % (
		      e.seconds), file=sys.stderr)
		p.flunkDirty()
		print("exiting...", file=sys.stderr)
		return 1
	return 0

def runQuickSelfTests():
	from libpwman.argon2 import Argon2
	Argon2.get().quickSelfTest()

	from libpwman.aes import AES
	AES.get().quickSelfTest()

def main():
	p = argparse.ArgumentParser(
		description="Commandline password manager - "
			    "pwman version %s" % libpwman.__version__)
	p.add_argument("-v", "--version", action="store_true",
		       help="show the pwman version and exit")
	grp = p.add_mutually_exclusive_group()
	grp.add_argument("-p", "--call-pymod", type=str, metavar="PYTHONSCRIPT.py",
			 help="Calls the Python function run(database) from "
			      "Python module PYTHONSCRIPT. An open PWManDatabase "
			      "object is passed to run().")
	grp.add_argument("-D", "--diff", type=pathlib.Path, default=None, metavar="OLD_DB_PATH",
			 help="Diff the database (see DB_PATH) to the "
			      "older version specified as OLD_DB_PATH.")
	grp.add_argument("-c", "--command", action="append",
			 help="Run this command instead of starting in interactive mode. "
			      "-c|--command may be used multiple times.")
	grp.add_argument("-I", "--info", action="store_true",
			 help="Dump basic information about the database (without decrypting it).")
	p.add_argument("-F", "--diff-format", type=lambda x: str(x).lower().strip(),
		       default="unified",
		       choices=("unified", "context", "ndiff", "html"),
		       help="Select the diff format for the -D|--diff argument.")
	p.add_argument("database", nargs="?", metavar="DB_PATH",
		       type=pathlib.Path, default=libpwman.database.getDefaultDatabase(),
		       help="Use DB_PATH as database file. If not given, %s is used." % (
			    libpwman.database.getDefaultDatabase()))
	p.add_argument("--no-mlock", action="store_true",
		       help="Do not lock memory and allow swapping to disk. "
			    "Do not use this option, if you don't know what this means, "
			    "because this option has security implications.")
	if libpwman.util.osIsPosix:
		p.add_argument("-t", "--timeout", type=int, default=600, metavar="SECONDS",
			       help="Sets the session timeout in seconds. Default is 10 minutes.")
	args = p.parse_args()

	if args.version:
		print("pwman version %s" % libpwman.__version__)
		return 0

	exitcode = 1
	try:
		interactiveMode = (not args.command and
				   not args.diff and
				   not args.call_pymod and
				   not args.info)

		# Lock memory to RAM.
		if not args.no_mlock and not args.info:
			err = libpwman.mlock.MLockWrapper.get().mlockall()
			baseMsg1 = "Failed to lock the pwman program memory to RAM to avoid "\
				   "swapping secrets to disk.\nThe system call returned:"
			baseMsg2 = "The contents of the decrypted password database "\
				   "or the master password could possibly be written "\
				   "to an unencrypted swap-file or swap-partition on disk."
			baseMsg3 = "If you have an unencrypted swap space and if this is a problem, "\
				   "please abort NOW."
			if err and interactiveMode:
				print("\nWARNING: %s '%s'\n%s\n%s\n" % (
				      baseMsg1,
				      err,
				      baseMsg2,
				      baseMsg3),
				      file=sys.stderr)
			if err and not interactiveMode:
				raise libpwman.PWManError("Failed to lock memory: %s" % (err, ))

		if not args.info:
			runQuickSelfTests()

		if args.info:
			assert not interactiveMode
			exitcode = run_infodump(dbPath=args.database)
		elif args.diff:
			assert not interactiveMode
			exitcode = run_diff(dbPath=args.database,
					    oldDbPath=args.diff,
					    diffFormat=args.diff_format)
		elif args.call_pymod:
			assert not interactiveMode
			exitcode = run_script(dbPath=args.database,
					      pyModName=args.call_pymod)
		else:
			assert interactiveMode != bool(args.command)
			exitcode = run_ui(dbPath=args.database,
					  timeout=args.timeout if libpwman.util.osIsPosix else None,
					  commands=args.command)
	except libpwman.database.CSQLError as e:
		print("SQL error: " + str(e), file=sys.stderr)
		return 1
	except libpwman.PWManError as e:
		print("Error: " + str(e), file=sys.stderr)
		return 1
	return exitcode

if __name__ == "__main__":
	sys.exit(main())
