# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import curses
import getpass
import os
import sys

__all__ = [
	"str2bool",
	"osIsWindows",
	"osIsPosix",
	"stdout",
	"clearScreen",
	"readPassphrase",
]

osIsWindows = os.name == "nt" or os.name == "ce"
osIsPosix = os.name == "posix"

def str2bool(string, default=False):
	s = string.lower().strip()
	if not s:
		return default
	if s in ("true", "yes", "on", "1"):
		return True
	if s in ("false", "no", "off", "0"):
		return False
	try:
		return bool(int(s))
	except ValueError:
		return default

def stdout(text, flush=True):
	if isinstance(text, str):
		stream = sys.stdout
	else:
		stream = getattr(sys.stdout, "buffer", None)
		if stream is None:
			stream = sys.stdout
			text = text.decode("UTF-8", "ignore")
	stream.write(text)
	if flush:
		stream.flush()

def clearScreen():
	try:
		stdscr = curses.initscr()
		stdscr.clear()
	finally:
		curses.endwin()
	stdout("\x1B[2J\x1B[0;0f")

def _do_getpass(prompt):
	if str2bool(os.getenv("PWMAN_RAWGETPASS", "")):
		return input(prompt)
	else:
		return getpass.getpass(prompt)

def readPassphrase(prompt, verify=False):
	if verify:
		prompt = "[New] " + prompt
	try:
		while True:
			p0 = _do_getpass(prompt + ": ")
			if not p0:
				continue
			if not verify:
				return p0
			p1 = _do_getpass(prompt + " (verify): ")
			if p0 == p1:
				return p0
			print("Passwords don't match. Try again...",
			      file=sys.stderr)
	except (EOFError, KeyboardInterrupt) as e:
		print("")
		return None
	except (getpass.GetPassWarning) as e:
		print(str(e), file=sys.stderr)
		return None
