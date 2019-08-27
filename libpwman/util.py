# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

import curses
import getpass
import os
import sys

__all__ = [
	"osIsWindows",
	"osIsPosix",
	"uniq",
	"stdout",
	"clearScreen",
	"readPassphrase",
]

osIsWindows = os.name == "nt" or os.name == "ce"
osIsPosix = os.name == "posix"

def uniq(l, sort=True):
	l = list(set(l))
	if sort:
		l.sort()
	return l

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
			print("Passwords don't match. Try again...",
			      file=sys.stderr)
	except (EOFError, KeyboardInterrupt) as e:
		print("")
		return None
	except (getpass.GetPassWarning) as e:
		print(str(e), file=sys.stderr)
		return None
