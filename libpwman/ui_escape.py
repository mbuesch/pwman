# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2024 Michael Büsch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

__all__ = [
	"EscapeError",
	"escapeCmd",
	"unescapeCmd",
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
