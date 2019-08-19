# -*- coding: utf-8 -*-
"""
# Simple password manager
# Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>
# Licensed under the GNU/GPL version 2 or later.
"""

__all__ = [
	"UndoStack",
]

class UndoCommand(object):
	def __init__(self, doCommands, undoCommands):
		if isinstance(doCommands, (tuple, list)):
			self.doCommands = tuple(doCommands)
		else:
			self.doCommands = (doCommands, )
		if isinstance(undoCommands, (tuple, list)):
			self.undoCommands = tuple(undoCommands)
		else:
			self.undoCommands = (undoCommands, )

class UndoStack(object):
	def __init__(self, limit=2**15):
		self.limit = limit
		self.frozen = 0
		self.clear()

	def __stackAppend(self, stack, c):
		stack.append(c)
		while len(stack) > self.limit:
			stack.pop(0)

	def do(self, doCommands, undoCommands):
		if self.frozen:
			return
		c = UndoCommand(doCommands, undoCommands)
		self.__stackAppend(self.undoStack, c)
		self.redoStack = []

	def undo(self):
		if not self.undoStack:
			return None
		c = self.undoStack.pop()
		self.__stackAppend(self.redoStack, c)
		return c

	def redo(self):
		if not self.redoStack:
			return None
		c = self.redoStack.pop()
		self.__stackAppend(self.undoStack, c)
		return c

	def clear(self):
		self.undoStack = []
		self.redoStack = []

	def freeze(self):
		assert(self.frozen >= 0)
		self.frozen += 1

	def thaw(self):
		self.frozen -= 1
		assert(self.frozen >= 0)
