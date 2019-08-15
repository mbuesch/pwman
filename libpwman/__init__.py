# -*- coding: utf-8 -*-

import sys
if sys.version_info.major <= 2:
	raise Exception("Python 2 is not supported.")
del sys

import libpwman.database
import libpwman.exception
import libpwman.ui
import libpwman.util
import libpwman.version

from libpwman.exception import *
from libpwman.ui import *
from libpwman.version import *
