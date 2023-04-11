# -*- coding: utf-8 -*-

import sys
if sys.version_info[0:2] < (3, 7):
	raise Exception("pwman requires Python >=3.7")
del sys

import libpwman.database
import libpwman.dbdiff
import libpwman.exception
import libpwman.mlock
import libpwman.otp
import libpwman.ui
import libpwman.util
import libpwman.version

from libpwman.exception import *
from libpwman.ui import *
from libpwman.version import *

__version__ = VERSION_STRING
