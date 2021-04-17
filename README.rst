pwman - Commandline password manager
====================================

https://bues.ch/h/pwman

pwman is a commandline based password manager. It encrypts the password database file using strong AES-256 encryption.

pwman has support for the following things:

* Store arbitrary attributes and text data along with the passwords and login credentials.
* Generate two factor authentication tokens (`TOTP <https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm>`_).
* Database search with Regular Expressions or SQL LIKE syntax.
* Database compare (diff). In pwman prompt, at pwman command line and as `git diff` extension.
* Shell-style Tab-completion for all commands.
* Custom Python scripts for arbitrary database processing.
* Export of the complete database as SQL text dump, CSV dump and human readable plain text dump.

Install pwman
=============

pwman does not have to be installed. The `pwman` script can be run directly from the source tree.

However if you want to install pwman, it can be done either directly from the source tree by running the following commands:

.. code:: sh

	./setup.py build
	sudo -i  # Or any other command to become root
	./setup.py install

Or it can be installed vi `PyPi <https://pypi.org/>`_ by running the following commands:

.. code:: sh

	pip3 install -U pyaes
	pip3 install -U pwman-python

Run pwman
=========

Just run the `pwman` executable to start pwman.

Type `pwman -h` for help about the command line options.


pwman prompt
============

If started without options, pwman enters the command prompt:

.. code::

	pwman$

Type the command `help` and press enter to see help about all possible commands.

Command help
============

To get help about a specific command, enter the command into the prompt and append a question mark without spaces in between:

.. code::

	pwman$ find?

Using a custom script to process the database content
=====================================================

A custom Python script can be passed to `pwman` as command line option. Such a script can do anything to the content of the database.

Please see the example script `examplescript.py` for more information.

API documentation
=================

The API documentation can be found in the `API documentation directory <doc/api/>`_.

License / Copyright
===================

Copyright (c) 2011-2021 Michael Buesch <m@bues.ch>

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
