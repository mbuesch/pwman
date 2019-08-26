pwman - Commandline password manager
====================================

https://bues.ch/h/pwman

pwman is a commandline based password manager. It encrypts the password database file using strong AES-256 encryption.

pwman has support for:

* Store arbitrary attributes and text data along with the passwords and login credentials.
* Generate two factor authentication tokens (`TOTP <https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm>`_).
* Database compare (diff). In pwman prompt, at pwman command line and as `git diff` extension.
* Shell-style Tab-completion for all commands.
* Export of the complete database as SQL text dump and plain text.

Install pwman
=============

Execute the following commands to install the application:

.. code:: sh

	./setup.py build
	sudo -i  # Or any other command to become root
	./setup.py install


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

License / Copyright
===================

Copyright (c) 2011-2019 Michael Buesch <m@bues.ch>

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
