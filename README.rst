pwman - Commandline password manager
====================================

`Homepage <https://bues.ch/h/pwman>`_

`Git repository <https://bues.ch/cgit/pwman.git>`_

`Github repository <https://github.com/mbuesch/pwman>`_

pwman is a commandline based password manager. It encrypts the password database file using strong AES-256 encryption.

pwman has support for the following things:

* Store arbitrary attributes and text data along with the passwords and login credentials.
* Generate two factor authentication tokens (`TOTP <https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm>`_).
* Database search with Regular Expressions or SQL LIKE syntax.
* Database compare (diff). In pwman prompt, at pwman command line and as `git diff` extension.
* Shell-style Tab-completion for all commands.
* Custom Python scripts for arbitrary database processing.
* Export of the complete database as SQL text dump, CSV dump and human readable plain text dump.

Algorithms
==========

+--------------------------------+--------------------------------------------+
| Encryption algorithm:          | AES in CBC mode with 256 bit key.          |
+--------------------------------+--------------------------------------------+
| Key derivation function (KDF): | Argon2id with 24 MiB memory cost           |
|                                | or more (see environment variables below). |
+--------------------------------+--------------------------------------------+

Install pwman
=============

pwman does not have to be installed. The `pwman` script can be run directly from the source tree.
It is not recommended to install pwman into the operating system.

Installing pwman into a virtualenv
----------------------------------

If you want to install pwman into a Python virtualenv, run the following commands to create a new venv and install pwman from `PyPi <https://pypi.org/>`_:

.. code:: sh

	python3 -m venv --system-site-packages ./pwman-venv
	. ./pwman-venv/bin/activate
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

Crypto backends
===============

Pwman uses either `Cryptodome <https://pypi.org/project/pycryptodomex/>`_ or `pyaes <https://pypi.org/project/pyaes/>`_ for AES encryption.
Therefore, either one of these Python modules has to be installed.
Pwman first tries to use Cryptodome and then falls back to pyaes, if Cryptodome is not installed.

For key derivation either `argon2-cffi <https://pypi.org/project/argon2-cffi/>`_ or `argon2pure <https://pypi.org/project/argon2pure/>`_ can be used.
Preferably `argon2-cffi` shall be installed.
As an option `argon2pure` is supported.
`argon2pure` is a pure Python implementation of the algorithm and it is *extremely* slow.
Therefore, it will never be selected automatically.
See environment variables.

Environment variables
=====================

Environment variables that affect pwman operation are:

+----------------------+--------------------------------------------+------------------------------+----------------+
| Environment variable | Description                                | Possible values              | Default        |
+======================+============================================+==============================+================+
| PWMAN_CRYPTOLIB      | Select the crypto backend                  | "cryptodome", "pyaes"        | probe in order |
+----------------------+--------------------------------------------+------------------------------+----------------+
| PWMAN_ARGON2LIB      | Select the Argon2 backend                  | "argon2-cffi", "argon2pure"  | "argon2-cffi"  |
+----------------------+--------------------------------------------+------------------------------+----------------+
| PWMAN_ARGON2MEM      | Set the amount of memory (in KiB) used     | Number of KiB,               | 131096         |
|                      | for key derivation.                        | but not less than 24584.     |                |
|                      | Increasing this value improves security,   |                              |                |
|                      | but it also increases the amount of memory |                              |                |
|                      | required during encryption and decryption. |                              |                |
+----------------------+--------------------------------------------+------------------------------+----------------+
| PWMAN_ARGON2TIME     | Set the time used for key derivation.      | Number of iterations,        | 31             |
|                      | Increasing this value improves security,   | but not less than 2          |                |
|                      | but it also increases the time required    | and not less than            |                |
|                      | for encryption and decryption.             | 2500000 / PWMAN_ARGON2MEM.   |                |
+----------------------+--------------------------------------------+------------------------------+----------------+
| PWMAN_DATABASE       | Path to the default database               | any file path                | ~/.pwman.db    |
+----------------------+--------------------------------------------+------------------------------+----------------+
| PWMAN_RAWGETPASS     | If true, do not use safe master            | boolean                      | false          |
|                      | password input. Read directly              | (0, 1, true, false, yes, no) |                |
|                      | from stdin instead.                        |                              |                |
+----------------------+--------------------------------------------+------------------------------+----------------+

You probably don't need to set any environment variable to use pwman.
The default values are most likely what you want.

Out of memory errors
====================

Pwman uses a strong and memory hard algorithm (Argon2id) to derive the master encryption key from the user supplied master passphrase.
This algorithm uses lots of memory (and time) to make brute forcing the key expensive.
This significantly improves security, if the master passphrase has less entropy than the raw AES-256 key.

Pwman also locks all memory to RAM, so that no secrets and keys are written to swap disk space.
Therefore, pwman might crash if the actual memory usage during key derivation exceeds the system's memory lock limit.

To increase the locked memory available to applications, please increase the OS limits by installing a raised limit as follows:

.. code:: sh

	# as root:
	cp pwman-memlock-limits.conf /etc/security/limits.d/
	reboot

Swap partition
==============

Pwman locks all memory to ensure that no secrets are copied from RAM to possibly unencrypted swap disk space.

However, pwman can only lock its own memory.
It cannot lock memory owned by the window manager, X11, Wayland, the terminal emulator or anything else.
Therefore, it is *strongly* recommended to avoid using unencrypted swap disk space when using pwman.
If you have unencrypted swap space it is possible that (parts of) the database or the master passphrase end up being written to it.

Therefore, please use encrypted swap space, if you need swap space.
If you do not need swap space, please disable swap entirely.

Do *not* use unencrypted swap space.

Pwman currently only locks memory on Linux and Android platforms.
If pwman is unable to lock memory, it will print a warning message and give you a chance to abort.

License / Copyright
===================

Copyright (c) 2011-2025 Michael Büsch <m@bues.ch>

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
