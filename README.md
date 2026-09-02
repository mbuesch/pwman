# pwman - Commandline password manager

[Homepage](https://bues.ch/h/pwman)

[Git repository](https://bues.ch/cgit/pwman.git)

[Github repository](https://github.com/mbuesch/pwman)

pwman is a commandline based password manager. It encrypts the password database file using strong AES-256 encryption.

pwman has support for the following things:

* Shell-style Tab-completion for all commands.
* Store arbitrary attributes and text data along with the passwords and login credentials.
* Generate two factor authentication tokens ([TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)).
* Database search with Regular Expressions or SQL LIKE syntax.
* Database compare (diff). In pwman prompt, at pwman command line and as `git diff` extension.
* Custom Python scripts for arbitrary database processing.
* Export of the complete database as SQL text dump, CSV dump and human readable plain text dump.
* Open multiple databases to safely copy/move entries between them.

## Algorithms

- Encryption algorithm: **AES in AEAD-GCM mode with 256 bit key.**
- Key derivation function (KDF): **Argon2id with 128 MiB memory cost.** (Default; See environment variables below)

## Install pwman

It is recommended to install pwman into a virtualenv.

### Installing pwman into a virtualenv

If you want to install pwman into a Python virtualenv, run the following commands to create a new venv and install pwman from [PyPi](https://pypi.org/):

```sh
python3 -m venv --system-site-packages ./pwman-venv
. ./pwman-venv/bin/activate
pip3 install -U pwman-python
```

It is recommended to have a `rustc` Rust compiler available in PATH before building/installing pwman.
For the `argon2purers` fallback module to be available, a `rustc` Rust compiler must be available in PATH.
If a Rust compiler is not available, the `argon2purers` option will be skipped, but pwman will still work fine if `argon2-cffi` is available.

## Run pwman

Just run the `pwman` executable to start pwman.

Type `pwman -h` for help about the command line options.

## pwman prompt

If started without options, pwman enters the command prompt:

```
pwman$
```

Type the command `help` and press enter to see help about all possible commands.

## Command help

To get help about a specific command, enter the command into the prompt and append a question mark without spaces in between:

```
pwman$ find?
```

## Using a custom script to process the database content

A custom Python script can be passed to `pwman` as command line option. Such a script can do anything to the content of the database.

Please see the example script `examplescript.py` for more information.

## API documentation

The API documentation can be found in the [API documentation directory](doc/api/).

## Crypto backends

The default backends used for cryptography are well established Python libraries:

- Encryption: [Cryptodome](https://pypi.org/project/pycryptodomex/)
- Key derivation: [argon2-cffi](https://pypi.org/project/argon2-cffi/)

These are well tested, widely used and audited Python libraries for cryptography.
Pwman will use these libraries, if they are installed and available.

As an alternative, if the default libraries are not available, pwman can fall back to other encryption libraries that come bundled with pwman.
The bundled libraries are also part of the pwman regression tests and are believed to be as secure and reliable as the default ones.

The reason for having bundled fallback libraries is password database access availability.
In case the default libraries are not installed or cannot be installed on the user's system, pwman will automatically use the bundled fallback libraries to ensure that encryption and decryption operations can still be performed and the password database can be accessed.

## Environment variables

Environment variables that affect pwman operation are:

| Environment variable | Description | Possible values | Default |
|---|---|---|---|
| PWMAN_CRYPTOLIB | Select the crypto backend | "cryptodome", "pyaes" | probe in order |
| PWMAN_ARGON2LIB | Select the Argon2 backend | "argon2-cffi", "argon2purers", "argon2pure" | probe in order (except for "argon2pure") |
| PWMAN_ARGON2MEM | Set the amount of memory (in KiB) used for key derivation. Increasing this value improves security, but it also increases the amount of memory required during encryption and decryption. | Number of KiB, but not less than 24584. | 131096 |
| PWMAN_ARGON2TIME | Set the time used for key derivation. Increasing this value improves security, but it also increases the time required for encryption and decryption. | Number of iterations, but not less than 2 and not less than 2500000 / PWMAN_ARGON2MEM. | 31 |
| PWMAN_DATABASE | Path to the default database | any file path | ~/.pwman.db |
| PWMAN_RAWGETPASS | If true, do not use safe master password input. Read directly from stdin instead. | boolean (0, 1, true, false, yes, no) | false |

You probably don't need to set any environment variable to use pwman.
The default values are most likely what you want.

## Out of memory errors

Pwman uses a strong and memory hard algorithm (Argon2id) to derive the master encryption key from the user supplied master passphrase.
This algorithm uses lots of memory (and time) to make brute forcing the key expensive.
This significantly improves security, if the master passphrase has less entropy than the raw AES-256 key.

Pwman also locks all memory to RAM, so that no secrets and keys are written to swap disk space.
Therefore, pwman might crash if the actual memory usage during key derivation exceeds the system's memory lock limit.

To increase the locked memory available to applications, please increase the OS limits by installing a raised limit as follows:

```sh
# as root:
cp pwman-memlock-limits.conf /etc/security/limits.d/
reboot
```

## Swap partition / Swap file

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

## License / Copyright

Copyright (c) 2011-2026 Michael Büsch <m@bues.ch>

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
