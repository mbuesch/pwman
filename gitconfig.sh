#!/bin/sh
#
# This script configures a git repository to support pwman database diff-ing.
#

set -e

if ! [ -d .git ]; then
	echo "ERROR: The current directory is not a git repository." >&2
	exit 1
fi

git config --replace-all diff.pwman.textconv "pwman -c \"dbdump -h\""

if ! [ -e .gitattributes ] ||\
   ! grep -q 'diff=pwman' .gitattributes; then
	echo "*.db diff=pwman" >> .gitattributes
fi

exit 0
