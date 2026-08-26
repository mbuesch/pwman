#!/bin/sh

basedir="$(dirname "$(realpath "$0")")"
base="$basedir/.."

set -e

if ! [ -x "$base/setup.py" ]; then
	echo "basedir sanity check failed"
	exit 1
fi

cd "$base"

find . \( \
	\( -name '__pycache__' \) -o \
	\( -name '*.pyo' \) -o \
	\( -name '*.pyc' \) -o \
	\( -name '*$py.class' \) \
       \) -delete

rm -rf doc/api
rm -rf build dist .pybuild *.egg-info
rm -f MANIFEST
rm -f *.html
