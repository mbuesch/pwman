#!/bin/bash
set -e

project="pwman"

basedir="$(dirname "$0")"
[ "${basedir:0:1}" = "/" ] || basedir="$PWD/$basedir"

origin="$basedir"

do_git_tag=1
[ "$1" = "--notag" ] && do_git_tag=0

version="$(cat libpwman.py | grep -e VERSION | head -n1 | cut -d'=' -f2 | tr -d ' ')"
if [ -z "$version" ]; then
	echo "Could not determine version!"
	exit 1
fi
release_name="$project-$version"
tarball="$release_name.tar.bz2"
tagname="release-$version"
tagmsg="$project-$version release"

export GIT_DIR="$origin/.git"

cd /tmp/
rm -Rf "$release_name" "$tarball"
echo "Creating target directory"
mkdir "$release_name"
cd "$release_name"
echo "git checkout"
git checkout -f

rm .gitignore makerelease.sh

echo "creating tarball"
cd ..
tar cjf "$tarball" "$release_name"
mv "$tarball" "$origin"

echo "running testbuild"
cd "$release_name"
./setup.py build
./pwman --help >/dev/null
./pwman-import-pwmanager --help >/dev/null

echo "removing testbuild"
cd ..
rm -R "$release_name"


if [ "$do_git_tag" -ne 0 ]; then
	echo "Tagging GIT"
	cd "$origin"
	git tag -m "$tagmsg" -a "$tagname"
fi

echo
echo "built release $version"
