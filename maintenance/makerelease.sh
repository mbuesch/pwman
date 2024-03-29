#!/bin/sh

srcdir="$(realpath "$0" | xargs dirname)"

srcdir="$srcdir/.."

die() { echo "$*"; exit 1; }

# Import the makerelease.lib
# https://bues.ch/cgit/misc.git/tree/makerelease.lib
for path in $(echo "$PATH" | tr ':' ' '); do
	[ -f "$MAKERELEASE_LIB" ] && break
	MAKERELEASE_LIB="$path/makerelease.lib"
done
[ -f "$MAKERELEASE_LIB" ] && . "$MAKERELEASE_LIB" || die "makerelease.lib not found."

hook_get_version()
{
	local file="$1/libpwman/version.py"
	local maj="$(cat "$file" | grep -Ee '^VERSION_MAJOR\s+=\s+' | head -n1 | awk '{print $3;}')"
	local min="$(cat "$file" | grep -Ee '^VERSION_MINOR\s+=\s+' | head -n1 | awk '{print $3;}')"
	local ext="$(cat "$file" | grep -Ee '^VERSION_EXTRA\s+=\s+' | head -n1 | awk '{print $3;}' | cut -d'"' -f2)"
	version="${maj}.${min}${ext}"
}

hook_regression_tests()
{
	default_hook_regression_tests "$@"

	# Run selftests
	sh "$1/tests/run.sh"
}

hook_post_documentation()
{
	"$1"/maintenance/gen-doc.sh -r
}

project=pwman-python
default_archives=py-sdist-xz
makerelease "$@"
