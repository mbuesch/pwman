#!/bin/sh

# basedir is the root of the test directory in the package
basedir="$(dirname "$0")"
[ "$(echo "$basedir" | cut -c1)" = '/' ] || basedir="$PWD/$basedir"

# rootdir is the root of the package
rootdir="$basedir/.."


die()
{
	[ -n "$*" ] && echo "$*" >&2
	exit 1
}

# $1=interpreter
# $2=test_dir
run_pyunit()
{
	local interpreter="$1"
	local test_dir="$2"

	(
		echo
		echo "==="
		echo "= Running $interpreter, PWMAN_CRYPTOLIB=\"$PWMAN_CRYPTOLIB\""
		echo "==="
		export PYTHONPATH="$rootdir/tests:$PYTHONPATH"
		cd "$rootdir" || die "Failed to cd to rootdir."
		"$interpreter" -m unittest --failfast --buffer --catch --verbose "$test_dir" ||\
			die "Test failed"
	) || die
}

# $1=test_dir
run_testdir()
{
	local test_dir="$1"

	unset PYTHONPATH
	unset PYTHONSTARTUP
	unset PYTHONY2K
	unset PYTHONOPTIMIZE
	unset PYTHONDEBUG
	export PYTHONDONTWRITEBYTECODE=1
	unset PYTHONINSPECT
	unset PYTHONIOENCODING
	unset PYTHONNOUSERSITE
	unset PYTHONUNBUFFERED
	unset PYTHONVERBOSE
	export PYTHONWARNINGS=once
	export PYTHONHASHSEED=random

	unset PWMAN_DATABASE
	unset PWMAN_RAWGETPASS
	unset PWMAN_CRYPTOLIB

	run_pyunit python3 "$test_dir"
	export PWMAN_CRYPTOLIB=cryptodome
	run_pyunit python3 "$test_dir"
	export PWMAN_CRYPTOLIB=pyaes
	run_pyunit python3 "$test_dir"
}

run_tests()
{
	run_testdir tests
}

run_tests
