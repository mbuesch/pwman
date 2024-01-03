#!/bin/sh
#
# Create a new Python virtualenv and install pwman into it.
#
# By default the virtualenv is created in the directory 'pwman-venv'.
# Another directory may be selected as an argument to this script.
#

basedir="$(realpath "$0" | xargs dirname)"

default_venvdir="$basedir/pwman-venv"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

usage()
{
	echo "Usage: install_to_venv.sh [OPTS] [VENV_PATH]"
	echo
	echo "VENV_PATH: Path to the venv to create. Default: $default_venvdir"
	echo
	echo "Opts:"
	echo "  -i|--no-install   Only create the venv. Do not install pwman into it."
}

venvdir="$default_venvdir"
opt_install=1

while [ $# -ge 1 ]; do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		-i|--no-install)
			opt_install=0
			;;
		*)
			venvdir="$1"
			shift
			break
			;;
	esac
	shift
done
if [ $# -ne 0 ]; then
	usage
	die "Invalid options"
fi

[ "$(id -u)" != "0" ] || die "Don't run this script as root."
cd "$basedir" || die "Failed to cd to basedir."
rm -rf "$venvdir" || die "Failed to rm."
python3 -m venv --clear --system-site-packages "$venvdir" || die "python3 -m venv failed."
. "$venvdir"/bin/activate || die "venv activate failed."
pip3 install pycryptodomex || die "pip install pycryptodomex failed."
pip3 install pyaes || die "pip install pyaes failed."
pip3 install argon2-cffi || die "pip install argon2-cffi failed."
pip3 install argon2pure || die "pip install argon2pure failed."
if [ $opt_install -ne 0 ]; then
	./setup.py install || die "Failed to install pwman."
fi
