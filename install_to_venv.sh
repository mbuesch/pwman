#!/bin/sh
#
# Create a new Python virtualenv and install pwman into it.
#
# By default the virtualenv is created in the directory 'pwman-venv'.
# Another directory may be selected as an argument to this script.
#

basedir="$(realpath "$0" | xargs dirname)"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

if [ $# -eq 0 ]; then
	venvdir="$basedir/pwman-venv"
elif [ $# -eq 1 ]; then
	venvdir="$1"
else
	die "Usage: $0 [VENV_PATH]"
fi

[ "$(id -u)" != "0" ] || die "Don't run this script as root."
cd "$basedir" || die "Failed to cd to basedir."
virtualenv --clear --system-site-packages "$venvdir" || die "virtualenv failed."
. "$venvdir"/bin/activate || die "venv activate failed."
pip3 install pycryptodomex || die "pip install pycryptodomex failed."
pip3 install pyaes || die "pip install pyaes failed."
./setup.py install || die "Failed to install pwman."
