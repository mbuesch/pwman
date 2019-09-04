#!/bin/sh
#
# Generate documentation
#


basedir="$(dirname "$0")"
[ "$(echo "$basedir" | cut -c1)" = '/' ] || basedir="$PWD/$basedir"

srcdir="$basedir/.."


die()
{
	echo "$*" >&2
	exit 1
}

gen_rst()
{
	local rst="$1"
	local docname="$(basename "$rst" .rst)"
	local dir="$(dirname "$rst")"
	local html="$dir/$docname.html"

	echo "Generating $(realpath --relative-to="$srcdir" "$html") from $(realpath --relative-to="$srcdir" "$rst") ..."
	python3 -m readme_renderer -o "$html" "$rst" ||\
		die "Failed to generate"
}

gen_pydoc()
{
	local py="$1"
	local basename="$(basename "$py" .py)"
	local dir="$(dirname "$py")"
	local reldir="$(realpath --relative-to="$srcdir" "$dir")"
	local targetdoc="$srcdir/doc/api/$reldir"

	if [ "$reldir" = "tests" -o \
	     "$basename" = "__init__" -o \
	     "$basename" = "__main__" -o \
	     "$basename" = "setup" -o \
	     "$basename" = "examplescript" ]; then
		return
	fi

	(
		mkdir -p "$targetdoc" || die "Failed to create target dir"
		cd "$targetdoc" || die "Failed to cd"
		export PYTHONPATH="$srcdir"
		pydoc3 -w "$py" || die "Failed to generate pydoc3"
	) || die
}

opt_genrst=1
opt_genpydoc=1

while [ $# -ge 1 ]; do
	case "$1" in
	-r)
		opt_genrst=0
		;;
	-p)
		opt_genpydoc=0
		;;
	*)
		die "Unknown option: $1"
		;;
	esac
	shift
done

if [ $opt_genrst -ne 0 ]; then
	for i in $(find "$srcdir" -name '*.rst' -print); do
		gen_rst "$i"
	done
fi

if [ $opt_genpydoc -ne 0 ]; then
	for i in $(find "$srcdir" -name '*.py' -print); do
		gen_pydoc "$i"
	done
fi

exit 0
