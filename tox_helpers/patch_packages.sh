#!/bin/sh

# Copyright (C) 2026 Keith Allen Bare II
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

my_dir="${0%/*}"
case my_dir in
/*)
    ;;
*)
    my_dir="$PWD/$my_dir"
    ;;
esac

usage() {
    echo "USAGE: ${0##*/} {env_dir} {patch ...} -- {pip_option ...} -- {package ...}" >&2
}

if [ x"$1" = x"" ]; then
    echo "missing env_dir" >&2
    usage
    exit 1
fi
if [ ! -e "$1" ]; then
    echo "env_dir '$1' does not exist" >&2
    exit 1
fi
if [ ! -d "$1" ]; then
    echo "env_dir '$1' is not a directory" >&2
    exit 1
fi
env_dir="$1"
shift

PYTHON="$env_dir/bin/python"
isolate="-I"

quote() {
    printf '%s\n' "$1" |
        sed -e "s/'/'\\\\''/g" -e "s/^/'/" -e "s/\$/'/"
}

patches=
while [ $# -gt 0 ] && [ x"$1" != x"--" ]; do
    patches="$patches `quote "$1"`"
    shift
done
if [ x"$1" != x"--" ]; then
    echo "missing pip_options" >&2
    usage
    exit 1
fi
shift

pip_options=
while [ $# -gt 0 ] && [ x"$1" != x"--" ]; do
    pip_options="$pip_options `quote "$1"`"
    shift
done
if [ x"$1" != x"--" ]; then
    echo "missing packages" >&2
    usage
    exit 1
fi
shift

constraints="$env_dir/tmp/constraints.txt"
cat /dev/null > "$constraints"

packages=
while [ $# -gt 0 ]; do
    packages="$packages `quote "$1"`"
    case "$1" in
    -c|-r)
        if [ x"$2" = x"" ]; then
            echo "no argument for $1 in packages" >&2
            exit 1
        fi
        if ! [ -r "$2" ] || ! [ -f "$2" ]; then
            echo "argument for $1 in packages is not a readable file" >&2
            exit 1
        fi
        packages="$packages `quote "$2"`"
        cat "$2" >> "$constraints"
        shift
        ;;
    *)
        printf '%s\n' "$1" >> "$constraints"
        ;;
    esac
    shift
done

do_patch_build_and_install() {
    local patch="$my_dir/$1"
    local requirement="$2"

    local tmp_dir="$env_dir/tmp" tarball distname stem res
    (cd "$tmp_dir" &&
     "$PYTHON" $isolate -m pip download --no-deps "$requirement")
    res=$?
    # Older versions of pip don't have a separate "download" command, so if we
    # failed above, we'll try "install --download" too.
    if [ $res -ne 0 ]; then
        (cd "$tmp_dir" &&
         "$PYTHON" $isolate -m pip install \
                   --no-deps --download . "$requirement") || return $?
    fi

    tarball=`cd "$tmp_dir" && ls -1d "${requirement%%[=<>!]*}"*.tar.gz`
    if [ x"$tarball" = x"" ] || ! [ -f "$tmp_dir/$tarball" ]; then
        return 1
    fi
    distname="${tarball%.tar.gz}"
    rm -rf "$tmp_dir/$distname"
    tar -zxf "$tmp_dir/$tarball" -C "$tmp_dir" || return $?
    (cd "$tmp_dir/$distname" && patch -f -p1 < "$patch") || return $?

    "$PYTHON" $isolate -m pip install \
              --force-reinstall --no-binary="${distname%-*}" \
              -c "$constraints" "$tmp_dir/$distname"
    res=$?
    # Pip 19.1.1 (the latest version that works with Python 3.4) can't satisfy
    # constraints with packages installed from a path or URL.  So if we failed
    # above, we'll try again leaving the package we've patched out of the
    # constraints file.
    if [ $res -ne 0 ]; then
        stem="${distname%-*}"
        grep -v "^$stem[=<>!]" "$contraints" > "${constraints%.txt}2.txt"
        "$PYTHON" $isolate -m pip install \
                  --force-reinstall --no-binary="${distname%-*}" \
                  -c "${constraints%.txt}2.txt" "$tmp_dir/$distname" || return $?
    fi

    return 0
}

eval "set -- $patches"
for patch in "$@"; do
    stem="${patch%-*}"
    requirement=
    eval "set -- $packages"
    while [ $# -gt 0 ]; do
        case "$1" in
        -c|-r)
            shift
            ;;
        "$stem"[=\<\>!]*)
            requirement="$1"
            break
            ;;
        esac
        shift
    done
    if [ x"$requirement" = x"" ]; then
        echo "could not find a requirement corresponding to $patch" >&2
        continue
    fi
    do_patch_build_and_install "$patch" "$requirement" || exit $?
done

eval "exec \"\$PYTHON\" $isolate -m pip install $pip_opts $packages"
