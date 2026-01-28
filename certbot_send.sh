#!/bin/sh

# Copyright (C) 2022, 2026 Keith Allen Bare II
#
# This file is part of cert-propagation.
#
# cert-propagation is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# cert-propagation is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with cert-propagation. If not, see <https://www.gnu.org/licenses/>.

set -e

usage() {
    echo "usage: ${0##*/} [--config-dir=DIR] [--config-file=FILE]" >&2
    echo "    [--defaults-file=FILE | --no-defaults-file] [--dry-run]" >&2
}

version() {
    echo "${0##*/} version 0.3"
    echo "Copyright (C) 2022, 2026 Keith Allen Bare II"
    echo
    echo "This script comes with ABSOLUTELY NO WARRANTY.  It is free software"
    echo "and you are welcome to redistribute it.  For details, see the GNU"
    echo "General Public License, either version 3, or (at your option) any"
    echo "later version.  <https://www.gnu.org/licenses/gpl.html>"
}

CONFIG_NAME=

check_renewed_lineage() {
    if [ -z "$RENEWED_LINEAGE" ]; then
        echo "Error: the RENEWED_LINEAGE environment variable is not set" >&2
        exit 1
    elif ! [ -d "$RENEWED_LINEAGE" ]; then
        echo "Error: the RENEWED_LINEAGE environment variable does not refer" >&2
        echo "to a directory" >&2
        exit 1
    fi
    CONFIG_NAME="${RENEWED_LINEAGE##*/}"
}

CONFIG_DIR=
if [ -d /etc/certbot_send ]; then
    CONFIG_DIR=/etc/certbot_send
fi
CONFIG_FILE=
DEFAULTS_FILE=
NO_DEFAULTS_FILE=
DRY_RUN=

while [ $# -gt 0 ]; do
    option=
    need_value=
    case "$1" in
    --config-dir|--config-dir=*)
        option=config-dir
        need_value=1
        ;;
    --config-file|--config-file=*)
        option=config-file
        need_value=1
        ;;
    --defaults-file|--defaults-file=*)
        option=defaults-file
        need_value=1
        ;;
    --no-defaults-file)
        NO_DEFAULTS_FILE=1
        ;;
    -n|--dry-run)
        DRY_RUN=1
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    -V|--version)
        version
        exit 0
        ;;
    --)
        shift
        break
        ;;
    -[^-]*|--[^-]*)
        echo "Error: unrecognized option: $1" >&2
        usage
        exit 1
        ;;
    *)
        break
        ;;
    esac

    if [ -n "$need_value" ]; then
        value="${1#*=}"
        if [ "$value" = "$1" ]; then
            if [ $# -lt 2 ]; then
                echo "Error: missing value for --$option option" >&2
                usage
                exit 1
            fi
            value="$2"
            shift
        fi
    fi

    case "$option" in
    config-dir)
        CONFIG_DIR="$value"
        ;;
    config-file)
        CONFIG_FILE="$value"
        ;;
    defaults-file)
        DEFAULTS_FILE="$value"
        ;;
    esac

    shift
done

if [ $# -ne 0 ]; then
    echo "Error: too many arguments" >&2
    usage
    exit 1
fi

if [ -z "$CONFIG_FILE" ]; then
    check_renewed_lineage
    CONFIG_FILE="$CONFIG_DIR/$CONFIG_NAME.conf"
fi
if ! [ -f "$CONFIG_FILE" ]; then
    echo "Error: configuration file does not exist" >&2
    echo "($CONFIG_FILE)" >&2
    exit 1
fi

if [ -n "$DEFAULTS_FILE" ] && ! [ -f "$DEFAULTS_FILE" ]; then
    echo "Error: defaults file does not exist" >&2
    echo "($DEFAULTS_FILE)" >&2
    exit 1
elif [ -z "$DEFAULTS_FILE" ] && [ -z "$NO_DEFAULTS" ]; then
    DEFAULTS_FILE="$CONFIG_DIR/defaults"
fi

hostname=
sshconfig=
if [ -e "$CONFIG_DIR"/ssh_config ]; then
    sshconfig=ssh_config
fi
sshkey=
timeout=90

if [ -n "$DEFAULTS_FILE" ] && [ -f "$DEFAULTS_FILE" ]; then
    if [ -n "$DRY_RUN" ]; then
        echo "Using defaults file $DEFAULTS_FILE" >&2
    fi
    . "$DEFAULTS_FILE"
fi
if [ -n "$DRY_RUN" ]; then
    echo "Using config file $CONFIG_FILE" >&2
fi
. "$CONFIG_FILE"

if [ -z "$hostname" ]; then
    echo "Error: configuration does not have a value for hostname" >&2
    exit 1
fi

for var in sshconfig sshkey; do
    if eval "[ -z \"\$$var\" ]"; then
        echo "Warning: configuration does not have a value for $var" >&2
    elif eval "[ \"\${$var#/}\" = \"\$$var\" ]"; then
        # The variable does not start with "/", prepend "$CONFIG_DIR"
        eval "$var=\"\$CONFIG_DIR/\$$var\""
    fi
done


check_renewed_lineage

if [ -n "$DRY_RUN" ]; then
    echo "Would execute the following commands:" >&2
fi

set -f

failed=
command="timeout -k \"\$((\$timeout + 10))\"  \"\$timeout\""\
\ "ssh \${sshconfig:+-F \"\$sshconfig\"}"\
\ "\${sshkey:+-o IdentityFile=\"\$sshkey\"} \"\$host\" cert_receive.py"
for host in $hostname; do
    if [ -n "$DRY_RUN" ]; then
        eval "echo $command" >&2
        continue
    fi
    (printf '%s\n' "$CONFIG_NAME";
     exec cat "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem") |
        eval "$command" || failed=1
done

set +f

if [ -n "$failed" ]; then
    exit 1
fi
exit 0
