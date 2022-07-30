#!/bin/sh

set -e

usage() {
    echo "${0##*/} [--config-dir=DIR] [--config-file=FILE]" >&2
    echo "    [--defaults-file=FILE | --no-defaults-file] [--dry-run]" >&2
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
    --help)
        usage
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

sequenced=
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
    . "$DEFAULTS_FILE"
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
    exit 0
fi

failed=
for host in $hostname; do
    (printf '%s\n' "$CONFIG_NAME";
     exec cat "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem") |
        timeout -k $(($timeout + 10)) "$timeout" \
            ssh ${sshconfig:+-F} ${sshconfig:+"$sshconfig"} \
                ${sshkey:+-o} ${sshkey:+IdentityFile="$sshkey"} \
                "$host" cert_receive.py || failed=1
done

if [ -n "$failed" ]; then
    exit 1
else
    exit 0
fi
