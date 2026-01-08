#!/bin/sh
# Safe helper to replace /bin/dsh with fixsh (or rollback).
# Usage:
#   deploy_fixsh_safe.sh [-s /path/to/fixsh] [-d /bin/dsh]
#   deploy_fixsh_safe.sh --rollback [-d /bin/dsh]
# Notes:
#   - Run as root (required to write /bin).
#   - Creates a single backup DEST.bak if absent. Rollback restores it.
#   - Deploy is atomic via a temporary file + mv.

set -euo pipefail

SRC_DEFAULT="$(cd "$(dirname "$0")" && pwd)/fixsh"
DEST=""
SRC="${SRC_DEFAULT}"
ROLLBACK=0
BACKUP_SUFFIX=".bak"

usage() {
    echo "Usage: $0 [--rollback] [-s SRC] [-d DEST]" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rollback)
            ROLLBACK=1; shift ;;
        -s)
            [ $# -ge 2 ] || usage
            SRC="$2"; shift 2 ;;
        -d)
            [ $# -ge 2 ] || usage
            DEST="$2"; shift 2 ;;
        -h|--help)
            usage ;;
        *)
            usage ;;
    esac
done

# Auto-detect DEST if not provided
if [ -z "$DEST" ]; then
    # Prefer PATH lookup (like which/command -v), fallback to common location
    if command -v dsh >/dev/null 2>&1; then
        DEST="$(command -v dsh)"
    elif [ -x /bin/dsh ]; then
        DEST="/bin/dsh"
    else
        echo "[ERR] dsh not found in PATH and /bin/dsh missing; specify with -d" >&2
        exit 1
    fi
fi

if [ "$(id -u)" != "0" ]; then
    echo "[ERR] Need root to write $DEST" >&2
    exit 1
fi

BACKUP="${DEST}${BACKUP_SUFFIX}"

if [ "$ROLLBACK" = "1" ]; then
    if [ ! -f "$BACKUP" ]; then
        echo "[ERR] Backup $BACKUP not found" >&2
        exit 1
    fi
    echo "[INFO] Restoring $BACKUP -> $DEST"
    install -m 755 "$BACKUP" "$DEST"
    echo "[OK] Rollback done"
    exit 0
fi

if [ ! -f "$SRC" ] || [ ! -s "$SRC" ]; then
    echo "[ERR] Source $SRC missing or empty: $SRC" >&2
    exit 1
fi
if [ ! -x "$SRC" ]; then
    echo "[ERR] Source $SRC is not executable" >&2
    exit 1
fi

if [ ! -f "$DEST" ]; then
    echo "[ERR] Target $DEST does not exist; abort" >&2
    exit 1
fi

DEST_DIR="$(dirname "$DEST")"
if [ ! -w "$DEST_DIR" ]; then
    echo "[ERR] No write permission to $DEST_DIR" >&2
    exit 1
fi

if [ ! -f "$BACKUP" ]; then
    echo "[INFO] Creating backup $BACKUP"
    if ! cp -p "$DEST" "$BACKUP" 2>/dev/null; then
        echo "[ERR] Failed to create backup $BACKUP" >&2
        exit 1
    fi
fi

TMP="$(mktemp "$DEST.tmp.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

echo "[INFO] Installing $SRC -> $DEST"
install -m 755 "$SRC" "$TMP"
mv "$TMP" "$DEST"

trap - EXIT
rm -f "$TMP" 2>/dev/null || true

echo "[OK] Deployed. Backup at $BACKUP. Use --rollback to restore."

