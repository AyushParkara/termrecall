#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# POSIX bootstrap for TermRecall per-user source install/upgrade.
#
# This script exclusively owns application fresh install and upgrade.  It
# validates shell syntax, resolves explicit source/home/XDG inputs, and runs
# the source-tree stdlib installer_probe.py as the authoritative planner and
# renderer before any build.  Dry-run exits with that output; real execution
# builds/stages the delegate and calls installer_probe.py launch-delegate,
# which re-plans read-only, verifies digest/drift, creates exactly two pipe
# pairs, and spawns the hidden installed bootstrap with bounded canonical
# request/plan descriptors.  The shell never creates regular payload files,
# FIFOs, process substitutions, or arbitrary pipe descriptors, and never
# substitutes the running process, performs unchecked recursive deletion,
# or escalates privileges.

# Strict mode for the parse/validate/probe phase; relaxed around delegate and
# cleanup so captured child/signal status is never overwritten.
set -u

USAGE='usage: install.sh [--bash STATE] [--autostart STATE] [--chooser STATE]
       install.sh MODE [--bash STATE] [--autostart STATE] [--chooser STATE] [--dry-run]
  MODE  := --full | --no-autostart | --commands-only | --upgrade
  STATE := enable | disable | preserve'

# Overridable surfaces for tests; defaults match the plan exactly.
PYTHON="${PYTHON:-python3.12}"
PYFLAGS="${PYFLAGS--B}"
LAUNCH_FLAGS="${LAUNCH_FLAGS--P}"
CLEANUP_HELPER="${CLEANUP_HELPER:-}"

# Resolved later by parse_args / resolve_roots.
MODE=""
BASH_STATE=""
AUTOSTART_STATE=""
CHOOSER_STATE=""
DRY_RUN=no
INTERACTIVE=0
SOURCE_ROOT=""
HOME_ROOT=""
XDG_DATA_ROOT=""
XDG_CONFIG_ROOT=""
XDG_STATE_ROOT=""

BUILD_ROOT=""
BUILD_PARENT_DEV=""
BUILD_PARENT_INO=""
BUILD_ROOT_DEV=""
BUILD_ROOT_INO=""
DELEGATE_PID=""
IN_FINISH=0
RECORDED_CHILD_STATUS=""
RECORDED_CLEANUP_STATUS=""

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

die_usage() {
    printf '%s\n' "$USAGE" >&2
    exit 2
}

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit "$1"
}

# Validate a single state word; empty means "unset".
valid_state() {
    case "$1" in
        enable|disable|preserve) return 0 ;;
        "") return 1 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# parse_args + validate_combination
# ---------------------------------------------------------------------------

parse_args() {
    MODE_SEEN=""
    BASH_SEEN=""
    AUTOSTART_SEEN=""
    CHOOSER_SEEN=""
    while [ $# -gt 0 ]; do
        arg="$1"
        case "$arg" in
            --full|--no-autostart|--commands-only|--upgrade)
                [ -n "$MODE_SEEN" ] && die_usage
                MODE_SEEN=1
                MODE="${arg#--}"
                ;;
            --bash|--autostart|--chooser)
                [ $# -lt 2 ] && die_usage
                case "$arg" in
                    --bash) field=BASH; seen=$BASH_SEEN; BASH_SEEN=1 ;;
                    --autostart) field=AUTOSTART; seen=$AUTOSTART_SEEN; AUTOSTART_SEEN=1 ;;
                    --chooser) field=CHOOSER; seen=$CHOOSER_SEEN; CHOOSER_SEEN=1 ;;
                esac
                [ -n "$seen" ] && die_usage
                value="$2"
                valid_state "$value" || die_usage
                case "$arg" in
                    --bash) BASH_STATE="$value" ;;
                    --autostart) AUTOSTART_STATE="$value" ;;
                    --chooser) CHOOSER_STATE="$value" ;;
                esac
                shift
                ;;
            --dry-run)
                DRY_RUN=yes
                ;;
            --help|-h)
                printf '%s\n' "$USAGE"
                exit 0
                ;;
            *)
                die_usage
                ;;
        esac
        shift
    done
    if [ -z "$MODE_SEEN" ]; then
        INTERACTIVE=1
        MODE=interactive
    fi
}

validate_combination() {
    # --dry-run requires exactly one noninteractive mode
    if [ "$DRY_RUN" = yes ] && [ "$INTERACTIVE" = 1 ]; then
        die_usage
    fi
    case "$MODE" in
        full)
            : # all 27 triples valid
            ;;
        no-autostart)
            [ -n "$AUTOSTART_STATE" ] && [ "$AUTOSTART_STATE" = enable ] && die_usage
            ;;
        commands-only|upgrade)
            for v in "$BASH_STATE" "$AUTOSTART_STATE" "$CHOOSER_STATE"; do
                [ -n "$v" ] && [ "$v" != preserve ] && die_usage
            done
            ;;
        interactive)
            : # prompted later
            ;;
        *)
            die_usage
            ;;
    esac
}

# ---------------------------------------------------------------------------
# privilege + prerequisites
# ---------------------------------------------------------------------------

refuse_privilege() {
    [ "$(id -u)" -eq 0 ] && die 3 "refused: cannot run as root"
    [ -n "${SUDO_USER:-}${SUDO_UID:-}" ] && die 3 "refused: cannot run under sudo"
}

require_prerequisites() {
    [ "${TR_SKIP_PREREQ:-0}" = 1 ] && return
    command -v "$PYTHON" >/dev/null 2>&1 || die 3 "refused: $PYTHON not found"
    "$PYTHON" -c 'import sys; v=sys.version_info; sys.exit(0 if (v[0],v[1])>=(3,12) else 1)' \
        >/dev/null 2>&1 || die 3 "refused: python 3.12 or newer is required"
    "$PYTHON" -c 'import venv' >/dev/null 2>&1 || die 3 "refused: python venv module is required"
    command -v cc >/dev/null 2>&1 || die 3 "refused: C11 compiler (cc) not found"
    command -v bash >/dev/null 2>&1 || die 3 "refused: bash not found"
}

# ---------------------------------------------------------------------------
# root resolution
# ---------------------------------------------------------------------------

resolve_roots() {
    # SOURCE_ROOT is the directory containing this script (no-follow via realpath).
    SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
    [ -f "$SOURCE_ROOT/installer_probe.py" ] || die 3 "refused: source root missing installer_probe.py"
    [ -f "$SOURCE_ROOT/cleanup_private_tree.py" ] || die 3 "refused: source root missing cleanup_private_tree.py"
    HOME_ROOT="${TR_HOME_ROOT:-$HOME}"
    [ -n "$HOME_ROOT" ] || die 3 "refused: HOME is not set"
    HOME_ROOT=$(cd -- "$HOME_ROOT" 2>/dev/null && pwd -P) || die 3 "refused: HOME is not a directory"
    XDG_DATA_ROOT="${TR_XDG_DATA_ROOT:-${XDG_DATA_HOME:-$HOME_ROOT/.local/share}}"
    XDG_CONFIG_ROOT="${TR_XDG_CONFIG_ROOT:-${XDG_CONFIG_HOME:-$HOME_ROOT/.config}}"
    XDG_STATE_ROOT="${TR_XDG_STATE_ROOT:-${XDG_STATE_HOME:-$HOME_ROOT/.local/state}}"
    case "$XDG_DATA_ROOT" in
        /*) : ;;
        *) die 3 "refused: XDG_DATA_HOME must be absolute" ;;
    esac
    case "$XDG_CONFIG_ROOT" in
        /*) : ;;
        *) die 3 "refused: XDG_CONFIG_HOME must be absolute" ;;
    esac
    case "$XDG_STATE_ROOT" in
        /*) : ;;
        *) die 3 "refused: XDG_STATE_HOME must be absolute" ;;
    esac
}

# ---------------------------------------------------------------------------
# interactive state collection (no mutation until all answers collected)
# ---------------------------------------------------------------------------

ask_state() {
    # Sets the global ANSWER and returns 0 on success, 1 on EOF.  Never uses
    # command substitution so a refusal propagates to the calling shell.
    prompt="$1"
    default="$2"
    while :; do
        printf '%s [%s] ' "$prompt" "$default"
        if ! read -r answer; then
            printf '\n'
            return 1
        fi
        if [ -z "$answer" ]; then
            ANSWER="$default"
            return 0
        fi
        case "$answer" in
            enable|disable|preserve) ANSWER="$answer"; return 0 ;;
            *) printf 'install.sh: invalid state; use enable, disable, or preserve\n' >&2 ;;
        esac
    done
}

collect_interactive_answers() {
    # Noninteractive paths never read stdin; interactive requires a terminal.
    if [ "${TR_FORCE_INTERACTIVE:-0}" != 1 ]; then
        [ -t 0 ] || die 2 "refused: interactive install requires a terminal"
    fi
    ask_state "Bash integration state?" enable || die 2 "refused: end of input"
    BASH_STATE="$ANSWER"
    ask_state "Autostart state?" disable || die 2 "refused: end of input"
    AUTOSTART_STATE="$ANSWER"
    ask_state "Chooser state?" preserve || die 2 "refused: end of input"
    CHOOSER_STATE="$ANSWER"
}

# ---------------------------------------------------------------------------
# probe + validate-plan (canonical JSON in a shell variable, no payload file)
# ---------------------------------------------------------------------------

run_probe() {
    # 1. plan: capture canonical JSON (command substitution strips trailing newline)
    unset PYTHONPATH PYTHONHOME PYTHONSTARTUP
    export PYTHONDONTWRITEBYTECODE=1
    PROBE_PLAN=$("$PYTHON" $PYFLAGS "$SOURCE_ROOT/installer_probe.py" plan \
        --source-root "$SOURCE_ROOT" --home "$HOME_ROOT" \
        --xdg-data-home "$XDG_DATA_ROOT" --xdg-config-home "$XDG_CONFIG_ROOT" \
        --xdg-state-home "$XDG_STATE_ROOT" \
        --mode "$MODE" --bash "$BASH_STATE" --autostart "$AUTOSTART_STATE" \
        --chooser "$CHOOSER_STATE" --dry-run "$DRY_RUN") \
        || die 4 "refused: source probe failed"
    # 2. validate-plan --emit json: replace the variable with canonical validated JSON
    PROBE_PLAN=$(printf '%s\n' "$PROBE_PLAN" | \
        "$PYTHON" $PYFLAGS "$SOURCE_ROOT/installer_probe.py" validate-plan \
        --source-root "$SOURCE_ROOT" --home "$HOME_ROOT" \
        --xdg-data-home "$XDG_DATA_ROOT" --xdg-config-home "$XDG_CONFIG_ROOT" \
        --xdg-state-home "$XDG_STATE_ROOT" \
        --mode "$MODE" --bash "$BASH_STATE" --autostart "$AUTOSTART_STATE" \
        --chooser "$CHOOSER_STATE" --dry-run "$DRY_RUN" --emit json) \
        || die 4 "refused: plan validation failed"
    # 3. extract plan_digest from the canonical JSON (pipe, no regular file)
    PROBE_PLAN_DIGEST=$(printf '%s\n' "$PROBE_PLAN" | \
        sed -n 's/.*"plan_digest":"\([0-9a-f]\{64\}\)".*/\1/p')
    [ -n "$PROBE_PLAN_DIGEST" ] || die 1 "internal: plan digest extraction failed"
}

print_plan() {
    # Dry-run renders the validated plan exactly as validate-plan --emit rendered.
    printf '%s\n' "$PROBE_PLAN" | \
        "$PYTHON" $PYFLAGS "$SOURCE_ROOT/installer_probe.py" validate-plan \
        --source-root "$SOURCE_ROOT" --home "$HOME_ROOT" \
        --xdg-data-home "$XDG_DATA_ROOT" --xdg-config-home "$XDG_CONFIG_ROOT" \
        --xdg-state-home "$XDG_STATE_ROOT" \
        --mode "$MODE" --bash "$BASH_STATE" --autostart "$AUTOSTART_STATE" \
        --chooser "$CHOOSER_STATE" --dry-run "$DRY_RUN" --emit rendered
}

# ---------------------------------------------------------------------------
# build staging + delegate launch + cleanup
# ---------------------------------------------------------------------------

record_build_root_identity() {
    parent=$(dirname -- "$BUILD_ROOT")
    BUILD_PARENT_DEV=$(stat -c '%d' -- "$parent" 2>/dev/null || stat -f '%d' -- "$parent")
    BUILD_PARENT_INO=$(stat -c '%i' -- "$parent" 2>/dev/null || stat -f '%i' -- "$parent")
    BUILD_ROOT_DEV=$(stat -c '%d' -- "$BUILD_ROOT" 2>/dev/null || stat -f '%d' -- "$BUILD_ROOT")
    BUILD_ROOT_INO=$(stat -c '%i' -- "$BUILD_ROOT" 2>/dev/null || stat -f '%i' -- "$BUILD_ROOT")
    BUILD_UID=$(id -u)
}

build_artifacts() {
    # One private 0700 external build root; isolated build venv; local wheel only.
    BUILD_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/termrecall-build.XXXXXX") || \
        die 3 "refused: cannot create build root"
    chmod 0700 "$BUILD_ROOT"
    record_build_root_identity
    if [ "${TR_SKIP_BUILD:-0}" = 1 ]; then
        # Test escape hatch: skip the real build/venv; the delegate is stubbed.
        WHEEL="$BUILD_ROOT/fake.whl"
        : >"$WHEEL"
        DELEGATE_PYTHON="${DELEGATE_PYTHON:-$PYTHON}"
        return
    fi
    # Build sdist then wheel into private paths with no index/cache/source output.
    : "${BUILD_FRONTEND:=uv build --wheel --no-progress}"
    # shellcheck disable=SC2086
    $BUILD_FRONTEND --out-dir "$BUILD_ROOT/wheelhouse" "$SOURCE_ROOT" \
        >/dev/null 2>&1 || die 3 "refused: wheel build failed"
    WHEEL=$(cd "$BUILD_ROOT/wheelhouse" && ls *.whl 2>/dev/null | head -n 1)
    [ -n "$WHEEL" ] || die 3 "refused: no wheel produced"
    WHEEL="$BUILD_ROOT/wheelhouse/$WHEEL"
    # Delegate staging venv: install only the local wheel, no index, no deps.
    "$PYTHON" -m venv "$BUILD_ROOT/delegate-venv" >/dev/null 2>&1 || \
        die 3 "refused: delegate venv creation failed"
    DELEGATE_PYTHON="${DELEGATE_PYTHON:-$BUILD_ROOT/delegate-venv/bin/python}"
    "$BUILD_ROOT/delegate-venv/bin/pip" install --no-index --no-deps "$WHEEL" \
        >/dev/null 2>&1 || die 3 "refused: delegate wheel install failed"
}

run_probe_launcher() {
    # Call (never exec) the source artifact available before the build.  The
    # delegate runs as a tracked background job so HUP/INT/TERM can be forwarded
    # exactly once to its PID; the captured child status survives cleanup.
    "$PYTHON" $LAUNCH_FLAGS "$SOURCE_ROOT/installer_probe.py" launch-delegate \
        --expected-digest "$PROBE_PLAN_DIGEST" \
        --delegate-python "$DELEGATE_PYTHON" \
        --wheel "$WHEEL" \
        --source-root "$SOURCE_ROOT" --home "$HOME_ROOT" \
        --xdg-data-home "$XDG_DATA_ROOT" --xdg-config-home "$XDG_CONFIG_ROOT" \
        --xdg-state-home "$XDG_STATE_ROOT" \
        --mode "$MODE" --bash "$BASH_STATE" --autostart "$AUTOSTART_STATE" \
        --chooser "$CHOOSER_STATE" --dry-run no &
    DELEGATE_PID=$!
    wait "$DELEGATE_PID" 2>/dev/null
    RECORDED_CHILD_STATUS=$?
    DELEGATE_PID=""
}

cleanup_build_root() {
    [ -z "$BUILD_ROOT" ] && { RECORDED_CLEANUP_STATUS=0; return; }
    helper="${CLEANUP_HELPER:-$SOURCE_ROOT/cleanup_private_tree.py}"
    "$PYTHON" "$helper" "$BUILD_ROOT" "$(dirname -- "$BUILD_ROOT")" \
        "$BUILD_PARENT_DEV" "$BUILD_PARENT_INO" \
        "$BUILD_ROOT_DEV" "$BUILD_ROOT_INO" "$BUILD_UID" \
        >/dev/null 2>&1
    RECORDED_CLEANUP_STATUS=$?
}

finish_with_status() {
    child_status="$1"
    cleanup_status="$2"
    if [ "$child_status" -ne 0 ]; then
        return "$child_status"
    elif [ "$cleanup_status" -ne 0 ]; then
        return 7
    fi
    return 0
}

# ---------------------------------------------------------------------------
# signal/exit traps (forward once, wait once, shared finish)
# ---------------------------------------------------------------------------

forward_signal() {
    sig="$1"
    if [ -n "$DELEGATE_PID" ] && kill -0 "$DELEGATE_PID" 2>/dev/null; then
        kill "-$sig" "$DELEGATE_PID" 2>/dev/null || true
        wait "$DELEGATE_PID" 2>/dev/null || true
        DELEGATE_PID=""
    fi
    RECORDED_CHILD_STATUS=$((128 + sig))
    exit $((128 + sig))
}

on_exit() {
    # Guard from being run twice during status selection.
    [ "$IN_FINISH" -eq 1 ] && return 0
    IN_FINISH=1
    cleanup_build_root
    status=0
    finish_with_status "$RECORDED_CHILD_STATUS" "$RECORDED_CLEANUP_STATUS"
    status=$?
    exit "$status"
}

trap_hup() { forward_signal 1; }
trap_int() { forward_signal 2; }
trap_term() { forward_signal 15; }

install_traps() {
    trap trap_hup HUP
    trap trap_int INT
    trap trap_term TERM
    trap on_exit EXIT
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"
    validate_combination
    refuse_privilege
    require_prerequisites
    resolve_roots

    if [ "$INTERACTIVE" = 1 ]; then
        # Interactive defaults: bash=enable, autostart=disable, chooser=preserve.
        BASH_STATE="${BASH_STATE:-enable}"
        AUTOSTART_STATE="${AUTOSTART_STATE:-disable}"
        CHOOSER_STATE="${CHOOSER_STATE:-preserve}"
        collect_interactive_answers
    else
        # Mode defaults.
        case "$MODE" in
            full)
                BASH_STATE="${BASH_STATE:-enable}"
                AUTOSTART_STATE="${AUTOSTART_STATE:-enable}"
                CHOOSER_STATE="${CHOOSER_STATE:-enable}"
                ;;
            no-autostart)
                BASH_STATE="${BASH_STATE:-enable}"
                AUTOSTART_STATE="${AUTOSTART_STATE:-disable}"
                CHOOSER_STATE="${CHOOSER_STATE:-preserve}"
                ;;
            commands-only|upgrade)
                BASH_STATE="${BASH_STATE:-preserve}"
                AUTOSTART_STATE="${AUTOSTART_STATE:-preserve}"
                CHOOSER_STATE="${CHOOSER_STATE:-preserve}"
                ;;
        esac
    fi

    run_probe

    if [ "$DRY_RUN" = yes ]; then
        # Dry-run renders the validated plan and returns before mktemp/build/delegate.
        print_plan
        exit 0
    fi

    install_traps
    build_artifacts
    run_probe_launcher
    # The EXIT trap performs cleanup and selects the final status so that the
    # captured child/signal status is never overwritten by cleanup failure.
}

main "$@"
