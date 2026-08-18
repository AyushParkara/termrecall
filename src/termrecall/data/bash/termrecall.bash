# SPDX-License-Identifier: GPL-3.0-or-later
# shellcheck shell=bash

[[ $- == *i* ]] || return 0
(( BASH_SUBSHELL == 0 )) || return 0
if [[ -n ${GNOME_TERMINAL_SCREEN-} ]]; then
    __termrecall_adapter="gnome-terminal"
elif [[ -n ${KITTY_WINDOW_ID-} ]]; then
    __termrecall_adapter="kitty"
elif [[ -n ${GHOSTTY_RESOURCES_DIR-} ]]; then
    __termrecall_adapter="ghostty"
elif [[ -n ${XFCE4_TERMINAL-} ]]; then
    __termrecall_adapter="xfce4-terminal"
elif [[ -n ${KONSOLE_DBUS_SERVICE-} ]]; then
    __termrecall_adapter="konsole"
else
    return 0
fi
[[ -z ${SSH_CONNECTION-}${SSH_CLIENT-}${SSH_TTY-} ]] || return 0
[[ -r /proc/$PPID/comm ]] || return 0
IFS= read -r __termrecall_parent </proc/$PPID/comm || return 0
[[ $__termrecall_parent != bash ]] || return 0
unset __termrecall_parent

if [[ ${__termrecall_installed-} == 1 ]]; then
    return 0
fi
__termrecall_busy=1

__termrecall_json_string() {
    local value=${1-}
    [[ $value != *[$'\001'-$'\037']* && $value != *$'\177'* ]] || return 1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    REPLY=$value
}

__termrecall_queue() {
    local frame=${1-} length
    local LC_ALL=C
    length=${#frame}
    [[ -n ${TERMRECALL_BRIDGE_FD-} && $length -lt 4096 ]] || return 0
    if ! builtin printf '%s\n' "$frame" >&"$TERMRECALL_BRIDGE_FD"; then
        exec {TERMRECALL_BRIDGE_FD}>&- 2>/dev/null || :
        unset TERMRECALL_BRIDGE_FD
    fi
    return 0
}

__termrecall_start_bridge() {
    local socket boot_id stat start_time
    local -a stat_fields
    [[ -z ${TERMRECALL_BRIDGE_PID-} ]] || return 0
    TERMRECALL_SHELL_ID="shell-$(< /proc/sys/kernel/random/uuid)"
    TERMRECALL_SHELL_ID=${TERMRECALL_SHELL_ID//-/}
    TERMRECALL_COMMAND_SEQUENCE=0
    boot_id=$(< /proc/sys/kernel/random/boot_id) || return 0
    stat=$(< "/proc/$$/stat") || return 0
    stat=${stat##*) }
    read -r -a stat_fields <<<"$stat"
    start_time=${stat_fields[19]-}
    [[ $start_time =~ ^[0-9]+$ ]] || return 0
    socket=${TERMRECALL_SOCKET:-${XDG_RUNTIME_DIR:?}/termrecall/service.sock}
    TERMRECALL_BRIDGE_PROGRAM=${TERMRECALL_BRIDGE_PROGRAM:-termrecall-bridge}
    TERMRECALL_NONBLOCK_PROGRAM=${TERMRECALL_NONBLOCK_PROGRAM:-termrecall-nonblock}
    coproc TERMRECALL_BRIDGE {
        exec "$TERMRECALL_BRIDGE_PROGRAM" --socket "$socket" \
            --shell-id "$TERMRECALL_SHELL_ID" --boot-id "$boot_id" \
            --pid "$$" --start-time "$start_time" \
            --adapter "$__termrecall_adapter"
    }
    TERMRECALL_BRIDGE_FD=${TERMRECALL_BRIDGE[1]}
    if ! "$TERMRECALL_NONBLOCK_PROGRAM" <&"$TERMRECALL_BRIDGE_FD"; then
        exec {TERMRECALL_BRIDGE_FD}>&- 2>/dev/null || :
        kill "$TERMRECALL_BRIDGE_PID" 2>/dev/null || :
        unset TERMRECALL_BRIDGE_FD TERMRECALL_BRIDGE_PID
        return 0
    fi
    return 0
}

__termrecall_preexec() {
    local prior_status=$? command=${1:-$BASH_COMMAND} escaped frame
    [[ ${__termrecall_busy-} != 1 ]] || return "$prior_status"
    __termrecall_busy=1
    if [[ $command == exit || $command == exit\ * || $command == logout || $command == logout\ * ]]; then
        if [[ ${__termrecall_explicit_exit_sent-} != 1 ]]; then
            frame="{\"schema_version\":1,\"type\":\"explicit_exit\",\"shell_id\":\"$TERMRECALL_SHELL_ID\"}"
            __termrecall_queue "$frame"
            __termrecall_explicit_exit_sent=1
        fi
    elif [[ -n ${__termrecall_active_sequence-} ]]; then
        :
    elif ((${#command} > 0 && ${#command} <= 3072)) && __termrecall_json_string "$command"; then
        escaped=$REPLY
        ((TERMRECALL_COMMAND_SEQUENCE++))
        __termrecall_active_sequence=$TERMRECALL_COMMAND_SEQUENCE
        frame="{\"schema_version\":1,\"type\":\"command_started\",\"shell_id\":\"$TERMRECALL_SHELL_ID\",\"command_sequence\":$TERMRECALL_COMMAND_SEQUENCE,\"command\":\"$escaped\"}"
        __termrecall_queue "$frame"
    fi
    __termrecall_busy=0
    return "$prior_status"
}

__termrecall_prompt() {
    local prior_status=$? cwd escaped frame
    if [[ ${__termrecall_busy-} == 1 ]]; then
        return "$prior_status"
    fi
    __termrecall_busy=1
    if [[ -n ${__termrecall_active_sequence-} ]]; then
        frame="{\"schema_version\":1,\"type\":\"command_finished\",\"shell_id\":\"$TERMRECALL_SHELL_ID\",\"command_sequence\":$__termrecall_active_sequence,\"exit_status\":$prior_status}"
        __termrecall_queue "$frame"
        unset __termrecall_active_sequence
    fi
    cwd=$PWD
    if ((${#cwd} <= 768)) && __termrecall_json_string "$cwd"; then
        escaped=$REPLY
        frame="{\"schema_version\":1,\"type\":\"prompt_ready\",\"shell_id\":\"$TERMRECALL_SHELL_ID\",\"cwd\":\"$escaped\"}"
        __termrecall_queue "$frame"
    fi
    __termrecall_busy=0
    return "$prior_status"
}

__termrecall_debug_trap() {
    local function_status=$? command=$BASH_COMMAND
    if [[ ${__termrecall_busy-} == 1 ]]; then
        return "$function_status"
    fi
    command=${1:-$command}
    local prior_status=${2:-$function_status} prior_debug_status=0
    trap - DEBUG
    if [[ -n ${__termrecall_previous_debug-} ]]; then
        __termrecall_busy=1
        (exit "$prior_status")
        eval -- "$__termrecall_previous_debug"
        prior_debug_status=$?
    else
        __termrecall_busy=1
    fi
    trap '__termrecall_debug_trap' DEBUG
    if ((prior_debug_status == 0)); then
        case $command in
            __termrecall_*|termrecall_uninstall*) ;;
            *)
                if [[ $command == exit || $command == exit\ * || $command == logout || $command == logout\ * ]]; then
                    if [[ ${__termrecall_explicit_exit_sent-} != 1 ]]; then
                        __termrecall_queue "{\"schema_version\":1,\"type\":\"explicit_exit\",\"shell_id\":\"$TERMRECALL_SHELL_ID\"}"
                        __termrecall_explicit_exit_sent=1
                    fi
                elif [[ -z ${__termrecall_active_sequence-} ]] && ((${#command} > 0 && ${#command} <= 3072)) && __termrecall_json_string "$command"; then
                    ((TERMRECALL_COMMAND_SEQUENCE++))
                    __termrecall_active_sequence=$TERMRECALL_COMMAND_SEQUENCE
                    __termrecall_queue "{\"schema_version\":1,\"type\":\"command_started\",\"shell_id\":\"$TERMRECALL_SHELL_ID\",\"command_sequence\":$TERMRECALL_COMMAND_SEQUENCE,\"command\":\"$REPLY\"}"
                fi
                ;;
        esac
    fi
    trap - DEBUG
    __termrecall_busy=0
    trap '__termrecall_debug_trap' DEBUG
    return "$prior_debug_status"
}

__termrecall_exit_trap() {
    local prior_status=$?
    __termrecall_busy=1
    if [[ -n ${__termrecall_previous_exit-} ]]; then
        (exit "$prior_status")
        eval -- "$__termrecall_previous_exit"
    fi
    __termrecall_busy=0
    return "$prior_status"
}

__termrecall_prompt_dispatch() {
    local prior_status=$? callback
    __termrecall_busy=1
    if declare -p __termrecall_previous_prompt >/dev/null 2>&1; then
        if [[ $(declare -p __termrecall_previous_prompt 2>/dev/null) == 'declare -a'* ]]; then
            for callback in "${__termrecall_previous_prompt[@]}"; do
                eval -- "$callback"
            done
        elif [[ -n $__termrecall_previous_prompt ]]; then
            eval -- "$__termrecall_previous_prompt"
        fi
    fi
    __termrecall_busy=0
    return "$prior_status"
}

termrecall_uninstall() {
    local prior_status=$?
    if declare -p __termrecall_previous_prompt >/dev/null 2>&1; then
        if [[ $(declare -p __termrecall_previous_prompt 2>/dev/null) == 'declare -a'* ]]; then
            PROMPT_COMMAND=("${__termrecall_previous_prompt[@]}")
        else
            PROMPT_COMMAND=$__termrecall_previous_prompt
        fi
    else
        unset PROMPT_COMMAND
    fi
    if [[ -n ${__termrecall_previous_debug_declaration-} ]]; then
        eval -- "$__termrecall_previous_debug_declaration"
    else
        trap - DEBUG
    fi
    if [[ -n ${__termrecall_previous_exit_declaration-} ]]; then
        eval -- "$__termrecall_previous_exit_declaration"
    else
        trap - EXIT
    fi
    if [[ -n ${TERMRECALL_BRIDGE_FD-} ]]; then
        exec {TERMRECALL_BRIDGE_FD}>&- 2>/dev/null || :
    fi
    if [[ -n ${TERMRECALL_BRIDGE_PID-} ]]; then
        kill "$TERMRECALL_BRIDGE_PID" 2>/dev/null || :
    fi
    unset TERMRECALL_BRIDGE_FD TERMRECALL_BRIDGE_PID __termrecall_installed
    return "$prior_status"
}

__termrecall_previous_debug_declaration=$(trap -p DEBUG)
__termrecall_previous_exit_declaration=$(trap -p EXIT)
__termrecall_previous_debug=
__termrecall_previous_exit=
if [[ -n $__termrecall_previous_debug_declaration ]]; then
    eval "set -- ${__termrecall_previous_debug_declaration#trap -- }"
    __termrecall_previous_debug=$1
fi
if [[ -n $__termrecall_previous_exit_declaration ]]; then
    eval "set -- ${__termrecall_previous_exit_declaration#trap -- }"
    __termrecall_previous_exit=$1
fi
if declare -p PROMPT_COMMAND >/dev/null 2>&1; then
    if [[ $(declare -p PROMPT_COMMAND) == 'declare -a'* ]]; then
        __termrecall_previous_prompt=("${PROMPT_COMMAND[@]}")
    else
        __termrecall_previous_prompt=$PROMPT_COMMAND
    fi
    PROMPT_COMMAND=(__termrecall_prompt_dispatch __termrecall_prompt)
else
    PROMPT_COMMAND=(__termrecall_prompt)
fi

__termrecall_start_bridge
if [[ -n ${TERMRECALL_BRIDGE_FD-} ]]; then
    __termrecall_installed=1
    trap '__termrecall_debug_trap' DEBUG
    trap '__termrecall_exit_trap' EXIT
    __termrecall_busy=0
else
    termrecall_uninstall
fi
