#!/bin/bash

set -euo pipefail

AVAILABLE_DIR=/etc/nginx/sites-available
ENABLED_DIR=/etc/nginx/sites-enabled

usage() {
    cat <<'USAGE'
Usage: bash update-symlinks.sh [--dry-run] (--all | SITE [SITE ...])

SITE       Enable the named file from sites-available.
--all      Synchronize eligible configurations and remove obsolete managed links.
--dry-run  Show the changes without applying them or reloading Nginx.
--help     Show this help.
USAGE
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_root() {
    if (( EUID != 0 )); then
        fail "Run with root privileges to apply the proposed changes."
    fi
}

is_config_name() {
    case "$1" in
        ''|.*|*/*|*[[:cntrl:]]*|*.bak|*~|*.swp|*.tmp|README*|*.md|*.dpkg-*|*.rpmnew|*.rpmsave)
            return 1
            ;;
    esac
}

is_available_config() {
    is_config_name "$1" && [[ -f "$AVAILABLE_DIR/$1" ]]
}

# Return the target name for a link that points inside sites-available.
managed_target() {
    local target parent
    target=$(readlink -- "$1") || return 1
    if [[ "$target" != /* ]]; then
        target="$ENABLED_DIR/$target"
    fi
    parent=$(realpath -m -- "$(dirname -- "$target")") || return 1
    [[ "$parent" == "$AVAILABLE_DIR" ]] || return 1
    printf '%s\n' "${target##*/}"
}

plan_link() {
    local name=$1 path="$ENABLED_DIR/$1" target previous
    if [[ -L "$path" ]]; then
        if ! target=$(managed_target "$path"); then
            fail "Existing symlink points outside sites-available: $path"
        fi
        if [[ "$target" == "$name" && -f "$path" ]]; then
            return
        fi
    elif [[ -e "$path" ]]; then
        fail "Existing entry occupies the site name: $path"
    fi

    for previous in "${links[@]}"; do
        if [[ "$previous" == "$name" ]]; then
            return
        fi
    done
    links+=("$name")
}

plan_all() {
    local path name
    for path in "$AVAILABLE_DIR"/*; do
        name=${path##*/}
        if is_available_config "$name"; then
            plan_link "$name"
        fi
    done

    for path in "$ENABLED_DIR"/*; do
        name=${path##*/}
        if [[ -L "$path" ]] && ! is_available_config "$name" && managed_target "$path" >/dev/null; then
            removals+=("$name")
        fi
    done
}

show_plan() {
    local name
    for name in "${removals[@]}"; do
        printf 'Remove link %s\n' "$ENABLED_DIR/$name"
    done
    for name in "${links[@]}"; do
        printf 'Link %s -> %s\n' "$ENABLED_DIR/$name" "$AVAILABLE_DIR/$name"
    done
    if (( ${#links[@]} == 0 && ${#removals[@]} == 0 )); then
        printf 'No link changes are needed.\n'
    fi
}

reload_nginx() {
    if command -v systemctl >/dev/null && systemctl is-active --quiet nginx; then
        systemctl reload nginx
        printf 'Nginx reload requested via systemctl.\n'
    elif command -v pgrep >/dev/null && pgrep -x nginx >/dev/null; then
        nginx -s reload
        printf 'Nginx reload requested via nginx -s reload.\n'
    else
        printf 'Nginx is inactive. Configuration checked, reload skipped.\n'
    fi
}

finish_apply() {
    local status=$1 name restore_failed=false
    trap - EXIT
    trap '' HUP INT TERM

    if (( status != 0 )); then
        for name in "${changed[@]}"; do
            if [[ -L "$backup_dir/$name" ]]; then
                mv -fT -- "$backup_dir/$name" "$ENABLED_DIR/$name" || restore_failed=true
            else
                rm -f -- "$ENABLED_DIR/$name" || restore_failed=true
            fi
        done
        if [[ "$created_enabled_dir" == true && -d "$ENABLED_DIR" ]]; then
            rmdir -- "$ENABLED_DIR" || restore_failed=true
        fi
        if [[ "$restore_failed" == true ]]; then
            printf 'Error: Could not fully restore %s.\n' "$ENABLED_DIR" >&2
            if [[ -n "$backup_dir" ]]; then
                printf 'Remaining backups: %s\n' "$backup_dir" >&2
            fi
            exit "$status"
        fi
        if (( ${#changed[@]} > 0 )); then
            printf 'Restored previous links in %s.\n' "$ENABLED_DIR" >&2
        fi
    fi

    if [[ -n "$backup_dir" ]]; then
        rm -rf -- "$backup_dir"
    fi
    exit "$status"
}

apply_plan() (
    backup_dir=''
    changed=()
    created_enabled_dir=false
    trap 'finish_apply "$?"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    if (( ${#links[@]} > 0 || ${#removals[@]} > 0 )); then
        backup_dir=$(mktemp -d -- "$enabled_parent/.nginx-sites.XXXXXXXX")
        for name in "${removals[@]}" "${links[@]}"; do
            if [[ -L "$ENABLED_DIR/$name" ]]; then
                cp -P -- "$ENABLED_DIR/$name" "$backup_dir/$name"
            fi
        done
        if [[ ! -d "$ENABLED_DIR" ]]; then
            created_enabled_dir=true
            mkdir -- "$ENABLED_DIR"
        fi
        for name in "${removals[@]}"; do
            changed+=("$name")
            rm -- "$ENABLED_DIR/$name"
        done
        for name in "${links[@]}"; do
            changed+=("$name")
            if [[ -L "$backup_dir/$name" ]]; then
                ln -sfnT -- "$AVAILABLE_DIR/$name" "$ENABLED_DIR/$name"
            else
                ln -sT -- "$AVAILABLE_DIR/$name" "$ENABLED_DIR/$name"
            fi
        done
    fi

    printf 'Testing Nginx configuration...\n'
    nginx -t
    reload_nginx
)

main() {
    local all=false dry_run=false name lock_fd enabled_parent
    local -a sites=() links=() removals=()

    while (( $# > 0 )); do
        case "$1" in
            --all) all=true ;;
            --dry-run) dry_run=true ;;
            -h|--help) usage; return ;;
            --) shift; sites+=("$@"); break ;;
            -*) fail "Unknown option: $1 (see --help)" ;;
            *) sites+=("$1") ;;
        esac
        shift
    done

    if [[ "$all" == true ]] && (( ${#sites[@]} > 0 )); then
        fail "Choose --all or name individual sites."
    fi
    if [[ "$all" == false ]] && (( ${#sites[@]} == 0 )); then
        usage >&2
        exit 2
    fi
    if [[ "$dry_run" == false ]]; then
        require_root
    fi

    [[ -d "$AVAILABLE_DIR" ]] || fail "Directory does not exist: $AVAILABLE_DIR"
    if [[ ( -e "$ENABLED_DIR" || -L "$ENABLED_DIR" ) && ! -d "$ENABLED_DIR" ]]; then
        fail "Expected a directory: $ENABLED_DIR"
    fi
    AVAILABLE_DIR=$(realpath -- "$AVAILABLE_DIR")
    ENABLED_DIR=$(realpath -m -- "$ENABLED_DIR")
    [[ "$AVAILABLE_DIR" != "$ENABLED_DIR" ]] || fail "The two site directories must be distinct."
    enabled_parent=$(dirname -- "$ENABLED_DIR")

    shopt -s nullglob
    exec {lock_fd}<"$enabled_parent"
    if [[ "$dry_run" == true ]]; then
        flock --shared "$lock_fd"
    else
        flock --exclusive "$lock_fd"
        command -v nginx >/dev/null || fail "nginx was not found on PATH."
    fi

    if [[ "$all" == true ]]; then
        plan_all
    else
        for name in "${sites[@]}"; do
            is_available_config "$name" || fail "No eligible site configuration named: $name"
            plan_link "$name"
        done
    fi

    show_plan
    if [[ "$dry_run" == false ]]; then
        apply_plan
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
