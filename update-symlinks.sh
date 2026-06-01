#!/bin/bash

# Exit immediately if a command exits with a non-zero status,
# treat unset variables as an error, and fail on pipeline errors.
set -euo pipefail

# Path configurations
AVAILABLE_DIR="/etc/nginx/sites-available"
ENABLED_DIR="/etc/nginx/sites-enabled"

# Ensure the script is run with root privileges
if [[ "$EUID" -ne 0 ]]; then
    echo "Error: Please run this script with root privileges (e.g., using sudo)." >&2
    exit 1
fi

# Verify sites-available directory exists
if [[ ! -d "$AVAILABLE_DIR" ]]; then
    echo "Error: Directory $AVAILABLE_DIR does not exist." >&2
    exit 1
fi

# Ensure sites-enabled directory exists
if [[ ! -d "$ENABLED_DIR" ]]; then
    echo "Creating directory: $ENABLED_DIR"
    mkdir -p "$ENABLED_DIR"
fi

# Use nullglob to handle empty directories safely
shopt -s nullglob
trap 'shopt -u nullglob' EXIT

echo "Cleaning up obsolete items in $ENABLED_DIR..."
removed_count=0
for item in "$ENABLED_DIR"/*; do
    filename=$(basename "$item")
    
    # If the file doesn't exist in sites-available, or it exists but the item in sites-enabled is not a symlink
    if [[ ! -e "$AVAILABLE_DIR/$filename" ]]; then
        rm -f "$item"
        echo " Removed obsolete item: $filename"
        removed_count=$((removed_count + 1))
    elif [[ ! -L "$item" ]]; then
        rm -f "$item"
        echo " Removed non-symlink item to be replaced: $filename"
        removed_count=$((removed_count + 1))
    fi
done

echo "Recreating symlinks in $ENABLED_DIR for files in $AVAILABLE_DIR..."
count=0
for file_path in "$AVAILABLE_DIR"/*; do
    # Explicitly check for regular files or symlinks
    if [[ -f "$file_path" || -L "$file_path" ]]; then
        filename=$(basename "$file_path")
        
        # Skip common non-config files
        case "$filename" in
            *.bak|*~|*.swp|*.tmp|README*|*.md|.git*)
                continue
                ;;
        esac
        
        target_link="$ENABLED_DIR/$filename"
        
        # Create or update the symlink forcefully
        ln -sfn "$file_path" "$target_link"
        echo " Linked: $filename -> $target_link"
        count=$((count + 1))
    fi
done

echo "Done! Removed $removed_count obsolete item(s), linked $count active config(s)."

echo "Testing Nginx configuration..."
if nginx -t; then
    echo "Nginx configuration test successful."
    
    nginx_active=false
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet nginx; then
            nginx_active=true
        fi
    elif pgrep -x nginx >/dev/null 2>&1; then
        nginx_active=true
    fi

    if [[ "$nginx_active" == true ]]; then
        if command -v systemctl >/dev/null 2>&1; then
            echo "Reloading Nginx via systemctl..."
            systemctl reload nginx
        else
            echo "Reloading Nginx via nginx -s reload..."
            nginx -s reload
        fi
        echo "Nginx reload completed."
    else
        echo "Config checked, but Nginx service is not running. Reload skipped."
    fi
else
    echo "Error: Nginx configuration test failed. Reload aborted." >&2
    exit 1
fi
