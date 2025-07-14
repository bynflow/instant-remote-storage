#!/usr/bin/env bash
set -euo pipefail

# ========================================
# instant-remote-storage - v0.1.0
# Ultima modifica: 2025-07-11
# === Informazioni autore ===
# Author : Carlo Capobianchi (bynflow)
# GitHub : https://github.com/bynflow
# Year   : 2025
# ======================
# ======================
# Watch $HOME/storage-remoto-nextcloud and sync to hetzner-nc:indifferenziato
# with checksum-based conflict resolution.
# ========================================

LOCAL_DIR="$HOME/storage-remoto-nextcloud"
REMOTE_DIR="hetzner-nc:indifferenziato"

REQUIRED_CMDS=(rclone inotifywait md5sum date grep find awk mapfile msmtp)

# Ensure prerequisites
for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "Error: '$cmd' not found. Please install it." >&2
        exit 1
    }
done

# Create local and remote folders if missing
mkdir -p "$LOCAL_DIR"
rclone mkdir "$REMOTE_DIR" 2>/dev/null || true

get_mime() {
    local file_path
    file_path="$1"
    local mime
    mime=$(file --mime-type -b "$file_path")
    echo "$mime"
}

read_extension() {
    local file_path
    file_path="$1"
    local original_name
    original_name=$(basename "$file_path")
    local ext mime new_name

    mime=$(get_mime "$file_path")
    case "$mime" in
        text/plain) ext="txt" ;;
        image/jpeg) ext="jpg" ;;
        image/png) ext="png" ;;
        application/pdf) ext="pdf" ;;
        application/zip) ext="zip" ;;
        application/json) ext="json" ;;
        application/xml) ext="xml" ;;
        *) ext="bin" ;;
    esac

    if [[ "$original_name" != *.* ]]; then
        new_name="${original_name}.${ext}"
        echo "$new_name"
    elif [[ "${file_path##*.}" =~ $ext ]]; then
        new_name="${file_path}.${ext}"
        echo "$new_name"
    else
        echo "$original_name"
    fi
}

clean_fname() {
    local file_path
    file_path="$1"
    local original_name
    original_name=$(basename "$file_path")
    local base
    base="${original_name%.*}"
    local ext
    ext="${original_name##*.}"
    local clean_name new_name 

    # Pulizia e normalizzazione del nome
    clean_name=$(echo "$base" | \
        tr '[:upper:]' '[:lower:]' | \
        sed -E 's/[^a-z0-9]+/-/g' | \
        sed -E 's/^-+|-+$//g')
    new_name="${clean_name}.${ext}"
    echo "$new_name"
}

# Fase 1 - NUOVO FILE NELLA CARTELLA
inotifywait -m \
    -e create \
    -e moved_to \
    -e modify \
    -e close_write \
    --format '%f' \
    "$LOCAL_DIR" | while read -r FILENAME; do
        LOCAL_FILE="$LOCAL_DIR/$FILENAME"
        REMOTE_PATH="$REMOTE_DIR/$FILENAME"

        # Compute local checksum
        LOCAL_HASH=$(md5sum "$LOCAL_FILE" | awk '{print $1}')

        # Try to get remote checksum (empty if not exists)
        EXISTING_HASH=$(rclone md5sum "$REMOTE_PATH" 2>/dev/null | awk '{print $1}' || echo "")

        # Check if file has extension
        NEW_FILENAME=$(read_extension "$LOCAL_FILE")

        # Get a save filename
        SAVE_FILENAME=$(clean_fname "$NEW_FILENAME")

        if [[ "$SAVE_FILENAME" != "$FILENAME" ]]; then
            mv "$LOCAL_DIR/$FILENAME" "$LOCAL_DIR/$SAVE_FILENAME"
            FILENAME="$SAVE_FILENAME"
            LOCAL_FILE="$LOCAL_DIR/$FILENAME"
            REMOTE_PATH="$REMOTE_DIR/$FILENAME"
        fi

        # Fase 2 - CLONA FILE IN REMOTO
        if [[ -z "$EXISTING_HASH" ]]; then
            # No remote file → copy directly
            rclone copyto "$LOCAL_FILE" "$REMOTE_PATH"
        else
            if [[ "$LOCAL_HASH" == "$EXISTING_HASH" ]]; then
                # Same content → skip
                continue
            else
                # Conflict: generate new name with suffix "(copia)", "(copia 2)", ...
                BASE="${FILENAME%.*}"
                EXT="${FILENAME##*.}"
                COUNT=1
                NEW_NAME="$BASE (copia).$EXT"

                # Loop until name is free
                while rclone lsf "$REMOTE_DIR/${NEW_NAME}" &>/dev/null; do
                    COUNT=$((COUNT + 1))
                    NEW_NAME="$BASE (copia $COUNT).$EXT"
                done

                rclone copyto "$LOCAL_FILE" "$REMOTE_DIR/$NEW_NAME"
            fi
        fi
    done
