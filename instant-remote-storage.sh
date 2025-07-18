#!/usr/bin/env bash

# ========================================
# instant-remote-storage - v0.1.2
# Author : Carlo Capobianchi (bynflow)
# GitHub : https://github.com/bynflow
# Last Modified: 2025-07-17
# ========================================
# Watches $HOME/storage-remoto-nextcloud and syncs files to
# hetzner-nc:indifferenziato with MIME-based renaming and
# checksum-based conflict resolution.
# ========================================

set -euo pipefail  # Stop on error, unset variables, or pipe failures

# === Logging functions ===
LOG_TAG="instant-remote-storage"
DEBUG="1"  # Set to "1" to enable verbose debug logs

log_info()    { logger -t "$LOG_TAG" "[INFO]    $*;"; }
log_debug()   { [[ "$DEBUG" == "1" ]] && logger -t "$LOG_TAG" "[DEBUG]   $*"; }
log_warning() { logger -t "$LOG_TAG" "[WARNING] $*"; }
log_error()   { logger -t "$LOG_TAG" "[ERROR]   $*"; }

# === Send error report via email if msmtp is configured ===
send_error_mail() {
    if [[ ! -s "$HOME/.msmtprc" ]]; then
        log_warning "⚠️ Missing or empty ~/.msmtprc. Email disabled."
        return 0
    fi

    local subject
    subject="❌ Error in instant-remote-storage on $(hostname) - $(date '+%Y-%m-%d %H:%M:%S')"
    local recipient
    recipient="amminflow@gmail.com"
    local body_head body_tail

    body_head=$(cat <<-EOF
        Hello,
        An error occurred during the execution of *instant-remote-storage*.

        • Command: "$BASH_COMMAND"
        • Line: $LINENO
        • Exit code: $?

        Below are the last 50 lines from the system journal:

EOF
    )

    body_tail=$(journalctl --user -t "$LOG_TAG" -n 50 2>/dev/null || echo "⚠️ Could not read journal for tag $LOG_TAG")

    {
        echo "To: $recipient"
        echo "Subject: $subject"
        echo "From: instant-remote-storage <amminflow@gmail.com>"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo
        echo "$body_head$body_tail"
    } | msmtp --from=amminflow -t 2>/dev/null
}

# === Configuration variables ===
LOCAL_DIR="$HOME/storage-remoto-nextcloud"
REMOTE_DIR="hetzner-nc:indifferenziato"

# Commands required by the script for execution
REQUIRED_CMDS=(rclone inotifywait md5sum date grep find awk mapfile msmtp)

# === Preflight checks ===
# Ensure all required commands exist
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "Missing required command: '$cmd'"
        send_error_mail
        exit 1
    fi
done

# Ensure local directory exists
mkdir -p "$LOCAL_DIR" || {
    log_error "Failed to create local directory: $LOCAL_DIR"
    send_error_mail
    exit 1
}

# Ensure remote directory is initialized
if ! rclone mkdir "$REMOTE_DIR" 2>/dev/null; then
    log_warning "Remote directory may not exist or cannot be created: $REMOTE_DIR"
fi

# Check remote connection
if ! rclone lsf "$REMOTE_DIR" &>/dev/null; then
    log_error "Remote '$REMOTE_DIR' not reachable"
    send_error_mail
    exit 1
fi

# === MIME to extension map (placeholder) ===
declare -A MIME_EXTENSIONS=(
    # Text
    ["text/plain"]="txt"
    ["text/html"]="html"
    ["text/css"]="css"
    ["text/csv"]="csv"
    ["text/markdown"]="md"

    # Images
    ["image/jpeg"]="jpg"
    ["image/png"]="png"
    ["image/gif"]="gif"
    ["image/webp"]="webp"
    ["image/svg+xml"]="svg"
    ["image/tiff"]="tiff"
    ["image/bmp"]="bmp"

    # Audio
    ["audio/mpeg"]="mp3"
    ["audio/wav"]="wav"
    ["audio/ogg"]="ogg"
    ["audio/flac"]="flac"
    ["audio/x-ms-wma"]="wma"

    # Video
    ["video/mp4"]="mp4"
    ["video/x-msvideo"]="avi"
    ["video/x-matroska"]="mkv"
    ["video/webm"]="webm"
    ["video/quicktime"]="mov"

    # PDF & Documents
    ["application/pdf"]="pdf"
    ["application/msword"]="doc"
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]="docx"
    ["application/vnd.ms-excel"]="xls"
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]="xlsx"
    ["application/vnd.ms-powerpoint"]="ppt"
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"]="pptx"

    # Archives & Packages (only simple extensions)
    ["application/zip"]="zip"
    ["application/gzip"]="gz"
    ["application/x-bzip2"]="bz2"
    ["application/x-xz"]="xz"
    ["application/x-zstd"]="zst"
    ["application/x-lz4"]="lz4"
    ["application/x-brotli"]="br"

    # Code / Data
    ["application/json"]="json"
    ["application/xml"]="xml"
    ["application/x-yaml"]="yaml"
    ["application/javascript"]="js"
    ["application/x-sh"]="sh"
    ["application/x-python-code"]="py"

    # Fonts
    ["font/ttf"]="ttf"
    ["font/otf"]="otf"
    ["application/font-woff"]="woff"
    ["application/font-woff2"]="woff2"

    # Other
    ["application/octet-stream"]="bin"
)

# Composite extensions (e.g., .tar.gz)
composite_exts=("tar.gz" "tar.bz2" "tar.xz" "tar.zst" "tar.lz4" "tar.br")

# === Utility Functions ===

# Splits a filename into base and extension, preserving known composite extensions
split_base_ext() {
    local filename="$1"
    for ext in "${composite_exts[@]}"; do
        [[ "$filename" == *".${ext}" ]] && {
            echo "${filename%."$ext"}:::${ext}"
            return
        }
    done
    echo "${filename%.*}:::${filename##*.}"
}

# Determines MIME type using `file` command; skips empty files
get_mime() {
    local file_path="$1"
    [[ ! -s "$file_path" ]] && {
        log_warning "'$file_path' is empty → skipped entirely (no upload attempt)."
        echo ""
        return
    }
    file --mime-type -b "$file_path"
}

# Determines the correct extension based on MIME type
# Returns new filename if extension is added or corrected
assign_extension() {
    local file_path
    file_path="$1"
    local original_name
    original_name=$(basename "$file_path")

    # Skip extension reassignment for composite types
    for ext in "${composite_exts[@]}"; do
        [[ "$original_name" == *".${ext}" ]] && {
            log_debug "Composite extension '$ext' detected. Keeping original name."
            echo "$original_name"
            return 0
        }
    done

    local mime ext
    mime=$(get_mime "$file_path")
    [[ -z "$mime" ]] && {
        log_warning "MIME detection failed. Skipping extension assignment."
        echo "$original_name"
        return 42
    }

    ext="${MIME_EXTENSIONS[$mime]}"
    [[ -z "$ext" ]] && {
        log_warning "MIME '$mime' not mapped. Skipping extension assignment."
        echo "$original_name"
        return 42
    }

    # If file already has correct extension, return it; else, append correct extension
    [[ "$original_name" == *".${ext}" ]] && echo "$original_name" || echo "${original_name}.${ext}"
}

# Sanitizes a filename:
# - Converts to lowercase
# - Replaces non-alphanumeric characters with hyphens
# - Trims leading/trailing hyphens
# - Preserves original extension
clean_name() {
    local file_path
    file_path="$1"
    local original_name
    original_name=$(basename "$file_path")
    local found
    found=0
    local base full_ext

    # Handle composite extensions
    for ext in "${composite_exts[@]}"; do
        if [[ "$original_name" == *".${ext}" ]]; then
            full_ext="$ext"
            base="${original_name%."$ext"}"
            found=1
            break
        fi
    done

    if [[ "$found" -eq 0 ]]; then
        full_ext="${original_name##*.}"
        base="${original_name%.*}"
    fi

    local clean_base
    clean_base=$(echo "$base" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g' | sed -E 's/^-+|-+$//g')
    echo "${clean_base}.${full_ext}"
}

# === Signal Handlers ===
trap 'log_error "Unhandled error at line $LINENO: command \`$BASH_COMMAND\` exited with $?"; send_error_mail' ERR
trap 'log_info "instant-remote-storage exited at $(date "+%Y-%m-%d %H:%M:%S")"' EXIT
trap 'log_warning "Script interrupted. Exiting..."; exit 130' INT TERM

# === Main Loop: Watches for new or closed files ===
# Uses inotifywait to monitor local directory
# On file write or move completion, reacts to each event
inotifywait -m \
    -e moved_to \
    -e close_write \
    --format '%f' \
    "$LOCAL_DIR" | while read -r FILENAME; do

    LOCAL_FILE="$LOCAL_DIR/$FILENAME"
    REMOTE_PATH="$REMOTE_DIR/$FILENAME"

    # Skip unwanted files: hidden dotfiles or temporary editor files
    [[ "$FILENAME" == .goutputstream* || "$FILENAME" =~ ^\.[^./]*$ ]] && {
        log_warning "Skipping unsupported file: '$FILENAME'"
        continue
    }

    [[ ! -f "$LOCAL_FILE" ]] && {
        log_error "File not found: '$LOCAL_FILE'"
        continue
    }

    # Compute local file hash
    LOCAL_HASH=$(md5sum "$LOCAL_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$LOCAL_HASH" ]] && {
        log_error "Checksum failed: '$LOCAL_FILE'"
        send_error_mail
        continue
    }

    # Retrieve remote hash if file exists remotely
    EXISTING_HASH=$(rclone md5sum "$REMOTE_PATH" 2>/dev/null | awk '{print $1}' || true)

    # Try to assign new extension (based on MIME), if needed
    NEW_FILENAME=$(assign_extension "$LOCAL_FILE")
    ASSIGN_EXIT_CODE=$?

    # Rename local file if new filename differs (extension corrected, sanitized)
    if [[ "$ASSIGN_EXIT_CODE" -ne 42 ]]; then
        SAVE_FILENAME=$(clean_name "$NEW_FILENAME")
        if [[ "$SAVE_FILENAME" != "$FILENAME" ]]; then
            if ! mv "$LOCAL_DIR/$FILENAME" "$LOCAL_DIR/$SAVE_FILENAME"; then
                log_error "Rename failed: '$FILENAME' → '$SAVE_FILENAME'"
                send_error_mail
                continue
            fi
            FILENAME="$SAVE_FILENAME"
            LOCAL_FILE="$LOCAL_DIR/$FILENAME"
            REMOTE_PATH="$REMOTE_DIR/$FILENAME"
        fi
    else
        # Extension couldn't be assigned, still try renaming to original if changed
        FILENAME="$NEW_FILENAME"
        LOCAL_FILE="$LOCAL_DIR/$FILENAME"
        REMOTE_PATH="$REMOTE_DIR/$FILENAME"
    fi

    # === Upload Decision Logic ===

    if [[ -z "$EXISTING_HASH" ]]; then
        # File doesn't exist remotely → upload it directly
        if ! rclone copyto "$LOCAL_FILE" "$REMOTE_PATH"; then
            log_error "Upload failed: '$LOCAL_FILE' → '$REMOTE_PATH'"
            send_error_mail
        fi

    elif [[ "$LOCAL_HASH" != "$EXISTING_HASH" ]]; then
        # Conflict: file with same name but different content
        # Append (copy), (copy 2), etc. to the filename until unique
        IFS=":::" read -r BASE EXT <<< "$(split_base_ext "$FILENAME")"
        COUNT=1
        NEW_NAME="$BASE (copia).$EXT"
        while [[ -f "$LOCAL_DIR/$NEW_NAME" ]] || rclone lsf "$REMOTE_DIR/$NEW_NAME" &>/dev/null; do
            COUNT=$((COUNT + 1))
            NEW_NAME="$BASE (copia $COUNT).$EXT"
        done
        if ! rclone copyto "$LOCAL_FILE" "$REMOTE_DIR/$NEW_NAME"; then
            log_error "Conflict upload failed: '$LOCAL_FILE' → '$NEW_NAME'"
            send_error_mail
        fi
    fi
done

