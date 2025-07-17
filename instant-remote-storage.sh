#!/usr/bin/env bash

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


# === 0 PHASE - INITIAL SETTING ===
set -euo pipefail

# === Logging settings ===
LOG_TAG="instant-remote-storage"
DEBUG="1"  # Imposta a "1" per abilitare log DEBUG dettagliati

log_info() {
    logger -t "$LOG_TAG" "[INFO]    $*;"
}

log_debug()   {
    [[ "$DEBUG" == "1" ]] && logger -t "$LOG_TAG" "[DEBUG]   $*";
}

log_warning() {
    logger -t "$LOG_TAG" "[WARNING] $*";
}

log_error()   {
    logger -t "$LOG_TAG" "[ERROR]   $*";
}

# Send an error email with last 50 log lines from journalctl
# Requires: ~/.msmtprc and msmtp configured
# Triggered only when something fails during execution
send_error_mail() {
    # Check that ~/.msmtprc exists and is not empty
    if [[ ! -s "$HOME/.msmtprc" ]]; then
        local warn_msg="⚠️ Missing or empty ~/.msmtprc. Email notification disabled."
        log_warning "$warn_msg"
        return 0  # Do not block the script
    fi

    local subject
    subject="❌ Error in instant-remote-storage on $(hostname) - $(date '+%Y-%m-%d %H:%M:%S')"

    local recipient
    recipient="amminflow@gmail.com"

    local body_head
    body_head=$(
        cat <<-EOF
            Hello,
            An error occurred during the execution of *instant-remote-storage*.

            • Command: "$BASH_COMMAND"
            • Line: $LINENO
            • Exit code: $?

            Below are the last 50 lines from the system journal:

EOF
  )

    local body_tail
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

LOCAL_DIR="$HOME/storage-remoto-nextcloud"
REMOTE_DIR="hetzner-nc:indifferenziato"

REQUIRED_CMDS=(rclone inotifywait md5sum date grep find awk mapfile msmtp)

# Ensure prerequisites
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "Required command '$cmd' not found. Please install it."
        send_error_mail
        exit 1
    fi
done

# Ensure local directory exists
if ! mkdir -p "$LOCAL_DIR"; then
    log_error "Failed to create local directory: $LOCAL_DIR"
    send_error_mail
    exit 1
fi

if ! rclone lsf "$REMOTE_DIR" &>/dev/null; then
    log_error "Remote '$REMOTE_DIR' not reachable"
    send_error_mail
    exit 1
fi

if ! rclone mkdir "$REMOTE_DIR" 2>/dev/null; then
    log_warning "Remote directory may not exist or cannot be created: $REMOTE_DIR"
    # No exit: may already exist or still be writable
fi


# Maps known MIME types to single, simple file extensions
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


# List of known composite extensions used by clean_name and assign_extension
composite_exts=("tar.gz" "tar.bz2" "tar.xz" "tar.zst" "tar.lz4" "tar.br")


# === 1 PHASE - DEFINING FUNCTIONS ===

# Split a filename into base name and extension (supporting composite extensions)
# Input : filename (e.g., "backup.tar.zst")
# Output: "base:::ext" (e.g., "backup:::tar.zst")
split_base_ext() {
    local filename="$1"
    for ext in "${composite_exts[@]}"; do
        if [[ "$filename" == *".${ext}" ]]; then
            echo "${filename%."$ext"}:::${ext}"
            return
        fi
    done
    echo "${filename%.*}:::${filename##*.}"
}

# Detect MIME type of a file using 'file --mime-type'
# Input: file path
# Output: MIME type string (e.g., "image/jpeg")
get_mime() {
    local file_path
    file_path="$1"
    local mime

    if [[ ! -s "$file_path" ]]; then
        log_warning "'$file_path' is empty. Skipping MIME detection."
        echo ""
        return
    fi

    mime=$(file --mime-type -b "$file_path")
    echo "$mime"
}

# Assign a proper extension based on MIME type if missing or wrong
# Input: file path
# Output: new filename with correct extension
assign_extension() {
    local file_path="$1"
    local original_name
    original_name=$(basename "$file_path")

    # If file ends with a known composite extension, keep it as is
    for ext in "${composite_exts[@]}"; do
        if [[ "$original_name" == *".${ext}" ]]; then
            log_debug "Composite extension '$ext' detected in '$original_name'. Keeping original name."
            echo "$original_name"
            return 0
        fi
    done

    # Detect MIME type
    local mime
    mime=$(get_mime "$file_path")

    if [[ -z "$mime" ]]; then
        log_warning "Could not detect MIME type for '$file_path'. Skipping extension assignment."
        echo "$original_name"
        return 42
    fi

    # Lookup extension from MIME type
    local ext="${MIME_EXTENSIONS[$mime]}"

    if [[ -z "$ext" ]]; then
        log_warning "MIME type '$mime' for '$file_path' is not mapped. Skipping extension assignment."
        echo "$original_name"
        return 42
    fi

    # Check if the filename already ends with the correct extension
    if [[ "$original_name" == *".${ext}" ]]; then
        echo "$original_name"
    else
        local new_name="${original_name}.${ext}"
        echo "$new_name"
    fi
}

# Normalize the filename: lowercase, remove special chars, clean dashes
# Input: file path
# Output: sanitized filename (e.g., "My File.txt" → "my-file.txt")
clean_name() {
    local file_path="$1"
    local original_name
    original_name=$(basename "$file_path")
    local base full_ext found

    full_ext=""
    base=""
    found=0

    # Detect if the filename ends with a known composite extension
    for ext in "${composite_exts[@]}"; do
        if [[ "$original_name" == *".${ext}" ]]; then
            full_ext="$ext"
            base="${original_name%."$ext"}"  # Remove the entire composite extension
            found=1
            break
        fi
    done

    # If no composite extension was found, fall back to standard logic
    if [[ "$found" -eq 0 ]]; then
        full_ext="${original_name##*.}"
        base="${original_name%.*}"
    fi

    # Normalize and clean the base name:
    # - Lowercase
    # - Replace non-alphanumeric chars with hyphens
    # - Trim leading/trailing hyphens
    local clean_base
    clean_base=$(echo "$base" | \
        tr '[:upper:]' '[:lower:]' | \
        sed -E 's/[^a-z0-9]+/-/g' | \
        sed -E 's/^-+|-+$//g')

    local new_name="${clean_base}.${full_ext}"

    log_debug "Filename cleaned: '$original_name' → '$new_name'"
    echo "$new_name"
}

# === 2 PHASE - DETECTING -> RENAMING -> UPLOADING NEW FILES IN THE FOLDER ===
inotifywait -m \
    -e moved_to \
    -e close_write \
    --format '%f' \
    "$LOCAL_DIR" | while read -r FILENAME; do

        LOCAL_FILE="$LOCAL_DIR/$FILENAME"
        REMOTE_PATH="$REMOTE_DIR/$FILENAME"

        # Escludi file temporanei
        if [[ "$FILENAME" == .goutputstream* ]]; then
            log_debug "Skipping temporary file: $FILENAME"
            continue
        fi

        # Blocca file senza nome base (es. .bashrc, .txt)
        if [[ "$FILENAME" =~ ^\.[^./]*$ ]]; then
            log_warning "File '$FILENAME' has no basename. Skipping. Please rename it if you want it synced."
            continue
        fi

        # Check if the file still exists (may have been deleted or moved before processing)
        if [[ ! -f "$LOCAL_FILE" ]]; then
            log_error "File not found: '$LOCAL_FILE'. Skipping upload."
            # TODO: Notify via email
            continue
        fi

        # Attempt to compute the local MD5 checksum
        LOCAL_HASH=$(md5sum "$LOCAL_FILE" 2>/dev/null | awk '{print $1}')
        if [[ -z "$LOCAL_HASH" ]]; then
            log_error "Could not compute local checksum for '$LOCAL_FILE'"
            send_error_mail
            continue  # skip this file, do not block script
        fi

        # Try to get remote checksum (empty if not exists)
        if ! EXISTING_HASH=$(rclone md5sum "$REMOTE_PATH" 2>/dev/null | awk '{print $1}'); then
            log_warning "Could not retrieve remote checksum for '$REMOTE_PATH'"
            EXISTING_HASH=""
        fi

        # Check if file has extension
        NEW_FILENAME=$(assign_extension "$LOCAL_FILE")
        ASSIGN_EXIT_CODE=$?

        # RENAMING - Get a save filename
        if [[ "$ASSIGN_EXIT_CODE" -eq 42 ]]; then
            NEW_FILENAME="$FILENAME"  # fallback esplicito
        else
            SAVE_FILENAME=$(clean_name "$NEW_FILENAME")
            if [[ "$SAVE_FILENAME" != "$FILENAME" ]]; then
                if ! mv "$LOCAL_DIR/$FILENAME" "$LOCAL_DIR/$SAVE_FILENAME"; then
                    log_error "Failed to rename '$FILENAME' → '$SAVE_FILENAME'"
                    send_error_mail
                    continue
                fi
                FILENAME="$SAVE_FILENAME"
                LOCAL_FILE="$LOCAL_DIR/$FILENAME"
                REMOTE_PATH="$REMOTE_DIR/$FILENAME"
            fi
        fi

        # UPLOADING - Copy to remote
        if [[ -z "$EXISTING_HASH" ]]; then
            # No remote file → copy directly
            if ! rclone copyto "$LOCAL_FILE" "$REMOTE_PATH"; then
                log_error "Failed to upload '$LOCAL_FILE' to '$REMOTE_PATH'"
                send_error_mail
                continue
            fi
        else
            if [[ "$LOCAL_HASH" == "$EXISTING_HASH" ]]; then
                # Same content → skip
                continue
            else
                # Conflict: generate new name with suffix "(copia)", "(copia 2)", ...
                IFS=":::" read -r BASE EXT <<< "$(split_base_ext "$FILENAME")"
                COUNT=1
                NEW_NAME="$BASE (copia).$EXT"

                # Loop until name is free
                while [[ -f "$LOCAL_DIR/$NEW_NAME" ]] || rclone lsf "$REMOTE_DIR/${NEW_NAME}" &>/dev/null; do
                    COUNT=$((COUNT + 1))
                    NEW_NAME="$BASE (copia $COUNT).$EXT"
                done

                if ! rclone copyto "$LOCAL_FILE" "$REMOTE_DIR/$NEW_NAME"; then
                    log_error "Failed to upload renamed copy '$LOCAL_FILE' → '$NEW_NAME'"
                    send_error_mail
                    continue
                fi
            fi
        fi
    done
