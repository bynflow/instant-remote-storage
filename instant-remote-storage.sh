#!/usr/bin/env bash

# ========================================
# instant-remote-storage - v0.2.0
# Author : Carlo Capobianchi (bynflow)
# GitHub : https://github.com/bynflow
# Last Modified: 2025-07-20
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
    # Check that ~/.msmtprc exists and is not empty
    if [[ ! -s "$HOME/.msmtprc" ]]; then
        log_warning "⚠️ Missing or empty ~/.msmtprc. Email disabled."
        return 0
    fi

    local subject recipient from_account from_address
    subject="❌ Error in instant-remote-storage on $(hostname) - $(date '+%Y-%m-%d %H:%M:%S')" 
    recipient="${EMAIL_TO:-default@example.com}"
    from_account="${MSMTP_ACCOUNT:-default}"
    from_address="${EMAIL_FROM:-instant-remote-storage <noreply@localhost>}"

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
        echo "From: $from_address"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo
        echo "$body_head$body_tail"
    } | msmtp --from="$from_account" -t 2>/dev/null
}

# === Configuration variables ===
LOCAL_DIR="$HOME/storage-remoto-nextcloud"
REMOTE_DIR="hetzner-nc:indifferenziato"

ENV_PATH="$HOME/.env"
if [[ -f "$ENV_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_PATH"
    log_info "📂 Loaded environment config from $ENV_PATH"
else
    log_warning "⚠️ Config file .env not found at $ENV_PATH"
fi

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

# Create a unique temporary lock directory (will be cleaned up automatically at script exit)
LOCKDIR="$(mktemp -d /tmp/irs-locks.XXXXXX)"
declare -A HASH_PROCESSED

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
    ["application/x-shellscript"]="sh"
    ["text/x-shellscript"]="sh"
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

handle_file() {
    local local_file="$1"
    local filename="$2"
    local remote_path="$REMOTE_DIR/$filename"

    # === 1. Calcolo hash e gestione lock ===
    local local_hash
    local_hash=$(compute_hash "$local_file")
    [[ -z "$local_hash" ]] && {
        log_error "❌ Hash failed: '$filename'"
        send_error_mail
        return 1
    }

    # Evita rielaborazione se già processato
    if [[ -n "${HASH_PROCESSED[$local_hash]:-}" ]]; then
        log_debug "🟡 Hash '$local_hash' already processed. Skipping '$filename'."
        return 0
    fi

    declare -g HASHLOCK
    HASHLOCK="$LOCKDIR/${local_hash}.lock"
    if [[ -e "$HASHLOCK" ]]; then
        log_warning "🚫 '$filename' already being processed (hash: $local_hash)"
        return 0
    fi
    touch "$HASHLOCK"

    log_debug "🔒 Lock acquired for '$filename'"

    # === 2. Pre-check: stabilità, file nascosti, visibilità ===
    if ! wait_for_stable_file "$local_file"; then
        log_warning "⏳ '$filename' not stable"
        return 1
    fi

    # Verifica visibilità reale file (MOVED_TO troppo anticipato)
    [[ ! -f "$local_file" ]] && {
        log_debug "⏳ File not yet available: '$filename'. Waiting for a later event."
        return 0
    }

    # Skippa file temporanei o dotfile
    [[ "$filename" =~ ^\.goutputstream || "$filename" =~ \.(swp|part|tmp|bak)$ || "$filename" =~ ^\..* ]] && {
        log_warning "⏭️ Skipped unsupported: '$filename'"
        return 0
    }

    # === 3. Rinominazione MIME + clean name ===
    # MIME + estensione
    local new_filename
    new_filename=$(assign_extension "$local_file")
    local assign_exit_code=$?

    if [[ "$assign_exit_code" -ne 42 ]]; then
        log_debug "Extension left unchanged for '$file_path' (original: '$original_name', MIME: '$mime')"
        local save_filename
        save_filename=$(clean_name "$new_filename")
        if [[ "$save_filename" != "$filename" ]]; then
            if ! mv "$local_file" "$LOCAL_DIR/$save_filename"; then
                log_error "Rename failed: '$filename' → '$save_filename'"
                send_error_mail
                return 1
            fi
            filename="$save_filename"
            log_info "🔁 Filename updated to: '$filename'"
            local_file="$LOCAL_DIR/$filename"
            remote_path="${remote_path:-$REMOTE_DIR/$filename}"
        fi
    else
        filename="$new_filename"
        log_info "🔁 Filename updated to: '$filename'"
        local_file="$LOCAL_DIR/$filename"
        remote_path="${remote_path:-$REMOTE_DIR/$filename}"
    fi

    # === 4. Upload con gestione conflitti ===
    if rclone lsf "$remote_path" &>/dev/null; then
        # Conflitto nome → genera filename alternativo
        IFS=":::" read -r BASE EXT <<< "$(split_base_ext "$filename")"
        COUNT=1
        BASE="${BASE//:/}"
        EXT="${EXT//:/}"
        NEW_NAME="${BASE}-(copia).${EXT}"

        while rclone lsf "$REMOTE_DIR/$NEW_NAME" &>/dev/null || [[ -f "$LOCAL_DIR/$NEW_NAME" ]]; do
            COUNT=$((COUNT + 1))
            NEW_NAME="${BASE}-(copia ${COUNT}).${EXT}"
        done

        local new_remote_path="$REMOTE_DIR/$NEW_NAME"
        if ! rclone copyto "$local_file" "$new_remote_path"; then
            log_error "⚠️ Conflict upload failed: '$filename' → '$NEW_NAME'"
            send_error_mail
            return 1
        fi
    else
        # Nessun conflitto → upload normale
        if ! rclone copyto "$local_file" "$remote_path"; then
            log_error "❌ Upload failed: '$filename'"
            send_error_mail
            return 1
        fi
        log_info "🔚 Done processing: '$filename'"
    fi
    rm -f "$HASHLOCK"
    HASH_PROCESSED[$local_hash]=1
    log_info "📦 File '$filename' marked as processed (hash: $local_hash)"
}

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
    xdg-mime query filetype "$file_path" 2>/dev/null || \
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

    ext="${MIME_EXTENSIONS[$mime]:-}"
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

# Questa funzione controlla che un file sia "stabile", cioè che la sua dimensione
# non cambi più dopo un certo numero di tentativi (default: 10), con un intervallo
# di 0.5 secondi tra ogni controllo.
# Utile per evitare di agire su file ancora in scrittura (es. durante copie di file grandi).
wait_for_stable_file() {
    local file="$1"                    # File da controllare
    local retries=1000                 # Numero massimo di tentativi
    local interval=0.5                 # Secondi di attesa tra ogni tentativo
    local last_size=-1                 # Dimensione del file al tentativo precedente (inizialmente -1)
    local size

    for ((i=0; i<retries; i++)); do
        # Ottiene la dimensione attuale del file in byte
        # -c %s stampa solo la dimensione (senza nome file o permessi ecc.)
        # Se stat fallisce, restituisce -1
        size=$(stat -c %s "$file" 2>/dev/null || echo -1)

        # Se la dimensione attuale è identica alla precedente e maggiore di 0,
        # consideriamo il file "stabile" e usciamo con successo (return 0)
        if [[ "$size" -eq "$last_size" && "$size" -gt 0 ]]; then
            return 0
        fi

        # Aggiorna la dimensione per il prossimo giro e attende
        last_size=$size
        sleep "$interval"
    done

    # Se il ciclo termina senza trovare una dimensione stabile, logga errore e ritorna fallimento
    log_error "File not stable after retries: '$file'"
    return 1
}

compute_hash() {
    [[ -f "$1" ]] || return 1
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

main_loop() {
    log_info "🚀 Starting instant-remote-storage watcher on $(hostname) at $(date)"

    inotifywait -m -e close_write -e moved_to --format '%w%f:::%e' "$LOCAL_DIR" |
    while IFS=":::" read -r FULLPATH EVENT; do
        FILENAME=$(basename "$FULLPATH")
        log_debug "📥 Event '$EVENT' received for: $FILENAME"

        handle_file "$FULLPATH" "$FILENAME"
    done
    log_info "🔁 Watch loop terminated unexpectedly"
}

# === Signal Handlers ===
trap 'log_error "Unhandled error at line $LINENO: command \`$BASH_COMMAND\` exited with $?"; send_error_mail' ERR
trap 'log_info "instant-remote-storage exited at $(date "+%Y-%m-%d %H:%M:%S")"' EXIT
# Clean up entire lockdir when script exits (even with Ctrl+C)
trap 'rm -rf "$LOCKDIR"' EXIT
trap 'log_warning "Script interrupted. Exiting..."; exit 130' INT TERM

main_loop

