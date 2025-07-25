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

ENV_PATH="$HOME/.env"
if [[ -f "$ENV_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_PATH"
    log_info "📂 Loaded environment config from $ENV_PATH"
else
    log_warning "⚠️ Config file .env not found at $ENV_PATH"
fi

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
# Mappe per evitare duplicati già elaborati
declare -A HASH_SEEN=()
declare -A FILE_SEEN=()
declare -A HASH_PROCESSED=()

# === MIME to extension map (placeholder) ===
declare -A MIME_EXTENSIONS=(
    # Text
    ["text/plain"]="txt"
    ["text/html"]="html"
    ["text/css"]="css"
    ["text/csv"]="csv"
    ["text/markdown"]="md"
    # ["application/x-bittorrent"]="torrent"

    # Images
    # ["image/jpeg"]="jpg"
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

# Rilascio lock in ogni exit anticipato dentro la funzione handle_file
cleanup_lock() {
    if [[ -z "${HASHLOCK:-}" ]]; then
        log_debug "🧼 cleanup_lock: HASHLOCK non inizializzato, nulla da rimuovere."
        return
    fi

    if [[ -e "$HASHLOCK" ]]; then
        rm -f "$HASHLOCK"
        log_debug "🔓 Lock released ($HASHLOCK)"
    fi
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

# Determines MIME type using `xdg-mime` or `file` command; skips empty files
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
    local file_path="$1"
    local original_name
    original_name=$(basename "$file_path")

    # Skip composite types
    for ext in "${composite_exts[@]}"; do
        [[ "$original_name" == *".${ext}" ]] && {
            log_debug "Composite extension '$ext' detected. Keeping original name."
            printf "%s\n" "$original_name"
            return 0
        }
    done

    local mime
    mime=$(get_mime "$file_path")
    if [[ -z "$mime" ]]; then
        log_warning "MIME detection failed. Skipping extension assignment."
        printf "%s\n" "$original_name"
        return 42
    fi

    local ext="${MIME_EXTENSIONS[$mime]:-}"
    # printf "Debug interno 2,2 -> assign_extension()::\t %s ext- $ext\t\n" >&2
    if [[ -z "$ext" ]]; then
        log_warning "MIME '$mime' not mapped. Skipping extension assignment."
        printf "%s\n" "$original_name"
        # printf "Debug interno 2,2 -> assign_extension(condizione 'ext')::\t %s original_name- $original_name\t\n" >&2
        return 42
    fi

    if [[ "$original_name" == *".${ext}" ]]; then
        printf "%s\n" "$original_name"
    else
        printf "%s\n" "${original_name}.${ext}"
    fi

    log_debug "✅ assign_extension: '$original_name' estensione confermata o corretta → '$ext'"
    return 0
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

    # printf "Debug interno 3 -> clean_name()::\t %s original_name- $original_name\t\n" >&2

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

    # printf "Debug interno 4 ->  clean_name()::\t %s base- $base\t\n" >&2
    # printf "Debug interno 5 ->  clean_name()::\t %s full_ext- $full_ext\t\n" >&2

    if [[ -z "$base" ]]; then
        base="unnamed"
    fi

    local clean_base
    clean_base=$(echo "$base" |\
    tr '[:upper:]' '[:lower:]' |\
    sed -E 's/[^a-z0-9]+/-/g' |\
    sed -E 's/^-+|-+$//g')
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
    if [[ ! -f "$1" ]]; then
        log_warning "compute_hash(): file non trovato o non valido: '$1'"
        return 1
    fi

    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

handle_file() {
    local local_file="$1"
    local filename="$2"
    local remote_path="$REMOTE_DIR/$filename"

    log_debug "➡️ handle_file: inizio per '$filename'"

    # === 1. Calcolo hash e gestione lock ===
    local local_hash
    local_hash=$(compute_hash "$local_file")
    [[ -z "$local_hash" ]] && {
        log_error "❌ Hash failed: '$filename'"
        send_error_mail
        EXIT_REASON="ERR"
        return 1
    }

    # Evita rielaborazione se già processato
    if [[ -n "${HASH_PROCESSED[$local_hash]:-}" ]]; then
        log_debug "🟡 Hash '$local_hash' already processed. Skipping '$filename'."
        EXIT_REASON="SKIP"
        return 0
    fi

    # Evita processamenti duplicati solo se hash + filename sono entrambi già visti
    if [[ -n "${HASH_SEEN[$local_hash]:-}" && -n "${FILE_SEEN[$filename]:-}" ]]; then
        log_debug "🟡 Already processed: '$filename' (hash: $local_hash). Skipping."
        EXIT_REASON="SKIP"
        return 0
    fi

    # Prosegui: registra questo file come visto
    HASH_SEEN["$local_hash"]=1
    FILE_SEEN["$filename"]=1

    # Procedura di lock (per evitare doppio trigger da inotify)
    local HASHLOCK="$LOCKDIR/${local_hash}.lock"
    HASHLOCK="$LOCKDIR/${local_hash}.lock"
    if [[ -e "$HASHLOCK" ]]; then
        log_debug "⏳ Hash '$local_hash' is currently locked. Skipping duplicate trigger."
        EXIT_REASON="LOCK"
        return 0
    fi
    touch "$HASHLOCK"

    log_debug "🔒 Lock acquired for '$filename'"

    local EXIT_REASON="OK"
    trap '[ "$EXIT_REASON" != "OK" ] && log_warning "⛔ handle_file crashed or exited early — cleaning up lock."; cleanup_lock' RETURN

    # === 2. Pre-check: stabilità, file nascosti, visibilità ===
    if ! wait_for_stable_file "$local_file"; then
        log_warning "⏳ '$filename' not stable"
        cleanup_lock
        EXIT_REASON="ERR"
        return 1
    fi

    # Verifica visibilità reale file (MOVED_TO troppo anticipato)
    [[ ! -f "$local_file" ]] && {
        log_debug "⏳ File not yet available: '$filename'. Waiting for a later event."
        cleanup_lock
        EXIT_REASON="SKIP"
        return 0
    }

    # Skippa file temporanei o dotfile
    [[ "$filename" =~ ^\.goutputstream || "$filename" =~ \.(swp|part|tmp|bak)$ || "$filename" =~ ^\..* ]] && {
        log_warning "⏭️ Skipped unsupported: '$filename'"
        cleanup_lock
        EXIT_REASON="SKIP"
        return 0
    }

    # === 3. Rinominazione MIME + clean name ===
    local new_filename
    local assign_exit_code

    # Cattura stdout + exit code
    new_filename=$(assign_extension "$local_file" | xargs)
    assign_exit_code=$?
    # printf "Debug interno 6 -> handle_file()::\t %s assign_exit_code- $assign_exit_code\t\n"

    log_debug "🔎 assign_exit_code = $assign_exit_code"
    log_debug "📝 new_filename = '$new_filename'"

    if [[ -z "$new_filename" ]]; then
        log_error "new_filename is unexpectedly empty after assign_extension"
        cleanup_lock
        EXIT_REASON="ERR"
        return 1
    fi

    if [[ "$assign_exit_code" -eq 42 ]]; then
        EXIT_REASON="SKIP"
        log_info "⚠️ MIME unassigned: skipping '$filename' (exit 42 from assign_extension)"
        cleanup_lock
        return 0
    fi

    # Clean name
    local save_filename
    save_filename=$(clean_name "$new_filename")

    # Se è cambiato qualcosa → rinomina file
    if [[ "$save_filename" != "$filename" ]]; then
        log_debug "🔁 Clean name differente: '$filename' → '$save_filename'"
        if ! mv "$local_file" "$LOCAL_DIR/$save_filename"; then
            log_error "Rename failed: '$filename' → '$save_filename'"
            send_error_mail
            cleanup_lock
            EXIT_REASON="ERR"
            return 1
        fi

        # Aggiorna variabili coerenti
        filename="$save_filename"
        local_file="$LOCAL_DIR/$filename"
        remote_path="$REMOTE_DIR/$filename"

        log_info "📦 File renamed to: '$filename'"
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
            EXIT_REASON="ERR"
            return 1
        fi
    else
        # Nessun conflitto → upload normale
        if ! rclone copyto "$local_file" "$remote_path"; then
            log_error "❌ Upload failed: '$filename'"
            send_error_mail
            cleanup_lock
            EXIT_REASON="ERR"
            return 1
        fi
        log_info "✅ Upload completed: '$filename'"
    fi
    cleanup_lock
    HASH_PROCESSED[$local_hash]=1
    log_info "📦 File '$filename' marked as processed (hash: $local_hash)"

    EXIT_REASON="OK"
    log_debug "⬅️ handle_file: fine per '$filename'"
    return 0
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

