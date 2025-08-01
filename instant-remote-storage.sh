#!/usr/bin/env bash

# Questo fa in modo tale che lo script parta una sola volta ← LUCCHETTO intero script
LOCKFILE="/tmp/instant-remote-storage.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "⚠️ Already running. Exiting."
    exit 1
fi

# ========================================
# instant-remote-storage - v0.5.0
# Author : Carlo Capobianchi (bynflow)
# GitHub : https://github.com/bynflow
# Last Modified: 2025-07-31
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
# ========================

# Qui informa circa il numero di processo dello script
log_info "🔒 Acquisito lock globale — PID: $$"

# === Email ===
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
# ========================

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
        if ! send_error_mail; then
            log_warning "❗ send_error_mail failed or unavailable"
        fi
        exit 1
    fi
done

# Ensure local directory exists
mkdir -p "$LOCAL_DIR" || {
    log_error "Failed to create local directory: $LOCAL_DIR"
    if ! send_error_mail; then
        log_warning "❗ send_error_mail failed or unavailable"
    fi
    exit 1
}

# Ensure remote directory is initialized
if ! rclone mkdir "$REMOTE_DIR" 2>/dev/null; then
    log_warning "Remote directory may not exist or cannot be created: $REMOTE_DIR"
fi

# Check remote connection
if ! rclone lsf "$REMOTE_DIR" &>/dev/null; then
    log_error "Remote '$REMOTE_DIR' not reachable"
    if ! send_error_mail; then
        log_warning "❗ send_error_mail failed or unavailable"
    fi
    exit 1
fi

# Create a unique temporary lock directory (will be cleaned up automatically at script exit)
LOCKDIR="$(mktemp -d /tmp/irs-locks.XXXXXX)"    # ← LUCCHETTO intero ciclo (+ hash del file) ↓

declare -A PATH_HASH_SEEN=()    # Traccia path LOCALE + nome + hash → deduplica effettiva
path_hash_key=""
declare -A FINAL_SEEN=()        # Traccia path REMOTO + nome + hash → skip upload

# === MIME to extension map (placeholder) ===
declare -A MIME_EXTENSIONS=(
    # Text
    ["text/plain"]="txt"
    ["text/html"]="html"
    ["text/css"]="css"
    ["text/csv"]="csv"
    ["text/markdown"]="md"
    ["application/x-bittorrent"]="torrent"

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
# ========================

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
            echo "${filename%."$ext"}:::${ext}" # Da intendere come lavora questa riga
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
    local file_path
    file_path="$1"
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
    local local_file="$1"   # path assoluto
    local filename="$2"     # path relativo + nome_file OPPURE solo filename se file in radice
    local remote_path="$REMOTE_DIR/$filename"
    local EXIT_REASON=""

    trap '[ "$EXIT_REASON" != "OK" ] && log_warning "⛔ handle_file EXIT_REASON='"$EXIT_REASON"' at line $LINENO: command \`$BASH_COMMAND\` exited with $? — cleaning up lock."; cleanup_lock' RETURN

    log_debug "➡️ handle_file: inizio per '$filename'" # ← cartella_relativa+nome_file

    # === 1. Calcolo hash e gestione lock ===
    local hash
    hash=$(compute_hash "$local_file")
    [[ -z "$hash" ]] && {
        log_error "❌ Hash failed: '$filename'"
        if ! send_error_mail; then
            log_warning "❗ send_error_mail failed or unavailable"
        fi
        EXIT_REASON="ERR"
        return 1
    }

    log_debug "🎯 handle_file start: $filename + hash = $hash"

    # Estrai path relativo e directory contenitore
    # Qui, se il file è nella root ('indifferenziato') $filepath e
    # $relative_path saranno uguali al nome del file, quindi si corregge
    # $relative_path con =""
    local filepath="${local_file#"$LOCAL_DIR"/}"    # path relativo+nome file
    local relative_path="${filepath%/*}"            # path relativo (senza nome file)
    log_debug "relative_path al rigo 403: $relative_path"
    [[ "$relative_path" == "$filepath" ]] && relative_path=""   # <<--- Non viene usato

    # Procedura di lock (per evitare doppio trigger da inotify) ← LUCCHETTO intero ciclo ↑
    local HASHLOCK # ="$LOCKDIR/${hash}.lock"
    HASHLOCK="$LOCKDIR/${hash}.lock"
    if [[ -e "$HASHLOCK" ]]; then
        log_debug "⏳ Hash '$hash' is currently locked. Skipping duplicate trigger."
        EXIT_REASON="LOCK"
        return 0
    fi
    touch "$HASHLOCK"   # <<------------- verificare l'efficacia di questo sistema
    log_debug "Lucchetto creato: $HASHLOCK"

    log_debug "🔒 Lock acquired for '$filename'"

    EXIT_REASON="OK"

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

    # Skippa file temporanei o dotfile - quindi esce dal ciclo con 'return 0' poi
    # inotifywait resta in attesa di altri eventi
    [[ "$filename" =~ ^\.goutputstream || "$filename" =~ \.(swp|part|tmp|bak)$ || "$filename" =~ ^\..* ]] && {
        log_warning "⏭️ Skipped unsupported: '$filename'"
        cleanup_lock
        EXIT_REASON="SKIP"
        return 0
    }

    # # # === Inizio della logica principale ===
    # new_filename ha 3 possibilità: 1. è come $filename non modificato perché è ben formato con estensione corretta,
    # 2. è filename più l'aggiunta di una estensione, 3. è lasciato com'è perché
    # non è stato riconosciuto né il MIME né l'estensione
    local new_filename
    local assign_exit_code

    local assign_output
    local save_filename
    local new_remote_path

    # Cattura stdout + exit code
    assign_output=$(assign_extension "$local_file"; echo "___EXIT:$?")
    assign_exit_code=$(printf '%s' "$assign_output" | sed -n 's/.*___EXIT:\([0-9]\+\)/\1/p')
    assign_output=$(printf '%s' "$assign_output" | sed 's/___EXIT:.*//')    # Output del filename ancora eventualmente malformato ma con estensione assegnata
    

    new_filename=$(printf "%s" "$assign_output" | xargs)

    log_debug "🔎 assign_exit_code = $assign_exit_code"
    log_debug "🧪 assign_output = '$assign_output'"
    log_debug "📝 new_filename = '$new_filename'"

    if [[ "$assign_exit_code" -eq 42 ]]; then
        # Caso 1: MIME non mappato → prosegui col nome originale
        log_info "⚠️ MIME non mappato per '$filename' → si prosegue con nome originale"
        new_filename="$filename"
        remote_path="$REMOTE_DIR/$new_filename"

    elif [[ "$assign_exit_code" -ne 0 ]]; then
        # Errore vero → interrompi
        log_error "❌ assign_extension failed for '$filename' (code: $assign_exit_code)"
        if ! send_error_mail; then
            log_warning "❗ send_error_mail failed or unavailable"
        fi
        cleanup_lock
        EXIT_REASON="ERR"
        return 1

    elif [[ -z "$new_filename" ]]; then
        # Errore anomalo
        log_error "new_filename is unexpectedly empty after assign_extension"
        if ! send_error_mail; then
            log_warning "❗ send_error_mail failed or unavailable"
        fi
        cleanup_lock
        EXIT_REASON="ERR"
        return 1

    else
        # Caso 2 e 3: MIME mappato, estensione assente o già presente
        save_filename=$(clean_name "$new_filename")
        log_debug "Questo è il 'save_filename': '$save_filename' appena ripulito da clean_name()"

        if [[ "$save_filename" != "$(basename "$filename")" ]]; then    # Qui $filename è ancora il path relativo + il filename grezzo, prima di clean_name, il basename è solo il nome del file
            log_debug "🔁 Clean name differente: '$filename' → '$save_filename'"

            local parent_dir
            parent_dir=$(dirname "$filename")
            log_debug "Questo è 'parent_dir': $parent_dir"
            # mkdir -p "$LOCAL_DIR/$parent_dir"   # <<----------------verificarne il senso

            # Check se la destinazione è lo stesso file
            if [[ "$local_file" == "$LOCAL_DIR/$parent_dir/$save_filename" ]]; then # $local_file è il path assoluto + nome -- $LOCAL_DIR/$parent_dir/$save_filename è il path assoluto + nome sanificato
                log_debug "🟡 Skip rename: sorgente e destinazione sono identici"
            else

                log_debug "RIGO 520 - parent_dir → $parent_dir _  save_filename → $save_filename"
                # Aggiorna variabili coerenti
                filename="$parent_dir/$save_filename" # NUOVO FILENAME - Qui filename viene rinominato per la PRIMA e UNICA volta
                filename="${filename#./}"  # ← Elimina prefisso ./ se presente
                log_debug "RIGO 520 - filename → $filename"

                # === Seconda verifica duplicati, dopo eventuale rinomina ===
                # local path_hash_key
                path_hash_key="${hash}___${filename}" # Hash + filename nuovo ---------->> questo sistema è qui perché qui si crea il MOVE_TO e non se il file non venisse rinominato
                if [[ -n "${PATH_HASH_SEEN[$path_hash_key]:-}" ]]; then # ← Traccia LOCALE
                    log_debug "🟡 Already handled after rename: $path_hash_key"
                    EXIT_REASON="SKIP"
                    cleanup_lock
                    return 0
                fi
                PATH_HASH_SEEN["$path_hash_key"]=1
                log_debug "RIGO 524 - path_hash_key → $path_hash_key"
                log_debug "RIGO 533 - PATH_HASH_SEEN[path_hash_key] → PATH_HASH_SEEN[$path_hash_key]"

                log_debug "parent_dir rigo 533: $parent_dir"    # ---- Verificare se nel caso il path+ filename siano identici ma hash diversi cosa succede i locale vosto che al momento sembra
                # che in locale il file venga sovrascritto
                if ! mv "$local_file" "$LOCAL_DIR/$parent_dir/$save_filename"; then # Qui il file reale $local_file viene rinominato per la PRIMA e UNICA volta (in path-assoluto+nome-normalizzato)
                    unset "PATH_HASH_SEEN[$path_hash_key]"
                    log_error "Rename failed: '$filename' → '$save_filename'"
                    if ! send_error_mail; then
                        log_warning "❗ send_error_mail failed or unavailable"
                    fi
                    cleanup_lock
                    EXIT_REASON="ERR"
                    return 1
                fi

                # Qui la variabile $local_file viene rinominata per la PRIMA e UNICA volta ← NOME DEL FILE MODIFICATO - path identico
                local_file="$LOCAL_DIR/$filename"   # qui path assoluto + nome

            fi
        fi

        remote_path="$REMOTE_DIR/$filename" # Qui abbiamo il remote_path di inizio funzione se il filename normalizzato è identico a quello originario, altrimenti abbiamo col nuovo filename
        log_debug "'filename' FUORI 'if [[ save_filename != basename filename) ]]' (cioè i 2 termini sono uguali) - al rigo 555: $filename"

    fi

    # Assicura che la cartella remota esista
    remote_dir_path=$(dirname "$remote_path")   # remote_path→path assoluto + nome originario o nome sanificato |||| remote_dir_path → path assoluto senza nome del file
    if ! rclone mkdir "$remote_dir_path" >/dev/null 2>&1; then
        log_warning "❗ Impossibile creare la directory remota: $remote_dir_path"
    fi

    # === 4. Upload con gestione conflitti ===
    if rclone lsf "$remote_path" &>/dev/null; then
        # Conflitto nome → genera filename alternativo
        log_debug "filename riga 563 prima di eventuale rinomina con (copia [n°]): $filename"
        IFS=":::" read -r BASE EXT <<< "$(split_base_ext "$filename")"  # Fare un check sul modo in cui funziona la funzione visto che filename è path relativo+nome del file
        COUNT=1
        BASE="${BASE//:/}"
        EXT="${EXT//:/}"
        NEW_NAME="${BASE}-(copia).${EXT}"

        while rclone lsf "$REMOTE_DIR/$NEW_NAME" &>/dev/null || [[ -f "$LOCAL_DIR/$NEW_NAME" ]]; do
            COUNT=$((COUNT + 1))
            NEW_NAME="${BASE}-(copia ${COUNT}).${EXT}"
        done

        new_remote_path="$REMOTE_DIR/$NEW_NAME"
        log_debug "new_remote_path riga 574 dopo eventuale rinomina con (copia [n°]): $new_remote_path"

        local final_key
        final_key="${hash}___${new_remote_path}"
        if [[ -n "${FINAL_SEEN[$final_key]:-}" ]]; then # Traccia REMOTA
            log_debug "🛑 Already uploaded (renamed): $final_key"
            EXIT_REASON="SKIP"
            cleanup_lock
            return 0
        fi
        FINAL_SEEN["$final_key"]=1

        if ! rclone copyto "$local_file" "$new_remote_path"; then
            log_error "⚠️ Conflict upload failed: '$filename' → '$NEW_NAME'"
            if ! send_error_mail; then
                log_warning "❗ send_error_mail failed or unavailable"
            fi
            EXIT_REASON="ERR"
            return 1
        fi
        log_info "📤 Conflict upload completed: '$filename' → '$NEW_NAME'"

    else

        local final_key="${hash}___${remote_path}"    # <<------------- forse (anche) questo non ha senso perché il file essendo già presente è già passato per la rinomina con (copia [n°])
        if [[ -n "${FINAL_SEEN[$final_key]:-}" ]]; then # Traccia REMOTA
            log_debug "🛑 Already uploaded: $final_key"
            EXIT_REASON="SKIP"
            cleanup_lock
            return 0
        fi
        FINAL_SEEN["$final_key"]=1

        # Nessun conflitto → upload normale
        if ! rclone copyto "$local_file" "$remote_path"; then   # local_file → path assoluto più nome originario o sanitizzato - remote_path → path remoto assoluto più nome originario o sanitizzato
            log_error "❌ Upload failed: '$filename'"
            if ! send_error_mail; then
                log_warning "❗ send_error_mail failed or unavailable"
            fi
            cleanup_lock
            EXIT_REASON="ERR"
            return 1
        fi
        log_info "✅ Upload completed: '$filename'"
    fi
    cleanup_lock
    log_info "📦 File '$filename' marked as processed (hash: $hash)"

    EXIT_REASON="OK"
    log_debug "⬅️ handle_file: fine per '$filename'"
    return 0
}

main_loop() {
    log_info "🚀 Starting instant-remote-storage watcher on $(hostname) at $(date)"

    while IFS=":::" read -r FULLPATH EVENT; do
        RELATIVE_PATH="${FULLPATH#"$LOCAL_DIR"/}"   # Path relativo + Filename OPPURE solo Filename (se il file è nella cartella radice)
        RELATIVE_PATH="${RELATIVE_PATH#./}"  # ← Elimina prefisso ./ se presente
        log_debug "RELATIVE_PATH alla riga 633 in main_loop: $RELATIVE_PATH"
        log_debug "📥 Event '$EVENT' received for: $RELATIVE_PATH"

        if [[ -d "$FULLPATH" ]]; then
            # 🔁 Replica tutta la struttura, anche se vuota
            log_debug "🛠️ Ricostruzione struttura remota per '$RELATIVE_PATH'"  # ← Questo log non viene registrato anche se dovrebbe
            while read -r DIR; do
                SUBPATH="${DIR#"$LOCAL_DIR"/}"
                if rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1; then    # ← Questo mkdir per remoto è già operato in handle_file ma il log seguente ↓ non viene registrato quindi il comando forse non viene dato mai
                    log_info "📁 Directory remota creata: '$REMOTE_DIR/$SUBPATH'"
                else
                    log_warning "⚠️ Impossibile creare directory remota: '$REMOTE_DIR/$SUBPATH'"
                fi
            done < <(find "$FULLPATH" -type d)

            # 📄 Elabora tutti i file contenuti
            while read -r FILE; do
                RELFILE="${FILE#"$LOCAL_DIR"/}"
                log_debug "RELFILE alla riga 658 in main_loop: $RELFILE"
                handle_file "$FILE" "$RELFILE"
            done < <(find "$FULLPATH" -type f)

        # Old
        # elif [[ -f "$FULLPATH" ]]; then
        #     # 📄 File singolo normale
        #     # log_debug "Sono in 'main_loop': FULLPATH → $FULLPATH - RELATIVE_PATH → $RELATIVE_PATH"
        #     handle_file "$FULLPATH" "$RELATIVE_PATH"
        # fi
        elif [[ -f "$FULLPATH" ]]; then
            # 📄 File singolo normale

            # Calcola hash e path_hash_key come in handle_file
            local FILE_HASH
            FILE_HASH=$(compute_hash "$FULLPATH")
            if [[ -z "$FILE_HASH" ]]; then
                log_warning "⚠️ Hash non calcolabile per $FULLPATH, passo oltre"
                continue
            fi

            path_hash_key="${FILE_HASH}___${RELATIVE_PATH}"
            log_debug "RIGO 680 - path_hash_key → $path_hash_key"

            if [[ -n "${PATH_HASH_SEEN[$path_hash_key]:-}" ]]; then
                log_debug "🟡 Already handled in main_loop: $path_hash_key"
                log_warning "📛 Skipped early in main_loop (already processed): $FULLPATH"
                continue
            fi

            # Debug: stampa tutto l’array PATH_HASH_SEEN    ---->> Questo array contiene SOLO le chiavi dei filename normalizzati
            for key in "${!PATH_HASH_SEEN[@]}"; do
                log_debug "Chiave: $key → Valore: ${PATH_HASH_SEEN[$key]}"
            done

            handle_file "$FULLPATH" "$RELATIVE_PATH"
        fi
    done < <(inotifywait -m -r -e close_write,moved_to --format '%w%f:::%e' "$LOCAL_DIR")

    log_info "🚨 Watch loop has terminated unexpectedly. Restart recommended."
}

# === Signal Handlers ===
trap 'log_error "Unhandled error at line $LINENO: command \`$BASH_COMMAND\` exited with $?"; send_error_mail' ERR
trap 'log_info "instant-remote-storage exited at $(date "+%Y-%m-%d %H:%M:%S")"' EXIT
# Clean up entire lockdir when script exits (even with Ctrl+C)
trap 'rm -rf "$LOCKDIR"' EXIT
trap 'log_warning "Script interrupted. Exiting..."; exit 130' INT TERM

main_loop

