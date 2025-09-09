#!/usr/bin/env bash

# ========================================
# instant-remote-storage - v3.0.0
# Author : Carlo Capobianchi (bynflow)
# GitHub : https://github.com/bynflow
# Last Modified: 2025-09-04
# ========================================
# Watches a local directory (LOCAL_DIR) and uploads files to a remote (REMOTE_DIR)
# using rclone. Features:
#   - MIME-based extension normalization (via external map)
#   - Two-phase upload with crash-safe recovery (tmp marker + promote)
#   - Persistent index (dev:inode -> remote path, last hash) to handle:
#       * content updates → overwrite in place (no conflict copy)
#       * pure renames → remote renames (no reupload)
#   - Dedup of simultaneous triggers (hash+inode lock and seen map)
#   - Optional mirroring of empty directories only on final name (MOVED_TO)
#   - Heuristics to detect tarballs inside compressed streams (tar.*)
# ========================================

set -Eeuo pipefail
shopt -s inherit_errexit || true

SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname "$SCRIPT_PATH")" && pwd)"

# shellcheck disable=SC1091
source "$SCRIPT_DIR/mime_map.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/irs_recovery.sh"

# === Logging ===
LOG_TAG=${LOG_TAG:-instant-remote-storage}
DEBUG=${DEBUG:-1}
log_info()    { logger -t "$LOG_TAG" "[INFO]    $*;"; }
log_debug()   { [[ "$DEBUG" == "1" ]] && logger -t "$LOG_TAG" "[DEBUG]   $*"; }
log_warning() { logger -t "$LOG_TAG" "[WARNING] $*"; }
log_error()   { logger -t "$LOG_TAG" "[ERROR]   $*"; }

# === Single-instance lock (whole script) ===
LOCKFILE="${LOCKFILE:-/tmp/instant-remote-storage.lock}"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
  logger -t "$LOG_TAG" "[WARNING] Already running. Exiting."
  exit 1
fi
log_info "Global lock acquired — PID: $$"

# === Environment (.env) ===
# Search order (first wins):
# 1) /etc/instant-remote-storage/$USER.env
# 2) /etc/instant-remote-storage/irs.env
# 3) $HOME/.config/instant-remote-storage/irs.env
# 4) $HOME/.env
__ENV_LOADED_FROM=""
for __CANDIDATE in \
  "/etc/instant-remote-storage/${USER}.env" \
  "/etc/instant-remote-storage/irs.env" \
  "$HOME/.config/instant-remote-storage/irs.env" \
  "$HOME/.env"; do
  if [[ -f "$__CANDIDATE" ]]; then
    # shellcheck source=/dev/null
    source "$__CANDIDATE"
    __ENV_LOADED_FROM="$__CANDIDATE"
    break
  fi
done
if [[ -n "$__ENV_LOADED_FROM" ]]; then
  log_info "Loaded environment from $__ENV_LOADED_FROM"
else
  log_warning "No environment file found (using built-in defaults)"
fi

# === Configuration (defaults; can be overridden by env files) ===
LOCAL_DIR=${LOCAL_DIR:-"$HOME/remote-storage"}
REMOTE_DIR=${REMOTE_DIR:-"remote:your-remote-directory"}

# State / recovery
STATE_DIR=${STATE_DIR:-"$HOME/.local/state/instant-remote-storage"}
INFLIGHT_DIR=${INFLIGHT_DIR:-"$STATE_DIR/inflight"}
REMOTE_TMP_DIR=${REMOTE_TMP_DIR:-"$REMOTE_DIR/.irs-tmp"}
IRS_TMP_TTL_SECONDS=${IRS_TMP_TTL_SECONDS:-86400}

# Index (persistent tracking for renames & content updates)
INDEX_FILE="${INDEX_FILE:-$STATE_DIR/index.tsv}"

# Behavior toggles
IRS_MIRROR_EMPTY_DIRS=${IRS_MIRROR_EMPTY_DIRS:-1}  # mirror empty dirs only on MOVED_TO

# === Error reporting (optional msmtp) ===
send_error_mail() {
  if [[ ! -s "$HOME/.msmtprc" ]]; then
    log_warning "Missing or empty ~/.msmtprc. Email disabled."
    return 0
  fi
  local subject recipient from_account from_address body_head body_tail
  subject="Error in instant-remote-storage on $(hostname) - $(date '+%Y-%m-%d %H:%M:%S')"
  recipient="${EMAIL_TO:-default@example.com}"
  from_account="${MSMTP_ACCOUNT:-default}"
  from_address="${EMAIL_FROM:-instant-remote-storage <noreply@localhost>}"
  body_head=$(cat <<-EOF
    Hello,
    An error occurred during the execution of instant-remote-storage.

    • Command: "$BASH_COMMAND"
    • Line: $LINENO
    • Exit code: $?

    Last 50 journal lines:
EOF
  )
  body_tail=$(journalctl --user -t "$LOG_TAG" -n 50 2>/dev/null || echo "Could not read journal for tag $LOG_TAG")
  {
    echo "To: $recipient"
    echo "Subject: $subject"
    echo "From: $from_address"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo
    echo "$body_head$body_tail"
  } | msmtp --from="$from_account" -t 2>/dev/null
  local rc=$?
  [[ $rc -ne 0 ]] && log_warning "msmtp failed (rc=$rc)"
  return $rc
}

on_err() {
  local ec=$?
  local cmd=$BASH_COMMAND
  log_error "Unhandled error at line $LINENO: \`$cmd\` exited with $ec"
  send_error_mail || log_warning "send_error_mail failed or unavailable"
  return $ec
}
trap 'on_err' ERR

# === Requirements ===
REQUIRED_CMDS=(rclone inotifywait sha256sum stat xdg-mime file awk sed grep find logger)
for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Missing required command: '$cmd'"; send_error_mail || true; exit 1
  fi
done

# === Preflight ===
mkdir -p "$LOCAL_DIR" || { log_error "Failed to create LOCAL_DIR: $LOCAL_DIR"; send_error_mail || true; exit 1; }
if ! rclone mkdir "$REMOTE_DIR" >/dev/null 2>&1; then
  log_warning "Remote directory may not exist or cannot be created: $REMOTE_DIR"
fi
if ! rclone lsf "$REMOTE_DIR" &>/dev/null; then
  log_error "Remote '$REMOTE_DIR' not reachable"; send_error_mail || true; exit 1
fi

# === State dirs and recovery ===
log_info "Recovery bootstrap: ensure_state_dirs"
ensure_state_dirs || log_warning "ensure_state_dirs best-effort failed"
log_info "Recovery bootstrap: recover_inflight (start)"
recover_inflight || log_info "recover_inflight: nothing to do or best-effort failed"
log_info "Recovery bootstrap: recover_inflight (done)"

# === Process-scoped lock dir ===
LOCKDIR="$(mktemp -d /tmp/irs-locks.XXXXXX)"

# === Dedup and transform tracking ===
declare -A PATH_HASH_SEEN=()           # key = "<hash>___<relative_path>", value = inode
path_hash_key=""

declare -A FILENAME_TRANSFORM_MAP=()   # key = "<hash>___<new>" -> value "<hash>___<old>"
original_pair=""
transformed_pair=""

# === Persistent index (dev:inode -> remote path, last hash) ===
declare -A INDEX_REMOTE_PATH=()
declare -A INDEX_HASH=()

load_index() {
  [[ -s "$INDEX_FILE" ]] || return 0
  while IFS=$'\t' read -r fid rpath fhash; do
    [[ -z "$fid" || "$fid" == \#* ]] && continue
    INDEX_REMOTE_PATH["$fid"]="$rpath"
    INDEX_HASH["$fid"]="$fhash"
  done < "$INDEX_FILE"
}

persist_index() {
  mkdir -p "$(dirname "$INDEX_FILE")"
  local tmp
  tmp="${INDEX_FILE}.tmp.$$"
  {
    echo -e "# file_id\tremote_path\tlast_hash"
    for fid in "${!INDEX_REMOTE_PATH[@]}"; do
      printf '%s\t%s\t%s\n' "$fid" "${INDEX_REMOTE_PATH[$fid]}" "${INDEX_HASH[$fid]:-}"
    done | sort
  } > "$tmp"
  mv -f "$tmp" "$INDEX_FILE"
}

update_index() { # $1=file_id  $2=remote_path  $3=hash
  local fid="$1"; local rpath="$2"; local h="$3"
  INDEX_REMOTE_PATH["$fid"]="$rpath"
  INDEX_HASH["$fid"]="$h"
  persist_index
}

# === Helpers ===
get_inode() { [[ -e "$1" ]] && stat --format="%i" "$1" || { log_debug "get_inode: not found: $1"; echo ""; }; }
get_file_id() { # dev:inode, stable across renames on same filesystem
  if [[ -e "$1" ]]; then
    stat -c '%d:%i' -- "$1" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

cleanup_lock() {
  if [[ -n "${HASHLOCK:-}" && -e "$HASHLOCK" ]]; then
    rm -f "$HASHLOCK"; log_debug "Per-file lock released ($HASHLOCK)"
  fi
}

# Composite extensions to preserve
composite_exts=("tar.gz" "tar.bz2" "tar.xz" "tar.zst" "tar.lz4" "tar.br")

split_base_ext() {
  local filename="$1"
  for ext in "${composite_exts[@]}"; do
    [[ "$filename" == *.${ext} ]] && { echo "${filename%."$ext"}:::${ext}"; return; }
  done
  echo "${filename%.*}:::${filename##*.}"
}

get_mime() {
  local file_path="$1"
  [[ ! -s "$file_path" ]] && { log_warning "'$file_path' is empty -> skipped."; echo ""; return; }
  xdg-mime query filetype "$file_path" 2>/dev/null || file --mime-type -b "$file_path"
}

log_rclone_progress() { local logfile="$1"; awk '/Transferred:/' "$logfile" | while read -r line; do logger -t "$LOG_TAG" "$line"; done || true; }

# --- Heuristics: detect tar archive inside compressed streams ---
is_tar_magic_stream() { dd bs=1 skip=257 count=5 2>/dev/null | grep -q 'ustar'; }
is_tar_gz()  { command -v gzip  >/dev/null 2>&1 && gzip  -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_bz2() { command -v bzip2 >/dev/null 2>&1 && bzip2 -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_xz()  { command -v xz    >/dev/null 2>&1 && xz    -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_zst() { command -v zstd  >/dev/null 2>&1 && zstd  -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_lz4() { command -v lz4   >/dev/null 2>&1 && lz4   -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }

assign_extension() {
  local file_path="$1"
  local original_name; original_name=$(basename "$file_path")

  # Preserve known composite extensions
  for ext in "${composite_exts[@]}"; do
    if [[ "$original_name" == *.${ext} ]]; then
      printf '%s\n' "$original_name"; return 0
    fi
  done

  local mime; mime=$(get_mime "$file_path")
  if [[ -z "$mime" ]]; then
    log_warning "MIME detection failed. Keeping original name."; printf '%s\n' "$original_name"; return 42
  fi
  local ext="${MIME_EXTENSIONS[$mime]:-}"
  if [[ -z "$ext" ]]; then
    log_warning "MIME '$mime' not mapped. Keeping original name."; printf '%s\n' "$original_name"; return 42
  fi

  local name_wo_ext cur_ext
  if [[ "$original_name" == *.* && "$original_name" != .* ]]; then
    name_wo_ext="${original_name%.*}"; cur_ext="${original_name##*.}"
  else
    name_wo_ext="$original_name"; cur_ext=""
  fi

  # If current extension already matches the canonical one
  if [[ -n "$cur_ext" && "${cur_ext,,}" == "${ext,,}" ]]; then
    printf '%s\n' "$original_name"; log_debug "assign_extension: confirmed .$ext"; return 0
  fi

  # If no extension yet, and MIME is a compressed stream, detect embedded tar
  if [[ -z "$cur_ext" ]]; then
    case "$ext" in
      gz)  is_tar_gz  "$file_path" && ext="tar.gz"  ;;
      bz2) is_tar_bz2 "$file_path" && ext="tar.bz2" ;;
      xz)  is_tar_xz  "$file_path" && ext="tar.xz"  ;;
      zst) is_tar_zst "$file_path" && ext="tar.zst" ;;
      lz4) is_tar_lz4 "$file_path" && ext="tar.lz4" ;;
    esac
  fi

  # Replace different extension, or add if missing
  if [[ -n "$cur_ext" ]]; then
    printf '%s.%s\n' "$name_wo_ext" "$ext"; log_debug "assign_extension: '$original_name' -> '${name_wo_ext}.${ext}'"; return 0
  fi
  printf '%s.%s\n' "$original_name" "$ext"; log_debug "assign_extension: '$original_name' -> '${original_name}.${ext}'"; return 0
}

clean_name() {
  local file_path="$1"
  local original_name; original_name=$(basename "$file_path")
  local base full_ext found=0
  for ext in "${composite_exts[@]}"; do
    if [[ "$original_name" == *.${ext} ]]; then
      full_ext="$ext"; base="${original_name%."$ext"}"; found=1; break
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    if [[ "$original_name" == .* || "$original_name" != *.* ]]; then
      full_ext=""; base="$original_name"
    else
      full_ext="${original_name##*.}"; base="${original_name%.*}"
    fi
  fi
  [[ -z "$base" ]] && base="unnamed"
  local clean_base
  clean_base=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')
  if [[ -n "$full_ext" ]]; then echo "${clean_base}.${full_ext,,}"; else echo "$clean_base"; fi
}

wait_for_stable_file() {
  local file="$1"; local retries=1000; local interval=0.5; local last_size=-1; local size
  for ((i=0; i<retries; i++)); do
    size=$(stat -c %s "$file" 2>/dev/null || echo -1)
    if [[ "$size" -eq "$last_size" && "$size" -gt 0 ]]; then return 0; fi
    last_size=$size; sleep "$interval"
  done
  log_error "File not stable after retries: '$file'"; return 1
}

compute_hash() { [[ -f "$1" ]] || { log_warning "compute_hash: invalid path '$1'"; return 1; }; sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
trim() { sed 's/^[[:space:]]*//;s/[[:space:]]*$//' ; }

should_skip_due_to_transform_map() {
  local original_pair="$1"
  local fullpath="$LOCAL_DIR/${original_pair#*___}"
  local inode; inode=$(get_inode "$fullpath")
  log_debug "[transform_map] original=$original_pair inode=$inode"
  for key in "${!FILENAME_TRANSFORM_MAP[@]}"; do
    if [[ "${FILENAME_TRANSFORM_MAP[$key]}" == "$original_pair" ]]; then
      if [[ "$key" == "$original_pair" ]]; then
        if [[ "${PATH_HASH_SEEN[$key]}" != "$inode" ]]; then
          log_info "Requeue with different inode"; unset 'PATH_HASH_SEEN[$key]'; return 1
        fi
        log_warning "Loop avoided: same name and inode ($original_pair)"; return 0
      else
        log_info "Requeue with original name ($original_pair)"; unset 'PATH_HASH_SEEN[$key]'; return 1
      fi
    fi
  done
  return 1
}

ensure_remote_dir() { local dir="$1"; rclone mkdir "$dir" >/dev/null 2>&1 || { log_warning "Cannot ensure remote dir: $dir"; return 1; }; }

# === Load persistent index ===
load_index

handle_file() {
  local local_file="$1"    # absolute path
  local filename="$2"      # relative path + filename (inside LOCAL_DIR)
  local inode="$3"
  local remote_path="$REMOTE_DIR/$filename"
  local EXIT_REASON="ERR"
  trap '[[ "${EXIT_REASON:-}" == "ERR" ]] && log_warning "handle_file aborted (ERR) — cleanup lock"; cleanup_lock' RETURN
  log_debug "handle_file start: '$filename'"

  # 0) Stabilize & existence
  if ! wait_for_stable_file "$local_file"; then
    log_info "'$filename' is not stable yet — will retry later"; EXIT_REASON="SKIP"; cleanup_lock; return 0; fi
  [[ -f "$local_file" ]] || { log_debug "File disappeared: '$filename'"; EXIT_REASON="SKIP"; cleanup_lock; return 0; }

  # 1) Filter on basename
  local bn; bn=$(basename "$filename")
  if [[ "$bn" =~ ^\.goutputstream || "$bn" =~ \.(swp|part|tmp|bak)$ || "$bn" =~ ^\..* ]]; then
    log_warning "Skipped temp/dot: '$filename'"; EXIT_REASON="SKIP"; cleanup_lock; return 0
  fi

  # 2) Hash + per-event lock
  local hash; hash=$(compute_hash "$local_file")
  if [[ -z "$hash" ]]; then log_error "Hash failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1; fi
  log_debug "hash=$hash"
  local HASHLOCK="$LOCKDIR/${hash}_${inode}.lock"
  if [[ -e "$HASHLOCK" ]]; then log_debug "Per-event lock exists (duplicate trigger). Skipping."; EXIT_REASON="LOCK"; return 0; fi
  : > "$HASHLOCK"; log_debug "Per-event lock acquired"

  # Ensure original_pair is set for this file if missing (e.g., cold-start path)
  if [[ -z "${original_pair:-}" ]]; then
    original_pair="${hash}___${filename}"
  fi

  # 3) Compute file-id (dev:inode) and consult index
  local file_id; file_id=$(get_file_id "$local_file")
  local idx_remote="${INDEX_REMOTE_PATH[$file_id]:-}"
  local idx_hash="${INDEX_HASH[$file_id]:-}"

  # 4) Extension + clean name normalization
  local assign_output assign_exit_code new_filename save_filename
  assign_output=$(assign_extension "$local_file"; echo "___EXIT:$?")
  assign_exit_code=$(printf '%s' "$assign_output" | sed -n 's/.*___EXIT:\([0-9]\+\)/\1/p')
  assign_output=$(printf '%s' "$assign_output" | sed 's/___EXIT:.*//')
  new_filename=$(printf '%s\n' "$assign_output" | trim)
  if [[ "$assign_exit_code" -eq 42 ]]; then
    new_filename="$filename"
  elif [[ "$assign_exit_code" -ne 0 || -z "$new_filename" ]]; then
    log_error "assign_extension failed for '$filename' (code: $assign_exit_code)"; send_error_mail || true; cleanup_lock; EXIT_REASON="ERR"; return 1
  fi
  save_filename=$(clean_name "$new_filename")
  if [[ "$save_filename" != "$(basename "$filename")" ]]; then
    local parent_dir; parent_dir=$(dirname "$filename")
    if [[ "$local_file" != "$LOCAL_DIR/$parent_dir/$save_filename" ]]; then
      filename="$parent_dir/$save_filename"; filename="${filename#./}"
      path_hash_key="${hash}___${filename}"
      transformed_pair="$path_hash_key"; FILENAME_TRANSFORM_MAP["$transformed_pair"]="$original_pair"
      if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then EXIT_REASON="SKIP"; cleanup_lock; return 0; fi
      PATH_HASH_SEEN["$path_hash_key"]="$inode"
      if ! mv "$local_file" "$LOCAL_DIR/$parent_dir/$save_filename"; then
        unset "PATH_HASH_SEEN[$path_hash_key]"; log_error "Local rename failed: '$filename'"; send_error_mail || true; cleanup_lock; EXIT_REASON="ERR"; return 1
      fi
      local_file="$LOCAL_DIR/$filename"
    fi
  fi
  remote_path="$REMOTE_DIR/$filename"

  # 5) Ensure remote dir exists
  local remote_dir_path; remote_dir_path=$(dirname "$remote_path")
  rclone mkdir "$remote_dir_path" >/dev/null 2>&1 || log_warning "Cannot create remote dir: $remote_dir_path"

  # 6) Handle pure rename (same file-id, same hash, different remote path)
  if [[ -n "$file_id" && -n "$idx_remote" && "$idx_remote" != "$remote_path" && -n "$idx_hash" && "$idx_hash" == "$hash" ]]; then
    log_info "Detected pure rename: '$idx_remote' -> '$remote_path' (no reupload)"
    ensure_remote_dir "$(dirname "$remote_path")" || true
    if rclone moveto "$idx_remote" "$remote_path" >/dev/null 2>&1; then
      update_index "$file_id" "$remote_path" "$hash"
      EXIT_REASON="OK"; log_info "Remote rename completed: '$filename'"; return 0
    else
      log_warning "Remote rename failed; will fallback to upload"
    fi
  fi

  # 7) Conflict policy (overwrite if we own the path, else copy-as-conflict)
  local rel_dir; rel_dir=$(dirname "$filename")
  local remote_dir_for_check="$REMOTE_DIR"; [[ "$rel_dir" != "." ]] && remote_dir_for_check="$REMOTE_DIR/$rel_dir"
  ensure_remote_dir "$remote_dir_for_check" || true
  local remote_base; remote_base=$(basename "$filename")
  local remote_exists=1
  # Prefer lsjson (more reliable on WebDAV); fallback to lsf
  if rclone lsjson --files-only "$remote_dir_for_check" 2>/dev/null | grep -F "\"Name\":\"$remote_base\"" >/dev/null \
     || rclone lsf --files-only "$remote_dir_for_check" 2>/dev/null | grep -Fxq "$remote_base"
  then
    remote_exists=0  # 0 == exists
  fi

  local final_remote
  if [[ $remote_exists -eq 0 && ( -z "$file_id" || "${INDEX_REMOTE_PATH[$file_id]:-}" != "$remote_path" ) ]]; then
    # Another file already owns that name → conflict copy in same dir
    local SPLIT_OUT BASE EXT DOTEXT; SPLIT_OUT="$(split_base_ext "$filename")"
    if [[ "$SPLIT_OUT" == *":::"* ]]; then BASE="${SPLIT_OUT%:::*}"; EXT="${SPLIT_OUT##*:::}"; else BASE="$SPLIT_OUT"; EXT=""; fi
    EXT="${EXT,,}"; [[ -n "$EXT" ]] && DOTEXT=".$EXT" || DOTEXT=""
    local BASE_DIR; BASE_DIR=$(dirname "$BASE"); local BASE_NAME; BASE_NAME=$(basename "$BASE")
    local COUNT=1; local NEW_BASE_NAME="${BASE_NAME}-(copy)"; local NEW_NAME_REL
    if [[ "$BASE_DIR" == "." ]]; then NEW_NAME_REL="${NEW_BASE_NAME}${DOTEXT}"; else NEW_NAME_REL="${BASE_DIR}/${NEW_BASE_NAME}${DOTEXT}"; fi
    while rclone lsf --files-only "$remote_dir_for_check" 2>/dev/null | grep -Fxq "${NEW_BASE_NAME}${DOTEXT}"; do
      COUNT=$((COUNT+1)); NEW_BASE_NAME="${BASE_NAME}-(copy ${COUNT})"
      if [[ "$BASE_DIR" == "." ]]; then NEW_NAME_REL="${NEW_BASE_NAME}${DOTEXT}"; else NEW_NAME_REL="${BASE_DIR}/${NEW_BASE_NAME}${DOTEXT}"; fi
    done
    final_remote="$REMOTE_DIR/$NEW_NAME_REL"
    if ! two_phase_upload "$local_file" "$final_remote" "$hash" "$inode" "conflict"; then
      log_error "Conflict upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
    fi
    log_info "Conflict upload completed: '$filename' -> '$(basename "$NEW_NAME_REL")'"
  else
    # Overwrite or first upload
    final_remote="$remote_path"
    if ! two_phase_upload "$local_file" "$final_remote" "$hash" "$inode"; then
      log_error "Upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
    fi
    log_info "Upload completed: '$filename'"
  fi

  # 8) Mark processed and update index
  path_hash_key="${hash}___${filename}"
  if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then EXIT_REASON="SKIP"; cleanup_lock; return 0; fi
  PATH_HASH_SEEN["$path_hash_key"]="$inode"
  [[ -n "$file_id" ]] && update_index "$file_id" "$final_remote" "$hash"

  EXIT_REASON="OK"; log_debug "handle_file end: '$filename'"; return 0
}

# === Exit & signals ===
on_exit() {
  log_info "instant-remote-storage exited at $(date '+%Y-%m-%d %H:%M:%S')"
  if [[ -n "${LOCKDIR:-}" && -d "$LOCKDIR" ]]; then rm -rf "$LOCKDIR" || true; log_debug "Removed LOCKDIR: $LOCKDIR"; fi
}
on_interrupt() { log_warning "Interrupted. Exiting..."; exit 130; }
trap 'on_exit' EXIT
trap 'on_interrupt' INT TERM

cold_start_rescan() {
  while IFS= read -r -d '' f; do
    local relfile inode; relfile="${f#"$LOCAL_DIR"/}"; inode=$(get_inode "$f"); [[ -z "$inode" ]] && continue
    log_debug "Cold-start: requeue $relfile"
    handle_file "$f" "$relfile" "$inode" || log_warning "Cold-start failed on $relfile"
  done < <(find "$LOCAL_DIR" -type f -perm -u+w -not -path '*/.*' -print0)
}

log_info "Cold-start rescan (start)"; declare -F handle_file >/dev/null || { log_error "handle_file missing"; exit 1; }
cold_start_rescan; log_info "Cold-start rescan (done)"

main_loop() {
  local inode=""
  log_info "Starting watcher on $(hostname) at $(date)"
  while IFS=":::" read -r FULLPATH EVENT; do
    RELATIVE_PATH="${FULLPATH#"$LOCAL_DIR"/}"; RELATIVE_PATH="${RELATIVE_PATH#./}"; log_debug "Event '$EVENT' -> $RELATIVE_PATH"
    local BN; BN=$(basename "$RELATIVE_PATH")
    if [[ "$BN" =~ ^\.goutputstream || "$BN" =~ \.(swp|part|tmp|bak)$ || "$BN" =~ ^\..* ]]; then
      log_warning "Skipped early in main_loop: $RELATIVE_PATH"; continue
    fi

    if [[ -d "$FULLPATH" ]]; then
      # Mirror empty directories only when the final name is committed (MOVED_TO)
      if [[ "$IRS_MIRROR_EMPTY_DIRS" == "1" && "$EVENT" == *"MOVED_TO"* ]]; then
        while IFS= read -r -d '' DIR; do
          SUBPATH="${DIR#"$LOCAL_DIR"/}"
          rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1 || log_warning "Cannot create remote dir: '$REMOTE_DIR/$SUBPATH'"
        done < <(find "$FULLPATH" -type d -empty -print0)
      fi
      # Process files within the directory
      while IFS= read -r -d '' FILE; do
        [[ -e "$FILE" ]] || { log_debug "Vanished after scan: ${FILE#"$LOCAL_DIR"/}"; continue; }
        RELFILE="${FILE#"$LOCAL_DIR"/}"; inode=$(get_inode "$FILE"); [[ -z "$inode" ]] && continue
        handle_file "$FILE" "$RELFILE" "$inode"
      done < <(find "$FULLPATH" -type f -print0)

    elif [[ -f "$FULLPATH" ]]; then
      [[ -e "$FULLPATH" ]] || { log_debug "Vanished after event: $RELATIVE_PATH"; continue; }
      local FILE_HASH=""; if ! FILE_HASH=$(compute_hash "$FULLPATH"); then log_debug "Hash race for $RELATIVE_PATH"; continue; fi
      path_hash_key="${FILE_HASH}___${RELATIVE_PATH}"; original_pair="$path_hash_key"
      if should_skip_due_to_transform_map "$original_pair"; then continue; fi
      [[ -e "$FULLPATH" ]] || { log_debug "Vanished before inode read: $RELATIVE_PATH"; continue; }
      inode=$(get_inode "$FULLPATH"); [[ -z "$inode" ]] && { log_debug "Empty inode (race) for $RELATIVE_PATH"; continue; }
      if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then
        log_warning "Skipped: already processed $FULLPATH"; continue
      fi
      handle_file "$FULLPATH" "$RELATIVE_PATH" "$inode"
    fi
  done < <(inotifywait -m -r -e create,close_write,moved_to --format '%w%f:::%e' "$LOCAL_DIR")
  log_info "Watch loop terminated unexpectedly"
}

main_loop
