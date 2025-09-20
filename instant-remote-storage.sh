#!/usr/bin/env bash

# ========================================
# instant-remote-storage - v3.6.5
# Author : Carlo Capobianchi (bynflow)
# GitHub : https://github.com/bynflow
# Last Modified: 2025-09-16
# ========================================
# Watches a local directory (LOCAL_DIR) and uploads files to a remote (REMOTE_DIR)
# using rclone. Features:
#   - MIME-based extension normalization (via external map)
#   - Two-phase upload with crash-safe recovery (tmp marker + promote)
#   - Persistent index (dev:inode -> remote path, last hash) to handle:
#       * unchanged files → skip forever (across reboots)
#       * content updates → always create a copy series ("(copy)", "(copy 2)", …); never overwrite
#       * pure renames → treated as new uploads; remote renames disabled by default
#   - Dedup of simultaneous triggers (hash+inode lock + seen map)
#   - Optional mirroring of empty directories only on final name (MOVED_TO)
#   - Heuristics to detect tarballs inside compressed streams (tar.*)
#   - Remote rename toggle: IRS_ALLOW_REMOTE_RENAME=1 re-enables server-side renames for pure renames
# ========================================

set -Eeuo pipefail
shopt -s inherit_errexit || true

SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname "$SCRIPT_PATH")" && pwd)"

# shellcheck disable=SC1091
source "$SCRIPT_DIR/mime_map.sh"

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

# Waiting for remote at bootstrap (default: no waiting, best-effort)
LOCAL_DIR=${LOCAL_DIR:-"$HOME/remote-storage"}
REMOTE_DIR=${REMOTE_DIR:-"remote:your-remote-directory"}

# Attesa del remote al bootstrap (default: nessuna attesa, best-effort)
IRS_REMOTE_WAIT_SECS=${IRS_REMOTE_WAIT_SECS:-0}

# State / recovery
STATE_DIR=${STATE_DIR:-"$HOME/.local/state/instant-remote-storage"}
INFLIGHT_DIR=${INFLIGHT_DIR:-"$STATE_DIR/inflight"}
REMOTE_TMP_DIR=${REMOTE_TMP_DIR:-"$REMOTE_DIR/.irs-tmp"}
IRS_TMP_TTL_SECONDS=${IRS_TMP_TTL_SECONDS:-86400}

# Index (persistent tracking for renames & content updates)
INDEX_FILE="${INDEX_FILE:-$STATE_DIR/index.tsv}"

# Offset per il numero mostrato: 0 = prima modifica -> (ver 1); 1 = -> (ver 2)
IRS_VER_BASE_OFFSET=${IRS_VER_BASE_OFFSET:-1}
[[ "$IRS_VER_BASE_OFFSET" =~ ^-?[0-9]+$ ]] || IRS_VER_BASE_OFFSET=0

# --- Behavior toggles -------------------------------------------------
# Zero-byte upload policy:
# 1 = eager: upload even on CREATE/CLOSE_WRITE (e.g., `touch` from a shell)
# 0 = hold : wait for MOVED_TO (final name) or for the file to become >0 bytes [DEFAULT]
IRS_UPLOAD_ZERO_ON_CREATE=${IRS_UPLOAD_ZERO_ON_CREATE:-0}

# Versioning scope:
# 1 = add " (ver N)" ONLY when we detect an on-place edit of the same path [DEFAULT]
# 0 = keep existing behavior (external collisions → "(copy)" etc.)
IRS_VERSION_ONLY_ON_PLACE=${IRS_VERSION_ONLY_ON_PLACE:-1}

# Remote rename toggle (pure renames):
# 1 = allow server-side rename; 0 = treat renames as new uploads [DEFAULT]
IRS_ALLOW_REMOTE_RENAME=${IRS_ALLOW_REMOTE_RENAME:-0}

# Empty directories mirroring:
# Enable feature and choose events (CREATE gated by IRS_MIRROR_DIRS_ON_CREATE)
IRS_MIRROR_EMPTY_DIRS=${IRS_MIRROR_EMPTY_DIRS:-1}
IRS_MIRROR_DIRS_ON_CREATE=${IRS_MIRROR_DIRS_ON_CREATE:-0}

# --- Debounce for first writes/creates (wait for a rename) ---
IRS_HOLD_CREATE_SECONDS=${IRS_HOLD_CREATE_SECONDS:-15}
declare -A FIRST_SEEN=()   # key=RELATIVE_PATH, val=epoch seconds

# Simple persistent state to count versions per relative path
IRS_STATE_DIR=${IRS_STATE_DIR:-"${XDG_STATE_HOME:-$HOME/.local/state}/instant-remote-storage"}
mkdir -p "$IRS_STATE_DIR"
IRS_VERS_DB="$IRS_STATE_DIR/versions.tsv"
touch "$IRS_VERS_DB"

# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/irs_recovery.sh"

# === Error reporting (optional msmtp) ===
send_error_mail() {
  local err_cmd="${1:-<unknown>}"
  local err_line="${2:-<unknown>}"
  local err_code="${3:-<unknown>}"

  # Must have a configured recipient
  if [[ -z "${EMAIL_TO:-}" || "${EMAIL_TO}" =~ @example\.com$ ]]; then
    log_warning "EMAIL_TO not configured (placeholder). Skipping email."
    return 0
  fi

  # Must have msmtp config
  if [[ ! -s "$HOME/.msmtprc" ]]; then
    log_warning "Missing or empty ~/.msmtprc. Email disabled."
    return 0
  fi

  local subject recipient from_account from_address body_head body_tail tag
  subject="Error in instant-remote-storage on $(hostname) - $(date '+%Y-%m-%d %H:%M:%S')"
  recipient="$EMAIL_TO"
  from_account="${MSMTP_ACCOUNT:-default}"
  from_address="${EMAIL_FROM:-instant-remote-storage <noreply@localhost>}"
  tag="${LOG_TAG:-instant-remote-storage}"

  body_head=$(cat <<-EOF
    Hello,
    An error occurred during the execution of instant-remote-storage.

    • Command: "$err_cmd"
    • Line: $err_line
    • Exit code: $err_code

    Last 50 journal lines:
EOF
  )
  body_tail=$(journalctl --user -t "$tag" -n 50 2>/dev/null || echo "Could not read journal for tag $tag")
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
  local line=${BASH_LINENO[0]:-$LINENO}
  log_error "Unhandled error at line $line: \`$cmd\` exited with $ec"
  send_error_mail "$cmd" "$line" "$ec" || log_warning "send_error_mail failed or unavailable"
  return $ec
}
trap 'on_err' ERR

# === Requirements ===
REQUIRED_CMDS=(rclone inotifywait sha256sum stat xdg-mime file awk sed grep find logger flock jq)
for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Missing required command: '$cmd'"; send_error_mail || true; exit 1
  fi
done

# === Preflight ===
mkdir -p "$LOCAL_DIR" || { log_error "Failed to create LOCAL_DIR: $LOCAL_DIR"; send_error_mail || true; exit 1; }

# Best-effort: non fallire se il remote non è pronto; eventuale attesa breve controllata da IRS_REMOTE_WAIT_SECS (default 0)
set +eE
rclone mkdir "$REMOTE_DIR" >/dev/null 2>&1 || log_warning "Remote directory may not exist or cannot be created: $REMOTE_DIR"

WAIT=${IRS_REMOTE_WAIT_SECS:-0}
while ! rclone lsf "$REMOTE_DIR" >/dev/null 2>&1; do
  (( WAIT-- <= 0 )) && { log_warning "Remote '$REMOTE_DIR' not reachable yet (continuing best-effort)"; break; }
  sleep 1
done
set -eE

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
  local old_rpath="${INDEX_REMOTE_PATH[$fid]:-}"
  local old_hash="${INDEX_HASH[$fid]:-}"

  INDEX_REMOTE_PATH["$fid"]="$rpath"
  INDEX_HASH["$fid"]="$h"
  persist_index

  # short hashes for readable logs
  local sh_old="${old_hash:0:12}"
  local sh_new="${h:0:12}"

  if [[ -z "$old_rpath" ]]; then
    log_debug "index: new fid=$fid → path='$rpath' hash=${sh_new:-<none>}"
  else
    if [[ "$old_rpath" != "$rpath" || "$old_hash" != "$h" ]]; then
      log_debug "index: update fid=$fid path:'$old_rpath'→'$rpath' hash:${sh_old:-<none>}→${sh_new:-<none>}"
    else
      log_debug "index: touch fid=$fid (unchanged)"
    fi
  fi
}

# === Helpers ===
get_inode() { [[ -e "$1" ]] && stat --format="%i" "$1" || { log_debug "get_inode: not found: $1"; echo ""; }; }
# Unique ID: device:inode (stable during renaming and saving)
get_file_id() {
  if [[ -e "$1" ]]; then
    stat -c '%d:%i' -- "$1" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

remote_file_exists() { # $1 = REMOTE_DIR/relpath
  local dest="$1" parent base
  parent="$(dirname "$dest")"
  base="$(basename "$dest")"
  rclone lsjson --files-only "$parent" 2>/dev/null \
    | jq -e --arg n "$base" 'any(.[]; .Name == $n)' >/dev/null
}

cleanup_lock() {
  if [[ -n "${HASHLOCK:-}" && -e "$HASHLOCK" ]]; then
    rm -f "$HASHLOCK"; log_debug "Per-file lock released ($HASHLOCK)"
  fi
  if [[ -n "${PATHLOCK:-}" && -e "$PATHLOCK" ]]; then
    rm -f "$PATHLOCK"; log_debug "Path lock released ($PATHLOCK)"
  fi
}

# Returns the last known hash for a given absolute remote path (REMOTE_DIR/rel).
# Looks up by path (not by file_id). Prints the hash or an empty string.
get_last_hash_for_remote_path() {
  local abs="$1" fid
  set +e
  for fid in "${!INDEX_REMOTE_PATH[@]}"; do
    if [[ "${INDEX_REMOTE_PATH[$fid]}" == "$abs" ]]; then
      printf '%s\n' "${INDEX_HASH[$fid]:-}"
      set -e
      return 0
    fi
  done
  set -e
  printf '\n'
}

# Composite extensions to preserve
composite_exts=("tar.gz" "tar.bz2" "tar.xz" "tar.zst" "tar.lz4" "tar.br")

split_base_ext() {
  local filename="$1"
  for ext in "${composite_exts[@]}"; do
    [[ "$filename" == *.${ext} ]] && { echo "${filename%."$ext"}:::${ext}"; return; }
  done
  # dotfiles or extensionless names → empty ext
  if [[ "$filename" == .* || "$filename" != *.* ]]; then
    echo "$filename:::"
  else
    echo "${filename%.*}:::${filename##*.}"
  fi
}

get_mime() {
  local file_path="$1"
  if [[ ! -s "$file_path" ]]; then
    log_warning "'$file_path' is empty → MIME undetectable; keeping original name."
    echo ""
    return
  fi
  xdg-mime query filetype "$file_path" 2>/dev/null || file --mime-type -b "$file_path"
}

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
  local path="$1" last_size=-1 size tries=${2:-5} sleep_s=${3:-0.4}

  while (( tries-- > 0 )); do
    [[ -e "$path" ]] || return 1
    size=$(stat -c %s -- "$path" 2>/dev/null || echo -1)
    # Treat as stable once size stops changing (even if it’s zero).
    if [[ "$size" -ge 0 && "$size" -eq "$last_size" ]]; then
      return 0
    fi
    last_size="$size"
    sleep "$sleep_s"
  done

  [[ -e "$path" ]] || return 1
  return 0
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

# Bump and return next N for "path\tN" in versions.tsv (robusto ai duplicati)
irs_next_ver() {
  local rel="$1" max
  max=$(awk -F'\t' -v p="$rel" '
    $1==p && $2 ~ /^[0-9]+$/ { if ($2>m) m=$2; f=1 }
    END { if (f) print m; else print 0 }
  ' "$IRS_VERS_DB" 2>/dev/null)
  : "${max:=0}"
  local next=$(( max + 1 ))

  # Scrivi una singola riga per la path con il nuovo valore e rimuovi duplicati
  awk -F'\t' -v p="$rel" -v n="$next" '
    BEGIN { done=0 }
    $1==p && !done { print p "\t" n; done=1; next }  # prima occorrenza aggiornata
    $1==p { next }                                   # scarta duplicati successivi
    { print }
    END { if (!done) print p "\t" n }
  ' "$IRS_VERS_DB" > "$IRS_VERS_DB.tmp" && mv -f "$IRS_VERS_DB.tmp" "$IRS_VERS_DB"

  printf '%s' "$next"
}

# Ensure the path exists once in the DB (idempotente, niente duplicati)
irs_touch_path() {
  local rel="$1"
  if grep -Fq "^${rel}"$'\t' "$IRS_VERS_DB" 2>/dev/null; then
    return 0
  fi
  printf '%s\t0\n' "$rel" >> "$IRS_VERS_DB"
}

# Build "name-(ver N).ext" while preserving the extension
add_version_suffix() {
  local rel="$1" ver="$2"
  local dir base ext
  dir=$(dirname -- "$rel"); base=$(basename -- "$rel"); ext=""
  if [[ "$base" == *.* ]]; then ext=".${base##*.}"; base="${base%.*}"; fi
  printf '%s/%s-(ver %s)%s' "$dir" "$base" "$ver" "$ext"
}

# Decide if we should version (ONLY for on-place edits of an already uploaded path)
should_version_on_place() {
  [[ "$IRS_VERSION_ONLY_ON_PLACE" != 1 ]] && return 1
  local rel="$1" ev="$2"
  case "$ev" in
    CLOSE_WRITE|MOVED_TO) ;;   # "save"-like events
    *) return 1 ;;
  esac
  grep -Fq "^${rel}"$'\t' "$IRS_VERS_DB" 2>/dev/null
}

ensure_remote_dir() { local dir="$1"; rclone mkdir "$dir" >/dev/null 2>&1 || { log_warning "Cannot ensure remote dir: $dir"; return 1; }; }

# === Load persistent index ===
load_index

# === State dirs and recovery ===
set +eE
log_info "Recovery bootstrap: ensure_state_dirs"
ensure_state_dirs || log_warning "ensure_state_dirs best-effort failed"

log_info "Recovery bootstrap: recover_inflight (start)"
recover_inflight || log_info "recover_inflight: nothing to do or best-effort failed"
log_info "Recovery bootstrap: recover_inflight (done)"

cleanup_stale_tmp || log_warning "cleanup_stale_tmp best-effort failed"
set -eE

handle_file() {
  local local_file="$1"    # absolute path
  local filename="$2"      # relative path + filename (inside LOCAL_DIR)
  local inode="$3"
  local remote_path="$REMOTE_DIR/$filename"
  local EXIT_REASON="ERR"
  trap '[[ "${EXIT_REASON:-}" == "ERR" ]] && log_warning "handle_file aborted (ERR) — cleanup lock"; cleanup_lock' RETURN
  log_debug "handle_file start: '$filename'"

  # Path lock (avoid back-to-back events on the same watched path)
  local path_key
  path_key=$(printf '%s' "$filename" | sha256sum | awk '{print $1}')
  PATHLOCK="$LOCKDIR/${path_key}.pathlock"
  if [[ -e "$PATHLOCK" ]]; then
    log_warning "Skipped: path busy '$filename'"
    EXIT_REASON="LOCK"
    cleanup_lock
    return 0
  fi
  : > "$PATHLOCK"
  log_debug "Path lock acquired ($PATHLOCK)"

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
  # always refresh original_pair for this file
  original_pair="${hash}___${filename}"
  HASHLOCK="$LOCKDIR/${hash}_${inode}.lock"
  if [[ -e "$HASHLOCK" ]]; then log_debug "Per-event lock exists (duplicate trigger). Skipping."; EXIT_REASON="LOCK"; return 0; fi
  : > "$HASHLOCK"; log_debug "Per-event lock acquired"

  # 3) Compute file-id (dev:inode) and consult index
  local file_id; file_id=$(get_file_id "$local_file")
  local idx_remote="${INDEX_REMOTE_PATH[$file_id]:-}"
  local idx_hash="${INDEX_HASH[$file_id]:-}"

  # 4) Extension + clean name normalization
  local assign_output assign_exit_code new_filename save_filename
  # Capture assign_extension rc without triggering the ERR trap (avoid set -E propagation)
  assign_output=$(
    set +eE
    assign_extension "$local_file"
    rc=$?
    echo "___EXIT:$rc"
  )
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

  # --- Unified on-place versioning (state-only, no remote calls) -------------
  # Se il *percorso* è già noto localmente (index/versions DB) e il contenuto è
  # cambiato, crea 'name-(ver N).ext'. Copre atomic save (inode nuovo) e rewrite.
  if should_version_on_place "$filename" "CLOSE_WRITE"; then
    # Ultimo hash noto per questo percorso (dal nostro index in RAM)
    local prev_hash_for_path=""
    prev_hash_for_path="$(get_last_hash_for_remote_path "$remote_path")"

    # Considera "path noto" anche se abbiamo solo la versions DB
    local path_known=""
    if [[ -z "$prev_hash_for_path" ]]; then
      if grep -Fq "^${filename}"$'\t' "$IRS_VERS_DB" 2>/dev/null; then
        path_known="1"
      fi
    else
      path_known="1"
    fi

    # Versiona se (path noto) e (hash cambia o non abbiamo hash precedente)
    if [[ "$path_known" == "1" && ( -z "$prev_hash_for_path" || "$prev_hash_for_path" != "$hash" ) ]]; then
      local ver show_ver dest_remote
      ver="$(irs_next_ver "$filename")"
      show_ver=$(( ver + IRS_VER_BASE_OFFSET ))
      dest_remote="$REMOTE_DIR/$(add_version_suffix "$filename" "$show_ver")"

      if ! two_phase_upload "$local_file" "$dest_remote" "$hash" "$inode" "content-change"; then
        log_error "Version upload failed: '$filename'"
        send_error_mail || true
        EXIT_REASON="ERR"; cleanup_lock; return 1
      fi

      irs_touch_path "$filename"
      [[ -n "$file_id" ]] && update_index "$file_id" "$dest_remote" "$hash"
      path_hash_key="${hash}___${filename}"
      PATH_HASH_SEEN["$path_hash_key"]="$inode"
      EXIT_REASON="OK"; cleanup_lock; return 0
    fi
  fi
  # ---------------------------------------------------------------------------

  # 4.5) Unchanged vs content-change
  if [[ -n "$file_id" && -n "$idx_remote" && -n "$idx_hash" ]]; then
    if [[ "$idx_hash" == "$hash" ]]; then
      if [[ "${IRS_COLD_START:-0}" == "1" ]]; then
        path_hash_key="${hash}___${filename}"
        PATH_HASH_SEEN["$path_hash_key"]="$inode"
        log_info "Skip unchanged (cold-start): '$filename'"
        EXIT_REASON="OK"; cleanup_lock; return 0
      elif [[ "$idx_remote" == "$remote_path" ]]; then
        # Always-copy ONLY if the target path already exists remotely.
        if remote_file_exists "$remote_path"; then
          local final_remote_copy
          final_remote_copy="$(_next_copy_dest "$REMOTE_DIR/$filename")"
          if ! two_phase_upload "$local_file" "$final_remote_copy" "$hash" "$inode" "repeat-copy"; then
            log_error "Repeat-copy upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; cleanup_lock; return 1
          fi
          log_info "Repeat-copy completed: '$filename' -> '$(basename "$final_remote_copy")'"
          path_hash_key="${hash}___${filename}"
          PATH_HASH_SEEN["$path_hash_key"]="$inode"
          [[ -n "$file_id" ]] && update_index "$file_id" "$final_remote_copy" "$hash"
          EXIT_REASON="OK"; cleanup_lock; return 0
        else
          log_debug "Repeat-copy bypassed: remote does not contain '$remote_path' yet"
          # fall-through to normal upload
        fi
      fi
    fi

    if [[ "$idx_hash" != "$hash" ]]; then
      # Content change on the same path → versioning-on-place OR fallback to (copy)
      local dest_remote

      if should_version_on_place "$filename" "CLOSE_WRITE"; then
        # produce ".../(ver N).ext" preserving the ext
        local ver
        ver=$(irs_next_ver "$filename")
        dest_remote="$REMOTE_DIR/$(add_version_suffix "$filename" "$ver")"
      else
        # safety net (shouldn't trigger often): use regular "(copy)" policy
        dest_remote="$(_next_copy_dest "$REMOTE_DIR/$filename")"
      fi

      if ! two_phase_upload "$local_file" "$dest_remote" "$hash" "$inode" "content-change"; then
        log_error "Content-change upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
      fi

      # Mark path as known for future on-place edits and index the last upload
      irs_touch_path "$filename"
      [[ -n "$file_id" ]] && update_index "$file_id" "$dest_remote" "$hash"

      path_hash_key="${hash}___${filename}"
      PATH_HASH_SEEN["$path_hash_key"]="$inode"
      EXIT_REASON="OK"; cleanup_lock; return 0
    fi
  fi

  # 5) Ensure remote dir exists
  local remote_dir_path; remote_dir_path=$(dirname "$remote_path")
  rclone mkdir "$remote_dir_path" >/dev/null 2>&1 || log_warning "Cannot create remote dir: $remote_dir_path"

  # 6) Handle pure rename (same file-id, same hash, different remote path)
  if [[ "${IRS_ALLOW_REMOTE_RENAME:-0}" == "1" && -n "$file_id" && -n "$idx_remote" && "$idx_remote" != "$remote_path" && -n "$idx_hash" && "$idx_hash" == "$hash" ]]; then
    log_info "Detected pure rename: '$idx_remote' -> '$remote_path' (no reupload)"
    ensure_remote_dir "$(dirname "$remote_path")" || true
    if rclone moveto "$idx_remote" "$remote_path" >/dev/null 2>&1; then
      update_index "$file_id" "$remote_path" "$hash"
      EXIT_REASON="OK"; log_info "Remote rename completed: '$filename'"; return 0
    else
      log_warning "Remote rename failed; will fallback to upload"
    fi
  fi


  # 7) Cold-start preflight (must run BEFORE conflict policy)
  ensure_remote_dir "$(dirname "$remote_path")" || true

  # Check remote existence once and reuse the result
  local remote_exists
  if remote_file_exists "$remote_path"; then
    remote_exists=0  # 0 == exists
  else
    remote_exists=1
  fi

  # If we are in cold-start and the target path already exists remotely with the same size,
  # assume it's the same file: index it and skip to avoid spurious "(copy)".
  if [[ "${IRS_COLD_START:-0}" == "1" && $remote_exists -eq 0 ]]; then
    local local_size
    local_size=$(stat -c%s "$local_file" 2>/dev/null || echo 0)
    if rclone lsjson --files-only "$(dirname "$remote_path")" 2>/dev/null \
      | jq -e --arg n "$(basename "$remote_path")" --argjson s "$local_size" \
           'any(.[]; .Name == $n and ((.Size // -1) == $s))' >/dev/null; then
      log_info "Skip unchanged (cold-start): '$filename' (indexed existing remote)"
      path_hash_key="${hash}___${filename}"
      PATH_HASH_SEEN["$path_hash_key"]="$inode"
      [[ -n "$file_id" ]] && update_index "$file_id" "$remote_path" "$hash"
      EXIT_REASON="OK"; cleanup_lock; return 0
    fi
  fi

    # 8) Conflict policy (name already taken by another file_id)
    if [[ $remote_exists -eq 0 && ( -z "$file_id" || "${INDEX_REMOTE_PATH[$file_id]:-}" != "$remote_path" ) ]]; then
    # --- LAST-CHANCE ON-PLACE VERSIONING GUARD ------------------------------
    # Se il nome remoto esiste già ed è lo stesso path, e:
    #  - abbiamo un hash precedente indicizzato per quel path diverso dall'attuale, OPPURE
    #  - il path risulta “conosciuto” in versions.tsv (=> on-place edit),
    # allora creiamo "…-(ver N).ext" invece di "…-(copy)".
    if [[ "${IRS_VERSION_ONLY_ON_PLACE:-1}" -eq 1 ]]; then
      # (a) lookup per path nell'indice
      last_hash_for_path="$(get_last_hash_for_remote_path "$remote_path")"
      # (b) path “conosciuto” in versions.tsv?
      if grep -Fq "^${filename}"$'\t' "$IRS_VERS_DB" 2>/dev/null || \
         { [[ -n "$last_hash_for_path" && "$last_hash_for_path" != "$hash" ]]; }; then
        ver="$(irs_next_ver "$filename")"
        dest_remote="$REMOTE_DIR/$(add_version_suffix "$filename" "$ver")"
        if ! two_phase_upload "$local_file" "$dest_remote" "$hash" "$inode" "content-change"; then
          log_error "Conflict→version upload failed: '$filename'"
          send_error_mail || true
          EXIT_REASON="ERR"; cleanup_lock; return 1
        fi
        log_info "Conflict resolved by versioning: '$filename' -> '$(basename "$dest_remote")'"
        irs_touch_path "$filename"
        [[ -n "$file_id" ]] && update_index "$file_id" "$dest_remote" "$hash"
        path_hash_key="${hash}___${filename}"
        PATH_HASH_SEEN["$path_hash_key"]="$inode"
        EXIT_REASON="OK"; cleanup_lock; return 0
      fi
    fi
    # -----------------------------------------------------------------------

    # Fallback: vero conflitto → serie "(copy)"
    final_remote="$(_next_copy_dest "$REMOTE_DIR/$filename")"
    if ! two_phase_upload "$local_file" "$final_remote" "$hash" "$inode" "conflict"; then
      log_error "Conflict upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
    fi
    log_info "Conflict upload completed: '$filename' -> '$(basename "$final_remote")'"
    path_hash_key="${hash}___${filename}"
    PATH_HASH_SEEN["$path_hash_key"]="$inode"
    [[ -n "$file_id" ]] && update_index "$file_id" "$final_remote" "$hash"
    irs_touch_path "$filename"
    EXIT_REASON="OK"; cleanup_lock; return 0
  fi

  # 9) Overwrite or first upload (with strict conflict guard) -------------------
  # Default path: try to upload to the expected remote path.
  final_remote="$remote_path"
  if ! two_phase_upload "$local_file" "$final_remote" "$hash" "$inode"; then
    local rc=$?
    if [[ $rc -eq 42 ]]; then
      # Race/strict-conflict fallback: do not overwrite, create a copy instead.
      final_remote="$(_next_copy_dest "$REMOTE_DIR/$filename")"
      if ! two_phase_upload "$local_file" "$final_remote" "$hash" "$inode" "conflict"; then
        log_error "Strict-conflict fallback failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
      fi
      log_info "Strict-conflict fallback copy: '$filename' -> '$(basename "$final_remote")'"
      path_hash_key="${hash}___${filename}"
      PATH_HASH_SEEN["$path_hash_key"]="$inode"
      [[ -n "$file_id" ]] && update_index "$file_id" "$final_remote" "$hash"
      irs_touch_path "$filename"
      EXIT_REASON="OK"
      cleanup_lock
      return 0
    else
      log_error "Upload failed (rc=$rc): '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
    fi
  else
    log_info "Upload completed: '$filename'"
  fi

  # 10) Mark processed and update index
  path_hash_key="${hash}___${filename}"
  if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then EXIT_REASON="SKIP"; cleanup_lock; return 0; fi
  PATH_HASH_SEEN["$path_hash_key"]="$inode"
  irs_touch_path "$filename"     # <- segna il path alla prima upload “normale”
  [[ -n "$file_id" ]] && update_index "$file_id" "$final_remote" "$hash"

  cleanup_lock
  EXIT_REASON="OK"; log_debug "handle_file end: '$filename'"; return 0
}

# === Exit & signals ===
on_exit() {
  log_info "instant-remote-storage exited at $(date '+%Y-%m-%d %H:%M:%S')"
  if [[ -n "${LOCKDIR:-}" && -d "$LOCKDIR" ]]; then rm -rf "$LOCKDIR" || true; log_debug "Removed LOCKDIR: $LOCKDIR"; fi
}

on_interrupt() { 
  log_warning "Interrupted. Exiting..."; 
  exit 0        # clean exit for systemd (no 'failed' status)
}
trap 'on_exit' EXIT
trap 'on_interrupt' INT TERM HUP

cold_start_rescan() {
while IFS= read -r -d '' f; do
  local relfile inode fh
  relfile="${f#"$LOCAL_DIR"/}"
  inode=$(get_inode "$f"); [[ -z "$inode" ]] && continue

  # align with watcher path/hash scheme (dedup/transform-map)
  if fh=$(compute_hash "$f"); then
    path_hash_key="${fh}___${relfile}"
    original_pair="$path_hash_key"
  else
    log_warning "Cold-start hash failed: $relfile"
  fi

  log_debug "Cold-start: requeue $relfile"
  handle_file "$f" "$relfile" "$inode" || log_warning "Cold-start failed on $relfile"
done < <(find "$LOCAL_DIR" -type f -not -path '*/.*' -print0)
}

# Cold-start pass (skip unchanged regardless of computed path)
IRS_COLD_START=1
log_info "Cold-start rescan (start)"
if ! type -t handle_file >/dev/null 2>&1; then
  log_error "handle_file missing (wrong file or not parsed yet). SCRIPT_PATH=${SCRIPT_PATH}"
  exit 1
fi
cold_start_rescan
log_info "Cold-start rescan (done)"
IRS_COLD_START=0

main_loop() {
  local inode=""
  log_info "Starting watcher on $(hostname) at $(date)"

  # Cold-start: mirror any pre-existing empty local directories to the remote
  if [[ "$IRS_MIRROR_EMPTY_DIRS" == "1" ]]; then
    while IFS= read -r -d '' DIR; do
      # Skip the root watch directory itself
      [[ "$DIR" == "$LOCAL_DIR" ]] && continue
      # Make SUBPATH robust whether or not $LOCAL_DIR ends with a slash
      local SUBPATH
      SUBPATH="${DIR#"$LOCAL_DIR"}"
      SUBPATH="${SUBPATH#/}"
      rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1 || log_warning "Cannot create remote dir: '$REMOTE_DIR/$SUBPATH'"
    done < <(find "$LOCAL_DIR" -mindepth 1 -type d -empty -print0 2>/dev/null)
  fi

  while IFS=":::" read -r FULLPATH EVENT; do
    local RELATIVE_PATH BN
    RELATIVE_PATH="${FULLPATH#"$LOCAL_DIR"/}"
    RELATIVE_PATH="${RELATIVE_PATH#./}"
    log_debug "Event '$EVENT' -> $RELATIVE_PATH"
    BN=$(basename "$RELATIVE_PATH")

    # Skip temp/hidden patterns
    if [[ "$BN" =~ ^\.goutputstream || "$BN" =~ \.(swp|part|tmp|bak)$ || "$BN" =~ ^\..* ]]; then
      log_warning "Skipped early in main_loop: $RELATIVE_PATH"
      continue
    fi

    # Handle directory events
    if [[ -d "$FULLPATH" ]]; then
      # Mirror directories on MOVED_TO (final name) and/or CREATE (toggle below)
      # If you want to avoid temporary names like "Untitled Folder", prefer MOVED_TO only.
      if [[ "$IRS_MIRROR_EMPTY_DIRS" == "1" && ( "$EVENT" == *"MOVED_TO"* || ( "$IRS_MIRROR_DIRS_ON_CREATE" == "1" && "$EVENT" == *"CREATE"* ) ) ]]; then
        # 1) Ensure the directory itself exists remotely
        local SUBPATH
        SUBPATH="${FULLPATH#"$LOCAL_DIR"}"
        SUBPATH="${SUBPATH#/}"
        rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1 || log_warning "Cannot create remote dir: '$REMOTE_DIR/$SUBPATH'"

        # 2) Ensure any currently-empty subdirectories inside it exist remotely
        while IFS= read -r -d '' DIR; do
          SUBPATH="${DIR#"$LOCAL_DIR"}"; SUBPATH="${SUBPATH#/}"
          rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1 || log_warning "Cannot create remote dir: '$REMOTE_DIR/$SUBPATH'"
        done < <( { find "$FULLPATH" -mindepth 1 -type d -empty -print0 2>/dev/null || true; } )
      fi

      # Process files within the directory (be tolerant to races)
      while IFS= read -r -d '' FILE; do
        [[ -e "$FILE" ]] || { log_debug "Vanished after scan: ${FILE#"$LOCAL_DIR"/}"; continue; }
        local RELFILE
        RELFILE="${FILE#"$LOCAL_DIR"/}"
        inode=$(get_inode "$FILE"); [[ -z "$inode" ]] && continue
        handle_file "$FILE" "$RELFILE" "$inode"
      done < <( { find "$FULLPATH" -type f -print0 2>/dev/null || true; } )

      continue

  elif [[ -f "$FULLPATH" ]]; then
    # File events
    [[ -e "$FULLPATH" ]] || { log_debug "Vanished after event: $RELATIVE_PATH"; continue; }

    # Clear debounce state when the final name arrives
    if [[ "$EVENT" == *"MOVED_TO"* ]]; then
      unset "FIRST_SEEN[$RELATIVE_PATH]" || true
    fi

    # Debounce: for non-MOVED_TO events, wait a small grace period for a rename
    if [[ "$EVENT" != *"MOVED_TO"* ]] && (( ${IRS_HOLD_CREATE_SECONDS:-0} > 0 )); then
      local now first
      now=$(date +%s)
      first=${FIRST_SEEN["$RELATIVE_PATH"]:-0}
      if (( first == 0 )); then
        FIRST_SEEN["$RELATIVE_PATH"]=$now
        log_info "hold: first sight of $RELATIVE_PATH on $EVENT → waiting up to ${IRS_HOLD_CREATE_SECONDS}s for rename."
        continue
      elif (( now - first < IRS_HOLD_CREATE_SECONDS )); then
        log_debug "hold: still within grace ($((now-first))s/${IRS_HOLD_CREATE_SECONDS}s) for $RELATIVE_PATH"
        continue
      fi
      # grace expired → proceed
    fi

    # ZERO-BYTE gate: hold zero-byte files until MOVED_TO (unless explicitly allowed)
    if (( ${IRS_UPLOAD_ZERO_ON_CREATE:-0} == 0 )) && [[ "$EVENT" != *"MOVED_TO"* ]]; then
      local sz
      sz=$(stat -c %s -- "$FULLPATH" 2>/dev/null || echo 0)
      if (( sz == 0 )); then
        log_info "hold: zero-byte $RELATIVE_PATH on $EVENT → waiting for rename or >0 content."
        continue
      fi
    fi

    # Compute content hash (race-safe)
    local FILE_HASH
    if ! FILE_HASH=$(compute_hash "$FULLPATH"); then
      log_debug "Hash race for $RELATIVE_PATH"
      continue
    fi

    # Transform-map guard (avoid loops after local renames/normalization)
    local path_hash_key original_pair
    path_hash_key="${FILE_HASH}___${RELATIVE_PATH}"
    original_pair="$path_hash_key"
    if should_skip_due_to_transform_map "$original_pair"; then
      continue
    fi

    # Re-check existence before reading inode
    [[ -e "$FULLPATH" ]] || { log_debug "Vanished before inode read: $RELATIVE_PATH"; continue; }

    inode=$(get_inode "$FULLPATH")
    [[ -n "$inode" ]] || { log_debug "Empty inode (race) for $RELATIVE_PATH"; continue; }

    # Dedup repeated triggers for same hash+path+inode
    if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then
      log_warning "Skipped: already processed $FULLPATH"
      continue
    fi

    handle_file "$FULLPATH" "$RELATIVE_PATH" "$inode"
  fi
  done < <(inotifywait -m -r -e create,close_write,moved_to --format '%w%f:::%e' "$LOCAL_DIR")

  log_info "Watch loop terminated unexpectedly"
}

main_loop
