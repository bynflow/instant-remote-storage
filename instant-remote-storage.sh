#!/usr/bin/env bash

# ========================================
# instant-remote-storage - v3.6.6
# Author : Carlo Capobianchi (bynflow)
# GitHub : https://github.com/bynflow
# Last Modified: 2025-09-20
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
log_info()    { logger -t "$LOG_TAG" "[INFO]    $*"; }
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

# === Configuration ===
LOCAL_DIR=${LOCAL_DIR:-"$HOME/remote-storage"}
REMOTE_DIR=${REMOTE_DIR:-"remote:your-remote-directory"}

# Optional wait for remote at bootstrap (default: 0 = best-effort, do not fail)
IRS_REMOTE_WAIT_SECS=${IRS_REMOTE_WAIT_SECS:-0}

# State / recovery
STATE_DIR=${STATE_DIR:-"$HOME/.local/state/instant-remote-storage"}
INFLIGHT_DIR=${INFLIGHT_DIR:-"$STATE_DIR/inflight"}
REMOTE_TMP_DIR=${REMOTE_TMP_DIR:-"$REMOTE_DIR/.irs-tmp"}
IRS_TMP_TTL_SECONDS=${IRS_TMP_TTL_SECONDS:-86400}

# Index (persistent tracking for renames & content updates)
INDEX_FILE="${INDEX_FILE:-$STATE_DIR/index.tsv}"

# --- Behavior toggles -------------------------------------------------
# When the same file-id re-triggers with identical hash AND the canonical remote path,
# 0 = skip (default); 1 = force creation of a new "(copy ...)" on each identical re-trigger
IRS_REPEAT_COPY_ON_SAME_HASH=${IRS_REPEAT_COPY_ON_SAME_HASH:-0}

# Zero-byte upload policy:
# 1 = eager: upload even on CREATE/CLOSE_WRITE (e.g., `touch` from a shell)
# 0 = hold : wait for MOVED_TO (final name) or for the file to become >0 bytes [DEFAULT]
IRS_UPLOAD_ZERO_ON_CREATE=${IRS_UPLOAD_ZERO_ON_CREATE:-0}

# Remote rename toggle (pure renames):
# 1 = allow server-side rename; 0 = treat renames as new uploads [DEFAULT]
IRS_ALLOW_REMOTE_RENAME=${IRS_ALLOW_REMOTE_RENAME:-0}

# Empty directories mirroring (CREATE gated by IRS_MIRROR_DIRS_ON_CREATE)
IRS_MIRROR_EMPTY_DIRS=${IRS_MIRROR_EMPTY_DIRS:-1}
IRS_MIRROR_DIRS_ON_CREATE=${IRS_MIRROR_DIRS_ON_CREATE:-0}

# Debounce for first writes/creates (wait for a rename)
IRS_HOLD_CREATE_SECONDS=${IRS_HOLD_CREATE_SECONDS:-15}
declare -A FIRST_SEEN=()   # key=RELATIVE_PATH, val=epoch seconds

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

# Best-effort remote readiness; optional short wait controlled by IRS_REMOTE_WAIT_SECS (default 0)
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
declare -A FILENAME_TRANSFORM_MAP=()   # key = "<hash>___<new>" -> value "<hash>___<old>"

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
get_file_id() {
  if [[ -e "$1" ]]; then
    stat -c '%d:%i' -- "$1" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

schedule_grace_flush() {
  local rel="$1" full="$2"
  (
    sleep "${IRS_HOLD_CREATE_SECONDS:-15}"
    [[ -f "$full" ]] || exit 0
    local sz; sz=$(stat -c %s -- "$full" 2>/dev/null || echo 0)
    (( sz == 0 )) && exit 0
    local inode; inode=$(stat -c %i -- "$full" 2>/dev/null || echo "")
    [[ -z "$inode" ]] && exit 0
    log_debug "grace-flush: forcing handle for $rel"
    handle_file "$full" "$rel" "$inode" || true
  ) & disown
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

# Returns 0 if ANY segment of the path begins with “.”
_has_dot_segment() {
  local rel="$1" seg
  IFS='/' read -r -a segs <<<"$rel"
  for seg in "${segs[@]}"; do
    [[ "$seg" == .* ]] && return 0
  done
  return 1
}

_should_skip_dot() {
  # Se l'utente NON vuole dotfile e il path contiene segmenti nascosti → skip
  (( ${IRS_INCLUDE_DOTFILES:-1} == 0 )) && _has_dot_segment "$1"
}

# Composite extensions to preserve
composite_exts=("tar.gz" "tar.bz2" "tar.xz" "tar.zst" "tar.lz4" "tar.br")

get_mime() {
  local file_path="$1"
  if [[ ! -s "$file_path" ]]; then
    log_warning "'$file_path' is empty → MIME undetectable; keeping original name."
    echo ""
    return
  fi
  xdg-mime query filetype "$file_path" 2>/dev/null || file --mime-type -b "$file_path"
}

is_tar_magic_stream() { dd bs=1 skip=257 count=5 2>/dev/null | grep -q 'ustar'; }
is_tar_gz()  { command -v gzip  >/dev/null 2>&1 && gzip  -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_bz2() { command -v bzip2 >/dev/null 2>&1 && bzip2 -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_xz()  { command -v xz    >/dev/null 2>&1 && xz    -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_zst() { command -v zstd  >/dev/null 2>&1 && zstd  -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }
is_tar_lz4() { command -v lz4   >/dev/null 2>&1 && lz4   -cd -- "$1" 2>/dev/null | is_tar_magic_stream; }

assign_extension() {
  local file_path="$1"
  local original_name; original_name=$(basename "$file_path")
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

  if [[ -n "$cur_ext" && "${cur_ext,,}" == "${ext,,}" ]]; then
    printf '%s\n' "$original_name"; log_debug "assign_extension: confirmed .$ext"; return 0
  fi

  if [[ -z "$cur_ext" ]]; then
    case "$ext" in
      gz)  is_tar_gz  "$file_path" && ext="tar.gz"  ;;
      bz2) is_tar_bz2 "$file_path" && ext="tar.bz2" ;;
      xz)  is_tar_xz  "$file_path" && ext="tar.xz"  ;;
      zst) is_tar_zst "$file_path" && ext="tar.zst" ;;
      lz4) is_tar_lz4 "$file_path" && ext="tar.lz4" ;;
    esac
  fi

  if [[ -n "$cur_ext" ]]; then
    printf '%s.%s\n' "$name_wo_ext" "$ext"; log_debug "assign_extension: '$original_name' -> '${name_wo_ext}.${ext}'"; return 0
  fi
  printf '%s.%s\n' "$original_name" "$ext"; log_debug "assign_extension: '$original_name' -> '${original_name}.${ext}'"; return 0
}

clean_name() {
  local s="$1"
  s=$(printf '%s' "$s" | tr -s '[:space:]' ' ')
  s="${s#"${s%%[! ]*}"}"; s="${s%"${s##*[! ]}"}"
  s=$(printf '%s' "$s" | sed -E 's/[[:space:]]+/ /g')
  s=$(printf '%s' "$s" | sed -E 's/[[:space:]]*\.[[:space:]]*/./g')
  local base ext
  base="${s%.*}"; ext="${s##*.}"
  if [[ "$base" != "$s" ]]; then
    if [[ ! "$ext" =~ ^[A-Za-z0-9]{1,7}$ ]]; then
      s="$base"
    fi
  fi
  s=$(printf '%s' "$s" | tr '/\000' '__')
  printf '%s' "$s"
}

wait_for_stable_file() {
  local path="$1" last_size=-1 size tries=${2:-5} sleep_s=${3:-0.4}
  while (( tries-- > 0 )); do
    [[ -e "$path" ]] || return 1
    size=$(stat -c %s -- "$path" 2>/dev/null || echo -1)
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

if _should_skip_dot "$REL_PATH"; then
  log "[DEBUG]" "Skipped dot path: '$REL_PATH'"
  continue
fi

handle_file() {
  local local_file="$1"    # absolute path
  local filename="$2"      # relative path + filename (inside LOCAL_DIR)
  local inode="$3"
  local EXIT_REASON="ERR"
  local path_hash_key transformed_pair remote_path remote_rel_canonical
  trap '[[ "${EXIT_REASON:-}" == "ERR" ]] && log_warning "handle_file aborted (ERR) — cleanup lock"; cleanup_lock' RETURN
  log_debug "handle_file start: '$filename'"

  # Path lock
  local path_key
  path_key=$(printf '%s' "$filename" | sha256sum | awk '{print $1}')
  local PATHLOCK
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
    log_info "'$filename' is not stable yet — will retry later"
    EXIT_REASON="SKIP"; cleanup_lock; return 0
  fi
  [[ -f "$local_file" ]] || { log_debug "File disappeared: '$filename'"; EXIT_REASON="SKIP"; cleanup_lock; return 0; }

  # Zero-byte gate
  if (( ${IRS_UPLOAD_ZERO_ON_CREATE:-0} == 0 )); then
    local fsz
    fsz=$(stat -c %s -- "$local_file" 2>/dev/null || echo 0)
    if (( fsz == 0 )); then
      log_info "Defer: zero-byte '$filename' (waiting for content)"
      EXIT_REASON="SKIP"; cleanup_lock; return 0
    fi
  fi

  # 1) Filter on basename
  local bn; bn=$(basename "$filename")
  if [[ "$bn" =~ ^\.goutputstream || "$bn" =~ \.(swp|part|tmp|bak)$ || "$bn" =~ ^\..* ]]; then
    log_warning "Skipped temp/dot: '$filename'"; EXIT_REASON="SKIP"; cleanup_lock; return 0
  fi

  # 2) Hash + per-event lock
  local hash; hash=$(compute_hash "$local_file")
  if [[ -z "$hash" ]]; then log_error "Hash failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1; fi
  log_debug "hash=$hash"
  local original_pair
  original_pair="${hash}___${filename}"
  local HASHLOCK
  HASHLOCK="$LOCKDIR/${hash}_${inode}.lock"
  if [[ -e "$HASHLOCK" ]]; then log_debug "Per-event lock exists (duplicate trigger). Skipping."; EXIT_REASON="LOCK"; return 0; fi
  : > "$HASHLOCK"; log_debug "Per-event lock acquired"

  # 3) Index consult
  local file_id; file_id=$(get_file_id "$local_file")
  local idx_remote="${INDEX_REMOTE_PATH[$file_id]:-}"
  local idx_hash="${INDEX_HASH[$file_id]:-}"

  # 4) Name normalization
  local assign_output assign_exit_code new_filename save_filename
  assign_output=$(
    ( set +eE; assign_extension "$local_file"; rc=$?; printf '___EXIT:%d' "$rc" ) || true
  )
  assign_exit_code=$(printf '%s' "$assign_output" | sed -n 's/.*___EXIT:\([0-9]\+\)/\1/p')
  : "${assign_exit_code:=0}"
  assign_output=$(printf '%s' "$assign_output" | sed 's/___EXIT:.*//')
  new_filename=$(printf '%s\n' "$assign_output" | trim)

  if [[ "$assign_exit_code" -eq 42 ]]; then
    if [[ ! -s "$local_file" ]]; then
      log_info "Defer: empty file with unknown MIME '$filename' (waiting for content)"
      EXIT_REASON="SKIP"; cleanup_lock; return 0
    fi
    new_filename="$(basename "$filename")"
  elif [[ "$assign_exit_code" -ne 0 || -z "$new_filename" ]]; then
    log_error "assign_extension failed for '$filename' (code: $assign_exit_code)"
    send_error_mail || true
    cleanup_lock; EXIT_REASON="ERR"; return 1
  fi

  save_filename=$(clean_name "$new_filename")
  local parent_dir
  parent_dir=$(dirname -- "$filename")
  local target_path
  target_path="$LOCAL_DIR/${parent_dir:+$parent_dir/}$save_filename"

  if [[ "$save_filename" != "$(basename "$filename")" ]]; then
    if [[ "$local_file" != "$target_path" ]]; then
      path_hash_key="${hash}___${parent_dir:+$parent_dir/}$save_filename"
      transformed_pair="$path_hash_key"
      FILENAME_TRANSFORM_MAP["$transformed_pair"]="$original_pair"
      if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then
        EXIT_REASON="SKIP"; cleanup_lock; return 0
      fi
      PATH_HASH_SEEN["$path_hash_key"]="$inode"

      if [[ -e "$target_path" && "$(get_inode "$target_path")" != "$inode" ]]; then
        log_warning "Local rename skipped (target exists): '$parent_dir/$save_filename'"
      else
        if ! mv -- "$local_file" "$target_path"; then
          unset "PATH_HASH_SEEN[$path_hash_key]"
          log_error "Local rename failed: '$parent_dir/$save_filename'"
          send_error_mail || true
          cleanup_lock; EXIT_REASON="ERR"; return 1
        fi
        filename="$parent_dir/$save_filename"
        filename="${filename#./}"
        local_file="$target_path"
      fi
    fi
  fi

  # Remote path canonicalization
  remote_rel_canonical="${parent_dir:+$parent_dir/}$save_filename"
  remote_path="$REMOTE_DIR/$remote_rel_canonical"

  # 4.5) Unchanged vs content-change
  if [[ -n "$file_id" && -n "$idx_remote" && -n "$idx_hash" ]]; then
    if [[ "$idx_hash" == "$hash" ]]; then
      if [[ "${IRS_COLD_START:-0}" == "1" && "$idx_remote" == "$remote_path" ]]; then
        path_hash_key="${hash}___${filename}"
        PATH_HASH_SEEN["$path_hash_key"]="$inode"
        log_info "Skip unchanged (cold-start same path): '$filename'"
        EXIT_REASON="OK"; cleanup_lock; return 0
      elif [[ "$idx_remote" == "$remote_path" ]]; then
        if remote_file_exists "$remote_path"; then
          if [[ "${IRS_REPEAT_COPY_ON_SAME_HASH:-0}" == "1" ]]; then
            local final_remote_copy
            final_remote_copy="$(_next_copy_dest "$remote_path")"
            if ! two_phase_upload "$local_file" "$final_remote_copy" "$hash" "$inode" "repeat-copy"; then
              log_error "Repeat-copy upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; cleanup_lock; return 1
            fi
            log_info "Repeat-copy completed: '$(basename "$remote_rel_canonical")' -> '$(basename "$final_remote_copy")'"
            path_hash_key="${hash}___${filename}"
            PATH_HASH_SEEN["$path_hash_key"]="$inode"
            EXIT_REASON="OK"; cleanup_lock; return 0
          else
            log_info "Skip unchanged (same path & hash): '$filename'"
            path_hash_key="${hash}___${filename}"
            PATH_HASH_SEEN["$path_hash_key"]="$inode"
            EXIT_REASON="OK"; cleanup_lock; return 0
          fi
        fi
      fi
    fi

    if [[ "$idx_hash" != "$hash" ]]; then
      local dest_remote
      dest_remote="$(_next_copy_dest "$remote_path")"
      if ! two_phase_upload "$local_file" "$dest_remote" "$hash" "$inode" "content-change"; then
        log_error "Content-change upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
      fi
      [[ -n "$file_id" ]] && update_index "$file_id" "$remote_path" "$hash"
      path_hash_key="${hash}___${filename}"
      PATH_HASH_SEEN["$path_hash_key"]="$inode"
      EXIT_REASON="OK"; cleanup_lock; return 0
    fi
  fi

  # 5) Ensure remote dir exists
  local remote_dir_path; remote_dir_path=$(dirname "$remote_path")
  rclone mkdir "$remote_dir_path" >/dev/null 2>&1 || log_warning "Cannot create remote dir: $remote_dir_path"

  # 6) Pure rename (optional)
  if [[ "${IRS_ALLOW_REMOTE_RENAME:-0}" == "1" && -n "$file_id" && -n "$idx_remote" && "$idx_remote" != "$remote_path" && -n "$idx_hash" && "$idx_hash" == "$hash" ]]; then
    log_info "Detected pure rename: '$idx_remote' -> '$remote_path' (no reupload)"
    ensure_remote_dir "$(dirname "$remote_path")" || true
    if rclone moveto "$idx_remote" "$remote_path" >/dev/null 2>&1; then
      [[ -n "$file_id" ]] && update_index "$file_id" "$remote_path" "$hash"
      EXIT_REASON="OK"; log_info "Remote rename completed: '$filename'"; return 0
    else
      log_warning "Remote rename failed; will fallback to upload"
    fi
  fi

  # 7) Cold-start preflight
  ensure_remote_dir "$(dirname "$remote_path")" || true

  # Existence cache
  local remote_exists
  if remote_file_exists "$remote_path"; then
    remote_exists=0
  else
    remote_exists=1
  fi

  # Cold-start size match → skip & index
  if [[ "${IRS_COLD_START:-0}" == "1" && $remote_exists -eq 0 ]]; then
    local local_size
    local_size=$(stat -c%s "$local_file" 2>/dev/null || echo 0)
    if rclone lsjson --files-only "$(dirname "$remote_path")" 2>/dev/null \
      | jq -e --arg n "$(basename "$remote_path")" --argjson s "$local_size" \
           'any(.[]; .Name == $n and ((.Size // -1) == $s))' >/dev/null; then
      log_info "Skip unchanged (cold-start size match): '$(basename "$remote_rel_canonical")'"
      path_hash_key="${hash}___${filename}"
      PATH_HASH_SEEN["$path_hash_key"]="$inode"
      [[ -n "$file_id" ]] && update_index "$file_id" "$remote_path" "$hash"
      EXIT_REASON="OK"; cleanup_lock; return 0
    fi
  fi

  # 8) Name conflict with different file_id → copy variant
  if [[ $remote_exists -eq 0 && ( -z "$file_id" || "${INDEX_REMOTE_PATH[$file_id]:-}" != "$remote_path" ) ]]; then
    local final_remote
    final_remote="$(_next_copy_dest "$remote_path")"
    if ! two_phase_upload "$local_file" "$final_remote" "$hash" "$inode" "conflict"; then
      log_error "Conflict upload failed: '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
    fi
    log_info "Conflict upload completed: '$(basename "$remote_rel_canonical")' -> '$(basename "$final_remote")'"
    path_hash_key="${hash}___${filename}"
    PATH_HASH_SEEN["$path_hash_key"]="$inode"
    [[ -n "$file_id" ]] && update_index "$file_id" "$remote_path" "$hash"
    EXIT_REASON="OK"; cleanup_lock; return 0
  fi

  # 9) First upload / overwrite with strict guard in lib
  local final_remote
  final_remote="$remote_path"
  if ! two_phase_upload "$local_file" "$final_remote" "$hash" "$inode"; then
    local rc=$?
    log_error "Upload failed (rc=$rc): '$filename'"; send_error_mail || true; EXIT_REASON="ERR"; return 1
  else
    log_info "Upload completed: '$(basename "$remote_rel_canonical")'"
  fi

  # 10) Mark processed & index
  path_hash_key="${hash}___${filename}"
  if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then EXIT_REASON="SKIP"; cleanup_lock; return 0; fi
  PATH_HASH_SEEN["$path_hash_key"]="$inode"
  [[ -n "$file_id" ]] && update_index "$file_id" "$remote_path" "$hash"

  cleanup_lock
  EXIT_REASON="OK"; log_debug "handle_file end: '$filename'"; return 0
}

# === Exit & signals ===
on_exit() {
  log_info "instant-remote-storage exited at $(date '+%Y-%m-%d %H:%M:%S')"
  if [[ -n "${LOCKDIR:-}" && -d "$LOCKDIR" ]]; then rm -rf "$LOCKDIR" || true; log_debug "Removed LOCKDIR: $LOCKDIR"; fi
}

on_interrupt() {
  log_warning "Interrupted. Exiting..."
  exit 0
}
trap 'on_exit' EXIT
trap 'on_interrupt' INT TERM HUP

cold_start_rescan() {
  while IFS= read -r -d '' f; do
    local relfile inode
    relfile="${f#"$LOCAL_DIR"/}"
    inode=$(get_inode "$f"); [[ -z "$inode" ]] && continue
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

  # Cold-start: mirror empty local dirs to remote
  if [[ "$IRS_MIRROR_EMPTY_DIRS" == "1" ]]; then
    while IFS= read -r -d '' DIR; do
      [[ "$DIR" == "$LOCAL_DIR" ]] && continue
      local SUBPATH
      SUBPATH="${DIR#"$LOCAL_DIR"}"; SUBPATH="${SUBPATH#/}"
      rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1 || log_warning "Cannot create remote dir: '$REMOTE_DIR/$SUBPATH'"
    done < <(find "$LOCAL_DIR" -mindepth 1 -type d -empty -print0 2>/dev/null)
  fi

  # Persist state in the same shell: process substitution (no subshell for while)
  while true; do
    while IFS=":::" read -r FULLPATH EVENT; do
      local RELATIVE_PATH BN
      RELATIVE_PATH="${FULLPATH#"$LOCAL_DIR"/}"
      RELATIVE_PATH="${RELATIVE_PATH#./}"
      BN=$(basename "$RELATIVE_PATH")
      log_debug "Event '$EVENT' -> $RELATIVE_PATH"

      # Skip temp/hidden patterns
      if [[ "$BN" =~ ^\.goutputstream || "$BN" =~ \.(swp|part|tmp|bak)$ || "$BN" =~ ^\..* ]]; then
        log_warning "Skipped early in main_loop: $RELATIVE_PATH"
        continue
      fi

      # Directory events
      if [[ -d "$FULLPATH" ]]; then
        if [[ "$IRS_MIRROR_EMPTY_DIRS" == "1" && ( "$EVENT" == *"MOVED_TO"* || ( "$IRS_MIRROR_DIRS_ON_CREATE" == "1" && "$EVENT" == *"CREATE"* ) ) ]]; then
          local SUBPATH
          SUBPATH="${FULLPATH#"$LOCAL_DIR"}"; SUBPATH="${SUBPATH#/}"
          rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1 || log_warning "Cannot create remote dir: '$REMOTE_DIR/$SUBPATH'"
          while IFS= read -r -d '' DIR; do
            SUBPATH="${DIR#"$LOCAL_DIR"}"; SUBPATH="${SUBPATH#/}"
            rclone mkdir "$REMOTE_DIR/$SUBPATH" >/dev/null 2>&1 || log_warning "Cannot create remote dir: '$REMOTE_DIR/$SUBPATH'"
          done < <( { find "$FULLPATH" -mindepth 1 -type d -empty -print0 2>/dev/null || true; } )
        fi

        # Process files within the directory
        while IFS= read -r -d '' FILE; do
          [[ -e "$FILE" ]] || { log_debug "Vanished after scan: ${FILE#"$LOCAL_DIR"/}"; continue; }
          local RELFILE
          RELFILE="${FILE#"$LOCAL_DIR"/}"
          inode=$(get_inode "$FILE"); [[ -z "$inode" ]] && continue
          handle_file "$FILE" "$RELFILE" "$inode"
        done < <( { find "$FULLPATH" -type f -print0 2>/dev/null || true; } )
        continue

      elif [[ -f "$FULLPATH" ]]; then
        [[ -e "$FULLPATH" ]] || { log_debug "Vanished after event: $RELATIVE_PATH"; continue; }

        # Clear debounce on final name
        if [[ "$EVENT" == *"MOVED_TO"* ]]; then
          unset "FIRST_SEEN[$RELATIVE_PATH]" || true
        fi

        # Debounce provisional names
        if [[ "$EVENT" != *"MOVED_TO"* ]] && (( ${IRS_HOLD_CREATE_SECONDS:-0} > 0 )); then
          if [[ "$BN" != .* && "$BN" == *.* ]]; then
            unset "FIRST_SEEN[$RELATIVE_PATH]" || true
          else
            case "$BN" in
              "Untitled"*|~\$*|*.tmp|*.part) ;;  # keep holding
              *) ;;                              # generic no-ext → hold
            esac
            local now first
            now=$(date +%s)
            first=${FIRST_SEEN["$RELATIVE_PATH"]:-0}
            if (( first == 0 )); then
              FIRST_SEEN["$RELATIVE_PATH"]=$now
              log_info "hold: first sight of $RELATIVE_PATH on $EVENT → waiting up to ${IRS_HOLD_CREATE_SECONDS}s for rename."
              schedule_grace_flush "$RELATIVE_PATH" "$FULLPATH"
              continue
            elif (( now - first < IRS_HOLD_CREATE_SECONDS )); then
              log_debug "hold: still within grace ($((now-first))s/${IRS_HOLD_CREATE_SECONDS}s) for $RELATIVE_PATH"
              continue
            fi
          fi
        fi

        # Zero-byte gate
        if (( ${IRS_UPLOAD_ZERO_ON_CREATE:-0} == 0 )); then
          local sz
          sz=$(stat -c %s -- "$FULLPATH" 2>/dev/null || echo 0)
          if (( sz == 0 )); then
            log_info "hold: zero-byte $RELATIVE_PATH on $EVENT → waiting for >0 content."
            continue
          fi
        fi

        # Hash
        local FILE_HASH
        if ! FILE_HASH=$(compute_hash "$FULLPATH"); then
          log_debug "Hash race for $RELATIVE_PATH"
          continue
        fi

        # Transform-map guard
        local path_hash_key original_pair
        path_hash_key="${FILE_HASH}___${RELATIVE_PATH}"
        original_pair="$path_hash_key"
        if should_skip_due_to_transform_map "$original_pair"; then
          continue
        fi

        # Re-check and inode
        [[ -e "$FULLPATH" ]] || { log_debug "Vanished before inode read: $RELATIVE_PATH"; continue; }
        inode=$(get_inode "$FULLPATH")
        [[ -n "$inode" ]] || { log_debug "Empty inode (race) for $RELATIVE_PATH"; continue; }

        # Dedup per hash+path+inode
        if [[ "${PATH_HASH_SEEN[$path_hash_key]:-}" == "$inode" ]]; then
          log_warning "Skipped: already processed $FULLPATH"
          continue
        fi

        handle_file "$FULLPATH" "$RELATIVE_PATH" "$inode"
      fi
    done < <(inotifywait -m -r -e create,close_write,moved_to --format '%w%f:::%e' "$LOCAL_DIR")

    log_warning "Watch stream ended unexpectedly; restarting in 0.5s"
    sleep 0.5
  done

  log_info "Watch loop terminated unexpectedly"
}

main_loop
