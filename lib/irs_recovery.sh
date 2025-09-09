# shellcheck shell=bash
# lib/irs_recovery.sh
# -----------------------------------------------------------------------------
# Two-phase upload with crash-safe markers and startup recovery.
# Adds a last-chance conflict guard before promoting tmp -> final:
# if the final path already exists and we didn't request overwrite,
# move to a "(copy)" name instead (configurable via IRS_STRICT_CONFLICT).
# Uses rclone lsjson for reliable existence checks on WebDAV-like backends.
# Also normalizes a few pathological server-side rename outcomes (.tar.gaz → .tar.gz).
# -----------------------------------------------------------------------------

# Include guard
[[ -n "${IRS_RECOVERY_SH:-}" ]] && return 0
IRS_RECOVERY_SH=1

# Configuration/state (expected to be provided by the main script)
STATE_DIR="${STATE_DIR:-$HOME/.local/state/instant-remote-storage}"
INFLIGHT_DIR="${INFLIGHT_DIR:-$STATE_DIR/inflight}"
REMOTE_TMP_DIR="${REMOTE_TMP_DIR:-$REMOTE_DIR/.irs-tmp}"
IRS_TMP_TTL_SECONDS="${IRS_TMP_TTL_SECONDS:-86400}"

# Conflict fallback behavior:
# 1 = if the final destination exists, promote tmp to a "(copy)" name instead of overwriting
# 0 = do not alter destination (keep whatever the caller passed)
IRS_STRICT_CONFLICT="${IRS_STRICT_CONFLICT:-1}"

ensure_state_dirs() {
  mkdir -p "$INFLIGHT_DIR" || true
  # Best-effort: do not fail if remote is currently unavailable
  rclone mkdir "$REMOTE_TMP_DIR" >/dev/null 2>&1 || true
}

# Marker helpers
# Local marker:  <hash>_<inode>.state
# Remote tmp:    <hash>_<inode>.upload  (same key → straightforward recovery)
_marker_path() { # $1=hash  $2=inode
  printf '%s/%s_%s.state\n' "$INFLIGHT_DIR" "$1" "$2"
}

_write_marker() {  # $1=path  $2=status  $3=hash  $4=inode  $5=local  $6=rel  $7=tmp_remote  $8=final_remote
  local p="$1"; shift
  {
    printf 'STATUS=%q\n'        "$1"
    printf 'HASH=%q\n'          "$2"
    printf 'INODE=%q\n'         "$3"
    printf 'LOCAL=%q\n'         "$4"
    printf 'REL=%q\n'           "$5"
    printf 'TMP_REMOTE=%q\n'    "$6"
    printf 'FINAL_REMOTE=%q\n'  "$7"
    printf 'STARTED_AT=%q\n'    "$(date +%s)"
  } > "$p"
}

_update_marker_status() { # $1=path  $2=status
  sed -i "s/^STATUS=.*/STATUS=$2/" "$1" 2>/dev/null || true
}

# Generic key update for the marker (value is shell-quoted like _write_marker)
_update_marker_kv() { # $1=path  $2=KEY  $3=VALUE
  local p="$1" k="$2" v="$3" qv
  qv=$(printf '%q' "$v")
  sed -i "s|^${k}=.*|${k}=${qv}|" "$p" 2>/dev/null || true
}

_clear_marker() { # $1=path
  rm -f "$1" 2>/dev/null || true
}

# ---- Helpers used by the last-chance conflict guard -------------------------

# Known composite extensions to preserve when generating "(copy)" names
_irs_comp_exts=("tar.gz" "tar.bz2" "tar.xz" "tar.zst" "tar.lz4" "tar.br")

# Returns "BASE:::EXT" from a RELATIVE path (no remote prefix), preserving composites
_split_base_ext_rel() {
  local rel="$1"
  for _e in "${_rs_comp_exts[@]:-tar.gz}" "${_irs_comp_exts[@]}"; do :; done # shell quiet
  for _e in "${_irs_comp_exts[@]}"; do
    if [[ "$rel" == *".${_e}" ]]; then
      printf '%s:::%s\n' "${rel%."$_e"}" "$_e"
      return
    fi
  done
  printf '%s:::%s\n' "${rel%.*}" "${rel##*.}"
}

# Checks if a remote destination path exists (exact basename match in its parent dir)
_dest_exists() { # $1=absolute remote path (REMOTE_DIR/…)
  # Use lsjson (more reliable on WebDAV) to detect exact basename collision
  local dest="$1"
  local parent; parent="$(dirname "$dest")"
  local base; base="$(basename "$dest")"
  rclone lsjson --files-only "$parent" 2>/dev/null | grep -F "\"Name\":\"$base\"" >/dev/null
}

# Normalize a few pathological server-side rename outcomes (defensive)
# e.g. some backends might produce ".tar.gaz" instead of ".tar.gz"
_normalize_final_path() {  # $1=absolute remote path
  case "$1" in
    *.tar.gaz)  printf '%s\n' "${1%gaz}gz"  ;;
    *.tar.bz)   printf '%s\n' "${1%bz}bz2"  ;;
    *)          printf '%s\n' "$1" ;;
  esac
}

# Given an absolute remote path (REMOTE_DIR/rel), returns a new absolute path
# with a "(copy)" suffix that does not collide. Prints the new path to stdout.
_next_copy_dest() { # $1=absolute remote path
  local dest="$1"
  local rel="${dest#"$REMOTE_DIR/"}"
  local split base ext dotext
  split="$(_split_base_ext_rel "$rel")"
  if [[ "$split" == *":::"* ]]; then
    base="${split%:::*}"
    ext="${split##*:::}"
  else
    base="$rel"; ext=""
  fi
  ext="${ext,,}"
  if [[ -n "$ext" ]]; then dotext=".$ext"; else dotext=""; fi

  local base_dir base_name new_base_name new_rel parent_for_check
  base_dir="$(dirname "$base")"
  base_name="$(basename "$base")"
  new_base_name="${base_name}-(copy)"

  if [[ "$base_dir" == "." ]]; then
    new_rel="${new_base_name}${dotext}"
    parent_for_check="$REMOTE_DIR"
  else
    new_rel="${base_dir}/${new_base_name}${dotext}"
    parent_for_check="$REMOTE_DIR/$base_dir"
  fi

  # increment until free
  local count=1
  while rclone lsf --files-only "$parent_for_check" 2>/dev/null | grep -Fxq "${new_base_name}${dotext}"; do
    count=$((count + 1))
    new_base_name="${base_name}-(copy ${count})"
    if [[ "$base_dir" == "." ]]; then
      new_rel="${new_base_name}${dotext}"
    else
      new_rel="${base_dir}/${new_base_name}${dotext}"
    fi
  done

  printf '%s\n' "$REMOTE_DIR/$new_rel"
}

# two_phase_upload LOCAL_FILE FINAL_REMOTE HASH INODE [CONFLICT_FLAG]
#   - CONFLICT_FLAG non-empty → log label "conflict"
#   - If omitted, auto-detect when basename contains "(copy"
two_phase_upload() {
  local local_file="$1"
  local final_remote="$2"
  local hash="$3"
  local inode="$4"
  local conflict_flag="${5:-}"
  local _tag="${LOG_TAG:-instant-remote-storage}"

  local tmp_remote="$REMOTE_TMP_DIR/${hash}_${inode}.upload"
  local rel="${final_remote#"$REMOTE_DIR/"}"

  # Auto-detect label if not provided
  if [[ -z "$conflict_flag" ]]; then
    [[ "$(basename "$final_remote")" =~ \(copy ]] && conflict_flag="conflict"
  fi

  # Create marker before starting the copy
  local MP
  MP="$(_marker_path "$hash" "$inode")"
  _write_marker "$MP" "copying" "$hash" "$inode" "$local_file" "$rel" "$tmp_remote" "$final_remote"

  # Capture rclone progress lines ("Transferred:")
  local TMP_LOG
  TMP_LOG="$(mktemp -t irs_rclone_XXXXXX.log)"

  # Phase 1: copy file → remote tmp
  if ! rclone copyto "$local_file" "$tmp_remote" --progress --stats=5s 1>"$TMP_LOG" 2>&1; then
    logger -t "$_tag" "[ERROR] copyto tmp failed: '$rel'"
    awk '/Transferred:/' "$TMP_LOG" | while read -r line; do logger -t "$_tag" "$line"; done || true
    rm -f "$TMP_LOG"
    return 1  # marker stays → recovery will handle
  fi

  : > "$TMP_LOG"
  _update_marker_status "$MP" "uploaded_tmp"

  # ---- Last-chance conflict guard (strict by default) -----------------------
  # If the destination already exists and we are not explicitly overwriting,
  # promote tmp to a "(copy)" destination to avoid clobbering existing files.
  if [[ "$IRS_STRICT_CONFLICT" == "1" && -z "$conflict_flag" ]]; then
    if _dest_exists "$final_remote"; then
      local new_final
      new_final="$(_next_copy_dest "$final_remote")"
      if [[ -n "$new_final" ]]; then
        logger -t "$_tag" "[INFO] Conflict fallback: '$rel' exists; promoting tmp to '$(basename "$new_final")'"
        final_remote="$new_final"
        conflict_flag="conflict"
        _update_marker_kv "$MP" "FINAL_REMOTE" "$final_remote"
      fi
    fi
  fi

  # Normalize extension if backend produced oddities (defensive)
  final_remote="$(_normalize_final_path "$final_remote")"
  # --------------------------------------------------------------------------

  # Phase 2: promote tmp → final (atomic when backend supports it)
  if ! rclone moveto "$tmp_remote" "$final_remote" 1>>"$TMP_LOG" 2>&1; then
    logger -t "$_tag" "[ERROR] moveto tmp→final failed: '$rel'"
    awk '/Transferred:/' "$TMP_LOG" | while read -r line; do logger -t "$_tag" "$line"; done || true
    rm -f "$TMP_LOG"
    return 1  # marker stays → recovery will handle
  fi
  awk '/Transferred:/' "$TMP_LOG" | while read -r line; do logger -t "$_tag" "$line"; done || true
  rm -f "$TMP_LOG"

  # Success: clear marker
  _clear_marker "$MP"
  return 0
}

# Startup recovery:
#  1) final already present → clear marker
#  2) tmp exists           → promote to final
#  3) tmp missing          → re-copy local → tmp, then promote
recover_inflight() {
  shopt -s nullglob
  for st in "$INFLIGHT_DIR"/*.state; do
    # shellcheck source=/dev/null
    source "$st" 2>/dev/null || continue

    # 1) final exists
    if rclone lsf --files-only "$(dirname "$FINAL_REMOTE")" 2>/dev/null | grep -Fxq "$(basename "$FINAL_REMOTE")"; then
      logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery: final already present → complete: ${REL:-<unknown>}"
      _clear_marker "$st"
      continue
    fi

    # 2) tmp exists → promote
    if rclone lsf --files-only "$(dirname "$TMP_REMOTE")" 2>/dev/null | grep -Fxq "$(basename "$TMP_REMOTE")"; then
      logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery: promote tmp → final: ${REL:-<unknown>}"
      if rclone moveto "$TMP_REMOTE" "$FINAL_REMOTE" >/dev/null 2>&1; then
        _clear_marker "$st"
        logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery ok: ${REL:-<unknown>}"
      else
        logger -t "${LOG_TAG:-instant-remote-storage}" "[WARNING] Recovery moveto failed: ${REL:-<unknown>} (marker kept)"
      fi
      continue
    fi

    # 3) tmp missing → re-copy and promote
    logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery: re-copy tmp → final: ${REL:-<unknown>}"
    if rclone copyto "$LOCAL" "$TMP_REMOTE" >/dev/null 2>&1 && \
       rclone moveto "$TMP_REMOTE" "$FINAL_REMOTE" >/dev/null 2>&1; then
      _clear_marker "$st"
      logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery ok (re-copy): ${REL:-<unknown>}"
    else
      logger -t "${LOG_TAG:-instant-remote-storage}" "[WARNING] Recovery failed: ${REL:-<unknown>} (marker kept)"
    fi
  done
  shopt -u nullglob
}
