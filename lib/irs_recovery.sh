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

# Normalize remote roots (avoid trailing '/')
_irs_remote_root="${REMOTE_DIR%/}"
_irs_tmp_root="${REMOTE_TMP_DIR%/}"

# Conflict fallback behavior:
# 1 = if the final destination exists, promote tmp to a "(copy)" name instead of overwriting
# 0 = do not alter destination (keep whatever the caller passed)
IRS_STRICT_CONFLICT="${IRS_STRICT_CONFLICT:-1}"

ensure_state_dirs() {
  mkdir -p "$INFLIGHT_DIR" || true
  rclone mkdir "$_irs_tmp_root" >/dev/null 2>&1 || true
}

# Marker helpers
# Local marker:  <hash>_<inode>.state
# Remote tmp:    <hash>_<inode>.upload  (same key → straightforward recovery)
_marker_path() { # $1=hash  $2=inode
  printf '%s/%s_%s.state\n' "$INFLIGHT_DIR" "$1" "$2"
}

_write_marker() {  # $1=path  $2=status  $3=hash  $4=inode  $5=local  $6=rel  $7=tmp_remote  $8=final_remote
  local p="$1"; shift
  # make sure parent dir exists (handles runtime deletions of STATE_DIR/INFLIGHT_DIR)
  mkdir -p -- "$(dirname -- "$p")" 2>/dev/null || true
  {
    printf 'STATUS=%q\n'        "$1"
    printf 'HASH=%q\n'          "$2"
    printf 'INODE=%q\n'         "$3"
    printf 'LOCAL=%q\n'         "$4"
    printf 'REL=%q\n'           "$5"
    printf 'TMP_REMOTE=%q\n'    "$6"
    printf 'FINAL_REMOTE=%q\n'  "$7"
    printf 'STARTED_AT=%q\n'    "$(date +%s)"
  } >"$p" || return 1
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

# Returns "BASE:::EXT" from a RELATIVE path (no remote prefix), preserving composites.
# If there is no extension (or it's a dotfile), EXT is empty.
_split_base_ext_rel() {
  local rel="$1"
  # Preserve known composite extensions
  for _e in "${_irs_comp_exts[@]}"; do
    if [[ "$rel" == *".${_e}" ]]; then
      printf '%s:::%s\n' "${rel%."$_e"}" "$_e"
      return
    fi
  done
  # No composite: handle extensionless names and dotfiles
  if [[ "$rel" == .* || "$rel" != *.* ]]; then
    printf '%s:::\n' "$rel"
  else
    printf '%s:::%s\n' "${rel%.*}" "${rel##*.}"
  fi
}

# Checks if a remote destination path exists (exact basename match in its parent dir)
_dest_exists() { # $1=absolute remote path (REMOTE_DIR/…)
  local dest="$1"
  local parent; parent="$(dirname "$dest")"
  local base; base="$(basename "$dest")"
  rclone lsjson --files-only "$parent" 2>/dev/null \
    | jq -e --arg name "$base" 'any(.[]; .Name == $name)' >/dev/null
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
  local rel="${dest#"${_irs_remote_root}/"}"
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
  new_base_name="${base_name} (copy)"

  if [[ "$base_dir" == "." ]]; then
    new_rel="${new_base_name}${dotext}"
    parent_for_check="$_irs_remote_root"
  else
    new_rel="${base_dir}/${new_base_name}${dotext}"
    parent_for_check="$_irs_remote_root/$base_dir"
  fi

  # increment until free
  local count=1
  while rclone lsjson --files-only "$parent_for_check" 2>/dev/null \
    | jq -e --arg n "${new_base_name}${dotext}" 'any(.[]; .Name == $n)' >/dev/null; do
    count=$((count + 1))
    new_base_name="${base_name} (copy ${count})"
    if [[ "$base_dir" == "." ]]; then
      new_rel="${new_base_name}${dotext}"
    else
      new_rel="${base_dir}/${new_base_name}${dotext}"
    fi
  done

  printf '%s\n' "$_irs_remote_root/$new_rel"
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

  # Ensure state dirs exist even if they were deleted while running (cheap & idempotent)
  ensure_state_dirs || true

  local tmp_remote="$_irs_tmp_root/${hash}_${inode}.upload"
  local rel="${final_remote#"${_irs_remote_root}/"}"

  # Auto-detect label if not provided
  if [[ -z "$conflict_flag" ]]; then
    [[ "$(basename "$final_remote")" =~ \(copy ]] && conflict_flag="conflict"
  fi

  # Create marker before starting the copy (degraded if it fails)
  local MP
  MP="$(_marker_path "$hash" "$inode")"
  if ! _write_marker "$MP" "copying" "$hash" "$inode" "$local_file" "$rel" "$tmp_remote" "$final_remote"; then
    logger -t "$_tag" "[WARNING] Could not create state marker for '$rel' (continuing without crash-safety)"
    MP=""  # no marker → recovery will be skipped for this upload
  fi

  # Capture rclone progress lines ("Transferred:")
  local TMP_LOG
  TMP_LOG="$(mktemp -t irs_rclone_XXXXXX.log)"

  # Phase 1: copy file → remote tmp
  if ! rclone copyto "$local_file" "$tmp_remote" --progress --stats=5s 1>"$TMP_LOG" 2>&1; then
    logger -t "$_tag" "[ERROR] copyto tmp failed: '$rel'"
    awk '/Transferred:/' "$TMP_LOG" | while read -r line; do logger -t "$_tag" "$line"; done || true
    rm -f "$TMP_LOG"
    return 1  # marker stays (if present) → recovery will handle
  fi

  : > "$TMP_LOG"
  # Inline marker update (avoid relying on helper visibility)
  if [[ -n "$MP" ]]; then
    sed -i 's/^STATUS=.*/STATUS=uploaded_tmp/' "$MP" 2>/dev/null || true
  fi

  # ---- Last-chance conflict guard (strict by default) -----------------------
  # Even if caller passed "conflict", double-check to avoid overwriting an existing path.
  if [[ "$IRS_STRICT_CONFLICT" == "1" ]]; then
    if _dest_exists "$final_remote"; then
      local new_final
      new_final="$(_next_copy_dest "$final_remote")"
      if [[ -n "$new_final" ]]; then
        logger -t "$_tag" "[INFO] Conflict fallback: '$rel' exists; promoting tmp to '$(basename "$new_final")'"
        final_remote="$new_final"
        conflict_flag="conflict"
        [[ -n "$MP" ]] && _update_marker_kv "$MP" "FINAL_REMOTE" "$final_remote"
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
    return 1  # marker stays (if present) → recovery will handle
  fi
  awk '/Transferred:/' "$TMP_LOG" | while read -r line; do logger -t "$_tag" "$line"; done || true
  rm -f "$TMP_LOG"

  # Success: clear the marker (index is handled by the main script)
  if [[ -n "$MP" && -f "$MP" ]]; then
    _clear_marker "$MP"
  fi
  return 0
}

cleanup_stale_tmp() {
  local now ts mp age orphan
  now=$(date +%s)

  # --- GC local markers (best-effort) ---------------------------------------
  shopt -s nullglob
  for mp in "$INFLIGHT_DIR"/*.state; do
    ts=$(sed -n 's/^STARTED_AT=\(.*\)$/\1/p' "$mp" 2>/dev/null || echo "")
    [[ -n "$ts" ]] || continue
    age=$(( now - ts ))
    if (( age > IRS_TMP_TTL_SECONDS )); then
      rm -f -- "$mp" 2>/dev/null || true
      logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] GC: removed stale marker $(basename "$mp")"
    fi
  done
  shopt -u nullglob

  # --- GC orphan remote tmp files (best-effort, never fatal) -----------------
  set +eE  # do not let errors here kill the daemon
  if rclone lsf "$_irs_tmp_root" >/dev/null 2>&1; then
    # Some backends don’t expose ModTime; we skip those entries
    rclone lsjson "$_irs_tmp_root" 2>/dev/null \
    | jq -r -j --arg now "$(date -u +%s)" --arg ttl "$IRS_TMP_TTL_SECONDS" '
        .[]
        | select((.IsDir // false) | not)
        | (.Path // .Name) as $name
        | (.ModTime // "") as $mt
        | select(($mt | length) > 0)
        | ($mt | sub("\\.[0-9]+Z$"; "Z")) as $mt2
        | ($mt2 | fromdateiso8601) as $t
        | select((($now | tonumber) - $t) > ($ttl | tonumber))
        | ($name + "\u0000")
    ' 2>/dev/null \
    | while IFS= read -r -d '' orphan; do
        [[ -n "$orphan" ]] || continue
        orphan="${orphan##/}"
        orphan="${orphan#./}"
        [[ -z "$orphan" || "$orphan" == "." || "$orphan" == ".." ]] && continue

        if rclone deletefile -- "$_irs_tmp_root/$orphan" >/dev/null 2>&1; then
          logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] GC: deleted stale remote tmp '$orphan'"
        else
          logger -t "${LOG_TAG:-instant-remote-storage}" "[WARNING] GC: failed to delete remote tmp '$orphan'"
        fi
    done
  else
    logger -t "${LOG_TAG:-instant-remote-storage}" "[DEBUG] GC: remote tmp dir missing/unreachable, skipping"
  fi
  set -eE  # restore -e
}

# Startup recovery:
#  1) final already present → clear marker
#  2) tmp exists           → promote to final
#  3) tmp missing          → re-copy local → tmp, then promote
recover_inflight() {
  set +eE
  shopt -s nullglob
  for st in "$INFLIGHT_DIR"/*.state; do
    (
      # Ogni marker è gestito in una subshell: variabili del marker isolate qui dentro
      # shellcheck source=/dev/null
      source "$st" 2>/dev/null || exit 0

      # Guard: servono questi campi minimi
      if [[ -z "${FINAL_REMOTE:-}" || -z "${TMP_REMOTE:-}" || -z "${REL:-}" || -z "${LOCAL:-}" ]]; then
        logger -t "${LOG_TAG:-instant-remote-storage}" "[WARNING] Recovery: bad marker '$(basename "$st")' (missing keys) — keeping for manual inspection"
        exit 0
      fi

      # 1) final già presente
      if rclone lsjson --files-only "$(dirname "$FINAL_REMOTE")" 2>/dev/null \
        | jq -e --arg n "$(basename "$FINAL_REMOTE")" 'any(.[]; .Name == $n)' >/dev/null; then
        logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery: final already present → complete: ${REL:-<unknown>}"
        _clear_marker "$st"
        exit 0
      fi

      # 2) tmp esiste → promuovi
      if rclone lsjson --files-only "$(dirname "$TMP_REMOTE")" 2>/dev/null \
        | jq -e --arg n "$(basename "$TMP_REMOTE")" 'any(.[]; .Name == $n)' >/dev/null; then
        logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery: promote tmp → final: ${REL:-<unknown>}"
        if rclone moveto "$TMP_REMOTE" "$FINAL_REMOTE" >/dev/null 2>&1; then
          _clear_marker "$st"
          logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery ok: ${REL:-<unknown>}"
        else
          logger -t "${LOG_TAG:-instant-remote-storage}" "[WARNING] Recovery moveto failed: ${REL:-<unknown>} (marker kept)"
        fi
        exit 0
      fi

      # 3) tmp mancante → ricopia e promuovi
      logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery: re-copy tmp → final: ${REL:-<unknown>}"
      if rclone copyto "$LOCAL" "$TMP_REMOTE" >/dev/null 2>&1 && \
         rclone moveto "$TMP_REMOTE" "$FINAL_REMOTE" >/dev/null 2>&1; then
        _clear_marker "$st"
        logger -t "${LOG_TAG:-instant-remote-storage}" "[INFO] Recovery ok (re-copy): ${REL:-<unknown>}"
      else
        logger -t "${LOG_TAG:-instant-remote-storage}" "[WARNING] Recovery failed: ${REL:-<unknown>} (marker kept)"
      fi
    )
  done
  shopt -u nullglob
  set -eE
}
