# shellcheck shell=bash
# ========================================
# lib/irs_recovery.sh
# Runtime & crash-safety helpers for instant-remote-storage
# Requires the following vars (defined in main script):
#   STATE_DIR, INFLIGHT_DIR, REMOTE_DIR, REMOTE_TMP_DIR, IRS_TMP_TTL_SECONDS
# And logging helpers: log_info, log_warning, log_error, log_debug
# ========================================

# --- Ensure local state dirs exist and remote TMP area is reachable -------------
ensure_state_dirs() {
  mkdir -p "$STATE_DIR" "$INFLIGHT_DIR" || {
    log_warning "Could not create state dirs: $STATE_DIR / $INFLIGHT_DIR"
    return 1
  }
  # Best-effort create remote tmp area
  rclone mkdir "$REMOTE_TMP_DIR" >/dev/null 2>&1 || {
    log_warning "Could not create remote TMP: $REMOTE_TMP_DIR (will retry later)"
  }
  return 0
}

# --- Build a tmp upload path for a final remote path + hash --------------------
# Preserves the relative subpath under REMOTE_TMP_DIR to keep structure readable.
_tmp_path_for() {
  # $1 = final remote path (e.g. "$REMOTE_DIR/path/to/file.ext")
  # $2 = sha256 hash (for uniqueness)
  local dst="$1" h="$2" rel tmp
  rel="${dst#"$REMOTE_DIR"/}"        # strip the remote root prefix if present
  [[ "$rel" == "$dst" ]] && rel="$dst"   # if not prefixed, keep as-is
  tmp="$REMOTE_TMP_DIR/$rel.__irsupload__.$h.tmp"
  printf '%s\n' "$tmp"
}

# --- Compute a non-colliding "(copy)" destination for a remote file ------------
# Produces: "name-(copy).ext", then "name-(copy 2).ext", ...
_next_copy_dest() {
  # $1 = preferred remote path (e.g. "$REMOTE_DIR/path/to/file.ext")
  local dst="$1" parent base name ext candidate i
  parent="$(dirname "$dst")"
  base="$(basename "$dst")"

  # split base into name + extension (preserve last dot; composite exts handled by main)
  if [[ "$base" == .* || "$base" != *.* ]]; then
    name="$base"
    ext=""
  else
    name="${base%.*}"
    ext=".${base##*.}"
  fi

  # If it already ends with "-(copy)" or "-(copy N)", start incrementing from N+1
  local suffix="-(copy)"
  local count_start=1
  if [[ "$name" =~ ^(.+)-\(copy\)$ ]]; then
    name="${BASH_REMATCH[1]}"; count_start=2
  elif [[ "$name" =~ ^(.+)-\(copy\ ([0-9]+)\)$ ]]; then
    name="${BASH_REMATCH[1]}"; count_start=$(( BASH_REMATCH[2] + 1 ))
  fi

  # Preload sibling names once
  local siblings_json
  siblings_json="$(rclone lsjson --files-only "$parent" 2>/dev/null)" || siblings_json="[]"

  # First try plain "-(copy)"
  candidate="$parent/${name}${suffix}${ext}"
  if ! jq -e --arg n "$(basename "$candidate")" 'any(.[]; .Name == $n)' >/dev/null 2>&1 <<<"$siblings_json"; then
    printf '%s\n' "$candidate"; return 0
  fi

  # Then "-(copy N)"
  for (( i=count_start; i<=9999; i++ )); do
    candidate="$parent/${name}-(${suffix#-(} ${i})${ext}"   # builds "-(copy N)"
    if ! jq -e --arg n "$(basename "$candidate")" 'any(.[]; .Name == $n)' >/dev/null 2>&1 <<<"$siblings_json"; then
      printf '%s\n' "$candidate"; return 0
    fi
  done

  # Fallback (should never happen)
  printf '%s\n' "$parent/${name}-copy-${RANDOM}${ext}"
  return 0
}

# --- Two-phase upload with crash-safe recovery --------------------------------
# Usage: two_phase_upload <local_file> <final_remote> <sha256> <inode> [mode]
# mode: "conflict" or "repeat-copy" (optional, informational)
# Returns:
#   0  -> success
#   42 -> strict conflict (final already exists and we were asked to avoid overwrite)
#   1  -> other error
two_phase_upload() {
  local src="$1" dst="$2" h="$3" inode="$4" mode="${5:-}"
  local tmp mark parent

  parent="$(dirname "$dst")"
  tmp="$(_tmp_path_for "$dst" "$h")"
  mark="$INFLIGHT_DIR/${h}_${inode}.json"

  # Ensure remote parents exist (tmp + final)
  rclone mkdir "$(dirname "$tmp")" >/dev/null 2>&1 || true
  rclone mkdir "$parent" >/dev/null 2>&1 || true

  # Write/refresh local inflight marker
  mkdir -p "$INFLIGHT_DIR" || true
  {
    echo '{'
    printf '  "src": %q,\n' "$src"
    printf '  "dst": %q,\n' "$dst"
    printf '  "tmp": %q,\n' "$tmp"
    printf '  "hash": %q,\n' "$h"
    printf '  "inode": %q,\n' "$inode"
    printf '  "mode": %q,\n' "$mode"
    printf '  "started_at": %q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo '}'
  } > "$mark" || true

  log_debug "two_phase: copyto -> tmp: '$tmp'"
  if ! rclone copyto -- "$src" "$tmp" >/dev/null 2>&1; then
    log_error "copyto failed: '$src' -> '$tmp'"
    return 1
  fi

  # Strict conflict guard (only in default path; caller decides for 'conflict' mode)
  if [[ -z "$mode" ]]; then
    # If final already exists at this exact path, we do NOT overwrite here.
    local exists=1
    if rclone lsjson --files-only "$parent" 2>/dev/null \
      | jq -e --arg n "$(basename "$dst")" 'any(.[]; .Name == $n)' >/dev/null; then
      exists=0
    fi
    if [[ $exists -eq 0 ]]; then
      log_warning "two_phase: strict-conflict at final path; returning 42"
      # Cleanup tmp best-effort and keep marker removal to caller
      rclone deletefile -- "$tmp" >/dev/null 2>&1 || rclone delete -- "$tmp" >/dev/null 2>&1 || true
      rm -f "$mark" || true
      return 42
    fi
  fi

  log_debug "two_phase: promote tmp -> final: '$dst'"
  if ! rclone moveto -- "$tmp" "$dst" >/dev/null 2>&1; then
    # If moveto fails, try a copy+delete fallback
    if rclone copyto -- "$tmp" "$dst" >/dev/null 2>&1; then
      rclone deletefile -- "$tmp" >/dev/null 2>&1 || rclone delete -- "$tmp" >/dev/null 2>&1 || true
    else
      log_error "promote failed: '$tmp' -> '$dst'"
      return 1
    fi
  fi

  # Success: drop local marker
  rm -f "$mark" || true
  return 0
}

# --- Resume any interrupted uploads and tidy stale remote tmp files ------------
recover_inflight() {
  # Ensure tmp area exists before scanning
  rclone mkdir "$REMOTE_TMP_DIR" >/dev/null 2>&1 || true

  local f cnt=0
  shopt -s nullglob
  for f in "$INFLIGHT_DIR"/*.json; do
    cnt=$((cnt+1))
    local src dst tmp h inode mode
    src="$(jq -r '.src'  "$f" 2>/dev/null || echo '')"
    dst="$(jq -r '.dst'  "$f" 2>/dev/null || echo '')"
    tmp="$(jq -r '.tmp'  "$f" 2>/dev/null || echo '')"
    h="$(jq -r '.hash'   "$f" 2>/dev/null || echo '')"
    inode="$(jq -r '.inode' "$f" 2>/dev/null || echo '')"
    mode="$(jq -r '.mode'  "$f" 2>/dev/null || echo '')"

    [[ -z "$dst" || -z "$tmp" || -z "$h" ]] && { log_warning "inflight marker malformed: $f"; rm -f "$f"; continue; }

    local tmp_exists=1 dst_exists=1
    if rclone lsjson --files-only "$(dirname "$tmp")" 2>/dev/null \
      | jq -e --arg n "$(basename "$tmp")" 'any(.[]; .Name == $n)' >/dev/null; then
      tmp_exists=0
    fi
    if rclone lsjson --files-only "$(dirname "$dst")" 2>/dev/null \
      | jq -e --arg n "$(basename "$dst")" 'any(.[]; .Name == $n)' >/dev/null; then
      dst_exists=0
    fi

    if [[ $dst_exists -eq 0 ]]; then
      # Final already present: drop marker and (best-effort) delete tmp
      log_info "recovery: final already present → drop marker"
      rclone deletefile -- "$tmp" >/dev/null 2>&1 || rclone delete -- "$tmp" >/dev/null 2>&1 || true
      rm -f "$f" || true
      continue
    fi

    if [[ $tmp_exists -eq 0 ]]; then
      # Resume promote; if a name collision appears now, generate a copy path
      local parent next
      parent="$(dirname "$dst")"
      if rclone lsjson --files-only "$parent" 2>/dev/null \
        | jq -e --arg n "$(basename "$dst")" 'any(.[]; .Name == $n)' >/dev/null; then
        next="$(_next_copy_dest "$dst")"
        log_warning "recovery: final path taken, promoting to copy: $(basename "$next")"
        rclone moveto -- "$tmp" "$next" >/dev/null 2>&1 \
          || rclone copyto -- "$tmp" "$next" >/dev/null 2>&1 || true
      else
        rclone moveto -- "$tmp" "$dst" >/dev/null 2>&1 \
          || rclone copyto -- "$tmp" "$dst" >/dev/null 2>&1 || true
      fi
      # Clean tmp and marker
      rclone deletefile -- "$tmp" >/dev/null 2>&1 || rclone delete -- "$tmp" >/dev/null 2>&1 || true
      rm -f "$f" || true
      log_info "recovery: promote completed for marker $(basename "$f")"
    else
      # Nothing to recover; drop marker (source probably vanished)
      log_warning "recovery: tmp missing and final absent → drop marker"
      rm -f "$f" || true
    fi
  done
  shopt -u nullglob

  # Optional: remote tmp TTL cleanup (best-effort)
  # Remove files older than IRS_TMP_TTL_SECONDS inside REMOTE_TMP_DIR
  local ttl now cutoff
  ttl=${IRS_TMP_TTL_SECONDS:-86400}
  now=$(date -u +%s)
  cutoff=$(( now - ttl ))
  # Walk remote tmp subtree and delete files older than cutoff
  # We rely on ModTime reported by rclone (RFC3339). If parsing fails, skip.
  local json rel_name rel_path mod epoch
  json="$(rclone lsjson -R --files-only "$REMOTE_TMP_DIR" 2>/dev/null)" || json="[]"
  # Iterate via jq to extract name+modtime and delete if older
  while IFS=$'\t' read -r rel_path mod; do
    epoch=$(date -u -d "$mod" +%s 2>/dev/null || echo 0)
    if [[ "$epoch" -gt 0 && "$epoch" -lt "$cutoff" ]]; then
      rclone deletefile -- "$REMOTE_TMP_DIR/$rel_path" >/dev/null 2>&1 \
        || rclone delete -- "$REMOTE_TMP_DIR/$rel_path" >/dev/null 2>&1 || true
      log_debug "recovery: pruned stale tmp '$rel_path'"
    fi
  done < <(jq -r '.[] | ( .Path // .Name ) as $p | [$p, (.ModTime // "")] | @tsv' <<<"$json" 2>/dev/null || echo "")

  [[ $cnt -gt 0 ]] && log_info "recovery: processed $cnt inflight marker(s)"
  return 0
}
