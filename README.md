# instant-remote-storage

A Bash script for instantly syncing files to a remote storage (e.g. Nextcloud) using `rclone`, designed for robustness, deduplication, and real-time responsiveness.

---

## Features

* **Instant upload** of new or modified files using `inotifywait`
* **Safe deduplication** with filename normalization and `(copy)`-style renaming
* **Checksum verification** using `sha256sum` to prevent duplicate uploads
* **Two-stage deduplication**:

  * Before filename normalization
  * After final filename assignment
* **Robust lock system**:

  * Global lock via `flock` to prevent concurrent invocations
  * Per-file soft locks to prevent race conditions during parallel syncs
* **Persistent deduplication tracking**:

  * Global associative arrays for tracking handled files (`PATH_HASH_SEEN`, `FINAL_SEEN`)
* **Crash-safe upload mechanism**:

  * Temporary `.uploading/` directory for files in transit
  * Clean-up mechanisms for incomplete transfers
* **Remote directory reconstruction**:

  * Automatic mirroring of nested directory structure
  * Creation of remote folders via `rclone mkdir`
* **Clean, normalized filenames**:

  * Whitespace and special character cleanup
  * Extension correction based on MIME type
* **Extensive logging**:

  * Debug and info logs via `logger`
  * Event traces for uploads, renames, skips, and errors

---

## Dependencies

* `bash`
* `rclone`
* `coreutils` (e.g. `sha256sum`, `find`, `awk`)
* `inotify-tools` (`inotifywait`)

---

## Use Case

This script is tailored for syncing files from multiple local machines to a shared remote location (e.g. Nextcloud/WebDAV). It avoids conflicts, silently deduplicates, and ensures data safety even across unstable network connections or repeated triggers.

---

## Author

Carlo Capobianchi (bynflow)
2025
License: MIT License

