# Changelog

All notable changes to this project are documented here. Dates use `YYYY-MM-DD`.

## [4.2.0] - 2025-10-01

### Docs

* README overhauled: clarified scope (instant storing, not a versioning system) and added a **Known issues** section with current limitations and workarounds.
* Introduced this `CHANGELOG.md` and aligned examples/config variables with the current stable baseline.
* **No functional changes from 3.7.0**; this is a documentation-only release.

## [3.7.0] - 2025-09-16

### Changed

* Consolidated the feature set used as the stable baseline (see README): MIME-based extension normalization, clean-name rules, two‑phase upload with crash‑safe recovery, strict no‑overwrite conflict policy with `(copy)` series, optional server‑side rename for pure renames, empty‑directory mirroring toggles, cold‑start rescan, and idempotency checks.

## [2.2.0] – 2025-08-29

### Added

* Two-phase upload (`copyto` → tmp, then server-side `moveto` → final).
* Local **in‑flight markers** (`~/.local/state/.../inflight/*.state`) to guarantee recovery.
* **Recovery** on startup: promote existing tmp → final; retry copy if needed.
* **Cold-start rescan** for user-writable files not covered by markers.
* **Conflict handling** with `(copia)`, `(copia 2)`, … suffixes.
* **Read‑only** (`chmod 444`) for local files after successful upload (configurable).
* **MIME‑based extension assignment** and safe filename cleaning.
* **systemd user unit** (`instant-remote-storage@.service`) with automatic restart.
* Interactive **setup wizard** (`irs-setup`) to configure per-user `.env` and enable the service.
* Makefile targets: `install`, `uninstall`, `configure`, `dist`, `clean`.

### Changed

* Logging improved: progress lines from rclone forwarded to the journal.
* Startup sequence: ensure state dirs, recover in-flight, then cold-start rescan.

### Fixed

* Various race conditions around inotify events and file stability checks.
* Safer lock handling and consistent cleanup on exit.

## [0.5.0] - 2025-07-31

### Added

* Global variable `path_hash_key` to share deduplication key state between `main_loop` and `handle_file`.
* Global associative array `PATH_HASH_SEEN` is now reliably updated with all processed keys.
* Early skip mechanism in `main_loop` using `PATH_HASH_SEEN` to prevent duplicate processing of files already handled in `handle_file`.

### Changed

* The key used in `PATH_HASH_SEEN` now uses the full normalized relative path (with no leading `./`) to ensure consistent matching between `main_loop` and `handle_file`.
* Improved debug logging to trace the deduplication mechanism and identify key state changes.
* Ensured keys are *accumulated*, not overwritten or skipped, when added to `PATH_HASH_SEEN`.

## [0.4.0] - 2025-07-28

### Added

* Global lock using `flock` to prevent multiple simultaneous script invocations.
* `FINAL_SEEN` associative array to ensure files are not uploaded multiple times, even if triggered again.

### Changed

* Improved deduplication logic: files with the same hash and filename are now allowed if located in different directories.
* Added a second deduplication check after potential filename normalization or renaming.
* Updated `inotifywait` event format to use a custom delimiter (`:::`) to prevent parsing issues.
