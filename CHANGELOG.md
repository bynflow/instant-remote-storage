# Changelog

## [0.4.0] - 2025-07-28

### Added
- Global lock using `flock` to prevent multiple simultaneous script invocations.
- `FINAL_SEEN` associative array to ensure files are not uploaded multiple times, even if triggered again.

### Changed
- Improved deduplication logic: files with the same hash and filename are now allowed if located in different directories.
- Added a second deduplication check after potential filename normalization or renaming.
- Updated `inotifywait` event format to use a custom delimiter (`:::`) to prevent parsing issues.


