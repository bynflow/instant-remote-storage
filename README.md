# instant-remote-storage

A Bash script to instantly upload files to a remote storage (e.g. Nextcloud) using `rclone`, with support for:

- safe renaming of duplicate filenames (`(copy)`, `(copy 2)`, `(parallel upload)`, etc.)
- checksum verification before and after upload (`md5sum`)
- soft remote lock to prevent simultaneous uploads from multiple devices
- log of uploaded files to skip duplicates
- automatic detection of new or modified files using `inotifywait`
- robust crash/connection failure recovery with `.uploading/` temp folder
- minimal dependencies: Bash + rclone + coreutils

> This is a personal project designed to sync files from multiple local machines to a shared remote folder, instantly and safely.

---

**Author**: Carlo Capobianchi (`bynflow`)  
**Year**: 2025  
**License**: [MIT License](LICENSE)

