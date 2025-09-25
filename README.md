# Instant Remote Storage

Directory watcher that mirrors a local folder to a remote **rclone** backend.
It normalizes filenames by **MIME type**, applies **clean names** locally,
uses **crash-safe two-phase uploads** with automatic recovery, and enforces a
**strict no-overwrite** policy (conflicts become `(...copy...)`).

Tested with **WebDAV/Nextcloud**; should work with any rclone backend.

> **Not a versioning system:** repeated saves of the same local path intentionally
> produce `name-(copy).ext`, `name-(copy 2).ext`, … (no `(ver N)` suffixes).

## Features

* inotify-based watcher → fast reaction, low overhead
* MIME-based extension normalization with local rename to match the remote
* clean names: lowercase, kebab-case, preserve composite extensions (`tar.gz`, …)
* zero-byte safety: empty files are deferred until they get content
* grace period on first sight (CREATE/CLOSE\_WRITE) to let you rename “Untitled…”
* crash-safe two-phase uploads (tmp marker → promote) + automatic recovery
* strict conflict guard: never overwrite existing remote paths (creates `(copy)`)
* optional server-side rename for pure renames (off by default)
* optional mirroring of empty directories
* templated **systemd** unit and a small setup helper

## Requirements

Runtime:

* `rclone`
* `inotify-tools` (for `inotifywait`)
* `file` and `xdg-mime` (MIME detection)
* `jq`
* coreutils: `sha256sum`, `stat`
* standard tools: `awk`, `sed`, `grep`, `find`, `logger`, `flock`

Optional:

* `gzip`, `bzip2`, `xz`, `zstd`, `lz4` (to detect `tar.*` inside compressed streams)
* `msmtp` (only if you want email error reports)

Linux with `systemd` (for the unit).

## Quick start

1. Configure `rclone` (example for WebDAV/Nextcloud):

   ```bash
   rclone config
   # create a remote, e.g. "nextcloud" (vendor=Nextcloud, url=https://example.tld)
   ```

2. Create the local/remote pair and enable the service:

   ```bash
   sudo irs-setup -u "$USER" \
     -l "$HOME/remote-storage" \
     -r "nextcloud:InstantRemoteStorage" \
     --enable --start
   ```

3. Drop files into the local folder and watch them being mirrored.

## How it works (short)

* On first sight of a new path, IRS waits up to `IRS_HOLD_CREATE_SECONDS`
  for a final rename (avoids pushing “Untitled…” placeholders).
* Empty files are **deferred** until they have content (even after `MOVED_TO`),
  unless you opt in to eager zero-byte uploads.
* Before upload, the daemon normalizes the name by MIME and “clean name”
  rules, **renaming the local file** so local and remote stay aligned.
* Uploads are two-phase: copy to a remote tmp (`.irs-tmp/…`) and then
  promote to the final path. Recovery finalizes any in-flight uploads.
* If the target name exists remotely, IRS never overwrites: it uploads to
  `name-(copy).ext`, `name-(copy 2).ext`, …

## Configuration

Main env file (created by `irs-setup`):

```
/etc/instant-remote-storage/irs.env
```

Key variables:

* `LOCAL_DIR` – local watched directory
* `REMOTE_DIR` – rclone destination (e.g. `nextcloud:InstantRemoteStorage`)
* `STATE_DIR` – state root (defaults under `$HOME/.local/state/instant-remote-storage`)
* `INFLIGHT_DIR` – local 2-phase markers (defaults under `$STATE_DIR/inflight`)
* `REMOTE_TMP_DIR` – remote tmp dir for 2-phase (default: `$REMOTE_DIR/.irs-tmp`)
* `IRS_TMP_TTL_SECONDS` – GC TTL for stale tmp/markers (default: `86400`)
* `IRS_HOLD_CREATE_SECONDS` – grace to wait for rename (default: `15`)
* `IRS_UPLOAD_ZERO_ON_CREATE` – `0` defer empty files (default), `1` upload them
* `IRS_ALLOW_REMOTE_RENAME` – `1` enable server-side rename for pure renames;
  `0` treat as new uploads (default)
* `IRS_MIRROR_EMPTY_DIRS` – `1` mirror empty dirs (default), `0` disable
* `IRS_MIRROR_DIRS_ON_CREATE` – mirror on `CREATE` too (default: `0`, use `MOVED_TO`)
* `IRS_REMOTE_WAIT_SECS` – seconds to best-effort wait at bootstrap if remote isn’t ready (default: `0`)
* `DEBUG` – `1` enables debug logs (default: `1`)
* `LOG_TAG` – syslog tag (default: `instant-remote-storage`)

Recovery helper (`lib/irs_recovery.sh`):

* `IRS_STRICT_CONFLICT` – `1` enforce last-chance `(copy)` before promote (default), `0` disable

## Behavior details

* **No overwrite policy:** if a remote path already exists, uploads go to a `(copy)` name.
* **Not a versioning system:** saving the same local file repeatedly will produce a `(copy)` series.
* **Local rename by design:** the daemon may rename files locally (extension fix + clean name)
  so that local and remote match exactly.
* **Composite extensions preserved:** `archive.tar.gz` stays `archive.tar.gz` (no double suffixes).

## Logs

```bash
journalctl -u instant-remote-storage@<user> -f
```

## Recovery

If the machine reboots mid-upload, the recovery helper finalizes the two-phase
uploads on the next start. You can also run it manually:

```bash
/usr/lib/instant-remote-storage/lib/irs_recovery.sh
```

## Limitations

* This is **not** a bidirectional sync tool.
* No historical versions: repeated saves intentionally create a `(copy)` series.
* MIME mapping depends on your system’s `file/xdg-mime`; uncommon types may keep the original suffix.
* Works best with stable rclone backends (WebDAV/Nextcloud well tested).

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Author

* **Carlo Capobianchi** ([@bynflow](https://github.com/bynflow)) — original author and maintainer.

## License

Licensed under the **Expat (MIT)** license. See [LICENSE](LICENSE).

