# Instant Remote Storage

Directory watcher that mirrors a local folder to a remote **rclone** backend.
It normalizes filenames by **MIME type**, detects **renames** (remote moves) and
uses **crash-safe two-phase uploads** with automatic recovery. Ships with a
templated **systemd** unit and a small setup helper.

Tested with **WebDAV/Nextcloud**; works with any rclone backend.

## Features

* inotify-based watcher → fast reaction, low overhead
* MIME-based extension normalization
* rename detection → remote server receives `move` instead of re-upload
* crash-safe two-phase uploads with recovery script
* templated systemd service (`instant-remote-storage@.service`)
* small `irs-setup` helper to create `/etc/instant-remote-storage/irs.env`

## Requirements

* `rclone` (configured remote, e.g. `myremote:bucket/path` or `nextcloud:Folder`)
* `inotify-tools`
* `file` (for MIME detection)
* Linux with `systemd` (for the unit)

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

## Configuration

Main env file (created by `irs-setup`):

```
/etc/instant-remote-storage/irs.env
```

Key variables:

* `LOCAL_DIR` – local watched directory
* `REMOTE_DIR` – rclone destination (e.g. `nextcloud:InstantRemoteStorage`)
* optional `STATE_DIR` – where to store runtime state (by default under \$HOME)

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

## Packaging

* Debian source package available on mentors.
* ITP: **#1114689**
* Runtime Depends: `rclone`, `inotify-tools`, `file`; Recommends: `xdg-utils`.

## Limitations

* MIME-based normalization relies on `file(1)`; unusual types may keep the
  original suffix.
* Works best with stable rclone backends (WebDAV/Nextcloud well tested).

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the **Expat (MIT)** license.
See [LICENSE](LICENSE).

