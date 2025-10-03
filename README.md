# Instant Remote Storage

Directory watcher that mirrors a local folder to a remote **rclone** backend. It normalizes filenames by **MIME type**, applies **clean names**, uses **crash-safe two-phase uploads** with automatic recovery, and enforces a **strict no-overwrite** policy (conflicts become `…(copy)…`).

Tested with **WebDAV/Nextcloud**; should work with any rclone backend.

> **Scope:** this is an *instant storing* daemon focused on pushing files-with-content as they appear. It is **not** a bidirectional sync, a full directory mirrorer, or a versioner. Empty directory trees and zero-byte placeholders are not guaranteed to be reflected remotely. Repeated saves of the same local path intentionally create a copy series: `name-(copy).ext`, `name-(copy 2).ext`, …

---

## Features

* inotify-based watcher → fast reaction, low overhead
* MIME-based extension normalization; composite extensions preserved (`tar.gz`, …)
* clean names: lowercase, kebab-case; dotfiles respected
* zero-byte safety: empty files can be deferred until they have content
* grace periods to avoid interfering with on-place renames (e.g. “Untitled…”)
* crash-safe two-phase uploads (tmp marker → promote) + automatic recovery
* strict conflict guard: **never overwrites** existing remote paths → creates `(copy)`
* optional server-side rename for pure renames (enabled by default)
* directory structure is created **on demand** when files are uploaded; empty dirs / pure placeholder trees are best-effort and may be skipped
* templated **systemd** unit and a small setup helper

---

## Status & caveats (important)

The **copy series** logic is stable in common workflows. There is, however, a known edge case:

* **On-place creations followed by rapid edits** (e.g. create a new file in place, keep the editor open, save repeatedly, and rename later) can occasionally lead to *basename artifacts* such as duplicated dashes or mixed suffixes like `--(copy 3)` or `copia-(copy)` on the remote and, more rarely, temporary local names that differ from the final remote name.

This stems from the interplay between editor temp files, event ordering, and the no-overwrite policy. It does **not** lose data, but the copy names can look odd. Treat the tool as an **instant store** rather than a versioner.

**Recommended practice**

* Prefer renaming the placeholder early (give the file its final name) before doing many saves.
* If your editor prompts to save when closing even after you saved, raise `IRS_LOCAL_RENAME_GRACE` to reduce the chance that a just-saved file is being locally normalized while the editor is still writing.

These caveats are reflected here so the README matches the current behavior.

---

## Requirements

**Runtime**

* `rclone`
* `inotify-tools` (for `inotifywait`)
* `file` and `xdg-mime` (MIME detection)
* `jq`
* coreutils: `sha256sum`, `stat`
* standard tools: `awk`, `sed`, `grep`, `find`, `logger`, `flock`

**Optional**

* `gzip`, `bzip2`, `xz`, `zstd`, `lz4` (to detect `tar.*` inside compressed streams)
* `msmtp` (only if you want email error reports)

Linux with `systemd` (for the unit).

---

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

---

## How it works (short)

* On first sight of a new path, IRS waits briefly for a final rename (avoids pushing “Untitled…” placeholders).
* Empty files can be **deferred** until they have content (policy is configurable).
* Before upload, the daemon normalizes the name by MIME and “clean name” rules. Local rename may occur so local and remote stay aligned.
* IRS primarily reacts to **files with content**. Creating nested empty directories or zero-byte files does not force a remote tree; directories are created on demand when real files are uploaded.
* Uploads are two-phase: copy to a remote tmp (`.irs-tmp/…`) and then promote to the final path. Recovery finalizes any in-flight uploads after crashes.
* If the target name exists remotely, IRS never overwrites: it uploads to `name-(copy).ext`, `name-(copy 2).ext`, …

---

## Configuration

Main env file (created by `irs-setup`):

```
/etc/instant-remote-storage/irs.env
```

### Config files & profiles

* `/etc/instant-remote-storage/irs.env` — global defaults. For single-profile setups you can put **everything** here.
* `/etc/instant-remote-storage/<profile>.env` — optional per-profile overrides loaded by `instant-remote-storage@<profile>`.
* **Precedence:** `<profile>.env` overrides variables from `irs.env`.

#### Enabling error emails with a single profile (only `irs.env`)

Add these to `/etc/instant-remote-storage/irs.env` (no per-profile file needed):

```bash
# Who receives error notifications
IRS_ERROR_MAIL_TO="you@example.com"

# Optional headers
IRS_ERROR_MAIL_FROM="irs@$(hostname -f)"
IRS_ERROR_MAIL_SUBJECT="[IRS] Error on %HOST% (%PROFILE%)"

# Mailer command reading the message on stdin
# (auto-detects mail/mailx if this is unset)
IRS_ERROR_MAILER="mail -a 'From: ${IRS_ERROR_MAIL_FROM}'"   # or: IRS_ERROR_MAILER="msmtp -t"
```

**Notes**

* Keep `%HOST%` and `%PROFILE%` as-is; the script expands them at send time.
* If `IRS_ERROR_MAILER` is **unset**, IRS tries `mail`/`mailx` automatically.
* When using `msmtp -t`, the script composes `To:`, `From:`, and `Subject:` headers.

#### Apply and test

After editing your `.env`:

**If installed via the Debian package (system service, default):**

```bash
sudo systemctl daemon-reload
sudo systemctl restart instant-remote-storage@<profile>
```

**If you run it as a user service:**

```bash
systemctl --user daemon-reload
systemctl --user restart instant-remote-storage@<profile>
```

*Tip:* `systemctl status instant-remote-storage@<profile>` → if `Loaded:` shows `/lib/systemd/system/...`, it’s the **system** unit; if it shows `~/.config/systemd/user` (or `/usr/lib/systemd/user`), it’s the **user** unit.

**Smoke test**

```bash
printf 'hello from IRS' | ${IRS_ERROR_MAILER:-mail} -s 'IRS test' "$IRS_ERROR_MAIL_TO"
```

Key variables (current defaults in parentheses):

* `LOCAL_DIR` — local watched directory (`$HOME/remote-storage`)
* `REMOTE_DIR` — rclone destination (e.g. `nextcloud:InstantRemoteStorage`)
* **State & recovery**

  * `STATE_DIR` — state root (default under `$HOME/.local/state/instant-remote-storage`)
  * `INFLIGHT_DIR` — local two-phase markers (`$STATE_DIR/inflight`)
  * `REMOTE_TMP_DIR` — remote tmp dir for two-phase (`$REMOTE_DIR/.irs-tmp`)
  * `IRS_TMP_TTL_SECONDS` — GC TTL for stale tmp/markers (`86400`)
* **Watcher timing**

  * `IRS_LOCAL_RENAME_GRACE` — seconds to avoid renaming while you’re still editing (`5`)
  * `IRS_FILE_CREATE_GRACE` — hold after a new file `CREATE` to await rename/content (`10`)
  * `IRS_DIR_CREATE_GRACE` — hold after a new dir `CREATE` before mirroring (`10`)
* **Zero-byte policy**

  * `IRS_UPLOAD_ZERO_ON_CREATE` — `0` defer empty files; `1` allow eager upload (`1`)
* **Renames & directories**

  * `IRS_ALLOW_REMOTE_RENAME` — enable server-side rename for pure renames (`1`)
  * `IRS_MIRROR_EMPTY_DIRS` — mirror empty dirs (`1`)
  * `IRS_MIRROR_DIRS_ON_CREATE` — mirror also on `CREATE` (`1`)
* **Diagnostics**

  * `DEBUG` — `1` enables debug logs (`1`)
  * `LOG_TAG` — syslog tag (`instant-remote-storage`)

Recovery helper (`lib/irs_recovery.sh`):

* No special tuning required; recovery finalizes two-phase uploads and prunes stale tmp files based on `IRS_TMP_TTL_SECONDS`.

---

## Error email notifications (optional)

Enable Instant Remote Storage (IRS) to send a short report by **email** whenever a fatal/irrecoverable error is detected (e.g., upload failure after retries, corrupted temp, recovery failed).

### Requirements

* A working local mailer in `$PATH` (`mail`, `mailx`, `s-nail`, `msmtp`, or a `sendmail`-compatible MTA`).
* If you prefer direct SMTP, configure **msmtp** (example below).

### Quick setup (in `.env`)

Add these variables to your profile’s `.env`:

```bash
# Who receives error notifications
IRS_ERROR_MAIL_TO="you@example.com"

# Optional overrides
IRS_ERROR_MAIL_FROM="irs@$(hostname -f)"          # envelope/from header
IRS_ERROR_MAIL_SUBJECT="[IRS] Error on %HOST% (%PROFILE%)"  # placeholders expanded by the script

# Mailer command that reads the message on stdin; default auto-detects mail/mailx
IRS_ERROR_MAILER="mail -a 'From: ${IRS_ERROR_MAIL_FROM}'"
```

**Notes**

* Keep `%HOST%` and `%PROFILE%` as-is; the script expands them at send time.
* If `IRS_ERROR_MAILER` is **unset**, the script tries to use `mail`/`mailx` automatically.
* The mailer must accept a subject flag (e.g. `-s` for `mail|mailx`) **or** a precomposed header mode like `msmtp -t`.

### Apply and test

After editing the `.env` for your profile (typically `/etc/instant-remote-storage/irs.env`):

**If you installed via the Debian package (default):**

```bash
sudo systemctl daemon-reload
sudo systemctl restart instant-remote-storage@<profile>
```

**If you run it as a user service:**

```bash
systemctl --user daemon-reload
systemctl --user restart instant-remote-storage@<profile>
```

*Tip:* `systemctl status instant-remote-storage@<profile>` → if `Loaded:` shows `/lib/systemd/system/...`, it’s the **system** service; if it shows `~/.config/systemd/user` or `/usr/lib/systemd/user`, it’s the **user** service.

### What the email contains

* Exit reason and failing step
* Local path, inode, size; content hash if known
* Recent log tail and short recovery hints

### Disable emails

Leave `IRS_ERROR_MAIL_TO` **empty** or **unset**.

### Example: msmtp (SMTP relay)

Configure **msmtp**:

```ini
# ~/.config/msmtp/config
account default
host smtp.example.com
port 587
auth on
user youruser
passwordeval "secret-tool lookup service irs smtp youruser"
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
from you@example.com
logfile ~/.local/state/msmtp/msmtp.log
```

Then in your `.env`:

```bash
IRS_ERROR_MAILER="msmtp -t"
IRS_ERROR_MAIL_FROM="you@example.com"  # used for From: header when composing
```

When `msmtp -t` is detected, the script composes proper `To:`, `From:`, and `Subject:` headers.

### Troubleshooting

* Check the service logs (system unit):
  `journalctl -u instant-remote-storage@<profile> -b`
* If running as a user unit:
  `journalctl --user -u instant-remote-storage@<profile> -b`
* For msmtp, inspect:
  `~/.local/state/msmtp/msmtp.log`
* Ensure the `.env` (if it holds credentials) is protected:
  `chmod 600 .env`

## Behavior details

* **No overwrite:** if a remote path already exists, uploads go to a `(copy)` name.
* **Not a versioning system:** repeated saves intentionally create a `(copy)` series.
* **Local rename:** extension fixes and clean-name normalization may rename files locally so local and remote match. Dotfiles are respected; composite extensions are preserved.
* **Idempotence safeguards:** on cold start or repeated events, IRS indexes existing remote files of the same size/hash to avoid duplicate uploads when safe.

---

## Known issues

* **Nested empty directories (and trees with only zero-byte files) may not be mirrored.**
  *Cause:* the daemon is content-driven and only materializes directories when promoting file uploads.
  *Workarounds:* drop at least one non-empty file in each directory you want created; or pre-create the structure remotely if your workflow requires empty trees.

* **On-place create + repeated saves can produce odd basenames** (e.g., `name--(copy 3).ext`, `...copia-(copy)...`).

  * **Cause:** race between local normalization (extension/clean-name) and the strict conflict policy while editors write multiple times in quick succession; legacy files created with older suffix styles.
  * **Workarounds:**

    * Rename the file once to its final name before editing (avoid working on “Untitled…” placeholders).
    * Increase grace windows: `IRS_FILE_CREATE_GRACE=10–15`, `IRS_LOCAL_RENAME_GRACE=10–30`.
    * Consider `IRS_UPLOAD_ZERO_ON_CREATE=0` to avoid early handling of 0-byte placeholders.
    * If you already have a mix of `(copia)`/`(copy)` from older versions, normalize names on the remote once.
  * **Status:** known limitation; a full fix would require a transactional per-path rename queue.

* **“Save on close” prompts even after saving.**

  * **Cause:** a local rename may happen shortly after saving (to align extension/clean-name), while the editor still holds the old path.
  * **Workarounds:** set `IRS_LOCAL_RENAME_GRACE` higher (e.g., 30–60) or extremely high to effectively avoid post-save renames; rename the file before editing; prefer editors with atomic-save (temp-write + rename) over true in-place writes.
  * **Status:** by-design trade-off; tunable with the grace period.

* **Copy-number gaps or duplicate `(copy N)` entries under heavy churn.**

  * **Cause:** concurrent events/latency—IRS never overwrites and may generate a new `(copy N)` while another promote/rename is still propagating.
  * **Workarounds:** avoid bursty auto-saves; raise auto-save interval; keep `DEBUG=1` and check logs—idempotent cases are indexed and skipped; recovery consolidates in-flight operations after restarts.
  * **Status:** acceptable under heavy churn; deeper fixes need backend-shared transactional locks.

* **Dotfiles and extensions behave conservatively.**

  * **Cause:** hidden files may skip MIME-based extension changes to avoid breaking configuration files.
  * **Workaround:** none required; intentional behavior.
  * **Status:** working as intended.

## Logs

Follow logs via systemd journal:

```bash
# System unit (default with this package)
journalctl -u instant-remote-storage@<profile> -f
# If running as a user unit:
# journalctl --user -u instant-remote-storage@<profile> -f
```

---

## Recovery

If the machine reboots mid-upload, the recovery helper finalizes the two-phase uploads on the next start. You can also run it manually:

```bash
/usr/lib/instant-remote-storage/lib/irs_recovery.sh
```

---

## Limitations

* One-way *instant storing* — not a bidirectional sync.
* No historical versions beyond the `(copy)` series.
* MIME mapping depends on your system’s `file/xdg-mime`; uncommon types may keep the original suffix.
* With certain editors/backends, **on-place create + rapid edits** may yield odd copy suffixes; data is preserved, but names can be non-uniform (see *Status & caveats*).
* Not a full directory mirroring tool: empty dirs and zero-byte placeholders may be ignored; directory creation is **on demand**.

---

## Contributing

Issues and PRs are welcome. Please describe your backend, editor, and a minimal sequence to reproduce naming anomalies.

---

## Author & License

* **Carlo Capobianchi** ([@bynflow](https://github.com/bynflow)) — original author and maintainer.

Licensed under the **Expat (MIT)** license. See `LICENSE`.
