# Contributing

Thanks for wanting to help!

## How to propose changes

1. Open an issue explaining the problem/feature.
2. Fork the repo and create a feature branch.
3. Follow the code style (POSIX shell) and keep changes focused.
4. Add/update docs when relevant.
5. Open a Pull Request linked to the issue.

## Testing locally

- Configure an rclone remote.
- Use a throw-away local folder and remote path.
- Watch service logs with `journalctl -u instant-remote-storage@<user> -f`.

## Reporting bugs

Please include:
- OS/distro and versions of `rclone`, `inotify-tools`, `file`
- your `rclone config` backend type (redact secrets)
- steps to reproduce and relevant logs
