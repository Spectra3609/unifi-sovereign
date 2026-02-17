# Changelog

## v3.0.0

Major rewrite of the Bash/Zsh version.

### Added
- Prerequisite auto-install engine with platform detection (macOS Homebrew, apt, dnf, pacman, apk)
- `--dry-run` flag for plan-only execution
- `--verbose` / `-v` flag for debug output
- `--quiet` / `-q` flag for minimal output
- `--no-color` flag for ANSI-free output
- `--version` flag
- Automatic TTY detection (disables color when piped)
- SSH connection retry with backoff (one retry per credential)
- Progress bar for port scanning
- Run metadata comment in CSV header
- Timestamped default CSV filenames

### Changed
- Redesigned TUI: restrained, clinical layout with consistent typography
- Replaced ASCII art banner with minimal box drawing
- CIDR expansion now uses Python exclusively (more reliable than ipcalc parsing)
- Device info collection uses temp files instead of eval (safer, more portable)
- Credential tracking passes correct user+password pair through entire device flow
- Help output reformatted for clarity
- README and PLATFORMS.md rewritten

### Fixed
- printf format string typo in progress display (`%d/%total` → `%d/%d`)
- CIDR expansion via ipcalc only returned network address, not host list
- Credential password mismatch (always used first password regardless of which user matched)
- Variable scoping in processing loop (declare -A reuse without unset)
- IP regex in argument parsing (`\d` → `[0-9]`)

### Removed
- ASCII art pyramid banner
- ipcalc dependency for CIDR parsing
- Magenta debug color

## v2.1.0

### Fixed
- SSH Shell Streams for UniFi builtins (info, set-inform, mca-cli-op)
- Added mca-cli-op fallback for already-adopted devices
- Added DebugInfo and InformMethod CSV columns

## v2.0.0

### Added
- Initial release
- Multi-credential rotation with factory defaults
- Factory reset cascade (3 methods)
- Parallel TCP/22 scanning (PowerShell)
- CSV logging
