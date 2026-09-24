# Changelog

## v3.8.0

Fixes for APs that went missing during scans and for renames failing after a factory reset.

### Fixed -- missed devices
- **Changed SSH host keys (PowerShell).** A factory reset gives the device a new SSH host key. Posh-SSH refused the new key and failed with "Key exchange negotiation failed", which the script reported as a legacy-algorithm problem. This broke re-login after a reset, so set-inform never ran and reset devices never reached the controller. It also broke every later run against those devices. The stored-key check is now skipped by default. `-StrictHostKeys` turns it back on.
- **Single-probe port scan.** Each host got one TCP/22 connect. Under a burst of connects, ARP resolution overflows and busy or mesh APs answer late, so real devices were missed. A retry pass now re-checks hosts that didn't answer, with a longer timeout and fewer parallel connects (`-ScanRetries` / `--scan-retries`, default 1). The Bash scan now runs in parallel batches too.
- **Class filter skipping unidentified APs (PowerShell).** If `info` replied too slowly, the model was empty, so the device was classed as "Other". With `-Class AP` it was then skipped, and the skip only showed with `-Verbose_`. `info` is now retried with a longer read window. The model/MAC fall back to `/etc/board.info`, then to the pre-scan result. A device with an unknown model is checked for a wifi radio. Any device that still can't be identified is shown on screen, never skipped silently.
- **Model classifier** now matches board short codes (U7PG2, UAL6, U6+, UAP6MP, ...) and more product lines (E7, UK-Ultra, UWB, UDB, UDW, EdgeSwitch). Gateways are checked before switches so USG no longer matches the US* switch prefix.
- **`-SkipAdopted` treated factory-reset devices as adopted.** Any inform URL counted as adopted, including the factory default `http://unifi:8080/inform`, so freshly reset devices were dropped. Skipped rows were also left out of the CSV. Both are fixed.
- **Post-reset wait.** One fixed 90s wait is now a poll of up to `-ResetWait` / `--reset-wait` seconds (default 240). A different device answering at the IP after the reset is flagged and left alone.
- **Bash scan output captured as hosts.** The scan's progress and status lines went to stdout inside the host-list capture, so they ended up in the list of hosts to process.

### Fixed -- rename / name restore
- **Only the `default` site was searched.** All sites are now searched. `-Site` / `--site` limits the search to one.
- **Pending devices.** After a reset and set-inform, a device is *pending adoption*, and a name only sticks once it is adopted. Pending devices are now reported as such. With `-AdoptPending` / `--adopt-pending`, or a yes at the prompt, they are adopted through the API, the script waits for adoption to finish, and then renames them.
- **CSRF token** is now sent on writes for username/password logins (UniFi OS and classic controllers).
- **TLS on Windows PowerShell 5.1:** loads System.Net.Http, enables TLS 1.2, and uses a compiled certificate callback. The old scriptblock callback could throw on the TLS worker thread.
- **Bash classic-controller fallback never fired.** `curl -s` exits 0 on a 404, so the fallback path was never tried.
- **Bash stripped spaces from names** ("Lobby AP" became "LobbyAP") and did not escape names placed in JSON.
- **Factory-default names are refused.** Renaming to a name like "U7PG2" (what a reset device reports) would overwrite the real name. Use a scan CSV from before the reset, or a CSV with a `Name` column.
- One login and one device listing per batch, instead of one listing plus up to 60s of polling per device. `-RestoreNames` now runs as a single batch at the end of the run.
- The API port is tried as 443 (UniFi OS) and then 8443 (classic) unless `-ApiPort` is given.

### Added
- The Rename CSV is read by column header: `MAC` plus `Name` / `NewName` / `DevHostname` / `Hostname`. A hand-made `mac,name` file works, and names can contain commas.
- Rename mode writes a CSV with one outcome per device (PowerShell). `-DryRun` previews what Rename would do.
- The results summary splits skips by reason (class / adopted / MAC) and counts hosts with no SSH session.

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
