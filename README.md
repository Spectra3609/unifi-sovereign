# UniFi Sovereign

SSH-based device migration and adoption toolkit for UniFi infrastructure.

---

## Overview

UniFi Sovereign provides three operational modes for managing UniFi devices via SSH:

- **SANITY** — Read-only credential verification and device inventory
- **MIGRATE** — Redirect devices to a new controller without reset
- **ADOPT** — Full adoption workflow with optional factory reset

## Platform Support

| Version | Platforms | File |
|---------|-----------|------|
| Bash/Zsh | macOS, Linux | `unifi-sovereign.sh` |
| PowerShell | Windows, macOS, Linux (PS7+) | `unifi-sovereign.ps1` |

See [PLATFORMS.md](PLATFORMS.md) for setup details per platform.

---

## Installation

### macOS / Linux (Bash)

**Download and run:**

```bash
curl -fsSL https://raw.githubusercontent.com/Spectra3609/unifi-sovereign/main/unifi-sovereign.sh -o unifi-sovereign.sh && chmod +x unifi-sovereign.sh
```

**One-off (no file saved):**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spectra3609/unifi-sovereign/main/unifi-sovereign.sh)
```

### Windows (PowerShell)

**Download and run:**

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Spectra3609/unifi-sovereign/main/unifi-sovereign.ps1" -OutFile "unifi-sovereign.ps1"; .\unifi-sovereign.ps1
```

**One-off (no file saved):**

```powershell
Set-ExecutionPolicy -Scope Process Bypass; iex (irm "https://raw.githubusercontent.com/Spectra3609/unifi-sovereign/main/unifi-sovereign.ps1")
```

### Clone the Repository

```bash
git clone https://github.com/Spectra3609/unifi-sovereign.git
cd unifi-sovereign
```

---

## Quick Start

### Interactive (recommended)

**macOS / Linux:**
```bash
./unifi-sovereign.sh
```

**Windows:**
```powershell
.\unifi-sovereign.ps1
```

Both versions detect missing dependencies and offer to install them automatically.

### Command-Line

**macOS / Linux:**
```bash
./unifi-sovereign.sh --mode MIGRATE --cidr 192.168.1.0/24 --controller 10.0.0.5
./unifi-sovereign.sh --mode SANITY --ips 192.168.1.100,192.168.1.101
./unifi-sovereign.sh --mode ADOPT --cidr 10.0.1.0/24 --controller 10.0.0.5 --reset
```

**Windows:**
```powershell
.\unifi-sovereign.ps1 -Mode Migrate -Cidr 192.168.1.0/24 -Controller 10.0.0.5
.\unifi-sovereign.ps1 -Mode Sanity -IPs "192.168.1.100,192.168.1.101"
.\unifi-sovereign.ps1 -Mode Adopt -Cidr 10.0.1.0/24 -Controller 10.0.0.5 -ResetFirst
```

### Dry Run

```bash
./unifi-sovereign.sh --mode MIGRATE --cidr 192.168.1.0/24 --controller 10.0.0.5 --dry-run
```

```powershell
.\unifi-sovereign.ps1 -Mode Migrate -Cidr 192.168.1.0/24 -Controller 10.0.0.5 -DryRun
```

Shows the full execution plan without making any changes.

---

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--mode` | `SANITY`, `MIGRATE`, or `ADOPT` | Interactive prompt |
| `--cidr` | Target subnet (e.g. `192.168.1.0/24`) | — |
| `--ips` | Comma-separated IP list | — |
| `--controller` | Target controller IP/hostname | — |
| `--username` | SSH username | `ubnt` |
| `--password` | SSH password | — |
| `--reset` | Factory reset before adopt (ADOPT only) | Off |
| `--ssh-timeout` | SSH timeout (seconds) | 7 |
| `--scan-timeout` | Port scan timeout per host (seconds) | 3 |
| `--output` | CSV output path | Auto-generated |
| `--dry-run` | Plan without executing | Off |
| `--verbose` / `-v` | Debug output | Off |
| `--quiet` / `-q` | Minimal output | Off |
| `--no-color` | Disable ANSI colors | Off |

---

## Dependency Management

### Automatic Installation (v3.0.0+)

On first run, the script checks for all required and optional dependencies:

**Required:** `ssh`, `sshpass`, `grep`, `awk`, `sed`, `python3`
**Optional:** `fzf` (interactive menus), `expect` (shell command execution)

If anything is missing, the script offers to install it using the appropriate package manager:

| Platform | Package Manager |
|----------|----------------|
| macOS | Homebrew (installs Homebrew if needed) |
| Debian/Ubuntu | apt |
| Fedora/RHEL | dnf |
| Arch | pacman |
| Alpine | apk |

---

## Modes

### SANITY

Read-only scan. Verifies SSH credentials, collects MAC, model, firmware, hostname, adoption status, and current inform URL.

Use for: credential testing, device inventory, pre-migration audit.

### MIGRATE

Sends `set-inform` commands to redirect devices to a new controller. Does not reset or wipe devices. Existing configuration is preserved.

Use for: controller migration, re-homing devices between environments.

### ADOPT

Full adoption workflow. Optionally performs factory reset before sending `set-inform` commands. Three reset methods are attempted in cascade.

Use for: reclaiming stuck devices, clean-slate adoption, recovery from dead controllers.

---

## How It Works

1. **Prerequisite check** — Detects platform, verifies dependencies, offers auto-install
2. **TCP/22 scan** — Sweeps target range for SSH-accessible hosts
3. **SSH authentication** — Tries provided credentials, then factory defaults (`ubnt/ubnt`, `root/ubnt`, `admin/ubnt`)
4. **Device info** — Collects inventory via `info` shell builtin (SSH shell stream)
5. **Action** — Per mode: log only (SANITY), set-inform (MIGRATE), reset + set-inform (ADOPT)
6. **CSV export** — Timestamped results with full device details

### SSH Shell Streams

UniFi devices use shell builtins (`info`, `set-inform`, `mca-cli-op`) that are not available via the standard SSH exec channel. The script uses interactive shell sessions (via `expect` when available) to execute these commands reliably.

If `expect` is not installed, the script falls back to piping commands via interactive SSH. This works in most cases but may be less reliable on some firmware versions.

---

## Output

CSV with the following columns:

| Column | Description |
|--------|-------------|
| Timestamp | UTC timestamp |
| IP | Device IP |
| MAC | Device MAC address |
| Connected | SSH success (true/false) |
| Username | Credential that worked |
| Model | Device model |
| DevHostname | Device hostname |
| Firmware | Firmware version |
| AdoptStatus | Adoption status |
| CurrentInform | Inform URL before changes |
| Reset | Reset status (N/A, OK, Failed) |
| Inform1 | First set-inform response |
| Inform2 | Second set-inform response |
| InformMethod | Method used (set-inform, mca-cli-op) |
| Status | Result (OK, CHECK, FAIL) |
| Note | Warnings or errors |
| DebugInfo | Raw command output |

---

## Troubleshooting

**No hosts found with SSH open**
- Verify network connectivity and firewall rules (TCP/22)
- Check target subnet is correct
- Confirm devices are powered on

**SSH auth failed**
- Verify credentials (custom or factory defaults)
- Ensure SSH is enabled on devices
- Check if device has been hardened with non-default credentials

**Controller inform endpoint unreachable**
- Verify controller IP and port 8080 access
- Ensure controller service is running
- Check firewall rules between devices and controller

**Device not back after reset**
- Factory reset takes 60-90 seconds; the script waits 90s
- Device may need additional time on some firmware versions
- Network changes during reset may affect connectivity

---

## Security

- Credentials are passed as plaintext parameters
- Factory defaults are always attempted as fallback
- No data leaves the local machine
- CSV logs contain device details — protect accordingly

---

## Version History

### v3.0.0 (Current)

Major rewrite of the Bash/Zsh version.

- **Prerequisite auto-install engine** — Detects platform and package manager, offers to install missing dependencies including Homebrew on macOS
- **TUI overhaul** — Restrained, clinical interface design. Clean typography, progress bars, aligned status indicators
- **Bug fixes** — Fixed credential tracking (correct password now passed to all operations per device), fixed CIDR expansion, fixed printf formatting, fixed variable scoping in processing loop
- **New flags** — `--dry-run`, `--verbose`, `--quiet`, `--no-color`, `--version`
- **Color detection** — Automatically disables ANSI when output is not a TTY
- **SSH retry** — One retry with backoff before marking a device as failed
- **Bash 3.2 compatible** — Removed associative arrays from hot path; works on macOS default shell

### v2.1.0

- SSH Shell Streams for UniFi builtins (info/set-inform/mca-cli-op)
- `mca-cli-op` fallback for already-adopted devices
- DebugInfo column in CSV output
- Better response validation

### v2.0.0

- Initial release with multi-credential support, factory reset cascade, parallel scanning (PowerShell)

---

## License

MIT License. Not affiliated with Ubiquiti Inc.

---

Built by [Spectra](https://github.com/Spectra3609).
