# UniFi Sovereign — Platform Setup

## macOS / Linux (Bash/Zsh) — `unifi-sovereign.sh`

**Recommended version** for macOS and Linux environments.

### Requirements

- Bash 3.2+ (macOS default) or Bash 4.0+ / Zsh
- Network access to target devices (TCP/22)
- `python3` (for CIDR expansion)

### Automatic Dependency Management

The script detects your platform and offers to install missing tools:

**macOS:**
- Checks for Homebrew; offers to install if missing
- Installs via `brew install`

**Linux:**
- Detects package manager (apt, dnf, pacman, apk)
- Installs via appropriate package manager with `sudo`

### Dependencies

| Tool | Required | Purpose | macOS | Debian/Ubuntu |
|------|----------|---------|-------|---------------|
| ssh | Yes | Device communication | Pre-installed | `openssh-client` |
| sshpass | Yes | Password-based SSH | `brew install sshpass` | `apt install sshpass` |
| python3 | Yes | CIDR expansion | Pre-installed | `apt install python3` |
| grep/awk/sed | Yes | Output parsing | Pre-installed | Pre-installed |
| fzf | No | Interactive menus | `brew install fzf` | `apt install fzf` |
| expect | No | Shell stream execution | `brew install expect` | `apt install expect` |

### Run

```bash
chmod +x unifi-sovereign.sh
./unifi-sovereign.sh
```

---

## Windows (PowerShell) — `unifi-sovereign.ps1`

### Requirements

- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
- Posh-SSH module (auto-installed on first run)

### Run

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\unifi-sovereign.ps1
```

---

## Feature Comparison

| Feature | Bash v3.0.0 | PowerShell v2.1.0 |
|---------|-------------|-------------------|
| Auto-install dependencies | Yes | Posh-SSH only |
| Homebrew detection (macOS) | Yes | N/A |
| Interactive menus | CLI / fzf | Built-in |
| Progress indicators | Progress bar | Percentage |
| Parallel scanning | Sequential | Runspaces |
| Shell streams | expect / pipe | Posh-SSH |
| Color output | ANSI (auto-detect) | Limited |
| CSV output | Full | Full |
| Dry-run mode | Yes | No |
| Verbose/quiet modes | Yes | No |
| Color toggle | `--no-color` | N/A |

---

## Recommended Setup

**macOS/Linux development or homelab:** Bash version. Run from a machine with SSH access to all UniFi devices.

**Windows administration:** PowerShell version. Run from admin workstation or bastion host.

**CI/automation:** Bash version with `--mode`, `--cidr`, `--controller` flags. Combine with `--no-color` and `--quiet` for clean log output.
