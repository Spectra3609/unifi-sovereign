# UniFi Sovereign

**Hunt. Claim. Adopt.**

A cross-platform PowerShell toolkit for UniFi device migration and adoption via SSH.

---

## Features

- **SANITY mode** - Read-only credential verification and device info collection
- **MIGRATE mode** - Redirect devices to a new controller without reset or factory wipe
- **ADOPT mode** - Full adoption workflow with optional factory reset

**Key capabilities:**
- Auto-installs dependencies (Posh-SSH)
- Native TCP/22 parallel scan (no Nmap required)
- CIDR or explicit IP list targeting
- Multi-credential rotation with factory defaults fallback
- Controller preflight check (8080 inform endpoint)
- CSV logging with full device details
- Factory reset cascade (3 methods for stubborn devices)

**Cross-platform:** Works on Windows PowerShell 5.1+, PowerShell 7+ (macOS/Linux)

---

## Quick Start

### Choose Your Version

**Windows?** → Use PowerShell version  
**macOS/Linux?** → Use Bash/Zsh version

See [PLATFORMS.md](PLATFORMS.md) for detailed comparison and setup.

### Interactive Mode (recommended for first run)

**Windows (PowerShell):**
```powershell
.\unifi-sovereign.ps1
```

**macOS/Linux (Bash):**
```bash
./unifi-sovereign.sh
```

Follow the prompts to select mode, targets, credentials, and options.

### One-Liner (remote execution)

**PowerShell (Windows):**
```powershell
irm https://raw.githubusercontent.com/Spectra3609/unifi-sovereign/main/unifi-sovereign.ps1 | iex
```

**Bash (macOS/Linux):**
```bash
curl -sSL https://raw.githubusercontent.com/Spectra3609/unifi-sovereign/main/unifi-sovereign.sh | bash
```

### Command-Line Examples

**PowerShell:**
```powershell
# Migrate a /24 subnet to new controller
.\unifi-sovereign.ps1 -Mode Migrate -Cidr 192.168.1.0/24 -Controller 10.0.0.5 -Username admin -Password ubnt

# Adopt specific devices with factory reset
.\unifi-sovereign.ps1 -Mode Adopt -IPs "192.168.1.10,192.168.1.11,192.168.1.12" -Controller 10.0.0.5 -ResetFirst

# Sanity check (read-only scan)
.\unifi-sovereign.ps1 -Mode Sanity -Cidr 172.16.5.0/24
```

**Bash:**
```bash
# Migrate a /24 subnet to new controller
./unifi-sovereign.sh --mode MIGRATE --cidr 192.168.1.0/24 --controller 10.0.0.5

# Adopt specific devices with factory reset
./unifi-sovereign.sh --mode ADOPT --ips 192.168.1.10,192.168.1.11,192.168.1.12 --controller 10.0.0.5 --reset

# Sanity check (read-only scan)
./unifi-sovereign.sh --mode SANITY --cidr 172.16.5.0/24
```

---

## Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `-Mode` | Operation mode: `Sanity`, `Migrate`, or `Adopt` | No (prompts if omitted) |
| `-Cidr` | Target subnet (e.g. `192.168.1.0/24`) | No (mutually exclusive with `-IPs`) |
| `-IPs` | Comma-separated IP list | No (mutually exclusive with `-Cidr`) |
| `-Controller` | Target controller IP/hostname | Yes (for Migrate/Adopt) |
| `-Username` | SSH username to try first | No (falls back to factory defaults) |
| `-Password` | SSH password (plaintext) | No |
| `-ResetFirst` | Factory reset before adopt (Adopt mode only) | No |
| `-SshTimeout` | SSH connection timeout (seconds) | No (default: 7) |
| `-ScanTimeout` | TCP scan timeout per host (seconds) | No (default: 3) |
| `-Parallel` | Max parallel scan threads | No (default: 128) |
| `-OutCsv` | CSV output path | No (auto-generated) |

---

## Modes Explained

### SANITY
Read-only scan. Verifies SSH credentials and collects device information. No changes are made.

**Use when:**
- Testing credentials before migration
- Auditing existing devices
- Collecting inventory (MAC, model, firmware, current inform URL)

### MIGRATE
Re-points devices to a new controller by sending `set-inform` commands. **Does not reset or factory wipe devices.**

**Use when:**
- Moving devices between controllers
- Devices are already adopted and configured
- You want to preserve existing configuration

### ADOPT
Full adoption workflow with optional factory reset. Sends `set-inform` commands after optional wipe.

**Use when:**
- Devices are stuck in "pending adoption"
- Previous controller is unreachable/dead
- Clean slate adoption required
- Devices need to be reclaimed from unknown state

---

## How It Works

1. **Dependency Check** - Auto-installs NuGet and Posh-SSH if needed
2. **TCP/22 Scan** - Parallel port sweep to find SSH-accessible devices
3. **SSH Authentication** - Tries provided credentials, then factory defaults (`ubnt/ubnt`, `root/ubnt`)
4. **Device Info Collection** - Pulls MAC, model, firmware, hostname, adopt status, current inform URL
5. **Action Execution:**
   - **SANITY:** Logs info, exits
   - **MIGRATE:** Sends `set-inform` twice for reliability
   - **ADOPT:** Optional factory reset → `set-inform` twice
6. **CSV Export** - Logs all results with timestamps and status

### SSH Shell Streams (v2.1.0+)

**Critical fix:** UniFi devices use a custom shell with built-in commands (`info`, `set-inform`, `mca-cli-op`) that **do NOT work via the standard SSH exec channel**. These are shell builtins, not executables in PATH.

**v2.0.0 and earlier** used `Invoke-SSHCommand` (SSH exec channel), which runs commands in `/bin/sh` — this broke device info collection. You'd see:
- MAC address populated ✓ (because `cat` is a real file)
- Model/Firmware empty ✗ (because `info` didn't run, it's a builtin)
- `set-inform` failing silently ✗ (same reason)

**v2.1.0 fix:**
- Uses **SSH Shell Streams** (interactive shell channel) for UniFi builtins
- `Send-ShellCommand()` function handles the shell prompt cleanup
- `Send-SetInform()` tries both `set-inform` and `mca-cli-op` (works on already-adopted devices)
- Captures raw output in `DebugInfo` column for troubleshooting
- More lenient response matching (doesn't require specific strings, just non-error output)

---

## Output

Results are exported to CSV with the following fields:

- `Timestamp` - When the device was processed
- `IP` - Device IP address
- `MAC` - Device MAC address
- `Connected` - SSH connection success (true/false)
- `Username` - Credential that worked
- `Model` - Device model (e.g. US-8-60W, UAP-AC-PRO)
- `DevHostname` - Device hostname
- `Firmware` - Current firmware version
- `AdoptStatus` - Adoption status from `info` command
- `CurrentInform` - Inform URL before changes
- `Reset` - Reset status (N/A, Requested, OK, Failed)
- `Inform1` - First set-inform response
- `Inform2` - Second set-inform response
- `InformMethod` - Which method worked (`set-inform`, `mca-cli-op`, etc.)
- `Status` - Overall result (OK, CHECK, FAIL)
- `Note` - Error messages or warnings
- `DebugInfo` - Raw output from `info` command (for troubleshooting)

---

## Troubleshooting

**"No hosts found with SSH (TCP/22) open"**
- Verify VLAN/firewall rules allow SSH from scan host
- Check that target subnet is correct
- Ensure devices are powered on and network-accessible

**"SSH auth failed (all credentials)"**
- Verify SSH is enabled on devices
- Check if custom credentials are set (not factory defaults)
- Try providing known credentials with `-Username` and `-Password`

**"Controller inform endpoint unreachable"**
- Verify controller IP/hostname is correct
- Check firewall rules allow port 8080
- Ensure controller is running and reachable from devices

**"Re-login failed post-reset"**
- Factory reset takes 60-90 seconds, script waits 90s
- Device may need more time, try manual SSH after a few minutes
- Network changes during reset may cause connectivity issues

---

## Factory Reset Methods

When `-ResetFirst` is used in ADOPT mode, the script attempts factory reset in this order:

1. **cp/cfgmtd/reboot** - Copies default.cfg → system.cfg, writes with cfgmtd, reboots
2. **syswrapper.sh** - Uses `syswrapper.sh restore-default`
3. **set-default** - Falls back to `set-default` command

Most devices support method 1. Methods 2 and 3 are fallbacks for edge cases.

---

## Security Notes

- Credentials are passed as plaintext parameters (use responsibly)
- Factory defaults are always tried as fallback
- Script requires SSH access (TCP/22)
- No data exfiltration - purely local operation
- CSV logs contain device details (protect accordingly)

---

## Requirements

### PowerShell Version (Windows / PowerShell 7+)
- **PowerShell 5.1+** (Windows) or **PowerShell 7+** (macOS/Linux)
- **Posh-SSH module** (auto-installed if missing)
- **Network access** to target devices via SSH (TCP/22)

### Bash/Zsh Version (macOS/Linux)
- **Bash 4.0+** or **Zsh** (pre-installed on macOS/Linux)
- **Standard Unix tools:** ssh, sshpass, grep, awk, sed
- **Optional:** fzf (better interactive menus), ipcalc (CIDR parsing), expect (shell commands)
- **Network access** to target devices via SSH (TCP/22)

**All versions require:**
- **Controller access** (for Migrate/Adopt modes)

---

## Version History

### v2.1.0 (Current)
**Major fix: SSH Shell Streams for UniFi builtins**
- Fixed critical bug where `info`, `set-inform`, and `mca-cli-op` commands didn't work
- Replaced `Invoke-SSHCommand` (exec channel) with SSH Shell Streams (interactive shell)
- Added `mca-cli-op set-inform` fallback (works on already-adopted devices and newer firmware)
- More lenient response validation (accepts non-standard output if no errors detected)
- Added `DebugInfo` column with raw `info` output for troubleshooting
- Added `InformMethod` column to show which set-inform method succeeded
- Better error handling for ANSI escape codes and shell prompt variations

**What was broken in v2.0.0:**
- MAC addresses populated correctly (because `cat /sys/class/net/eth0/address` is a real file)
- Model/Firmware showed "-" for all devices (because `info` builtin didn't execute)
- `set-inform` often returned "unexpected output" (because the command failed silently)

### v2.0.0
- Initial release with multi-credential support, factory reset, parallel scanning

---

## License

MIT License - Use at your own risk. Not affiliated with Ubiquiti Inc.

---

## Credits

Built by [Spectra](https://github.com/Spectra3609) for network engineers who've had enough of the UI.

**Hunt. Claim. Adopt.** 🜂
