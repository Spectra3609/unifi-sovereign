# UniFi Sovereign — Platform Versions

Choose the right version for your OS:

## Windows (PowerShell)

**File:** `unifi-sovereign.ps1`

**Requires:**
- PowerShell 5.1+ (Windows) or 7+ (if on Windows)
- Posh-SSH module (auto-installs)
- Internet connection (first run)

**Features:**
- Parallel TCP/22 scanning
- Interactive prompts with validation
- Full factory reset cascade (3 methods)
- Comprehensive CSV output with DebugInfo column
- Shell stream support for UniFi builtins

**Run:**
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\unifi-sovereign.ps1
```

---

## macOS / Linux (Bash/Zsh)

**File:** `unifi-sovereign.sh`

**Requires:**
- Bash 4.0+ or Zsh (macOS has both pre-installed)
- Standard Unix tools: `ssh`, `sshpass`, `grep`, `awk`, `sed`
- Optional: `fzf` (for better interactive menus)
- Optional: `ipcalc` (for CIDR expansion; falls back to Python)
- Optional: `expect` (for better shell command execution)

**Features:**
- ANSI color output (works in Terminal.app, iTerm2, Linux terminals)
- Interactive menus (with fzf if installed, else numbered)
- Port scanning with progress indicator
- Full CSV output with DebugInfo column
- Cross-platform compatible

**Install Dependencies:**

**macOS (Homebrew):**
```bash
brew install openssh ssh-keyscan  # Core
brew install fzf ipcalc expect    # Optional (nice to have)
```

**Ubuntu/Debian:**
```bash
sudo apt-get install openssh-client openssh-server  # Core
sudo apt-get install sshpass fzf ipcalc expect      # Optional
```

**Run:**
```bash
chmod +x unifi-sovereign.sh
./unifi-sovereign.sh
```

---

## Comparison

| Feature | PowerShell | Bash/Zsh |
|---------|-----------|----------|
| **Platforms** | Windows, macOS, Linux | macOS, Linux |
| **Interactive Menus** | Built-in UI | CLI (enhanced with fzf) |
| **Parallel Scanning** | Yes (runspaces) | Sequential (fast enough) |
| **Shell Streams** | Posh-SSH | Expect (if available) |
| **CIDR Parsing** | Built-in | ipcalc or Python fallback |
| **CSV Output** | Full | Full |
| **Color Output** | Limited | ANSI (rich) |
| **Package Mgmt** | PowerShell Gallery | Homebrew / APT |

---

## Recommended Setup

### Development / Homelab
- **Primary:** Bash version on a Linux VM or macOS
- **Fallback:** PowerShell version if you have a Windows machine
- Run from a central spot with SSH access to all UniFi devices

### Production / Enterprise
- Use **PowerShell version on Windows** (more mature, tested)
- Run from a bastion host or admin workstation
- Schedule runs via Task Scheduler / cron

### Quick Testing
- **macOS/Linux:** Bash version (already have ssh)
- **Windows:** PowerShell version (no extra installs needed after Posh-SSH)

---

## Troubleshooting

### "ssh: command not found"
- **macOS:** `brew install openssh`
- **Linux:** `sudo apt-get install openssh-client`
- **Windows:** Use PowerShell version instead

### "sshpass: command not found"
- **macOS:** `brew install sshpass`
- **Linux:** `sudo apt-get install sshpass`
- Note: If you have SSH keys configured, sshpass is optional

### "fzf not found (interactive menus disabled)"
- This is optional. Script falls back to numbered menus.
- To enable: `brew install fzf` (macOS) or `apt-get install fzf` (Linux)

### SSH Key Auth Instead of Passwords
Both versions support SSH keys. Set up your `.ssh/config`:
```
Host 192.168.*
  User ubnt
  IdentityFile ~/.ssh/unifi_key
  StrictHostKeyChecking no
```

Then run **Bash version** without `--password`:
```bash
./unifi-sovereign.sh --mode SANITY --cidr 192.168.1.0/24
```

---

## Version History

### v2.1.0 (Both)
- SSH Shell Streams for UniFi builtins (info/set-inform/mca-cli-op)
- Added mca-cli-op fallback (works on already-adopted devices)
- DebugInfo column with raw command output
- Better error handling and validation

### v2.0.0
- PowerShell version (Windows-only initially)
- Multi-credential rotation
- Factory reset cascade
- CSV logging

---

## Contributing

**Issues specific to:**
- **PowerShell:** Check Posh-SSH version, Windows firewall
- **Bash/Zsh:** Check ssh version, sshpass installation, target device shell

Always run `--help` first to verify your environment is ready.
