#!/usr/bin/env bash

#
# UniFi Sovereign v3.0.0
# SSH-based device migration & adoption toolkit
# macOS / Linux (Bash 3.2+)
#
# Usage: ./unifi-sovereign.sh [OPTIONS]
#        ./unifi-sovereign.sh --help
#

set -uo pipefail

SCRIPT_VERSION="3.0.1"

# Bash 3.2 compat: BASH_SOURCE may be empty when piped via bash <(curl ...)
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR="$(pwd)"
fi

# ===================================================================
# GLOBAL STATE
# ===================================================================

MODE=""
CIDR=""
IPS_ARG=""
CONTROLLER=""
USERNAME="ubnt"
PASSWORD=""
RESET_FIRST=0
SSH_TIMEOUT=7
SCAN_TIMEOUT=3
OUT_CSV=""
DRY_RUN=0
VERBOSE=0
QUIET=0
NO_COLOR=0
DEPS_CHECKED=0

# ===================================================================
# COLOR & OUTPUT
# ===================================================================

_setup_colors() {
  if [ "$NO_COLOR" -eq 1 ] || [ ! -t 1 ]; then
    RED="" GRN="" YLW="" CYN="" DIM="" BLD="" RST=""
  else
    RED='\033[0;31m'
    GRN='\033[0;32m'
    YLW='\033[1;33m'
    CYN='\033[0;36m'
    DIM='\033[2m'
    BLD='\033[1m'
    RST='\033[0m'
  fi
}

_rule() {
  local label="${1:-}"
  local width=50
  if [ -n "$label" ]; then
    local pad=$(( width - ${#label} - 4 ))
    [ "$pad" -lt 2 ] && pad=2
    printf "\n  ${CYN}── %s " "$label"
    printf '%0.s─' $(seq 1 "$pad")
    printf "${RST}\n\n"
  else
    printf "\n  ${DIM}"
    printf '%0.s─' $(seq 1 "$width")
    printf "${RST}\n\n"
  fi
}

_banner() {
  echo ""
  echo -e "  ${CYN}╭─────────────────────────────────────╮${RST}"
  echo -e "  ${CYN}│${RST}  UniFi Sovereign  ${DIM}v${SCRIPT_VERSION}${RST}            ${CYN}│${RST}"
  echo -e "  ${CYN}│${RST}  SSH Device Migration & Adoption    ${CYN}│${RST}"
  echo -e "  ${CYN}╰─────────────────────────────────────╯${RST}"
  echo ""
}

_info()  { echo -e "  ${CYN}●${RST} $*"; }
_ok()    { echo -e "  ${GRN}●${RST} $*"; }
_warn()  { echo -e "  ${YLW}●${RST} $*"; }
_fail()  { echo -e "  ${RED}●${RST} $*"; }
_opt()   { echo -e "  ${DIM}○${RST} $*"; }
_item()  { echo -e "  ${DIM}▸${RST} $*"; }
_debug() { [ "$VERBOSE" -eq 1 ] && echo -e "  ${DIM}[dbg] $*${RST}"; }

_progress_bar() {
  local current="$1"
  local total="$2"
  local label="${3:-}"
  local width=20

  local pct=0
  [ "$total" -gt 0 ] && pct=$(( current * 100 / total ))
  local filled=$(( pct * width / 100 ))
  local empty=$(( width - filled ))

  local bar=""
  local i=0
  while [ "$i" -lt "$filled" ]; do bar="${bar}▓"; i=$((i+1)); done
  i=0
  while [ "$i" -lt "$empty" ]; do bar="${bar}░"; i=$((i+1)); done

  printf "\r  ${label}${bar}  %3d%%  %d/%d  " "$pct" "$current" "$total"
}

# ===================================================================
# PLATFORM DETECTION
# ===================================================================

_detect_os() {
  local uname_s
  uname_s="$(uname -s)"
  case "$uname_s" in
    Darwin) echo "macos" ;;
    Linux)  echo "linux" ;;
    *)      echo "unknown" ;;
  esac
}

_detect_pkg_manager() {
  if command -v apt-get &>/dev/null; then echo "apt"
  elif command -v dnf &>/dev/null; then echo "dnf"
  elif command -v pacman &>/dev/null; then echo "pacman"
  elif command -v apk &>/dev/null; then echo "apk"
  else echo "unknown"
  fi
}

_has() { command -v "$1" &>/dev/null; }

# ===================================================================
# PREREQUISITE ENGINE
# ===================================================================

_install_homebrew() {
  echo ""
  _info "Homebrew is the standard package manager for macOS."
  _info "It's required to install some dependencies (sshpass, fzf, etc.)."
  echo ""
  local answer
  answer=$(_yes_no "Install Homebrew?" "y")
  if [ "$answer" = "Y" ]; then
    _info "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # shellcheck disable=SC2015
    if _has brew; then
      _ok "Homebrew installed"
    else
      # Try common install paths
      if [ -f /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
      elif [ -f /usr/local/bin/brew ]; then
        eval "$(/usr/local/bin/brew shellenv)"
      fi
      if _has brew; then
        _ok "Homebrew installed"
      else
        _fail "Homebrew installation may have failed. Check manually."
        return 1
      fi
    fi
  else
    _warn "Skipping Homebrew. Some dependencies may require manual installation."
    return 1
  fi
}

_install_pkg() {
  local pkg="$1"
  local os="$2"
  local mgr="$3"

  case "$os" in
    macos)
      if _has brew; then
        _info "Installing ${pkg} via Homebrew..."
        brew install "$pkg" 2>/dev/null
      else
        _warn "Cannot install ${pkg}: Homebrew not available"
        return 1
      fi
      ;;
    linux)
      case "$mgr" in
        apt)    _info "Installing ${pkg}..."; sudo apt-get install -y "$pkg" 2>/dev/null ;;
        dnf)    _info "Installing ${pkg}..."; sudo dnf install -y "$pkg" 2>/dev/null ;;
        pacman) _info "Installing ${pkg}..."; sudo pacman -S --noconfirm "$pkg" 2>/dev/null ;;
        apk)    _info "Installing ${pkg}..."; sudo apk add "$pkg" 2>/dev/null ;;
        *)      _warn "Unknown package manager. Install ${pkg} manually."; return 1 ;;
      esac
      ;;
  esac
}

# Map tool names to package names per manager
_pkg_name() {
  local tool="$1"
  local os="$2"
  local mgr="$3"

  case "$tool" in
    ssh)
      case "$mgr" in
        apt)    echo "openssh-client" ;;
        dnf)    echo "openssh-clients" ;;
        pacman) echo "openssh" ;;
        apk)    echo "openssh-client" ;;
        *)      echo "openssh" ;;
      esac
      ;;
    sshpass) echo "sshpass" ;;
    python3)
      case "$mgr" in
        pacman) echo "python" ;;
        *)      echo "python3" ;;
      esac
      ;;
    fzf)    echo "fzf" ;;
    ipcalc) echo "ipcalc" ;;
    expect) echo "expect" ;;
    *)      echo "$tool" ;;
  esac
}

check_prerequisites() {
  [ "$DEPS_CHECKED" -eq 1 ] && return 0
  DEPS_CHECKED=1

  local os mgr
  os="$(_detect_os)"
  mgr=""
  [ "$os" = "linux" ] && mgr="$(_detect_pkg_manager)"
  [ "$os" = "macos" ] && mgr="brew"

  _rule "Prerequisites"
  _info "Platform: ${os}$([ -n "$mgr" ] && echo " ($mgr)")"
  echo ""

  # Check Homebrew on macOS
  if [ "$os" = "macos" ] && ! _has brew; then
    _warn "Homebrew not found"
    _install_homebrew || true
    echo ""
  fi

  # Required dependencies
  local required_tools="ssh sshpass grep awk sed python3"
  local optional_tools="fzf expect"
  local missing_required=""
  local missing_optional=""

  for tool in $required_tools; do
    if _has "$tool"; then
      _ok "$(printf '%-12s' "$tool") installed"
    else
      _fail "$(printf '%-12s' "$tool") missing"
      missing_required="${missing_required} ${tool}"
    fi
  done

  echo ""

  for tool in $optional_tools; do
    if _has "$tool"; then
      _ok "$(printf '%-12s' "$tool") installed"
    else
      _opt "$(printf '%-12s' "$tool") not found ${DIM}(optional)${RST}"
      missing_optional="${missing_optional} ${tool}"
    fi
  done

  # Install missing required
  if [ -n "$missing_required" ]; then
    echo ""
    _warn "Missing required:${missing_required}"
    local answer
    answer=$(_yes_no "Install missing dependencies?" "y")
    if [ "$answer" = "Y" ]; then
      for tool in $missing_required; do
        local pkg
        pkg="$(_pkg_name "$tool" "$os" "$mgr")"
        _install_pkg "$pkg" "$os" "$mgr"
      done
      # Re-check
      for tool in $missing_required; do
        if ! _has "$tool"; then
          _fail "${tool} still not available after install attempt."
          _fail "Install it manually and re-run."
          exit 1
        fi
      done
      _ok "All required dependencies installed"
    else
      _fail "Cannot continue without required dependencies."
      exit 1
    fi
  fi

  # Offer to install optional
  if [ -n "$missing_optional" ]; then
    echo ""
    local answer
    answer=$(_yes_no "Install optional dependencies?${missing_optional}" "n")
    if [ "$answer" = "Y" ]; then
      for tool in $missing_optional; do
        local pkg
        pkg="$(_pkg_name "$tool" "$os" "$mgr")"
        _install_pkg "$pkg" "$os" "$mgr" || true
      done
    fi
  fi

  echo ""
  _ok "Ready"
}

# ===================================================================
# INTERACTIVE PROMPTS
# ===================================================================

_menu() {
  local prompt="$1"
  shift
  local options=("$@")

  if _has fzf; then
    local selected
    selected=$(printf '%s\n' "${options[@]}" | fzf --height=40% --border --prompt="  ${prompt} " --no-preview)
    echo "$selected"
    return 0
  fi

  echo ""
  echo -e "  ${BLD}${prompt}${RST}"
  echo ""
  local i=0
  for opt in "${options[@]}"; do
    i=$((i + 1))
    echo "    [${i}] ${opt}"
  done
  echo ""

  local choice
  read -r -p "    Choice [1]: " choice
  choice="${choice:-1}"

  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
    echo "${options[$((choice - 1))]}"
  else
    _fail "Invalid choice"
    _menu "$prompt" "${options[@]}"
  fi
}

_input() {
  local prompt="$1"
  local default="${2:-}"
  local input

  if [ -n "$default" ]; then
    read -r -p "    ${prompt} [${default}]: " input
    echo "${input:-$default}"
  else
    while true; do
      read -r -p "    ${prompt}: " input
      if [ -n "$input" ]; then
        echo "$input"
        return
      fi
      _warn "Cannot be blank"
    done
  fi
}

_password() {
  local prompt="$1"
  local pass
  read -r -s -p "    ${prompt}: " pass
  echo ""
  echo "$pass"
}

_yes_no() {
  local prompt="$1"
  local default="${2:-n}"
  local input
  read -r -p "    ${prompt} [${default}]: " input
  input="${input:-$default}"
  case "$input" in
    [Yy]*) echo "Y" ;;
    *)     echo "N" ;;
  esac
}

# ===================================================================
# CIDR EXPANSION
# ===================================================================

cidr_to_ips() {
  local cidr="$1"
  python3 -c "
import ipaddress, sys
try:
    net = ipaddress.ip_network('${cidr}', strict=False)
    for ip in net.hosts():
        print(str(ip))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

# ===================================================================
# SSH FUNCTIONS
# ===================================================================

_ssh_exec() {
  local ip="$1" user="$2" pass="$3" cmd="$4" tout="${5:-7}"
  if [ -n "$pass" ]; then
    timeout "$tout" sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      -o BatchMode=no \
      "$user@$ip" "$cmd" 2>/dev/null || true
  else
    timeout "$tout" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      "$user@$ip" "$cmd" 2>/dev/null || true
  fi
}

_ssh_shell() {
  local ip="$1" user="$2" pass="$3" cmd="$4" tout="${5:-14}"

  if _has expect; then
    expect -c "
      log_user 0
      set timeout $tout
      spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $user@$ip
      expect {
        \"*assword*\" { send \"$pass\r\"; exp_continue }
        \"*#*\" { }
        timeout { exit 1 }
      }
      send \"$cmd\r\"
      expect \"*#*\"
      set output \$expect_out(buffer)
      send \"exit\r\"
      expect eof
      puts \$output
    " 2>/dev/null || true
  else
    # Fallback: pipe command into interactive SSH
    echo "$cmd" | timeout "$tout" sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      -tt "$user@$ip" 2>/dev/null || true
  fi
}

_test_ssh() {
  local ip="$1" user="$2" pass="$3" tout="${4:-7}"
  local result
  result=$(_ssh_exec "$ip" "$user" "$pass" "echo __ALIVE__" "$tout")
  case "$result" in
    *__ALIVE__*) return 0 ;;
    *)           return 1 ;;
  esac
}

_get_device_info() {
  local ip="$1" user="$2" pass="$3" tout="${4:-14}"
  local output

  # Try interactive shell first (for UniFi builtins)
  output=$(_ssh_shell "$ip" "$user" "$pass" "info" "$tout")

  if [ -z "$output" ]; then
    # Fallback to exec channel
    output=$(_ssh_exec "$ip" "$user" "$pass" "info" "$tout")
  fi

  # Parse fields from info output
  local model firmware hostname mac status inform_url

  model=$(echo "$output" | grep -i '^Model:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//' | cut -c1-30)
  firmware=$(echo "$output" | grep -i '^Version:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')
  hostname=$(echo "$output" | grep -i '^Hostname:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')
  mac=$(echo "$output" | grep -ioE '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}' | head -1)
  status=$(echo "$output" | grep -i '^Status:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')
  inform_url=$(echo "$output" | grep -i 'Inform.*URL' | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')

  # MAC fallback: try system files
  if [ -z "$mac" ]; then
    mac=$(_ssh_exec "$ip" "$user" "$pass" "cat /sys/class/net/eth0/address 2>/dev/null || cat /sys/class/net/br0/address 2>/dev/null" "$tout" | grep -ioE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
  fi

  # Write to temp file for caller
  local tmpfile="${TMPDIR:-/tmp}/usov_info_$$"
  cat > "$tmpfile" <<DEVEOF
MODEL=${model:-}
FIRMWARE=${firmware:-}
HOSTNAME=${hostname:-}
MAC=${mac:-}
STATUS=${status:-}
INFORM_URL=${inform_url:-}
DEVEOF
  # Raw output on separate lines, sanitized
  echo "RAW_OUTPUT<<RAWEOF" >> "$tmpfile"
  echo "$output" | tr -cd '[:print:]\n' | head -50 >> "$tmpfile"
  echo "RAWEOF" >> "$tmpfile"

  echo "$tmpfile"
}

_read_info_field() {
  local file="$1" field="$2"
  grep "^${field}=" "$file" 2>/dev/null | head -1 | sed "s/^${field}=//"
}

_read_info_raw() {
  local file="$1"
  sed -n '/^RAW_OUTPUT<<RAWEOF$/,/^RAWEOF$/p' "$file" 2>/dev/null | sed '1d;$d'
}

_send_set_inform() {
  local ip="$1" user="$2" pass="$3" url="$4" tout="${5:-14}"

  local output1 output2

  # Try set-inform (shell builtin)
  output1=$(_ssh_shell "$ip" "$user" "$pass" "set-inform $url" "$tout")
  _debug "set-inform output: $output1"

  if echo "$output1" | grep -iqE 'adoption|inform|request|accepted'; then
    echo "METHOD=set-inform"
    echo "SUCCESS=1"
    echo "OUTPUT=$output1"
    return 0
  fi

  # Try mca-cli-op fallback (adopted devices / newer firmware)
  output2=$(_ssh_shell "$ip" "$user" "$pass" "mca-cli-op set-inform $url" "$tout")
  _debug "mca-cli-op output: $output2"

  if echo "$output2" | grep -iqE 'adoption|inform|request|accepted'; then
    echo "METHOD=mca-cli-op"
    echo "SUCCESS=1"
    echo "OUTPUT=$output2"
    return 0
  fi

  # Accept if no explicit error
  local combined="${output1} ${output2}"
  if ! echo "$combined" | grep -iqE 'not found|unknown command|error|denied|invalid'; then
    echo "METHOD=set-inform+mca-cli-op"
    echo "SUCCESS=1"
    echo "OUTPUT=$combined"
    return 0
  fi

  echo "METHOD=none"
  echo "SUCCESS=0"
  echo "OUTPUT=$combined"
  return 1
}

_send_factory_reset() {
  local ip="$1" user="$2" pass="$3" tout="${4:-14}"

  _debug "Attempting factory reset on $ip"

  # Method 1: cp + cfgmtd + reboot
  local r1
  r1=$(_ssh_shell "$ip" "$user" "$pass" "cp /etc/default.cfg /tmp/system.cfg && cfgmtd -w -p /etc/ && reboot" "$tout")
  if [ $? -eq 0 ]; then
    echo "METHOD=cfgmtd"
    return 0
  fi

  # Method 2: syswrapper
  local r2
  r2=$(_ssh_shell "$ip" "$user" "$pass" "syswrapper.sh restore-default" "$tout")
  if [ $? -eq 0 ]; then
    echo "METHOD=syswrapper"
    return 0
  fi

  # Method 3: set-default
  local r3
  r3=$(_ssh_shell "$ip" "$user" "$pass" "set-default" "$tout")
  if [ $? -eq 0 ]; then
    echo "METHOD=set-default"
    return 0
  fi

  echo "METHOD=none"
  return 1
}

# ===================================================================
# PORT SCANNING
# ===================================================================

_port_scan() {
  local ips=("$@")
  local total=${#ips[@]}
  local current=0
  local found=()

  _rule "Port Scan (TCP/22)"
  _info "Scanning ${total} hosts..."
  echo ""

  for ip in "${ips[@]}"; do
    current=$((current + 1))
    _progress_bar "$current" "$total" "Scanning "

    if timeout "$SCAN_TIMEOUT" bash -c "cat < /dev/null > /dev/tcp/$ip/22" 2>/dev/null; then
      found+=("$ip")
    fi
  done

  echo ""
  echo ""

  if [ ${#found[@]} -eq 0 ]; then
    _fail "No hosts with SSH (TCP/22) open"
    exit 1
  fi

  _ok "${#found[@]} hosts with SSH open"

  printf '%s\n' "${found[@]}"
}

# ===================================================================
# CSV OUTPUT
# ===================================================================

_csv_init() {
  local outfile="$1"
  local mode="$2"
  local target_count="$3"

  cat > "$outfile" <<CSVHDR
# UniFi Sovereign v${SCRIPT_VERSION} | Mode: ${mode} | Targets: ${target_count} | Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Timestamp,IP,MAC,Connected,Username,Model,DevHostname,Firmware,AdoptStatus,CurrentInform,Reset,Inform1,Inform2,InformMethod,Status,Note,DebugInfo
CSVHDR
}

_csv_escape() {
  local val="$1"
  val="${val//\"/\"\"}"
  echo "\"$val\""
}

_csv_row() {
  local outfile="$1"
  local timestamp="$2" ip="$3" mac="$4" connected="$5" username="$6"
  local model="$7" devhostname="$8" firmware="$9"
  shift 9
  local adopt_status="$1" current_inform="$2" reset="$3"
  local inform1="$4" inform2="$5" inform_method="$6"
  local status="$7" note="$8" debug_info="$9"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(_csv_escape "$timestamp")" \
    "$(_csv_escape "$ip")" \
    "$(_csv_escape "$mac")" \
    "$connected" \
    "$(_csv_escape "$username")" \
    "$(_csv_escape "$model")" \
    "$(_csv_escape "$devhostname")" \
    "$(_csv_escape "$firmware")" \
    "$(_csv_escape "$adopt_status")" \
    "$(_csv_escape "$current_inform")" \
    "$(_csv_escape "$reset")" \
    "$(_csv_escape "$inform1")" \
    "$(_csv_escape "$inform2")" \
    "$(_csv_escape "$inform_method")" \
    "$status" \
    "$(_csv_escape "$note")" \
    "$(_csv_escape "$debug_info")" \
    >> "$outfile"
}

# ===================================================================
# MAIN
# ===================================================================

main() {
  _setup_colors
  _banner

  if [ "$DRY_RUN" -eq 1 ]; then
    _warn "DRY RUN — no changes will be made"
    echo ""
  fi

  check_prerequisites

  # ── Mode ──
  if [ -z "$MODE" ]; then
    MODE=$(_menu "Operation mode:" \
      "SANITY   — verify SSH access, collect device info (read-only)" \
      "MIGRATE  — re-point devices to a new controller (no reset)" \
      "ADOPT    — full adoption with optional factory reset")
    MODE=$(echo "$MODE" | awk '{print $1}')
  fi
  MODE=$(echo "$MODE" | tr '[:lower:]' '[:upper:]')

  _rule "Configuration"
  _info "Mode: ${BLD}${MODE}${RST}"

  # ── Targets ──
  local target_ips=()

  if [ -n "$CIDR" ]; then
    while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(cidr_to_ips "$CIDR")
  elif [ -n "$IPS_ARG" ]; then
    while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(echo "$IPS_ARG" | tr ',' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
  else
    local input_type
    input_type=$(_menu "Target input:" \
      "CIDR subnet  (e.g. 192.168.1.0/24)" \
      "IP list      (comma-separated)")
    if echo "$input_type" | grep -qi "list"; then
      local ips_str
      ips_str=$(_input "IPs (comma-separated)")
      while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(echo "$ips_str" | tr ',' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    else
      CIDR=$(_input "CIDR (e.g. 192.168.1.0/24)")
      while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(cidr_to_ips "$CIDR")
    fi
  fi

  if [ ${#target_ips[@]} -eq 0 ]; then
    _fail "No valid target IPs"
    exit 1
  fi
  _info "Targets: ${#target_ips[@]} IPs"

  # ── Controller ──
  local controller_url=""
  if [ "$MODE" = "MIGRATE" ] || [ "$MODE" = "ADOPT" ]; then
    if [ -z "$CONTROLLER" ]; then
      CONTROLLER=$(_input "Target controller IP or hostname")
    fi
    controller_url="http://${CONTROLLER}:8080/inform"
    _info "Inform URL: ${controller_url}"

    if [ "$MODE" = "ADOPT" ] && [ "$RESET_FIRST" -eq 0 ]; then
      local do_reset
      do_reset=$(_yes_no "Factory reset before adoption?" "n")
      [ "$do_reset" = "Y" ] && RESET_FIRST=1
    fi
    [ "$RESET_FIRST" -eq 1 ] && _warn "Factory reset: ENABLED"
  fi

  # ── Credentials ──
  _rule "Credentials"

  local cred_users=()
  local cred_passes=()

  if [ -n "$PASSWORD" ]; then
    cred_users+=("$USERNAME")
    cred_passes+=("$PASSWORD")
  else
    local add_cred
    add_cred=$(_yes_no "Provide a known SSH credential?" "n")
    if [ "$add_cred" = "Y" ]; then
      local u p
      u=$(_input "SSH username")
      p=$(_password "SSH password")
      cred_users+=("$u")
      cred_passes+=("$p")
    fi
  fi

  # Factory defaults (always tried as fallback)
  cred_users+=("ubnt" "root" "admin")
  cred_passes+=("ubnt" "ubnt" "ubnt")

  _info "Credential chain: $(echo "${cred_users[@]}" | tr ' ' ', ')"

  # ── CSV Output ──
  if [ -z "$OUT_CSV" ]; then
    local default_csv="unifi-$(echo "$MODE" | tr '[:upper:]' '[:lower:]')-$(date +%Y%m%d-%H%M%S).csv"
    OUT_CSV=$(_input "CSV output path" "$default_csv")
  fi

  # ── Plan Summary ──
  _rule "Plan"
  _item "Mode:        ${MODE}"
  _item "Targets:     ${#target_ips[@]} IPs"
  if [ -n "$controller_url" ]; then
    _item "Controller:  ${CONTROLLER}"
    _item "Inform URL:  ${controller_url}"
  fi
  [ "$RESET_FIRST" -eq 1 ] && _item "Reset First: ${RED}YES${RST}"
  _item "SSH Timeout: ${SSH_TIMEOUT}s"
  _item "Output:      ${OUT_CSV}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo ""
    _warn "DRY RUN — stopping before execution"
    exit 0
  fi

  echo ""
  local confirm
  confirm=$(_yes_no "Execute?" "y")
  if [ "$confirm" != "Y" ]; then
    echo ""
    _info "Aborted."
    exit 0
  fi

  # ── Port Scan ──
  local open_hosts=()
  local open_hosts=()
  while IFS= read -r _ip; do open_hosts+=("$_ip"); done < <(_port_scan "${target_ips[@]}")

  # ── Process Devices ──
  _rule "Processing (${MODE})"

  _csv_init "$OUT_CSV" "$MODE" "${#open_hosts[@]}"

  local total=${#open_hosts[@]}
  local current=0
  local count_ok=0 count_check=0 count_fail=0

  for ip in "${open_hosts[@]}"; do
    current=$((current + 1))

    # Try credentials
    local connected="false"
    local used_user="" used_pass=""

    local ci=0
    for ci_user in "${cred_users[@]}"; do
      local ci_pass="${cred_passes[$ci]}"

      # Retry once on failure
      if _test_ssh "$ip" "$ci_user" "$ci_pass" "$SSH_TIMEOUT"; then
        connected="true"
        used_user="$ci_user"
        used_pass="$ci_pass"
        break
      fi
      # One retry with short backoff
      sleep 1
      if _test_ssh "$ip" "$ci_user" "$ci_pass" "$SSH_TIMEOUT"; then
        connected="true"
        used_user="$ci_user"
        used_pass="$ci_pass"
        break
      fi

      ci=$((ci + 1))
    done

    # Init row vars
    local r_ts r_mac r_model r_host r_fw r_adopt r_inform
    local r_reset="N/A" r_inf1="N/A" r_inf2="N/A" r_method="" r_status="FAIL" r_note="" r_debug=""

    r_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    if [ "$connected" = "false" ]; then
      r_note="SSH auth failed"
      _item "${ip}  ${DIM}---${RST}  ${RED}[FAIL]${RST}  SSH auth failed"
      count_fail=$((count_fail + 1))
      _csv_row "$OUT_CSV" "$r_ts" "$ip" "" "false" "" "" "" "" "" "" "$r_reset" "$r_inf1" "$r_inf2" "" "FAIL" "$r_note" ""
      continue
    fi

    # Get device info
    local info_file
    info_file=$(_get_device_info "$ip" "$used_user" "$used_pass" "$((SSH_TIMEOUT * 2))")

    r_mac=$(_read_info_field "$info_file" "MAC")
    r_model=$(_read_info_field "$info_file" "MODEL")
    r_host=$(_read_info_field "$info_file" "HOSTNAME")
    r_fw=$(_read_info_field "$info_file" "FIRMWARE")
    r_adopt=$(_read_info_field "$info_file" "STATUS")
    r_inform=$(_read_info_field "$info_file" "INFORM_URL")
    r_debug=$(_read_info_raw "$info_file" | head -5 | tr '\n' ' ')

    rm -f "$info_file"

    local display_model="${r_model:-${DIM}---${RST}}"

    # SANITY mode: done
    if [ "$MODE" = "SANITY" ]; then
      r_status="OK"
      count_ok=$((count_ok + 1))
      _item "${ip}  ${display_model}  ${GRN}[OK]${RST}  ${DIM}${r_adopt:-unknown}${RST}"
      _csv_row "$OUT_CSV" "$r_ts" "$ip" "$r_mac" "true" "$used_user" \
        "$r_model" "$r_host" "$r_fw" "$r_adopt" "$r_inform" \
        "$r_reset" "$r_inf1" "$r_inf2" "$r_method" "OK" "" "$r_debug"
      continue
    fi

    # ADOPT: optional factory reset
    if [ "$MODE" = "ADOPT" ] && [ "$RESET_FIRST" -eq 1 ]; then
      local reset_out
      reset_out=$(_send_factory_reset "$ip" "$used_user" "$used_pass" "$((SSH_TIMEOUT * 2))")
      local reset_method
      reset_method=$(echo "$reset_out" | grep '^METHOD=' | sed 's/METHOD=//')
      if [ "$reset_method" != "none" ]; then
        r_reset="OK ($reset_method)"
        _debug "Reset OK: $reset_method"
        # Wait for device to come back
        _info "${ip}: Reset sent, waiting 90s for reboot..."
        sleep 90
        # Re-test SSH with factory defaults
        used_user="ubnt"
        used_pass="ubnt"
        if ! _test_ssh "$ip" "$used_user" "$used_pass" "$SSH_TIMEOUT"; then
          r_reset="Sent (device not back yet)"
          r_note="Reset sent but device didn't come back within 90s"
          _warn "${ip}: Device not back after reset"
        fi
      else
        r_reset="Failed"
        r_note="Factory reset failed (all methods)"
        _warn "${ip}: Reset failed"
      fi
    fi

    # MIGRATE / ADOPT: send set-inform
    if [ "$MODE" = "MIGRATE" ] || [ "$MODE" = "ADOPT" ]; then
      local inform_out
      inform_out=$(_send_set_inform "$ip" "$used_user" "$used_pass" "$controller_url" "$((SSH_TIMEOUT * 2))" 2>&1) || true

      local inf_method inf_success inf_output
      inf_method=$(echo "$inform_out" | grep '^METHOD=' | sed 's/METHOD=//')
      inf_success=$(echo "$inform_out" | grep '^SUCCESS=' | sed 's/SUCCESS=//')
      inf_output=$(echo "$inform_out" | grep '^OUTPUT=' | sed 's/OUTPUT=//')

      r_inf1="$inf_output"
      r_method="$inf_method"

      # Send a second time for reliability
      local inform_out2
      inform_out2=$(_send_set_inform "$ip" "$used_user" "$used_pass" "$controller_url" "$((SSH_TIMEOUT * 2))" 2>&1) || true
      r_inf2=$(echo "$inform_out2" | grep '^OUTPUT=' | sed 's/OUTPUT=//')

      if [ "$inf_success" = "1" ]; then
        r_status="OK"
        count_ok=$((count_ok + 1))
        _item "${ip}  ${display_model}  ${GRN}[OK]${RST}  set-inform accepted (${inf_method})"
      else
        r_status="CHECK"
        count_check=$((count_check + 1))
        r_note="${r_note}${r_note:+; }set-inform may have failed"
        _item "${ip}  ${display_model}  ${YLW}[CHECK]${RST}  verify in controller"
      fi

      _csv_row "$OUT_CSV" "$r_ts" "$ip" "$r_mac" "true" "$used_user" \
        "$r_model" "$r_host" "$r_fw" "$r_adopt" "$r_inform" \
        "$r_reset" "$r_inf1" "$r_inf2" "$r_method" "$r_status" "$r_note" "$r_debug"
    fi
  done

  # ── Summary ──
  _rule "Results"

  local total_processed=$((count_ok + count_check + count_fail))

  _item "Total scanned:     ${total}"
  _item "SSH accessible:    ${total_processed}"
  _item "Successful:        ${GRN}${count_ok}${RST}"
  [ "$count_check" -gt 0 ] && _item "Needs attention:   ${YLW}${count_check}${RST}"
  [ "$count_fail" -gt 0 ] && _item "Failed:            ${RED}${count_fail}${RST}"
  echo ""
  _item "Output: ${OUT_CSV}"

  echo ""
  case "$MODE" in
    SANITY)  _ok "Sanity check complete." ;;
    MIGRATE) _ok "Migration complete. Devices should check in with ${CONTROLLER} shortly." ;;
    ADOPT)   _ok "Adoption run complete. Watch for pending devices in the controller." ;;
  esac
  echo ""
}

# ===================================================================
# ARGUMENT PARSING
# ===================================================================

_show_help() {
  cat <<HELPEOF

  UniFi Sovereign v${SCRIPT_VERSION}
  SSH Device Migration & Adoption Toolkit

  USAGE
    $(basename "$0") [OPTIONS]

  OPTIONS
    --mode MODE          SANITY | MIGRATE | ADOPT
    --cidr SUBNET        Target subnet (e.g. 192.168.1.0/24)
    --ips IP1,IP2,...    Comma-separated IP list
    --controller IP      Target controller IP/hostname
    --username USER      SSH username (default: ubnt)
    --password PASS      SSH password
    --reset              Factory reset before adoption (ADOPT only)
    --ssh-timeout SEC    SSH timeout in seconds (default: 7)
    --scan-timeout SEC   Port scan timeout per host (default: 3)
    --output FILE        CSV output path
    --dry-run            Show plan without executing
    --verbose, -v        Show debug output
    --quiet, -q          Minimal output
    --no-color           Disable ANSI colors
    --version            Print version and exit
    --help, -h           Show this help

  EXAMPLES
    # Interactive mode (recommended first run)
    $(basename "$0")

    # Migrate a /24 subnet to new controller
    $(basename "$0") --mode MIGRATE --cidr 192.168.1.0/24 --controller 10.0.0.5

    # Sanity check specific IPs
    $(basename "$0") --mode SANITY --ips 192.168.1.100,192.168.1.101

    # Adopt with factory reset, verbose
    $(basename "$0") --mode ADOPT --cidr 10.0.1.0/24 --controller 10.0.0.5 --reset -v

HELPEOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode)        MODE="$2"; shift 2 ;;
    --cidr)        CIDR="$2"; shift 2 ;;
    --ips)         IPS_ARG="$2"; shift 2 ;;
    --controller)  CONTROLLER="$2"; shift 2 ;;
    --username)    USERNAME="$2"; shift 2 ;;
    --password)    PASSWORD="$2"; shift 2 ;;
    --reset)       RESET_FIRST=1; shift ;;
    --ssh-timeout) SSH_TIMEOUT="$2"; shift 2 ;;
    --scan-timeout) SCAN_TIMEOUT="$2"; shift 2 ;;
    --output)      OUT_CSV="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --verbose|-v)  VERBOSE=1; shift ;;
    --quiet|-q)    QUIET=1; shift ;;
    --no-color)    NO_COLOR=1; shift ;;
    --version)     echo "UniFi Sovereign v${SCRIPT_VERSION}"; exit 0 ;;
    --help|-h)     _show_help; exit 0 ;;
    *)             echo "Unknown option: $1"; echo "Try --help"; exit 1 ;;
  esac
done

main
